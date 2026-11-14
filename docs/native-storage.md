# Native storage boundary (hfdrive-hf)

`crates/hfdrive-hf` is the only crate that speaks to the official `hf-hub` Git
revision (`473de9430b0fbc544fb1d91102180eb713f8dc87`) and `hf-xet` 1.8.1. No
SDK type escapes it; consumers see `hfdrive_core` identities, `hfdrive_auth`
authorization handles, and the sanitized types of this crate. It emits no log
records, and its errors never carry bearer tokens, CAS/CDN or presigned URL
material, SDK error strings, or response bodies.

## Surfaces

- `NativeApi<T: TokenSource>` — one account's native API handle: the shared
  token source (static dispatch over the RPITIT `TokenSource` contract; the
  provider's concrete `T` is `AuthManager`), one shared rustls transport, and
  immutable SDK clients keyed by credential generation. `capture_lease()` hands
  out the operation lease (`NativeLease`: epoch + account identity) that every
  dispatch re-checks immediately before a request leaves the process. A 401
  response triggers exactly one controlled refresh
  (`TokenSource::refresh_after_unauthorized`) and one retry; nothing loops.
  After rotation the hf-hub client and the bucket Xet read groups are rebuilt.
- `NativeControl` — namespace control plane. All of it works from a
  `BucketBinding` + `RemotePrefix` **before any workspace identity exists** and
  never creates a Xet session or cache directory:
  - `list_buckets` / `resolve_bucket` / `create_bucket` — verified identity.
    Every returned record is checked against the requested canonical
    namespace (the validated `AuthProfile.namespace`; an organization's
    display `name` is never used) and bare bucket name; the stable service
    `_id` is the identity that survives display renames. A live `_id` differing
    from the expected one is `IdentityMismatch`, never silently re-bound.
    `resolve_bucket` returns `None` for a real 404. Creation is always
    `private: true`, optionally with the documented `region: "us" | "eu"`;
    HTTP 409 is `AlreadyExists` and is **never** ownership proof or adoption.
  - `inspect_prefix` — verified bucket identity plus bounded prefix
    emptiness: `Missing` (bucket itself unavailable), `Empty`, `Populated`
    (+ bounded entry sample). Unreadable prefixes surface as errors and are
    never reported as empty.
  - `read_head_record` — bounded native read of the mutable managed HEAD
    record at `<prefix>/HEAD`, small-record-only (default bound 16 KiB). It is
    not a payload HTTP fallback and never reads whole payloads. Result:
    `Missing` **only** on a real 404; `TooLarge { size }` for records over the
    bound (not read); `Record(HeadRecord)` carrying the exact bounded bytes
    plus a format classification (`V1 { workspace_id }`, `Newer
    { schema_version }`, `Foreign`). An unsupported or oversized HEAD is never
    treated as an empty workspace; the setup coordinator decides between
    binding to the decoded workspace id and reserving an explicit
    initialization with a fresh UUID.
  - `object_metadata`, `check_native_read`, `check_native_write` — metadata
    lookup and real authorization probes usable before every publication
    transaction. The write probe hits the documented `xet-write-token` route
    (write permission required) and discards the body without reading it.
  - `open_store(DriveBinding)` — the storage plane; rejects a binding whose
    `account_key` differs from the API account.
- `NativeBucketStore` — drive-bound storage plane:
  - `list_tree_page` / `list_tree` — tree listing with `Link rel="next"`
    pagination confined to the API origin and the bucket's API prefix;
    persisted cursors are re-validated on every use. `list_tree` never returns
    a partial listing silently (`TooManyEntries` on the configured bound).
  - `paths_info` — chunked at the service's 1000-path limit with per-key
    reconciliation: found entries plus explicitly missing keys. A missing key
    is an observed absence at lookup time, never a deletion.
  - `file_metadata` — native HEAD metadata (`None` on a real 404). Payloads
    without a Xet identifier fail `require_xet()` with `XetRequired`; managed
    payloads are never silently turned into generic HTTP objects.
  - `apply_batch` — NDJSON add/delete batches chunked at 1000 operations with
    adds always sent before deletes (the documented wire rule). The service's
    per-operation report (`success/processed/succeeded/failed[]`) is fully
    reconciled: a 200 can still be partial, and a report that does not account
    for every sent operation is `InvalidResponse`. `BatchReport::is_complete()`
    must hold before a caller advances past the mutation. Duplicate keys
    within one call are refused.
  - `check_native_read` / `check_native_write` — the same probes at store
    level.
  - `events` — raw SSE source (`ready`, `changes`, `reset`, `reconnect`;
    `: ping` comments are consumed by the parser) with the last observed
    opaque `EventCursor`. Events are HEAD invalidations only. End-of-stream is
    `Ok(None)`; the caller reconnects with its cursor. The later scheduler
    owns reconnect/heartbeat policy.
  - `open_range(ObjectRef, ByteRange)` — bounded ordered cancellable range
    reads via `XetDownloadStreamGroup::download_stream(XetFileInfo, Some(range))`.
    The group and stream live inside the `RangeReader`; empty ranges complete
    with zero SDK work; out-of-bounds ranges fail before any SDK call; the
    range is revalidated against the immutable object size. Explicit
    `start()`/`cancel()`/`abort()` (per-stream cancel keeps siblings alive;
    `abort` tears down the whole bucket read group), chunks are ordered and
    capped (`range_chunk_bytes`), a short read is `RemoteContentUnavailable`
    ("no deletion is inferred"), and there is no whole-file download fallback.

## Durable upload checkpoints

Uploads cross three separately observable, separately persistable boundaries.
Nothing is hidden behind one completion:

1. `StagedUpload::ingest()` -> `(StagedIngested, IngestionCheckpoint)` —
   bytes handed to Xet ingestion. The SDK recomputes SHA-256 from the ingested
   data and the result is compared against the capture-time digest; size must
   match exactly. A mismatch is `SourceChanged` and the upload must be
   recaptured — it is never bound.
2. `StagedIngested::commit_cas()` -> `(StagedCommitted, CasCommitCheckpoint)`
   — ingestion metadata pushed to the Xet CAS; the per-file result is
   retrieved by `XetFileUpload::task_id()` from the commit report and
   re-verified against the checkpoint.
3. `StagedCommitted::bind()` -> `BoundObject` — the committed content is
   bound to the exact managed key (`prefix/objects/<upload-uuid>`,
   `versions/...`, `catalog/...`, `commits/...`; the typed `ImmutableKey`
   excludes HEAD by construction) and the binding is confirmed by the
   service's per-operation accounting.

`upload_snapshot` composes all three and returns `ObjectRef` only after each
is confirmed; `upload_metadata` is the same native immutable-upload path for
small metadata records (bounded at 1 MiB) with no S3 payload fallback.
`BoundObject::payload_ref()` rebuilds the payload `ObjectRef`. A cancellation
or transport failure after a request was dispatched is reported as such; it is
never described as rollback, and re-running a staged upload is safe (Xet
dedup) with the digest checks above.

## Authorization rules

- One `NativeLease` is captured per durable operation and checked (epoch +
  `lease.account() == binding.account_key`) immediately before every dispatch.
  Sign-out/rebinding (epoch advance) and cross-account lease substitution both
  fail closed before any request leaves the process; a denial prevents further
  mutation through that operation's captured lease.
- Resource authorization is real: `check_native_read`/`check_native_write`
  perform actual native probes, so the parent can gate every publication
  transaction on current native access, not just the account epoch.
- The HF bearer credential is attached only to URLs this crate constructs from
  the validated endpoint. Xet refresh URLs (`/api/buckets/{ns}/{name}/xet-read-token`,
  `/api/buckets/{ns}/{name}/xet-write-token`) live on the trusted HF API origin and are the only
  authenticated routes the Xet stack's refresher contacts; CAS/CDN/presigned
  URLs never see HF credentials and their query strings never reach callers or
  errors.

## Redirect and pagination policy

- Control JSON calls never follow redirects. A `3xx` is an error.
- Bounded HEAD-record reads (resolve route) follow same-origin locations with
  the bearer (at most 10 hops). Cross-origin locations are followed without
  any credentials (the location is a scoped service URL) and are never echoed
  into results or errors; if that is not acceptable in a deployment, the read
  fails as `RemoteContentUnavailable` rather than leaking or guessing.
- Pagination follows `Link rel="next"` only when the next URL keeps the
  endpoint's scheme/host/port, stays under `/api/buckets/{ns}/{name}` (or the
  namespace prefix for owner listings), and carries no embedded credentials.
  Duplicate `rel="next"` entries are rejected. Persisted `PageCursor`s are
  re-validated on every use.

## SDK reuse and capability gaps (evidence)

Reused from the pinned SDK: `HFClient` (immutable per credential generation,
repository caching disabled, no blind in-SDK retries), `HFClient::bucket`,
`HFBucket::get_file_metadata` (HEAD with the SDK's manual same-origin relative
redirect handling).

Raw documented HTTP is used where the SDK cannot meet the contract:

- `HFBucket::batch_operations` discards the batch response body
  (`check_response(...)` only, `crates` source `hf-hub/src/buckets/mod.rs`,
  `batch_operations`), while the documented 200 body carries
  `success/processed/succeeded/failed[]` (official OpenAPI,
  `/api/buckets/{namespace}/{repo}/batch`). Partial results must be inspected,
  so batch mutations are issued raw with full per-operation reconciliation.
  The same SDK method also orders deletes before copies, which violates the
  documented "all add/copy operations must come before all delete operations"
  for copy+delete mixes.
- hf-hub's `paginate` follows whatever absolute URL a `Link` header names with
  no origin or path validation (`hf-hub/src/pagination.rs`,
  `parse_link_header_next`), and its `BucketInfo`/tree types drop the stable
  `_id` identity and require `xetHash` to be present. Listings, tree,
  paths-info, create/resolve info, and events are therefore issued raw with
  same-origin pagination and tolerant-but-strict entry parsing (a missing Xet
  id is surfaced as `None` for the capability gate, not a parse failure).
- hf-xet is used exactly as documented: `XetSessionBuilder::new_with_config`
  with programmatic concurrency bounds (`enable_adaptive_concurrency=false`,
  bounded upload/download/ingestion counts — never process-global environment
  variables), `with_cache_dir` for the per account/drive persistent shard and
  upload-metadata cache (not `HF_XET_CHUNK_CACHE_SIZE_BYTES`), and
  `AuthGroupBuilder::with_token_refresh_url` to the selected bucket's
  `xet-read-token` / `xet-write-token` routes.

## Live gates not run (named external constraints)

- Actual HF OAuth granted-scope matrix (personal/org list/read/write/create,
  Xet read/write, events) — `not_run`: no registration/credentials supplied.
- Actual Xet range/download behavior against live CAS (ordering, short-read
  semantics, cancel/abort behavior under load) — `not_run`.
- Whether the live resolve route serves managed HEAD records directly (as
  expected for S3-written records) or issues a cross-origin redirect —
  `not_run`; the redirect policy above is the documented fallback and fails
  closed.
- Native write authorization probes against live buckets (permission denial
  vs. restricted org roles) — `not_run`.
- Live batch response-shape confirmation (`failed[]` accounting) — the code
  follows the official OpenAPI schema and rejects unaccounted reports;
  `not_run` against a live bucket.
- Proxy/trust-store behavior of both transports is exercised elsewhere (M0
  TLS acceptance); this crate performs no TLS of its own beyond reqwest's
  rustls default.
