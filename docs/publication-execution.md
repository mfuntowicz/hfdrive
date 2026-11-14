# Publication execution: coordinator, ancestry, capability probe

Owned modules in `crates/hfdrive-publication`:

| Module | Responsibility |
| --- | --- |
| `coordinator.rs` | The guarded publication transaction: validate -> write immutable dependencies via native Xet -> verify payloads -> one conditional `HEAD` write -> ancestry-based uncertain-write resolution. |
| `ancestry.rs` | Bounded, validated, resumable committed-ancestry traversal over any commit-record reader (`AncestrySource`). |
| `probe.rs` | The real capability probe: deterministic 16 MiB Xet upload with native full/ranged verification, S3 coherence, conditional-write measurements, discarded-response recovery, exact-key journal, owned cleanup. |
| `transport.rs` | (integration) explicitly credentialed S3 transport; dispatches on `hfdrive_hf::NativeLease`, meters encoded bodies on the shared `hfdrive_hf::wire_budget::WireBudget`. |

## Publication transaction

`PublicationCoordinator::new` cross-validates the exact stable identity: the
store binding must equal the publication binding, and the native drive must
agree on account, owner, bucket, workspace and prefix (display locators never
participate). One `NativeLease` is captured per durable operation and threaded
through every dispatch; fresh native resource authorization
(`check_native_read`/`check_native_write`) runs immediately before **each** S3
transaction.

Order enforced by `initialize_if_absent` / `publish_if_match`:

1. Candidate shape and binding validation (`InvalidResponse` for shape,
   `BindingMismatch` for identity, `ImmutableRecordConflict` for reused
   commit/generation identities or a base the candidate does not advance).
2. Immutable records written through the native Xet staged chain
   (ingestion -> CAS commit -> binding, each checkpoint returned as evidence)
   in dependency order: versions, hash-addressed catalog pages, commit.
   An existing immutable key must hold exactly the candidate bytes (idempotent
   resume); anything else is `ImmutableRecordConflict` and is never overwritten.
3. Every referenced payload verified bound with its exact size and native Xet
   identity. Missing dependencies are retryable `RemoteContentUnavailable`,
   never inferred deletions.
4. Exactly one conditional `HEAD` write: `If-None-Match: *` for the initial
   publication, `If-Match` with the preserved strong validator otherwise.

Outcomes: `Committed(evidence)`, `PreconditionFailed { current }` (the current
`HEAD` is re-read for fresh reconciliation; `None` means absent -> pause, never
deletion), `Ambiguous(evidence)` (dispatched but unanswered -> resolve).

`resolve_uncertain_write` walks validated bounded committed ancestry for the
exact candidate commit and all of its operation UUIDs:

- `Committed { commit_id }` — the exact candidate is committed.
- `CommittedElsewhere { matches }` — operations were committed by other
  commits (first chunk of a multi-commit workflow, or a rebased publication);
  the caller reconciles the exact intent per operation and never treats the
  candidate as complete.
- `NotCommitted { current }` — chain fully consumed inside the bound; build a
  new candidate with NEW commit/generation ids.
- `Unresolved { cursor, .. }` — bound reached; resume with the persisted
  cursor. Absence is never claimed from an incomplete walk.

Every ancestry fetch validates canonical bounded bytes, key/body agreement
(`commits/<id>.json` must contain that id) and workspace agreement. A missing
referenced record is retryable `RemoteContentUnavailable`; corruption is
`InvalidResponse`; newer schemas/unknown features are `UnsupportedFormat`;
repeated commits on one chain are corruption, never a cycle to follow.

## Capability probe

An explicit setup/CLI action (`ProbeMode::Full`). All effects happen under the
owned `hfdrive-probe/<run-id>/` namespace and every key is journaled in the
account state (`reserve_probe_key` -> `CreateInFlight` -> `Created`/`NotCreated`)
before its external effect. Measured dimensions (`hfdrive_protocol::ProbeCheck`
records; every unexecuted dimension is reported `NotRun` with its reason):

- `NativeUploadVisibleNatively`, `XetRangeReads` — deterministic 16 MiB file
  (xorshift64* blocks, fixed seeds; `probe_payload_*` helpers) uploaded through
  the actual native Xet staged chain and verified by full and boundary/EOF/empty
  range reads against the known source bytes.
- `NativeUploadVisibleS3`, `GetBodyEtagCoherence` — S3 read-back of the same
  object and body/entity-tag coherence of a small owned record.
- `GuardedCreate`, `ConcurrentSameEtag`, `StaleOverwriteRejected` — exact
  conditional-write behavior of the publication path.
- `AmbiguousCasRecovery` — a tiny publication chain (`HEAD` + two commit
  records) whose conditional `HEAD` replacement verdict is discarded on
  purpose and then resolved purely from validated committed ancestry.

`ProbeMode::ReadOnly` requires no S3 credentials: every write dimension is
`NotRun` with that reason, nothing is journaled, and no traffic flows.

Interrupted runs resume with the same `run_id`: ambiguous `CreateInFlight`
effects are reconciled against observed existence, then every provably-owned
key of the run is deleted idempotently (`probe_cleanup_candidates` is the only
deletable set; no listing, no prefix delete). The report (`ProbeReport`,
`serde::Serialize`) is the capability evidence the caller persists to
`artifacts/capabilities/<run-id>.json`; it contains no secrets or user paths.

## Wire budget

`S3Transport::bind` takes the provider's shared `WireBudget` handle (the same
instance metering the native/Xet boundaries). Encoded S3 request bodies are
gated before dispatch and response body chunks are gated as they are admitted;
counters come from `WireCounters` (`wire_write_bytes`/`wire_read_bytes` are
encoded wire bytes; logical counters are never merged in).

## Required parent wiring (exact delta)

`crates/hfdrive-publication/src/lib.rs`:

```rust
pub mod ancestry;
pub mod coordinator;
pub mod probe;
```

and four `PublicationError` variants (see the request note for exact wording):
`RemoteContentUnavailable`, `ImmutableRecordConflict`, `SearchIncomplete`,
`XetRequired`.

`crates/hfdrive-publication/Cargo.toml`:

```toml
[dependencies]
hfdrive-hf.workspace = true
hfdrive-state.workspace = true
sha2.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

Tests live in `crates/hfdrive-publication/tests/`
(`publication.rs`, `records.rs`, `ancestry.rs`, `probe.rs`, shared fixtures in
`tests/common/`). They exercise the production seams over in-memory local
service fixtures with exact conditional semantics and fault injection; the
production wiring uses the real `S3Transport` + `NativeBucketStore`.
