# Vendored `xet-client` 1.8.1 — HF Drive transport-budget and API compatibility patch

## What this is

`xet-client/` is the **published crates.io `xet-client` 1.8.1 source, unmodified
except for the minimal patch recorded in `xet-client.patch`** (unified diff
against the pristine registry source). The transport-budget changes are
authorized by the HF Drive plan ("if absent, add a narrowly pinned source patch
exposing body-stream token-bucket hooks and wire counters at the actual transport
boundary"). Three behavior-preserving API renames also avoid deprecation warnings.

The pinned official Xet SDK (hf-xet 1.8.1 → xet-client 1.8.1) has **no public
hook** at its HTTP body transport boundary. Its `XetConfig` exposes only
concurrency/retry/timeout knobs (`client.*`, `data.*`, `reconstruction.*`, all
inspected); `reqwest-middleware` middlewares cannot see body bytes; response
bodies are consumed as opaque `reqwest::Response` streams. Therefore HF Drive
cannot pace or count the encoded CAS/dedup/range wire bytes from outside the
crate. The transport-budget portion of the patch adds that hook.

## What the patch changes (and what it does not)

Added (one new file):
- `src/common/transport_budget.rs` — `TransportBudgetHook` (a gate future per
  encoded body chunk), the process-global hook registry, a zero-copy
  `GatedStream` adapter, `collect_gated` (the gated form of
  `Response::bytes()`), `gated_static_body`, and deterministic unit tests.

Wired into the **existing** body streams (six call sites, no logic changes):
- `src/cas_client/progress_tracked_streams.rs` — `UploadProgressStream::wrap_bytes_as_stream`
  and `DownloadProgressStream::wrap_stream` now return their streams gated at
  the encoded upload/download boundary. This covers every xorb upload, grant
  upload, shard upload and xorb/multipart download body: all CAS payload
  transfers funnel through these two constructors.
- `src/cas_client/remote_client.rs` — the xorb-upload-grant JSON request body
  (`gated_static_body`), the multipart/byteranges response collection, and the
  global-dedup shard download (`collect_gated`).
- `src/cas_client/shard_upload_v2.rs` — the `/v2/shards` NDJSON response stream.
- `src/cas_client/retry_wrapper.rs` — `run_and_extract_bytes`, the generic
  bounded response collector.

API compatibility (no policy or ordering changes):
- `src/cas_client/retry_wrapper.rs` — `RetryIf::spawn` → `RetryIf::start`.
- `src/cas_client/adaptive_concurrency/controller.rs` — `AtomicU64::fetch_update`
  → `try_update`, preserving the throttling closure and both memory orderings.
- `src/cas_client/telemetry/sink.rs` — `AtomicUsize::fetch_update` → `try_update`,
  preserving the in-flight limit, closure, and both memory orderings.

**Untouched:** Xet chunking, CAS protocol, deduplication, reconstruction,
authentication, retry policy, adaptive concurrency, telemetry accounting, and
all request shapes. The transport edits wrap existing body streams; the API
compatibility edits only replace deprecated entry-point names.

Deliberately not metered by this patch (documented in `docs/transfers.md`):
small JSON control bodies of hub/token-refresh calls and telemetry POSTs —
they are not CAS/dedup/range payload paths.

## Provenance

| Item | Value |
| --- | --- |
| Package | `xet-client` 1.8.1 (crates.io) |
| License | Apache-2.0 (declared in `Cargo.toml`, upstream repository) |
| Upstream | https://github.com/huggingface/xet-core |
| Upstream commit | `0b04d7e9a4989808a05799a5f9bc3d66947d5aef` |
| `.crate` archive SHA-256 | `5d2ecf14e1f7ef15b721bd0eaf79116360c2bad6a81edc7ce52b78a17439186a` |
| `Cargo.lock` checksum | `5d2ecf14e1f7ef15b721bd0eaf79116360c2bad6a81edc7ce52b78a17439186a` (identical) |

Verification performed at vendoring time (2026-11-13):
- Registry `.crate` archive SHA-256 equals the workspace `Cargo.lock`
  checksum entry for `xet-client` (the exact artifact the build pinned).
- Byte-level equality of vendored files against upstream at the recorded
  commit: `src/cas_client/progress_tracked_streams.rs` SHA-256
  `0ede157475cc8c291a07c11f8a70986481f5305470765d432da0af859e0be5aa` and
  `src/common/http_client.rs` SHA-256
  `13164dbd03e888a16d6f4063eb087c2462a6b178409c5f15ff856127c402e2b7`
  match both the registry source and `raw.githubusercontent.com` at
  `0b04d7e9…`.

`xet-client.patch` is the complete delta (pristine registry source → this
directory); regenerate with:

```
diff -ruN <registry-src>/xet-client-1.8.1 vendor/xet-core/xet-client > vendor/xet-core/xet-client.patch
```

## Integration (exact manifest changes; applied by the parent)

In the workspace root `Cargo.toml`:

```toml
[workspace]
members = ["crates/*"]
exclude = ["vendor"]          # vendored patch target is not a workspace member

[workspace.dependencies]
xet-client = { version = "=1.8.1", default-features = false, features = ["rustls-tls"] }

[patch.crates-io]
xet-client = { path = "vendor/xet-core/xet-client" }
```

In `crates/hfdrive-hf/Cargo.toml` `[dependencies]`:

```toml
xet-client.workspace = true
```

(`hfdrive-hf` names the hook trait to adapt its shared `WireBudget`; the
feature set matches the one `hf-xet` forwards into `xet-client`, so no TLS
feature graph changes.)

Then regenerate `Cargo.lock` once (`cargo update -p xet-client` or a plain
build) and re-run the resolved-feature inspection (rustls-only, no
native-tls/OpenSSL).

## Checks for this tree (named for the parent's acceptance run)

```
cargo test --manifest-path vendor/xet-core/xet-client/Cargo.toml transport_budget
cargo test -p hfdrive-hf --locked --target x86_64-pc-windows-msvc
```

The first runs the vendored module's deterministic hook/stream tests (its
dev-dependencies resolve standalone); the second runs HF Drive's
transport-level gating scenario (`tests/wire_budget.rs`) against the installed
hook, proving bytes/rate/cancellation with no SDK-path bypass.
