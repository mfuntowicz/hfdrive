# Transfers: budgets, wire accounting, scheduling, and remote observation

This document describes the implemented Step 7 transfer behavior: how HF Drive
bounds, paces, counts and schedules every byte it moves. It is a contract
document for the provider/desktop integration, not a benchmark report.

## One shared transfer budget (`hfdrive_hf::wire_budget`)

A process runs exactly **one** [`WireBudget`](../crates/hfdrive-hf/src/wire_budget.rs):
one token bucket per direction plus four byte counters. It is created at
provider initialization (`WireBudget::new(config)` + `install_global()`, or
`WireBudget::global()` configured in place) and the same instance is handed to
`NativeApi::new_with_budget`, the provider `Scheduler`, and the publication S3
adapter.

- **Rates**: `upload_bytes_per_second` / `download_bytes_per_second`; `0` means
  unlimited. Both are live-adjustable (`WireBudget::set_rates` /
  `Scheduler::set_transfer_rates`, e.g. from `UpdateSettings`); a rate increase
  wakes current waiters immediately.
- **Burst**: 1 MiB per direction (the `burst_bytes` contract value). A chunk
  larger than the burst is admitted in burst-sized pieces, so no chunk can
  block forever and no chunk is ever reordered or split at delivery.
- **Pacing boundary**: a gated chunk is *counted once* when the transport
  boundary admits it and its delivery may be delayed by at most the burst
  window. An aborted transfer can leave at most its in-flight chunks counted
  without final delivery (bounded by burst + in-flight); this is the only
  accounting skew and it is deliberate (a dropped gate future can never leak
  bucket state).

### Wire counters vs logical counters (never conflated)

| Counter | Meaning | Recorded at |
| --- | --- | --- |
| `wire_write_bytes` | encoded body bytes leaving the process | upload transport boundary (request bodies) |
| `wire_read_bytes` | encoded body bytes entering the process | download transport boundary (response bodies) |
| `logical_write_bytes` | captured content bytes accepted from consumers | upload ingestion seam (`StagedUpload`) |
| `logical_read_bytes` | reconstructed content bytes delivered to consumers | `RangeReader::next_chunk` delivery |

Wire counters count **encoded transport bytes** (CAS shards/xorbs, HTTP body
bytes). Logical counters count **reconstructed file content**. A deduplicated
upload moves fewer wire bytes than logical bytes; both numbers are exposed
separately in `WireBudget::counters()` and must never be summed or substituted.

## Where the wire boundary sits

| Path | Boundary | Metered |
| --- | --- | --- |
| Native HF API (listings, paths-info, batch, HEAD records, whoami, probes) | `hfdrive-hf/src/http.rs` body loops (`read_bounded`, `post_body`) | yes — every encoded body chunk |
| Native SSE events | `wire_budget::Direction::Download` gate in `wire.rs::sse_stream` (heartbeats included) | yes |
| Xet CAS uploads (xorbs, grants, shards, multipart) | vendored `xet-client` `UploadProgressStream::wrap_bytes_as_stream` gate | yes |
| Xet CAS/dedup/range downloads (xorbs, multipart ranges, dedup shards, NDJSON) | vendored `xet-client` `DownloadProgressStream::wrap_stream`, `collect_gated`, `read_shard_upload_ndjson` gate | yes |
| S3 publication (HEAD CAS, probe records) | explicit hook: `WireBudget::gate_write` / `gate_read` / `gate_stream` around the adapter's encoded bodies | yes (parent wires) |
| hf-hub bounded JSON (`get_file_metadata`) | inside the pinned SDK's typed response handling | **no** — bounded control records; request count is governed by the metadata permit |
| Xet token refresh, hub-client JSON, telemetry POSTs | inside the SDK control paths | **no** — small control records on the auth/telemetry paths, not CAS/dedup/range payload |

The unmetered rows are documented limits of the pinned SDK surface, not
silently ignored bytes: they carry bounded control records and are governed by
the scheduler's request permits. All payload-scale traffic (the CAS/dedup/range
paths, native bodies, S3 bodies) is metered at the encoded boundary. The
vendored hook (`vendor/xet-core/README.md`) exists precisely because the SDK
offered no public hook at those boundaries.

**S3 adapter integration** (for `hfdrive-publication/src/transport.rs`):
per encoded body chunk call `budget.gate_write(len).await` /
`budget.gate_read(len).await`, or wrap a streamed body with
`budget.gate_stream(Direction::Upload|Download, stream)` (zero-copy; item type
unchanged). The budget handle is supplied at construction
(`S3Transport::bind(.., budget: WireBudget)`).

## Bounded ranges and the range cache

`NativeBucketStore::open_range` validates the range against the immutable
object before any SDK call and streams ordered bounded chunks (default 1 MiB,
`NativeConfig::range_chunk_bytes`); there is no whole-file fallback.
`open_range_cached(.., &RangeCache, ..)` serves complete cache hits without SDK
work and records delivered chunks as clean immutable segments on misses.

`hfdrive_hf::RangeCache` (provider holds the shared instance
`scheduler.range_cache()`):
- keyed strictly by the content version (managed payload key + Xet file id +
  exact size) — a newer version can never be served from old bytes;
- byte-bounded LRU over clean segments only (everything cached is
  reconstructible; eviction never touches pending/dirty work);
- live-resizable (`Scheduler::set_memory_limits(.., range_cache_bytes, ..)`);
  shrinking evicts clean segments immediately;
- lookup returns the exact window as zero-copy slices on complete coverage, or
  a miss; partial answers are never returned.

## Scheduling (`hfdrive_provider::scheduler`)

Two distinct layers:

- **Permits** bound concurrent operations globally: 4 range reads (1 slot
  reserved for `BlockingHydration`; background classes are capped at 3),
  2 uploads, 8 metadata requests. Classes by priority:
  `BlockingHydration` > `DirectoryMetadata` > `LocalEdit` > `OfflinePin` >
  `BackgroundScan`. Admission queues are bounded per class (default 128;
  overflow → `ScheduleError::Busy`), grants follow class priority with
  round-robin fairness across drives (connection ids), and every wait is
  cancellation-aware (drop/cancel never leaks a slot).
- **Bytes** are bounded by RAII reservations: `reserve_transfer_memory`
  (256 MiB default), `reserve_staging` (10 GiB default; free-space floor
  `minimum_free_bytes` = 1 GiB enforced through the parent's
  `FreeSpaceProbe`), and the range-cache budget above. Reservations survive
  live resizes (shrink blocks new admission, never cancels held work).

Policy gates are explicit and never lose work (callers keep durable intent and
retry):

| Condition | Uploads / staging | BlockingHydration + DirectoryMetadata | OfflinePin + BackgroundScan |
| --- | --- | --- | --- |
| Paused | denied `Paused` (staging is local: allowed) | allowed | denied `Paused` |
| Metered, no consent | denied `Metered` | allowed (user-blocking opens) | denied `Metered` |
| Metered, consented | allowed | allowed | allowed |
| Offline | denied `Offline` | denied `Offline` | denied `Offline` |

Staging admission is local capture work and is bounded only by budget and free
space. Resume after pause is admission-time only: the caller must revalidate
account/resource capabilities before dispatching resumed mutations.

## Xet session bounds (`hfdrive_hf::XetLimits`)

Configured programmatically (never process-global environment variables):
adaptive concurrency disabled (the scheduler owns pacing), 2 upload / 4
download concurrency, 2 concurrent ingestions / 4 concurrent downloads, and
buffering caps (`ingestion_block_bytes` 8 MiB, `download_buffer_bytes`
4 MiB, `download_buffer_per_file_bytes` 8 MiB, `max_download_buffer_bytes`
64 MiB) mapped onto the SDK's `data.*` / `reconstruction.*` config groups.
These are upper bounds for the SDK's own allocations; actual SDK memory use is
verified by measurement in the benchmark gate, never assumed to equal the
provider's buffer budget.

## Remote observation (`hfdrive_provider::remote_watch`)

One watch loop per connected drive coalesces three invalidation sources:

1. **Native change-feed events** (SSE): events are HEAD invalidations, never
   deletions. Cursor semantics: a cursor advances the resume position **only
   after `WatchControl::acknowledge` reports durable application**; until then
   reconnects replay from the last acknowledged cursor (a lost acknowledgment
   can never skip a change). `reset`/replay expiry discards the cursor and
   requests an authoritative HEAD re-read (`WatchNotice::Reset`).
2. **Independent jittered HEAD polling** every 60–90 s — the "missing
   notification" fallback; it runs regardless of stream health.
3. **Stream-silence fallback**: no encoded body bytes (heartbeats included,
   tracked at byte level via `NativeEventStream::idle_for`) for 90 s triggers
   a reconnect.

Coalescing: at most one notice is outstanding awaiting acknowledgment; further
triggers merge into one follow-up notice. Failures surface explicitly
(`WatchNotice::StreamUnavailable { issue, retry_in }`) with `Retry-After`
honored and exponential full-jitter backoff (1 s base, 60 s ceiling) — no busy
loop. Metered/offline states do not stop observation; they surface as notices
while polling continues.

## Settings keys (provider `UpdateSettings`)

`upload_bytes_per_second`, `download_bytes_per_second` (0 = unlimited) map to
`Scheduler::set_transfer_rates`; `transfer_memory_bytes`, `range_cache_bytes`,
`staging_admission_bytes`, `minimum_free_bytes` map to
`Scheduler::set_memory_limits`. All changes are live and affect waiters
immediately.

## What this document does not claim

- No live HF/Xet/S3 acceptance is claimed here; wire pacing through the Xet
  SDK path is proven by deterministic tests over the exact transport wrappers
  plus the local-streaming scenario in
  `crates/hfdrive-hf/tests/wire_budget.rs`, and is measured on the wire in the
  M4 benchmark gate.
- Cache/dedup statistics beyond the counters above are unavailable from the
  pinned SDK and are reported as such, never invented.
