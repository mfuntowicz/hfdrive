# Synchronization engine — durable model and Windows runtime scenarios

This documents the behavior implemented in `crates/hfdrive-provider/src/sync/**`
and the Windows runtime scenarios the integration owner executes against a
packaged build. Everything here describes implemented behavior or an explicit
procedure; no scenario below is claimed to have been executed by this slice.

## Durability contract

Every external effect is preceded by a durable record on the account database
(`hfdrive-state`, one bounded WAL worker):

1. **Observation** — a local change persists its per-item generation
   (`local_observations`, monotonically increasing) and its outbox intent
   (`outbox`, state `Observed`) before anything is captured or sent.
   Generation bumps are never discarded: coalescing (750 ms) merges only the
   work.
2. **Capture** — a partially hydrated placeholder is fully materialized from
   its bound immutable version first; the source is then read through one
   handle denying concurrent write/delete (`capture_snapshot`), staged into
   the drive's staging directory and flushed (`FlushFileBuffers`) before the
   snapshot row turns `Ready`.
3. **Payload upload** — the native Xet chain persists each durable checkpoint
   (`IngestionCheckpoint` → `CasCommitCheckpoint` → exact key binding) in the
   transfer journal before the next external boundary; the entry becomes
   `PayloadReady` only with a bound `ObjectRef`.
   A committed CAS checkpoint resumes at binding without another ingestion.
   Bound bucket keys include the workspace prefix; `ObjectRef` construction
   strips that exact validated prefix at a slash boundary, never another
   workspace or a similarly named sibling prefix.
4. **Publication** — the reconciliation plan's fresh commit/generation/version
   identifiers are persisted as `MetadataReady` candidate evidence before the
   single conditional `HEAD` write (`If-Match` on the preserved ETag, or
   `If-None-Match: *` for explicit initialization). An uncertain outcome parks
   the entry at `PublishUnknown`.
   Reconciliation reads common-base records only for the exact Applied commit.
   Historical and merely Observed commits never contribute duplicate or
   prematurely adopted item states to that namespace.
   File tombstones retain their content binding; digest caching uses immutable
   `VersionId`, not `ItemId`, so different revisions cannot share stale bytes.
5. **Resolution** — a dispatched candidate is resolved **by identity only**:
   the live `HEAD` commit, then a bounded committed-ancestry search for the
   entry's operation UUID. Absent candidates are never re-driven from
   incomplete evidence (no fabricated publish sets, no stale-ETag writes);
   they re-plan with fresh identifiers against the current base, which is
   self-correcting — an already-landed change converges instead of rewriting.
6. **Local application** — remote-to-local effects run through the guarded
   CFAPI operations with journaled expectations (file id, generation, USN).
   Unknown or drifted expectations never count as a match; a guard refusal
   keeps the old content and the durable pending action.
   Refused namespace actions block Applied advancement. Replanning an equivalent
   pending action reuses its original journal identity and file/generation/USN
   expectations; a retry never grants itself permission by replacing that guard.
7. **Completion** — `complete_outbox` closes the entry only from
   `LocalApplyPending` and clears `dirty` only when the persisted generation
   still matches. A newer generation stays dirty and gets its own follow-up
   intent: **a superseded upload never clears newer edits**.

Echo control: every provider-applied local change is journaled in
`local_actions` before it runs and absorbed by the observation classifier
inside its echo window, so remote application can never turn into a local
upload echo. `LocalOrigin::RemoteMaterialization` intents never publish.

Deletion evidence: a disappearance becomes a deletion intent only after a
fully completed, non-invalidated metadata scan. Watcher overflow, USN
reset/wrap, denied directories and budget exhaustion void deletion inference
until a fresh completed scan; none of them ever creates a tombstone.
Repeated watcher removals, parent/child subtree removals, and replayed deletion
work are idempotent: existing tombstones keep their provenance. They never
recreate content or publish another deletion merely to close duplicate work.

Read-only connections: committed state is materialized through the native
bounded record reads and range streams without any S3 credential. Local edits
stay durable and recoverable, are reported as pending, and never dispatch.
A native-only `HEAD` read carries no ETag and therefore can never authorize a
conditional write.

## Remote refresh scheduling

Bucket SSE notifications and the independent jittered 60–90-second fallback
request managed-HEAD reconciliation. The two-second runtime tick checks durable
dispatch readiness; an idle tick does not perform another network HEAD read.
Startup/resume forces a refresh, and pending directory-only outbox work and
local-apply journals remain eligible even when the pending-file count is zero.

Each persisted invalidation increments `head_refresh_generation`. A successful
HEAD read acknowledges only the generation captured before that round;
invalidations arriving during the read remain pending, even when their opaque
SSE cursor is unchanged. A paused connection retains these invalidations.
Account schema 5 stores this generation through a forward migration with an
online pre-migration backup; older binaries must not open the newer schema.

This is managed-catalog reconciliation, not import of arbitrary website edits.
The external-edit/destination-write limitations are recorded in ADR 002.

An established connection with a remembered Observed, Published, or Applied
baseline cannot treat a missing remote HEAD as a fresh workspace. It reports
`RemoteContentUnavailable` and retains local bytes and all known baselines.

## Mode and lifecycle distinctions

| Action | Observation | Remote scheduling | Registration / data |
|---|---|---|---|
| `pause` | continues | stopped | intact |
| `resume` | continues | revalidated before dispatch | intact |
| `sign_out` (auth layer) | continues | both auth paths disabled | intact |
| unlink (safe) | stopped | stopped | hydrated/exported, then converted + unregistered |
| unlink (disconnect-keep-registration) | stopped | stopped | retained for explicit reconnect |
| provider drain (exit/upgrade) | stopped | stopped | registration, state, snapshots retained |

Finalized connections have durable event/scan bookkeeping before remote
notifications are acknowledged. Reconciliation repairs a missing row from an
interrupted or older setup without replacing an existing cursor, journal or
scan result. Initial bookkeeping is not a completed scan and never authorizes
deletion inference.

The remote-event watcher has its own child cancellation scope. A notification
persistence failure does not acknowledge its cursor or disconnect CFAPI;
the connection's independent reconciliation remains available. Missing,
cancelled or stopped CFAPI runtimes must not be reported as **Up to date**.
Reconnect preserves the existing folder, workspace and registration rather
than running setup or initializing remote storage again.

The local observer starts only after CFAPI callbacks are attached and native
notification arming succeeds. Its lifetime is owned and shutdown joins off the
async worker; an unavailable observer is not healthy sync. Initial discovery,
periodic scans, and removal/loss reconciliation inspect real metadata. A
complete, non-invalidated scan is required before absence becomes deletion.
New local item identity, generation, and outbox work commit in one transaction,
so capture can resolve the file and a failed enqueue cannot orphan its create.

After publication, captured bytes are bound to the committed placeholder
identity without invalidating resident data. Normal files are converted; an
existing placeholder's identity advances under the expected USN. The returned
provider-owned USN is remembered without creating another edit. Newer local
generations or refused capture guards never become falsely clean.

The authenticated IPC listener binds before root restoration. An unavailable
folder or remote endpoint must not prevent the desktop's Hello/GetStatus
exchange. Restore failures are published without holding a status-watch read
guard while acquiring its write lock.

A registered cloud root is not an ordinary junction. Reconnection admits its
cloud reparse tag only when the expected Windows sync-root registration ID
resolves to the same root identity. Other reparse points, foreign registrations
and reparse ancestors remain invalid; persisted volume checks still apply.
Registration adoption normalizes DOS and extended-length path spellings before
comparison; the registered file and volume identities remain authoritative.

CFAPI callback paths are absolute from the volume root. The Windows adapter
checks the connected root's component boundary and delivers root-relative paths
to the sync engine; the root itself resolves to the managed root item. An empty
directory transfer uses a null placeholder array and zero processed entries.

Full population delivers the entire authoritative directory, not just names
matching Windows' lookup pattern. Bounded transfers use the true request total
and a terminal fully-populated flag only after all names are present. Empty
directories need that terminal flag too; returning empty success alone leaves
Windows repeating name resolution.

Native directory notifications decode the flexible `FILE_NOTIFY_INFORMATION`
name at its field offset, not at the padded structure size. Subtree names are
validated component-by-component. Watch startup succeeds only after native
arming; malformed/lost notifications void deletion evidence, and fatal native
errors stop observation instead of masquerading as quiet timeouts.

`hfdrive pause --connection <UUID>` and `hfdrive resume --connection <UUID>`
operate on that existing connection. Resume restores its runtime and remote
bindings before clearing the durable pause flag; it never initializes a new
workspace or replaces the registered folder.

Unlink (`engine::SyncEngine::prepare_unlink`/`execute_unlink`) counts
online-only, partial, dirty and conflict content plus the required export
bytes. The safe default **hydrates or durably exports** every required item:
dirty content is exported to the recovery area outside the root, online-only
content is hydrated and residency verified, then every resident placeholder is
converted to a normal file through the guarded `cfapi::revert_to_normal`
(`CfRevertPlaceholder`):

* an already-normal file is idempotent `Applied` without an OS call
  (`Applied { usn: None }` fast path; `Applied { usn: Some(_) }` records a
  conversion that landed just now);
* a strict identity/size/mtime/exact-expected-USN guard runs first; `Mismatch`
  leaves the file preserved untouched on the recovery path and never forces
  the conversion;
* `Mismatch(UsnUnknown)` is distinguished by cause: on a volume with **no
  usable USN journal** (expected and live USN absent on every read) the strict
  guard can never match — this is an actionable block ("volume provides no USN
  evidence; conversion cannot be verified") rather than the dirty-content
  recovery path, since no bytes are at risk and the file simply stays managed;
  a one-read evidence gap on a journalled volume is re-observed and retried
  once, and a persistent gap is listed as unverifiable rather than treated as
  dirty content. Missing USN is never a match;
* content that is not fully resident (or any OS refusal) blocks unlink naming
  the affected files — never a silent partial removal;
* pin state is not a precondition: pinned resident content converts with its
  bytes kept.

Only after every preservation check passes does the safe path disconnect and
unregister. `blockers` holds only known impossibilities visible before
execution (e.g. an unavailable recovery area); retention failures surface
during `execute_unlink` with the exact file list. The explicit
disconnect-keep-registration path keeps the registration and warns that
online-only bytes cannot open.

## Public API surface (parent integration)

- `SyncEngine::new(EngineConfig, Arc<StateStore>, Arc<Scheduler>, CancellationToken)`
  — one engine per provider; the scheduler is shared provider-wide and the
  state store stays `Arc<StateStore>`.
- `admit(connection, root, binding)` → `AdmissionEvidence` (pure validation).
- `connect(ConnectionConfig, ConnectionServices<R>, &ValidatedRoot, AccountStore)`
  → `Arc<ConnectionRuntime<R>>` (registers idempotently, starts the runtime,
  runs the startup recovery classification).
- `initialize(connection)` — explicit new-workspace initialization only.
- `pause/resume/set_pin/free_space/set_excluded/retry/restore_item`.
- `prepare_unlink/execute_unlink(..., keep_registration)` and `drain()`.
- `ConnectionRuntime::set_pin/free_space/set_excluded/retry_now/recover_actions`
  plus `health()` for the parent's status projection.

Remote seams consumed as delivered:
`hfdrive_publication::coordinator::{PublicationCoordinator, PublicationCandidate, HeadVersion}`,
`hfdrive_publication::ancestry::{AncestryCursor, UncertainResolution}`,
`hfdrive_core::reconcile::{reconcile, ReconcileInput, CatalogView, LocalIntent}`,
`hfdrive_provider::scheduler::Scheduler`,
`hfdrive_hf::{NativeBucketStore, NativeControl, read_record}`,
`hfdrive_windows::{cfapi, filesystem}`.

## Windows runtime scenarios (execute after integration)

Each scenario lists the expected observable behavior. They require the
packaged provider on a Windows 11 x64 host; run against disposable private
test buckets only.

1. **Explorer hydration.** Connect a folder, create placeholders from remote
   state, open a file with normal Win32/.NET I/O. Expect: `FETCH_DATA` serves
   the required ranges (4096-aligned except EOF) from the bound immutable
   version; bytes equal the published payload; cancel of an overlapping read
   leaves other range interests alive.
2. **Local save → publication.** Save a file in the root. Expect: generation
   bump + `Observed` intent within the coalescing window; one staged snapshot;
   three Xet checkpoints in the transfer journal; one conditional `HEAD` write;
   placeholders on a second device converge; the source file ends in-sync only
   when its live identity/generation still matches the capture.
3. **Edit during upload.** Save again while the first upload is in flight.
   Expect: the first may publish; the second stays dirty with its own intent
   and publishes separately; `complete_outbox` reports
   `CompletedWithNewerGeneration` for the first.
4. **Crash boundaries.** Kill the provider at after-observation,
   after-snapshot, after-payload, after-metadata and after-`HEAD`-CAS. Expect
   on restart: no acknowledged version lost; a dispatched candidate is found
   through committed ancestry (or re-planned with new identifiers, never
   re-driven from incomplete evidence); a staged snapshot resumes upload
   without recapture; open local actions are classified against real file
   identity/USN before any replay.
5. **Watcher overflow / USN reset.** Overflow the directory watcher or reset
   the journal. Expect: `RescanRequired` invalidates scan evidence; parked
   removals stay parked; a fresh completed scan releases deletions; nothing is
   deleted from an incomplete scan.
6. **Remote-only change.** Commit changes from another device while this
   connection has no local intents. Expect: the round materializes guarded
   local actions and updates the base without uploading anything.
7. **Read-only connection.** Connect without publication credentials. Expect:
   committed content browsable and hydratable through native reads; local
   edits remain pending with the read-only explanation; no remote mutation is
   ever dispatched.
8. **Pause/resume.** Pause during pending work. Expect: observation and
   intent continue; no remote dispatch; resume revalidates capabilities before
   the next dispatch.
9. **Pin / free space.** Pin an online-only file (expect requested-vs-resident
   reported separately), then free space on a clean committed file (expect
   dehydration only with all evidence flags) and on a dirty file (expect
   refusal).
10. **Safe unlink.** With hydrated, partial and dirty content present, run
    `prepare_unlink`. Expect: exact counts and blockers; with blockers, safe
    removal is refused; clear them, then `execute_unlink` preserves, converts
    and unregisters. The explicit disconnect-keep-registration path keeps the
    registration and warns that online-only bytes cannot open.
11. **Provider drain.** `Exit provider`/upgrade. Expect: scheduling stops,
    state checkpoints, CFAPI callbacks disconnect while the context is valid,
    registration and data survive; the next logon reconnects idempotently.
12. **Two-device reconciliation.** With two hosts on one disposable managed
    drive: divergent edits converge as one conflict identity with both
    versions preserved; a delete-vs-edit keeps the edit as recovered content;
    history restore publishes a new operation against the latest head and the
    ancestry advances monotonically.
