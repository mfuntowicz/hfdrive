# Filesystem semantics (HF Drive Windows layer)

This document describes the exact filesystem semantics implemented by
`crates/hfdrive-windows` (`filesystem` and `cfapi` modules) and the precise
boundaries of its tests. It describes **implemented behavior**, not planned
behavior. It makes no claim of Explorer or Hugging Face acceptance: those are
separate milestone gates executed through `scripts/acceptance.ps1` against a
packaged build, a real account and real storage.

## Scope

The layer owns: sync-root validation (handles only), Windows name rules,
coherent snapshot capture, metadata enumeration, `ReadDirectoryChangesW`
watching, USN journal catch-up/reset, sync-root registration, the CFAPI
callback pipeline, transfer completion, and guarded placeholder operations.
It deliberately contains **no provider**: remote bytes come from
`hfdrive-hf`, durable generations/journaling from `hfdrive-state`, and
scheduling from `hfdrive-provider`.

## Supported semantics (V1)

* Ordinary file content and directory structure, with exact names (original
  spelling preserved; no normalization is applied to stored names).
* Creation, write, rename/move (including case-only renames, journaled via
  unique intermediate paths by the provider), and delete.
* Display timestamps (creation/modification) and the basic attribute bits
  (directory, hidden, read-only, archive) as display metadata.
* Empty files and empty directories.
* Partial hydration through CFAPI (`PARTIAL`), with on-demand range fetches
  served by the provider's immutable-object pipeline.

## Unsupported or refused semantics (exact behavior)

| Situation | Behavior |
| --- | --- |
| Symlinks, junctions, mount points, any foreign reparse tag | Refused at root validation (including ancestors) and at capture (`FsError::ReparsePoint` / `UnsupportedFileType`). Never followed. Only this provider's cloud placeholders are supported inside a root. |
| Multiply linked files (hard links, `NumberOfLinks > 1`) | Refused for upload (`FsError::HardLinked`); the local file is preserved untouched and the provider surfaces an actionable error. Placeholder hard links are disabled at registration (`HardlinkPolicy = None`). |
| EFS-encrypted files | Refused for upload (`FsError::EncryptedFile`). **No E2EE claim of any kind.** |
| Alternate data streams (ADS) | Preserved locally (never removed during local replacement), **not replicated** to the remote namespace; capture records a `SnapshotWarning::AlternateStreams` so the UI can warn. |
| NTFS ACLs / owner / auditing | Preserved locally; not replicated. New remote files inherit destination ACLs. No backup fidelity is claimed. |
| Compressed / sparse / integrity streams | Treated as ordinary bytes on read; attribute-level replication of these states is not supported. |
| Case-sensitive NTFS directories (`FILE_CS_FLAG_CASE_SENSITIVE_DIR`) | Refused (`FsError::CaseSensitiveDirectory`): the portable namespace requires case-insensitive directories. Additional `CompareStringOrdinal(..., TRUE)` collisions are resolved by the provider before apply. |
| Reserved DOS names (`CON`, `NUL`, `LPT1`… including superscript-digit spellings), trailing dot/space, `< > : " / \ | ? *`, control chars, > 255 UTF-16 units, unpaired UTF-16 surrogates, embedded NUL | Rejected by `names::validate_component` / `names::decode_component` (rules centralized in `hfdrive_core::names`). |
| Continuously changing files (live databases, VM images) | Unsupported: capture requires a stable file. A file that changes during capture fails `FsError::SourceChanged` and is retried; torn or hole-filled snapshots can never be produced. |

## Snapshot capture contract

`snapshot::capture_snapshot` is the only local-to-immutable boundary:

1. The source is opened read-only with share mode `FILE_SHARE_READ` —
   concurrent writers and deleters are denied for the whole capture. A
   conflicting writer yields `FsError::SharingViolation` (retry class).
2. Not-fully-materialized sources (partial placeholders,
   recall-on-open/data-access data) are refused with
   `FsError::NotMaterialized` **before** any read; the provider materializes
   content first. There is no path that reads cloud holes as zeroes.
3. Identity evidence (volume serial + 128-bit file ID, link count,
   attributes, reparse tag), size and modification time are checked against
   the caller's observed `FileState` and re-checked after the read. Any drift
   is `FsError::IdentityChanged` / `SourceChanged`, and the staged partial is
   deleted. `FileState.usn` is compared when present; a **missing** USN is
   recorded as `SnapshotWarning::UsnUnavailable` and is never a wildcard
   match later.
4. Bytes are streamed in bounded (1 MiB) chunks, SHA-256 hashed, and staged
   under the account's staging directory, then flushed
   (`FlushFileBuffers`) before the snapshot is reported ready. The staged
   file name is `<snapshot-uuid>.snap`; a snapshot is only referenced by the
   provider after this flush. Untracked staged remnants after a crash are
   retained until reconciled — the staging directory is never blindly wiped.
5. Retry classes (`FsError::retryable()`): sharing violation, disk full,
   source changed, identity changed, not materialized, budget exceeded. The
   caller keeps its durable intent and retries; none of these are deletions.

## Watch semantics

`watch::DirectoryWatcher` runs one armed `ReadDirectoryChangesW` (64 KiB
buffer, subtree) per root and delivers to a **bounded** channel. A full
channel or a directory buffer overflow emits `WatchAction::Overflow` and sets
`DirectoryWatcher::overflowed()`; while overflowed, the caller must not infer
deletions and must rescan. Un-decodable names (unpaired surrogates) are
treated as overflow, never mis-decoded. The watcher never blocks its thread
on a full channel and never drops events silently.

## USN semantics

`usn::UsnReader` keeps a cursor `(journal_id, usn)`. Catch-up is guarded:

* different journal id → `Reset(JournalIdChanged)`;
* cursor below `LowestValidUsn` or `ERROR_JOURNAL_ENTRY_DELETED` →
  `Reset(RecordsLost)`;
* journal inactive/deleted-in-progress → `Reset(JournalNotActive)`;
* returned USN behind the cursor (wrap) → `Reset(JournalWrapped)`.

On any reset the caller must run a full metadata scan
(`enumerate::scan_metadata`) and rebuild its cursor; deletion evidence is
void across the gap. `ScanReport.complete` (true only for a fully walked,
fully accessible scan with budget left) is the sole license to infer
disappearance. Per-file USN evidence comes from `FSCTL_READ_FILE_USN_DATA`;
`None` means "USN unknown", which guarded operations treat as **not a match**.

## Placeholder identity (HFDR v1)

53-byte immutable record in every placeholder: magic `HFDR`, schema `1`,
workspace UUID, item UUID, content version UUID (all-zero only for
directories). Decoding validates exact length, magic, known schema and the
connection's workspace **before** interpreting any identifier; foreign or
newer records are rejected (`IdentityError`), never guessed or re-bound.

## CFAPI integration facts

* Registration is `StorageProviderSyncRootManager.Register` **only**
  (`CfRegisterSyncRoot` is never called). Frozen identities: provider GUID
  `f727443d-0db5-4746-a08f-16afb2d2f289`; sync root id
  `HFDrive!<user-sid>!<connection-uuid>` (≤ 174 chars; overlong ids are
  rejected, never truncated).
* Frozen policy: hydration `PARTIAL` with **no** streaming,
  auto-dehydration or validation-required modifiers; population `FULL`;
  hard links `NONE`; connect flags include
  `CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH`.
* Callbacks are deep-copied into bounded per-kind queues
  (fetch/placeholders/cancels/renames/deletes/completions) on panic-safe
  trampolines. Queue exhaustion completes the affected request truthfully
  with `STATUS_CLOUD_FILE_INSUFFICIENT_RESOURCES`; notification acks fail
  with the same status; dropped completion notifications are counted
  (`CfConnection::dropped_completions`) and mean "rescan required".
* Transfers: ≤ 1 MiB buffers, 4096-aligned offsets/lengths except the EOF
  exception, required range fully covered, optional read-ahead ≤ 4 MiB;
  planned by `cfapi::transfers::plan_chunks` and re-validated at completion.
  Empty ranges complete with zero bytes. Progress reflects actually
  transferred bytes.
* Cancellation cancels only the matching request's overlapping range
  interests; shared overlapping requests keep their own flags and stay alive.
* Shutdown order (enforced by `CfConnection::shutdown`): stop scheduling
  (caller), mark cancellation, `CfDisconnectSyncRoot` with the callback
  context still valid, join in-flight callbacks, then free the context.
  Transfer keys that arrive in callbacks are never released by the provider;
  only provider-obtained keys (`CfGetTransferKey`) are, exactly once.

## Guarded placeholder operations

* `set_in_sync` / `update_placeholder` / `convert_published` require the
  caller's observed `FileState` and verify identity, size, modification time
  and **the exact expected USN** through handles before acting. A missing
  expected USN or a missing current USN is `GuardOutcome::Mismatch(UsnUnknown)`
  — never a successful match. Mismatches keep the file dirty/old and the
  provider keeps its durable pending action.
* `update_placeholder` runs `CfUpdatePlaceholder` with
  `VERIFY_IN_SYNC | MARK_IN_SYNC` and invalidates exactly the supplied old
  ranges; the caller must have drained old-version requests first.
* `dehydrate` requires a `FreeSpaceEvidence` with every flag true (committed,
  clean, unpinned, conflict-free, no snapshot dependency) and additionally
  verifies live pin and in-sync state. Pinned or dirty content is preserved
  and the call refuses.
* `set_pin_state` reports requested pin state and full hydration separately,
  computed from real on-disk ranges. A failed pin never claims availability.
* `create_placeholders` runs ≤ 1000-entry batches, checks every per-entry
  result, and reports existing paths as `AlreadyExists` for reconciliation —
  they are never overwritten.
* `revert_to_normal` (safe unlink) is the documented inverse of
  `convert_published`: the SDK defines **no** `CfUninitializePlaceholder`; the
  supported clearing path is `CfRevertPlaceholder(handle,
  CF_REVERT_FLAG_NONE, NULL)`. It requires the strict identity/size/mtime/
  expected-USN guard (dirty or changed content stays a placeholder and is
  preserved) and proves full residency from real on-disk ranges before
  touching CFAPI (online-only content must be hydrated/exported first). An
  already-normal file is the desired end state and is reported applied
  without an OS call (idempotent). It performs no remote effects and discards
  no bytes.

## Exact test boundaries

Deterministic tests (run with `cargo test -p hfdrive-windows
--target x86_64-pc-windows-msvc`): HFDR v1 identity round-trip and every
reject path (`tests/cfapi_identity.rs`); transfer planning invariants
(alignment, EOF exception, 1 MiB bound, 4 MiB read-ahead bound, empty and
out-of-bounds ranges) (`tests/transfer_planning.rs`); name rules, strict
UTF-16 decoding, ordinal case comparison, frozen provider GUID, sync-root-id
bounds and frozen policy (`tests/sync_root_registration.rs`); plus module
unit tests for observation matching, scan budgets, watch delivery policy and
USN cursor display.

Isolated Windows smoke scenarios (`tests/windows_smoke.rs`, all
`#[ignore]`d, **authored but not run in this slice**, requiring a disposable
NTFS scratch area `HFDRIVE_SMOKE_ROOT` and, for the placeholder scenario, a
pre-registered dev root `HFDRIVE_SMOKE_SYNC_ROOT`; they never
register/unregister roots): root validation accept/overlap-reject, coherent
capture with digest/identity binding, refusal of hard-linked files, refusal
of concurrently-written files, watch delivery, scan completeness, USN
catch-up + reset conditions, and placeholder creation with existing-path
reconciliation.

**Not claimed by any test here:** Explorer shell integration, packaged-app
launch, WinUI behavior, CFAPI fetch against real HF storage, S3 publication,
two-device convergence, upgrade/uninstall behavior, and performance. Those
are the M0–M5 acceptance gates and remain external.
