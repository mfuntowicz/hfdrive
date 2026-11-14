# HF Drive reconciliation contract v1

Normative specification of pure three-way reconciliation, the hash-skipping
catalog diff, and history/restore planning. The implementation lives in
`crates/hfdrive-core/src/reconcile.rs`, `catalog_diff.rs` and `history.rs`;
the deterministic identity and naming rules below are frozen by
`crates/hfdrive-core/tests/reconcile_races.rs` and must not change without a
remote format migration. This document describes implemented behaviour, not
promised behaviour.

## Inputs and outputs

`reconcile(input, ids)` merges a common base catalog, the device's pending
local intents and the committed remote catalog into one `ReconcilePlan`:

- `CatalogView` values are **complete namespace snapshots** (`ItemState`
  records with payload digests). Incomplete input is refused with
  `MissingContext(Vec<MissingRef>)` naming the exact missing items, parents or
  ancestors; reconciliation never guesses missing ancestry or descendants and
  never truncates a plan.
- `LocalIntent` values carry the caller's durable `operation_id`, the observed
  local `generation` (recorded, never compared), and one `LocalChange`
  (create / content / move / move-and-content / delete, or a
  `Materialized` bookkeeping state). A directory delete covers the locally
  known subtree.
- All ordinary identifiers (operation, version, action) are caller-supplied.
  The caller's `IdSource` mints `LocalAction` ids so they can be persisted
  before any effect. Reconciliation itself generates only deterministic
  UUIDv5 conflict identities.

The plan contains: ordered CAS-ready `RemoteOp`s (final `ItemRecord`s plus the
`ChangeKind` and `old_revision` for the commit summary), `PlannedVersion`s to
upload before the commit, sorted `changes` and `operation_ids`, guarded
`LocalAction`s (`expected`/`target` item states; the provider binds file
identity, generation and USN at persist time and never fakes a match),
`ConflictRecord`s, NTFS `AliasPlan`s, and one `IntentOutcome` per intent.

## Component provenance

Content, location (parent + exact name) and deletion are compared and merged
independently. Every emitted record carries the operation responsible for each
component (`content_operation`, `location_operation`, `deletion_operation`);
`item_revision` is the operation responsible for the emitted change kind
(create → content op for files / location op for directories, deletion → the
deletion op, undelete → content op when content changed else location op,
content → content op, location → location op). The commit `changes` entry
names the change kind versus the record being replaced; `old_revision` is
`null` exactly for creates.

Merge outcomes by race family:

| Race | Outcome |
| --- | --- |
| local content + remote location (or vice versa) | composed on one record; no conflict |
| both changed content to equal digests | converges to the committed version binding; no upload, no conflict |
| both changed content differently | `ContentDivergence`, keep-both (below) |
| both changed location incompatibly | `RenameRace`, keep-both (below) |
| both changed content and location, one side lost both | `ContentAndLocation`, one keep-both copy of the loser's complete claim |
| delete vs unchanged | tombstone |
| delete vs delete | converges to the committed tombstone |
| delete vs any change | the change survives (`DeleteVsChange`, outcome `Recovered`); the deletion is dropped and recorded |
| directory delete vs new/edited/moved descendants | unchanged known descendants are tombstoned; changed descendants survive under a deterministic recovered directory (`DirectoryDeleteRecovery`) |
| ancestor moves forming a parent cycle | the move with the greatest location operation is not applied; its item is redirected to a root-level `Recovered (conflict …)` directory (`CycleMove`) |
| delete then recreate the same name | free name slot; no conflict |
| case-only rename | ordinary location change; composes with content edits |
| two live siblings sharing one portable collision key | `NameCollision`; the lower lexical operation UUID keeps the spelling, the other is renamed |
| names distinct portably but colliding under NTFS comparison | `NtfsAlias`; remote names unchanged, one deterministic local alias |

The winner of a component race is the side with the **lower operation UUID**
(UUID byte order equals the lexical order of the canonical lowercase
spelling). A keep-both conflict preserves the loser's complete claim as a
deterministic copy item at the loser's claimed parent named with the conflict
marker (for same-path races this is exactly "the lower operation retains the
contested original path; the other gets `<stem> (conflict …)<ext>`"). A copy
references the existing content version: payloads are never re-uploaded and
never deleted. Copies and recovered directories that already exist remotely
with the same claim are adopted, so retries converge on the same item instead
of creating a second copy.

Dirty local content always survives: it is published, preserved as the
conflict copy, kept locally (read-only), or preserved to the recovery area
(`PreserveDirty`) before any destructive local replacement or removal.

## Canonical conflict tuple (frozen)

`conflict_identity(workspace_id, kind, items, operations)` derives three
UUIDv5 identifiers. The **namespace** is the workspace UUID. The **name
bytes** are:

```
items || operations || kind_tag || 0x00 || purpose
```

- `items`: the 16 raw bytes of each involved item UUID, ascending, duplicates
  removed.
- `operations`: the 16 raw bytes of each competing operation UUID, ascending,
  duplicates removed.
- `kind_tag`: the frozen ASCII tag of the `ConflictKind`:
  `content_divergence`, `content_and_location`, `rename_race`,
  `name_collision`, `delete_vs_change`, `directory_delete_recovery`,
  `cycle_move`, `ntfs_alias`.
- `purpose`: `conflict` (the conflict id), `conflict-item` (the keep-both copy
  item id) or `recovered-dir` (the recovered directory item id).

No wall-clock value, randomness, or caller ordering leaks into the tuple.
`DirectoryDeleteRecovery` tuples contain only the deleted directory and its
deletion operations (never the survivor set), so they stay stable as survivors
accumulate. Regression pins (workspace `00112233-4455-6677-8899-aabbccddeeff`)
are frozen in the tests.

## Canonical conflict name policy (frozen)

- `<stem> (conflict <hex>)<ext>`: the stem/extension split is at the last dot
  when that dot is not the first character (`.gitignore` has no extension).
- `<hex>` is the first **12** lowercase hex characters of the conflict UUID's
  32-hex spelling.
- The whole component is truncated to 255 UTF-16 units by trimming the stem
  (then, if unavoidable, the front of the extension), never the marker.
- If the candidate spelling's portable name slot is occupied, the same
  conflict id's hex is progressively lengthened (12..=32), then suffixed
  `-2`…`-999`; an occupant is **never overwritten**. Deterministic
  `ConflictNames` produces the candidate sequence.
- Recovered directories are named `Recovered (conflict <hex12>)` with the
  same extension rule. Cycle recovery places them at the root; deletion
  recovery places them at the deleted directory's nearest live parent.
- Items whose name already came from the conflict generator extend their own
  hex instead of starting a new conflict; placement extension is not a new
  conflict record.
- NTFS-only aliases use the same generator with `ntfs_alias` identities and
  exist only in local apply/state. The pure plan-time comparator is a simple
  uppercase-fold approximation; the Windows layer passes a
  `CompareStringOrdinal(..., TRUE)`-backed comparator and resolves any
  additional collisions it finds with the same deterministic alias function.

## Read-only connections and materialization echo

Read-only mode emits **zero** remote mutations and zero version publications.
Local divergence becomes `IntentOutcome::Deferred` (dirty work stays local and
recoverable; "Read-only — local changes cannot be uploaded"); only committed
remote state is applied to clean local items. Intents with
`LocalOrigin::RemoteMaterialization` can never publish and never generate
local actions; a materialized payload that is not traceable to a known
content binding is refused with `MaterializationEchoMismatch` rather than
echoed as a local write.

## Batching oversized plans (provider contract)

`ReconcilePlan::commit_batches(max_changes, max_operations)` splits the
ordered mutations into contiguous-prefix batches bounded by the v1 commit
limits (1000 changes / 1000 operations). Every op lands in exactly one batch
in the original order; a batch is one commit applied after its predecessor,
and the plan refuses (`InvalidBatchBound`) rather than truncating an
operation that cannot fit. **Partial publication is never a completed
operation**: the provider keeps the intent open until every batch is
committed and every local action applied, records `operation_ids` per batch
for ancestry search, and re-runs reconciliation after any failure — the
already-published part then appears in the remote view and converges (the
same deterministic conflict items are adopted, not duplicated).

## Catalog diff

`catalog_diff::diff_items(before, after)` yields exactly the item record
differences (`ItemDelta` add/remove/change) in item-id order. It skips whole
subtrees whose page hashes match, verifies the hash of every page it loads,
and handles unequal tree heights and split boundaries by range-aligned
descent; identical entry sets with different page shapes produce no deltas.
Derived `c/`/`n/` index entries never produce item deltas.

## History and restore

`history::history_page` walks the retained committed ancestry newest-first
with strict per-call bounds (`page_limit`, `max_loads_per_page`); a cursor
resumes exactly at the next commit, missing commits are errors, and parent
cycles are detected. `history::plan_restore` plans a restore as a **new
committed mutation** against the latest state: it rebinds the item to the
historical version record (no payload re-upload), revives tombstones, never
rewrites historical commits or HEAD, never deletes old blobs, preserves the
occupant of a contested name (the restored item takes the deterministic
conflict name), and defers entirely on read-only connections.

## Known limits

- Read-only delete-vs-change keeps the local file and defers; it never claims
  a successful remote restore.
- The transient name-swap safety net in mutation ordering (unreachable for
  legal single-device renames) demotes one participant to its deterministic
  conflict name so emission is always sequentially applicable.
- `operation_ids` lists every operation identifier referenced by the emitted
  records' provenance, so ancestry search for a caller's operation id always
  finds it once published.
