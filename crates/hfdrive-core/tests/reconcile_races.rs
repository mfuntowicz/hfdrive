//! Consumer-visible deterministic regression cases for three-way
//! reconciliation: every race family, conflict retry identity/name
//! stability, incomplete-context refusal, and read-only behaviour.

use hfdrive_core::format::{DisplayMetadata, ItemKind, MAX_COMMIT_OPERATIONS};
use hfdrive_core::ids::{ItemId, OperationId, UploadId, VersionId, WorkspaceId};
use hfdrive_core::reconcile::{
    conflict_identity, conflict_name, reconcile, CatalogView, CommitBatch, ConflictKind,
    ConflictNames, ConflictOutcome, DeterministicIds, IntentOutcomeKind, ItemState, LocalActionKind,
    LocalChange, LocalIntent, LocalOrigin, MissingRef, NewContent, NtfsNameCompare, OrdinalIgnoreCase,
    ReconcileError, ReconcileInput, ReconcileMode, ReconcilePlan,
};
use hfdrive_core::storage::{ObjectRef, PayloadKey, Sha256Digest, XetFileId};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Fixture identities (fixed, canonical, non-nil).
// ---------------------------------------------------------------------------

const NS: Uuid = Uuid::from_u128(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff);

fn ws() -> WorkspaceId {
    WorkspaceId::from_uuid(NS).unwrap()
}
fn uid(n: u128) -> ItemId {
    ItemId::from_uuid(Uuid::from_u128(n)).unwrap()
}
fn op(n: u128) -> OperationId {
    OperationId::from_uuid(Uuid::from_u128(n)).unwrap()
}
fn ver(tag: &str) -> VersionId {
    VersionId::from_uuid(Uuid::new_v5(&NS, tag.as_bytes())).unwrap()
}

const ROOT: u128 = 0x2222_2222_2222_4222_8222_2222_2222_2222;
const ITEM_A: u128 = 0xaaaa_aaaa_aaaa_4aaa_8aaa_aaaa_aaaa_aaaa;
const ITEM_B: u128 = 0xbbbb_bbbb_bbbb_4bbb_8bbb_bbbb_bbbb_bbbb;

fn digest(n: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([n; 32])
}

fn object(n: u8, size: u64) -> ObjectRef {
    ObjectRef {
        key: PayloadKey::new(UploadId::from_uuid(Uuid::new_v5(&NS, &[n])).unwrap()),
        sha256: digest(n),
        size,
        xet_file_id: XetFileId::new(format!("{n:064x}")).unwrap(),
    }
}

fn new_content(tag: &str, n: u8, size: u64) -> NewContent {
    NewContent {
        version_id: ver(tag),
        object: object(n, size),
        display: DisplayMetadata {
            name: "payload".to_owned(),
            modified_at: "2026-01-01T00:00:00Z".to_owned(),
        },
    }
}

fn root_state() -> ItemState {
    ItemState {
        item_id: uid(ROOT),
        parent_id: None,
        name: String::new(),
        kind: ItemKind::Directory,
        deleted: false,
        item_revision: op(0x1000),
        content_version_id: None,
        content_operation: op(0x1000),
        location_operation: op(0x1000),
        deletion_operation: None,
        content_sha256: None,
        content_size: None,
    }
}

fn file_state(
    id: ItemId,
    parent: ItemId,
    name: &str,
    version: VersionId,
    digest: Sha256Digest,
    size: u64,
    rev: OperationId,
) -> ItemState {
    ItemState {
        item_id: id,
        parent_id: Some(parent),
        name: name.to_owned(),
        kind: ItemKind::File,
        deleted: false,
        item_revision: rev,
        content_version_id: Some(version),
        content_operation: rev,
        location_operation: rev,
        deletion_operation: None,
        content_sha256: Some(digest),
        content_size: Some(size),
    }
}

fn dir_state(id: ItemId, parent: ItemId, name: &str, rev: OperationId) -> ItemState {
    ItemState {
        item_id: id,
        parent_id: Some(parent),
        name: name.to_owned(),
        kind: ItemKind::Directory,
        deleted: false,
        item_revision: rev,
        content_version_id: None,
        content_operation: rev,
        location_operation: rev,
        deletion_operation: None,
        content_sha256: None,
        content_size: None,
    }
}

fn tombstone(state: &ItemState, del_op: OperationId) -> ItemState {
    let mut t = state.clone();
    t.deleted = true;
    t.deletion_operation = Some(del_op);
    t.item_revision = del_op;
    t
}

fn view(items: Vec<ItemState>) -> CatalogView {
    CatalogView::new(items).expect("fixture view is valid")
}

fn edit(op_id: OperationId, item: ItemId, change: LocalChange) -> LocalIntent {
    LocalIntent {
        operation_id: op_id,
        item_id: item,
        origin: LocalOrigin::LocalEdit,
        observed_generation: 1,
        change,
    }
}

fn run(mode: ReconcileMode, base: &CatalogView, local: &[LocalIntent], remote: &CatalogView) -> ReconcilePlan {
    let mut ids = DeterministicIds::new(NS);
    let input = ReconcileInput {
        workspace_id: ws(),
        mode,
        base,
        local,
        remote,
        ntfs: &OrdinalIgnoreCase,
    };
    reconcile(&input, &mut ids).expect("reconcile succeeds")
}

fn op_count(plan: &ReconcilePlan, item: ItemId) -> usize {
    plan.remote_ops.iter().filter(|o| o.item_id() == item).count()
}

fn outcome_of(plan: &ReconcilePlan, operation: OperationId) -> IntentOutcomeKind {
    plan.intents
        .iter()
        .find(|i| i.operation_id == operation)
        .expect("intent outcome present")
        .outcome
}

/// The exact operation-id set a batch must claim: every id referenced by the
/// batch's own records, ascending. `CommitBatch::operation_ids` must equal
/// this recomputation over just the batch's records.
fn batch_ids(batch: &CommitBatch) -> Vec<OperationId> {
    let mut ids = std::collections::BTreeSet::new();
    for op in &batch.remote_ops {
        ids.insert(op.record.item_revision);
        ids.insert(op.record.content_operation);
        ids.insert(op.record.location_operation);
        if let Some(deleted) = op.record.deletion_operation {
            ids.insert(deleted);
        }
    }
    ids.into_iter().collect()
}

fn assert_batch_commits(batches: &[CommitBatch]) {
    let mut parent_commit_id = hfdrive_core::ids::CommitId::from_uuid(Uuid::from_u128(0xc000)).unwrap();
    for batch in batches {
        let commit = hfdrive_core::format::CommitV1 {
            format: hfdrive_core::format::FORMAT_NAME.to_owned(),
            schema_version: hfdrive_core::format::SCHEMA_VERSION,
            workspace_id: ws(),
            commit_id: hfdrive_core::ids::CommitId::from_uuid(
                Uuid::from_u128(0xc001 + batch.index as u128),
            ).unwrap(),
            parent_commit_id: Some(parent_commit_id),
            catalog_root: digest(0),
            operation_ids: batch.operation_ids.clone(),
            changes: batch.changes.clone(),
            device_id: hfdrive_core::ids::DeviceId::from_uuid(NS).unwrap(),
            created_at: "2026-11-17T00:00:00Z".to_owned(),
        };
        // Exercise the publication codec, including non-no-op revisions and
        // both the record-count and encoded-byte bounds.
        let bytes = hfdrive_core::format::to_commit_bytes(&commit)
            .unwrap_or_else(|error| panic!("invalid batch {} commit: {error}", batch.index));
        assert_eq!(hfdrive_core::format::from_commit_bytes(&bytes).unwrap(), commit);
        assert_eq!(commit.operation_ids, batch_ids(batch));
        parent_commit_id = commit.commit_id;
    }
}

/// Apply only complete commits and validate each independently visible prefix.
fn assert_batch_namespaces(
    remote: &CatalogView,
    plan: &ReconcilePlan,
    max_changes: usize,
    max_operations: usize,
) -> CatalogView {
    let mut items: std::collections::BTreeMap<_, _> =
        remote.iter().map(|state| (state.item_id, state.clone())).collect();
    let mut versions: std::collections::BTreeMap<_, _> = remote
        .iter()
        .filter_map(|state| {
            state.content_version_id.map(|version| {
                (version, (state.content_sha256.unwrap(), state.content_size.unwrap()))
            })
        })
        .collect();
    for version in &plan.versions {
        versions.insert(version.version_id, (version.object.sha256, version.object.size));
    }
    let batches = plan.commit_batches(max_changes, max_operations).expect("bounded batches");
    assert_batch_commits(&batches);
    let mut committed = remote.clone();
    for batch in &batches {
        assert!(batch.remote_ops.len() <= max_changes);
        assert!(batch.operation_ids.len() <= max_operations);
        assert_eq!(batch.operation_ids, batch_ids(batch), "batch-local provenance only");
        for operation in &batch.remote_ops {
            let content = operation.record.content_version_id.map(|version| versions[&version]);
            let state = ItemState::from_record(
                &operation.record,
                content.map(|(digest, _)| digest),
                content.map(|(_, size)| size),
            )
            .expect("complete content binding");
            items.insert(state.item_id, state);
        }
        committed = CatalogView::new(items.values().cloned().collect())
            .unwrap_or_else(|error| panic!("invalid committed prefix {}: {error}", batch.index));
    }
    committed
}

// ---------------------------------------------------------------------------
// Race families
// ---------------------------------------------------------------------------

#[test]
fn compatible_content_and_location_compose_without_conflict() {
    // Local edits content; remote renames the same item. The merged record
    // takes each component from its own side with explicit provenance.
    let base = view(vec![
        root_state(),
        file_state(uid(ITEM_A), uid(ROOT), "old.txt", ver("v0"), digest(0), 10, op(0x2000)),
    ]);
    let remote = view(vec![
        root_state(),
        file_state(uid(ITEM_A), uid(ROOT), "new.txt", ver("v0"), digest(0), 10, op(0x3000)),
    ]);
    let local = vec![edit(
        op(0x0001),
        uid(ITEM_A),
        LocalChange::Content { content: new_content("v1", 1, 11) },
    )];
    let plan = run(ReconcileMode::Writable, &base, &local, &remote);

    assert_eq!(plan.conflicts.len(), 0, "compatible composition is not a conflict");
    assert_eq!(plan.remote_ops.len(), 1);
    let record = &plan.remote_ops[0].record;
    assert_eq!(record.name, "new.txt", "location comes from the remote rename");
    assert_eq!(record.content_version_id, Some(ver("v1")), "content comes from the local edit");
    assert_eq!(record.content_operation, op(0x0001));
    assert_eq!(record.location_operation, op(0x3000));
    // Both components changed; the change kind names the revision's
    // responsible component (content wins the single-valued kind).
    assert_eq!(plan.remote_ops[0].change, hfdrive_core::format::ChangeKind::Content);
    assert_eq!(plan.remote_ops[0].old_revision, Some(op(0x3000)));
    // The local file keeps its bytes; only the remote rename applies to it.
    assert_eq!(plan.local_actions.len(), 1);
    assert_eq!(plan.local_actions[0].action, LocalActionKind::Rename);
    assert_eq!(plan.local_actions[0].item_id, uid(ITEM_A));
    assert_eq!(outcome_of(&plan, op(0x0001)), IntentOutcomeKind::Published);
}

#[test]
fn divergent_content_edits_keep_both_with_stable_identity() {
    let base = view(vec![
        root_state(),
        file_state(uid(ITEM_A), uid(ROOT), "report.txt", ver("v0"), digest(0), 10, op(0x2000)),
    ]);
    let remote = view(vec![
        root_state(),
        file_state(uid(ITEM_A), uid(ROOT), "report.txt", ver("v2"), digest(2), 22, op(0x0002)),
    ]);
    let local = vec![edit(
        op(0x0001),
        uid(ITEM_A),
        LocalChange::Content { content: new_content("v1", 1, 11) },
    )];
    let plan = run(ReconcileMode::Writable, &base, &local, &remote);

    // Exactly one conflict, deterministic identity and name.
    assert_eq!(plan.conflicts.len(), 1);
    let conflict = &plan.conflicts[0];
    assert_eq!(conflict.kind, ConflictKind::ContentDivergence);
    assert_eq!(conflict.outcome, ConflictOutcome::KeepBoth);
    assert_eq!(conflict.competing_operations, vec![op(0x0001), op(0x0002)]);

    // The lower operation UUID (the local edit) keeps the contested path.
    let winner = plan
        .remote_ops
        .iter()
        .find(|o| o.item_id() == uid(ITEM_A))
        .expect("winner upsert");
    assert_eq!(winner.record.content_version_id, Some(ver("v1")));
    assert_eq!(winner.change, hfdrive_core::format::ChangeKind::Content);

    // The losing remote claim is preserved as the deterministic copy.
    let copy_id = conflict.preserved_item_id.expect("copy preserved");
    let copy = plan
        .remote_ops
        .iter()
        .find(|o| o.item_id() == copy_id)
        .expect("copy upsert");
    assert_eq!(copy.record.content_version_id, Some(ver("v2")));
    assert_eq!(copy.record.name, "report (conflict 2ea6eb6c228c).txt");
    assert_eq!(conflict.preserved_name.as_deref(), Some("report (conflict 2ea6eb6c228c).txt"));
    assert_eq!(conflict.preserved_version_id, Some(ver("v2")));

    // Deterministic identity is pinned to the exact tuple (regression
    // against accidental tuple changes).
    let ident = conflict_identity(
        ws(),
        ConflictKind::ContentDivergence,
        &[uid(ITEM_A)],
        &[op(0x0001), op(0x0002)],
    );
    assert_eq!(ident.conflict_id.to_string(), "2ea6eb6c-228c-57be-8fa9-2364145bbd40");
    assert_eq!(ident.copy_item_id.to_string(), "a51ec676-b2e2-5993-8ad3-5d0c0aae8fe5");
    assert_eq!(copy_id, ident.copy_item_id);

    // The losing local... local won, so no local replacement; only the copy
    // materializes. The plan uploads exactly one new version record (v1).
    assert_eq!(plan.versions.len(), 1);
    assert_eq!(plan.versions[0].version_id, ver("v1"));
    assert_eq!(
        plan.local_actions
            .iter()
            .filter(|a| a.action == LocalActionKind::CreatePlaceholder)
            .count(),
        1,
        "the conflict copy materializes locally"
    );
    assert_eq!(outcome_of(&plan, op(0x0001)), IntentOutcomeKind::Published);
}

#[test]
fn conflict_identity_and_name_are_run_stable() {
    // Same inputs twice -> byte-identical identities and names.
    let items = [uid(ITEM_A)];
    let ops = [op(0x0002), op(0x0001)];
    let a = conflict_identity(ws(), ConflictKind::RenameRace, &items, &ops);
    let b = conflict_identity(ws(), ConflictKind::RenameRace, &items, &[op(0x0001), op(0x0002)]);
    assert_eq!(a, b, "input ordering does not leak into the tuple");
    let c = conflict_identity(ws(), ConflictKind::ContentDivergence, &items, &ops);
    assert_ne!(a.conflict_id, c.conflict_id, "conflict kind is part of the tuple");
    assert_eq!(conflict_name("x.txt", a.conflict_id).len() > "x.txt".len(), true);
    // Extension candidates never repeat the canonical spelling.
    let mut names = ConflictNames::new("x.txt", a.conflict_id);
    let first = names.next().unwrap();
    assert_eq!(first, conflict_name("x.txt", a.conflict_id));
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(first);
    for candidate in names.take(8) {
        assert!(seen.insert(candidate), "candidates are distinct");
    }
}

#[test]
fn rename_rename_race_preserves_both_location_claims() {
    let base = view(vec![
        root_state(),
        dir_state(uid(ITEM_B), uid(ROOT), "dir-b", op(0x2001)),
        file_state(uid(ITEM_A), uid(ROOT), "f.txt", ver("v0"), digest(0), 10, op(0x2000)),
    ]);
    // Remote moves f.txt into dir-b; local renames it to g.txt at root.
    let remote = view(vec![
        root_state(),
        dir_state(uid(ITEM_B), uid(ROOT), "dir-b", op(0x2001)),
        file_state(uid(ITEM_A), uid(ITEM_B), "f.txt", ver("v0"), digest(0), 10, op(0x0002)),
    ]);
    let local = vec![edit(
        op(0x0001),
        uid(ITEM_A),
        LocalChange::Move { parent_id: uid(ROOT), name: "g.txt".to_owned() },
    )];
    let plan = run(ReconcileMode::Writable, &base, &local, &remote);

    assert_eq!(plan.conflicts.len(), 1);
    let conflict = &plan.conflicts[0];
    assert_eq!(conflict.kind, ConflictKind::RenameRace);
    assert_eq!(conflict.outcome, ConflictOutcome::KeepBoth);
    // Local move wins (lower op): the item lands at g.txt under root.
    let winner = plan
        .remote_ops
        .iter()
        .find(|o| o.item_id() == uid(ITEM_A))
        .expect("winner upsert");
    assert_eq!(winner.record.name, "g.txt");
    assert_eq!(winner.record.parent_id, Some(uid(ROOT)));
    // The losing remote claim materializes as the deterministic copy in
    // dir-b, referencing the same content version (no re-upload).
    let copy_id = conflict.preserved_item_id.expect("copy preserved");
    let copy = plan
        .remote_ops
        .iter()
        .find(|o| o.item_id() == copy_id)
        .expect("copy upsert");
    assert_eq!(copy.record.parent_id, Some(uid(ITEM_B)));
    assert_eq!(copy.record.content_version_id, Some(ver("v0")));
    assert_eq!(copy.record.name, "f (conflict ca8cac2a8571).txt");
}

#[test]
fn move_versus_remote_delete_recovers_the_move() {
    let f = file_state(uid(ITEM_A), uid(ROOT), "f.txt", ver("v0"), digest(0), 10, op(0x2000));
    let base = view(vec![root_state(), f.clone()]);
    let remote = view(vec![root_state(), tombstone(&f, op(0x0002))]);
    let local = vec![edit(
        op(0x0001),
        uid(ITEM_A),
        LocalChange::Move { parent_id: uid(ROOT), name: "moved.txt".to_owned() },
    )];
    let plan = run(ReconcileMode::Writable, &base, &local, &remote);

    // The changed side survives; the committed deletion is recorded and
    // dropped; the item is revived at the mover's location.
    assert_eq!(plan.remote_ops.len(), 1);
    let record = &plan.remote_ops[0].record;
    assert!(!record.deleted);
    assert_eq!(record.deletion_operation, None);
    assert_eq!(record.name, "moved.txt");
    assert_eq!(plan.remote_ops[0].change, hfdrive_core::format::ChangeKind::Undelete);
    assert_eq!(plan.conflicts.len(), 1);
    assert_eq!(plan.conflicts[0].kind, ConflictKind::DeleteVsChange);
    assert_eq!(plan.conflicts[0].outcome, ConflictOutcome::Recovered);
    assert_eq!(outcome_of(&plan, op(0x0001)), IntentOutcomeKind::Published);
}

#[test]
fn local_delete_versus_remote_edit_preserves_the_edit() {
    let f = file_state(uid(ITEM_A), uid(ROOT), "f.txt", ver("v0"), digest(0), 10, op(0x2000));
    let base = view(vec![root_state(), f.clone()]);
    let remote = view(vec![
        root_state(),
        file_state(uid(ITEM_A), uid(ROOT), "f.txt", ver("v2"), digest(2), 22, op(0x0002)),
    ]);
    let local = vec![edit(op(0x0001), uid(ITEM_A), LocalChange::Delete)];
    let plan = run(ReconcileMode::Writable, &base, &local, &remote);

    // Nothing is published: the edit already exists remotely and the
    // deletion is dropped with a recovery record.
    assert_eq!(plan.remote_ops.len(), 0);
    assert_eq!(plan.conflicts.len(), 1);
    assert_eq!(plan.conflicts[0].kind, ConflictKind::DeleteVsChange);
    assert_eq!(plan.conflicts[0].outcome, ConflictOutcome::Recovered);
    assert_eq!(outcome_of(&plan, op(0x0001)), IntentOutcomeKind::Conflicted);
    // The local file was removed; the surviving edit is re-materialized.
    assert!(plan
        .local_actions
        .iter()
        .any(|a| a.action == LocalActionKind::CreatePlaceholder && a.item_id == uid(ITEM_A)));
}

#[test]
fn delete_versus_delete_converges_without_conflict() {
    let f = file_state(uid(ITEM_A), uid(ROOT), "f.txt", ver("v0"), digest(0), 10, op(0x2000));
    let base = view(vec![root_state(), f.clone()]);
    let remote = view(vec![root_state(), tombstone(&f, op(0x0002))]);
    let local = vec![edit(op(0x0001), uid(ITEM_A), LocalChange::Delete)];
    let plan = run(ReconcileMode::Writable, &base, &local, &remote);

    assert_eq!(plan.remote_ops.len(), 0);
    assert_eq!(plan.conflicts.len(), 0);
    assert_eq!(plan.local_actions.len(), 0);
    assert_eq!(outcome_of(&plan, op(0x0001)), IntentOutcomeKind::Converged);
}

#[test]
fn directory_delete_tombstones_unchanged_descendants() {
    let d = dir_state(uid(ITEM_B), uid(ROOT), "docs", op(0x2001));
    let f = file_state(uid(ITEM_A), uid(ITEM_B), "a.txt", ver("v0"), digest(0), 10, op(0x2000));
    let base = view(vec![root_state(), d.clone(), f.clone()]);
    let remote = base.clone();
    let local = vec![edit(op(0x0001), uid(ITEM_B), LocalChange::Delete)];
    let plan = run(ReconcileMode::Writable, &base, &local, &remote);

    assert_eq!(plan.conflicts.len(), 0);
    assert_eq!(plan.remote_ops.len(), 2);
    assert!(plan.remote_ops.iter().all(|o| o.is_tombstone()));
    // Deepest tombstone applies first.
    assert_eq!(plan.remote_ops[0].item_id(), uid(ITEM_A));
    assert_eq!(plan.remote_ops[1].item_id(), uid(ITEM_B));
    assert_eq!(plan.remote_ops[0].record.deletion_operation, Some(op(0x0001)));
    assert_batch_namespaces(&remote, &plan, 1, 2);
}

#[test]
fn directory_delete_preserves_new_descendants_under_recovered_directory() {
    // Device A deletes "docs"; device B created docs/new.txt after the base.
    let d = dir_state(uid(ITEM_B), uid(ROOT), "docs", op(0x2001));
    let base = view(vec![root_state(), d.clone()]);
    let remote = view(vec![
        root_state(),
        d.clone(),
        file_state(uid(ITEM_A), uid(ITEM_B), "new.txt", ver("v9"), digest(9), 9, op(0x0002)),
    ]);
    let local = vec![edit(op(0x0001), uid(ITEM_B), LocalChange::Delete)];
    let plan = run(ReconcileMode::Writable, &base, &local, &remote);

    // The delete tombstones docs; the new descendant survives under the
    // deterministic recovered directory at the root.
    let recovery = plan
        .conflicts
        .iter()
        .find(|c| c.kind == ConflictKind::DirectoryDeleteRecovery)
        .expect("recovery record");
    assert_eq!(recovery.item_id, uid(ITEM_B));
    assert_eq!(recovery.outcome, ConflictOutcome::RecoveredDirectory);
    let recovered_dir = recovery.preserved_item_id.expect("recovered dir");
    let dir_op = plan
        .remote_ops
        .iter()
        .find(|o| o.item_id() == recovered_dir)
        .expect("recovered dir upsert");
    assert_eq!(dir_op.record.name, "Recovered (conflict fec8fbb959d8)");
    assert_eq!(dir_op.record.parent_id, Some(uid(ROOT)));

    let survivor = plan
        .remote_ops
        .iter()
        .find(|o| o.item_id() == uid(ITEM_A))
        .expect("survivor upsert");
    assert_eq!(survivor.record.parent_id, Some(recovered_dir));
    assert!(!survivor.record.deleted);
    assert_eq!(survivor.change, hfdrive_core::format::ChangeKind::Location);
    assert_eq!(outcome_of(&plan, op(0x0001)), IntentOutcomeKind::Published);
    assert_batch_namespaces(&remote, &plan, 1, 2);
}

#[test]
fn ancestor_move_cycle_is_redirected_to_root_recovered_directory() {
    let a = dir_state(uid(ITEM_A), uid(ROOT), "a", op(0x2000));
    let b = dir_state(uid(ITEM_B), uid(ROOT), "b", op(0x2001));
    let base = view(vec![root_state(), a.clone(), b.clone()]);
    // Local moves a under b; remote moved b under a -> parent cycle.
    let remote = view(vec![
        root_state(),
        a.clone(),
        dir_state(uid(ITEM_B), uid(ITEM_A), "b", op(0x0002)),
    ]);
    let local = vec![edit(
        op(0x0001),
        uid(ITEM_A),
        LocalChange::Move { parent_id: uid(ITEM_B), name: "a".to_owned() },
    )];
    let plan = run(ReconcileMode::Writable, &base, &local, &remote);

    let cycle = plan
        .conflicts
        .iter()
        .find(|c| c.kind == ConflictKind::CycleMove)
        .expect("cycle record");
    assert_eq!(cycle.outcome, ConflictOutcome::RecoveredDirectory);
    // The cycle-producing move (greatest location op: op(0x0002) on b) is
    // not applied; b lands under the root-level recovered directory.
    let recovered_dir = cycle.preserved_item_id.expect("redirected item");
    assert_eq!(recovered_dir, uid(ITEM_B));
    let dir = plan
        .remote_ops
        .iter()
        .find(|o| o.item_id() == recovered_dir)
        .expect("b upsert");
    let parent = dir.record.parent_id.expect("b has a parent");
    let parent_op = plan
        .remote_ops
        .iter()
        .find(|o| o.item_id() == parent)
        .expect("recovered dir upsert");
    assert_eq!(parent_op.record.parent_id, Some(uid(ROOT)), "recovered dir is root-level");
    assert!(parent_op.record.name.starts_with("Recovered (conflict "));
    // a keeps its intended location under b.
    let a_op = plan
        .remote_ops
        .iter()
        .find(|o| o.item_id() == uid(ITEM_A))
        .expect("a upsert");
    assert_eq!(a_op.record.parent_id, Some(uid(ITEM_B)));
    assert_batch_namespaces(&remote, &plan, 1, 2);
}

#[test]
fn directory_recreation_after_delete_takes_the_freed_name() {
    let d = dir_state(uid(ITEM_B), uid(ROOT), "docs", op(0x2001));
    let base = view(vec![root_state(), d.clone()]);
    let remote = base.clone();
    let local = vec![
        edit(op(0x0001), uid(ITEM_B), LocalChange::Delete),
        edit(
            op(0x0002),
            uid(ITEM_A),
            LocalChange::Create {
                parent_id: uid(ROOT),
                name: "docs".to_owned(),
                kind: ItemKind::Directory,
                content: None,
            },
        ),
    ];
    let plan = run(ReconcileMode::Writable, &base, &local, &remote);

    assert_eq!(plan.conflicts.len(), 0, "recreation after delete is not a conflict");
    assert_eq!(plan.remote_ops.len(), 2);
    assert!(plan.remote_ops[0].is_tombstone(), "the tombstone frees the name first");
    assert_eq!(plan.remote_ops[1].item_id(), uid(ITEM_A));
    assert_eq!(plan.remote_ops[1].record.name, "docs");
    assert_batch_namespaces(&remote, &plan, 1, 2);
}

#[test]
fn case_only_rename_composes_with_remote_content_edit() {
    let base = view(vec![
        root_state(),
        file_state(uid(ITEM_A), uid(ROOT), "Report.txt", ver("v0"), digest(0), 10, op(0x2000)),
    ]);
    let remote = view(vec![
        root_state(),
        file_state(uid(ITEM_A), uid(ROOT), "Report.txt", ver("v2"), digest(2), 22, op(0x0002)),
    ]);
    let local = vec![edit(
        op(0x0001),
        uid(ITEM_A),
        LocalChange::Move { parent_id: uid(ROOT), name: "report.txt".to_owned() },
    )];
    let plan = run(ReconcileMode::Writable, &base, &local, &remote);

    assert_eq!(plan.conflicts.len(), 0);
    let record = &plan.remote_ops[0].record;
    assert_eq!(record.name, "report.txt", "case-only rename survives");
    assert_eq!(record.content_version_id, Some(ver("v2")));
    assert_eq!(record.content_operation, op(0x0002));
    assert_eq!(record.location_operation, op(0x0001));
    // The local file keeps its bytes; only content replacement is needed
    // once the rename is applied.
    assert!(plan
        .local_actions
        .iter()
        .any(|a| a.action == LocalActionKind::UpdatePlaceholder && a.item_id == uid(ITEM_A)));
}

#[test]
fn portable_name_collision_renames_the_higher_operation_loser() {
    // "straße" and "strasse" share one portable collision key.
    let base = view(vec![
        root_state(),
        file_state(uid(ITEM_A), uid(ROOT), "straße", ver("v0"), digest(0), 10, op(0x0002)),
    ]);
    let remote = base.clone();
    let local = vec![edit(
        op(0x0001),
        uid(ITEM_B),
        LocalChange::Create {
            parent_id: uid(ROOT),
            name: "strasse".to_owned(),
            kind: ItemKind::File,
            content: Some(new_content("v1", 1, 11)),
        },
    )];
    let plan = run(ReconcileMode::Writable, &base, &local, &remote);

    let collision = plan
        .conflicts
        .iter()
        .find(|c| c.kind == ConflictKind::NameCollision)
        .expect("name collision record");
    assert_eq!(collision.preserved_item_id, Some(uid(ITEM_A)), "the higher op loses");
    // The lower operation keeps its spelling; the loser keeps its spelling
    // plus the deterministic marker.
    let loser = plan
        .remote_ops
        .iter()
        .find(|o| o.item_id() == uid(ITEM_A))
        .expect("loser upsert");
    assert!(loser.record.name.starts_with("straße (conflict "), "{}", loser.record.name);
    assert_eq!(loser.record.location_operation, op(0x0001));
    assert_eq!(loser.record.item_revision, op(0x0001));
    assert_eq!(loser.old_revision, Some(op(0x0002)));
    assert_eq!(collision.competing_operations, vec![op(0x0001), op(0x0002)]);
    let winner = plan
        .remote_ops
        .iter()
        .find(|o| o.item_id() == uid(ITEM_B))
        .expect("winner upsert");
    assert_eq!(winner.record.name, "strasse");
    let committed = assert_batch_namespaces(&remote, &plan, 1, 2);
    let replay = run(ReconcileMode::Writable, &base, &local, &committed);
    assert!(replay.remote_ops.is_empty());
}

#[test]
fn generated_name_relocation_keeps_remote_content_and_uses_the_competing_cause() {
    let original = file_state(
        uid(ITEM_A), uid(ROOT), "straße", ver("before-content-edit"), digest(0), 10, op(2),
    );
    let base = view(vec![root_state(), original.clone()]);
    let mut changed = original;
    changed.content_version_id = Some(ver("remote-content-edit"));
    changed.content_sha256 = Some(digest(3));
    changed.content_size = Some(30);
    changed.content_operation = op(0x3000);
    changed.item_revision = op(0x3000);
    let remote = view(vec![root_state(), changed]);
    let local = vec![edit(op(1), uid(ITEM_B), LocalChange::Create {
        parent_id: uid(ROOT),
        name: "strasse".to_owned(),
        kind: ItemKind::File,
        content: Some(new_content("new-colliding-file", 1, 11)),
    })];
    let plan = run(ReconcileMode::Writable, &base, &local, &remote);
    let relocated = plan.remote_ops.iter().find(|operation| operation.item_id() == uid(ITEM_A)).unwrap();
    assert_eq!(relocated.old_revision, Some(op(0x3000)));
    assert_eq!(relocated.record.content_operation, op(0x3000));
    assert_eq!(relocated.record.location_operation, op(1));
    assert_eq!(relocated.record.item_revision, op(1));
    let committed = assert_batch_namespaces(&remote, &plan, 1, 2);
    assert_eq!(committed.get(uid(ITEM_A)).unwrap().content_sha256, Some(digest(3)));
    let replay = run(ReconcileMode::Writable, &base, &local, &committed);
    assert!(replay.remote_ops.is_empty());
}

#[test]
fn ntfs_only_collision_plans_a_deterministic_local_alias() {
    // "maı" (dotless i) and "mai" are portable-distinct but collide under
    // case-insensitive NTFS comparison. Both arrive from remote, so the alias
    // rides on the loser's materialization.
    struct FoldI;
    impl NtfsNameCompare for FoldI {
        fn equal(&self, a: &str, b: &str) -> bool {
            a.replace('\u{131}', "i").to_lowercase() == b.replace('\u{131}', "i").to_lowercase()
        }
    }
    let base = view(vec![root_state()]);
    let remote = view(vec![
        root_state(),
        file_state(uid(ITEM_A), uid(ROOT), "ma\u{131}", ver("v0"), digest(0), 10, op(0x0002)),
        file_state(uid(ITEM_B), uid(ROOT), "mai", ver("v0"), digest(0), 10, op(0x0001)),
    ]);
    let local: Vec<LocalIntent> = Vec::new();
    let mut ids = DeterministicIds::new(NS);
    let input = ReconcileInput {
        workspace_id: ws(),
        mode: ReconcileMode::Writable,
        base: &base,
        local: &local,
        remote: &remote,
        ntfs: &FoldI,
    };
    let plan = reconcile(&input, &mut ids).expect("reconcile succeeds");

    assert_eq!(plan.conflicts.len(), 0, "portable names are distinct: nothing to rename remotely");
    assert_eq!(plan.aliases.len(), 1);
    let alias = &plan.aliases[0];
    assert_eq!(alias.item_id, uid(ITEM_A), "the higher operation takes the alias");
    assert_eq!(alias.remote_name, "ma\u{131}", "the remote name never changes");
    assert!(alias.local_alias.starts_with("ma\u{131} (conflict "), "{}", alias.local_alias);
    // The loser materializes under its deterministic local alias.
    let action = plan
        .local_actions
        .iter()
        .find(|a| a.item_id == uid(ITEM_A))
        .expect("loser has a local action");
    assert_eq!(action.action, LocalActionKind::CreatePlaceholder);
    assert_eq!(action.local_alias.as_deref(), Some(alias.local_alias.as_str()));
    // The winner materializes under its remote name.
    let winner = plan
        .local_actions
        .iter()
        .find(|a| a.item_id == uid(ITEM_B))
        .expect("winner has a local action");
    assert!(winner.local_alias.is_none());
}

// ---------------------------------------------------------------------------
// Context refusal, read-only, echo suppression
// ---------------------------------------------------------------------------

#[test]
fn incomplete_context_is_refused_not_guessed() {
    let base = view(vec![
        root_state(),
        file_state(uid(ITEM_A), uid(ROOT), "f.txt", ver("v0"), digest(0), 10, op(0x2000)),
    ]);
    let remote = base.clone();
    // A move into a parent that exists in no view must be refused.
    let local = vec![edit(
        op(0x0001),
        uid(ITEM_A),
        LocalChange::Move { parent_id: uid(ITEM_B), name: "f.txt".to_owned() },
    )];
    let mut ids = DeterministicIds::new(NS);
    let input = ReconcileInput {
        workspace_id: ws(),
        mode: ReconcileMode::Writable,
        base: &base,
        local: &local,
        remote: &remote,
        ntfs: &OrdinalIgnoreCase,
    };
    let result = reconcile(&input, &mut ids);
    match &result {
        Err(ReconcileError::MissingContext(missing)) => {
            assert!(missing.contains(&MissingRef::Parent {
                item_id: uid(ITEM_A),
                missing: uid(ITEM_B),
            }));
        }
        other => panic!("expected MissingContext, got {other:?}"),
    }

    // A view with a dangling parent is refused at construction.
    let orphan = ItemState {
        item_id: uid(ITEM_A),
        parent_id: Some(uid(ITEM_B)),
        name: "f.txt".to_owned(),
        kind: ItemKind::File,
        deleted: false,
        item_revision: op(0x2000),
        content_version_id: Some(ver("v0")),
        content_operation: op(0x2000),
        location_operation: op(0x2000),
        deletion_operation: None,
        content_sha256: Some(digest(0)),
        content_size: Some(10),
    };
    let view_result = CatalogView::new(vec![root_state(), orphan]);
    match &view_result {
        Err(ReconcileError::MissingContext(missing)) => {
            assert!(missing.contains(&MissingRef::Ancestor {
                item_id: uid(ITEM_A),
                missing: uid(ITEM_B),
            }));
        }
        other => panic!("expected MissingContext, got {other:?}"),
    }
}

#[test]
fn read_only_defers_dirty_work_and_never_publishes() {
    let base = view(vec![
        root_state(),
        file_state(uid(ITEM_A), uid(ROOT), "f.txt", ver("v0"), digest(0), 10, op(0x2000)),
        file_state(uid(ITEM_B), uid(ROOT), "g.txt", ver("v0"), digest(0), 10, op(0x2001)),
    ]);
    // Remote renames g.txt (a clean item must follow); local dirties f.txt.
    let remote = view(vec![
        root_state(),
        file_state(uid(ITEM_A), uid(ROOT), "f.txt", ver("v0"), digest(0), 10, op(0x2000)),
        file_state(uid(ITEM_B), uid(ROOT), "h.txt", ver("v0"), digest(0), 10, op(0x0002)),
    ]);
    let local = vec![edit(
        op(0x0001),
        uid(ITEM_A),
        LocalChange::Content { content: new_content("v1", 1, 11) },
    )];
    let plan = run(ReconcileMode::ReadOnly, &base, &local, &remote);

    assert_eq!(plan.remote_ops.len(), 0, "read-only publishes nothing");
    assert_eq!(plan.versions.len(), 0);
    assert_eq!(outcome_of(&plan, op(0x0001)), IntentOutcomeKind::Deferred);
    // The dirty item is left alone; the clean item follows the remote rename.
    assert_eq!(plan.local_actions.len(), 1);
    assert_eq!(plan.local_actions[0].item_id, uid(ITEM_B));
    assert_eq!(plan.local_actions[0].action, LocalActionKind::Rename);
}

#[test]
fn materialization_echo_never_publishes() {
    let base = view(vec![
        root_state(),
        file_state(uid(ITEM_A), uid(ROOT), "f.txt", ver("v0"), digest(0), 10, op(0x2000)),
    ]);
    let remote = view(vec![
        root_state(),
        file_state(uid(ITEM_A), uid(ROOT), "f.txt", ver("v2"), digest(2), 22, op(0x0002)),
    ]);
    let materialized = remote.get(uid(ITEM_A)).unwrap().clone();
    let local = vec![LocalIntent {
        operation_id: op(0x0001),
        item_id: uid(ITEM_A),
        origin: LocalOrigin::RemoteMaterialization,
        observed_generation: 7,
        change: LocalChange::Materialized { state: materialized },
    }];
    let plan = run(ReconcileMode::Writable, &base, &local, &remote);
    assert_eq!(plan.remote_ops.len(), 0, "materialization never publishes");
    assert_eq!(plan.local_actions.len(), 0, "materialization never re-applies");
    assert_eq!(outcome_of(&plan, op(0x0001)), IntentOutcomeKind::Converged);

    // A materialization whose content is not traceable to any known binding
    // is refused rather than echoed as a local write.
    let mut unknown = remote.get(uid(ITEM_A)).unwrap().clone();
    unknown.content_sha256 = Some(digest(0xEE));
    unknown.content_version_id = Some(ver("vX"));
    unknown.item_revision = op(0x0003);
    unknown.content_operation = op(0x0003);
    let local = vec![LocalIntent {
        operation_id: op(0x0004),
        item_id: uid(ITEM_A),
        origin: LocalOrigin::RemoteMaterialization,
        observed_generation: 7,
        change: LocalChange::Materialized { state: unknown },
    }];
    let mut ids = DeterministicIds::new(NS);
    let input = ReconcileInput {
        workspace_id: ws(),
        mode: ReconcileMode::Writable,
        base: &base,
        local: &local,
        remote: &remote,
        ntfs: &OrdinalIgnoreCase,
    };
    let result = reconcile(&input, &mut ids);
    match &result {
        Err(ReconcileError::MaterializationEchoMismatch) => {}
        other => panic!("expected MaterializationEchoMismatch, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Retry convergence and batching
// ---------------------------------------------------------------------------

#[test]
fn retry_finds_the_same_conflict_item_instead_of_a_second_copy() {
    let base = view(vec![
        root_state(),
        file_state(uid(ITEM_A), uid(ROOT), "report.txt", ver("v0"), digest(0), 10, op(0x2000)),
    ]);
    let remote = view(vec![
        root_state(),
        file_state(uid(ITEM_A), uid(ROOT), "report.txt", ver("v2"), digest(2), 22, op(0x0002)),
    ]);
    let local = vec![edit(
        op(0x0001),
        uid(ITEM_A),
        LocalChange::Content { content: new_content("v1", 1, 11) },
    )];
    let first = run(ReconcileMode::Writable, &base, &local, &remote);
    let copy_id = first.conflicts[0].preserved_item_id.unwrap();
    let copy_name = first.conflicts[0].preserved_name.clone().unwrap();

    // Simulate a retry after the copy's half of the plan was published: the
    // copy now exists remotely at its conflict name with the losing content.
    let copy_published = {
        let mut state = remote.get(uid(ITEM_A)).unwrap().clone();
        state.item_id = copy_id;
        state.name = copy_name.clone();
        state.item_revision = op(0x0002);
        state
    };
    let remote2 = view(vec![
        root_state(),
        remote.get(uid(ITEM_A)).unwrap().clone(),
        copy_published,
    ]);
    let second = run(ReconcileMode::Writable, &base, &local, &remote2);

    assert_eq!(op_count(&second, copy_id), 0, "the retry reuses the same conflict item");
    assert_eq!(second.conflicts.len(), 1);
    assert_eq!(second.conflicts[0].preserved_item_id, Some(copy_id));
    assert_eq!(second.conflicts[0].preserved_name.as_deref(), Some(copy_name.as_str()));
    assert_eq!(second.conflicts[0].conflict_id, first.conflicts[0].conflict_id);
    // The winner mutation is still planned exactly once.
    assert_eq!(op_count(&second, uid(ITEM_A)), 1);
}

#[test]
fn commit_batches_cover_every_op_in_order_without_truncation() {
    let base = view(vec![root_state()]);
    let remote = base.clone();
    let local: Vec<LocalIntent> = (0u128..25)
        .map(|n| {
            edit(
                op(0x0001 + n),
                uid(0x1000_0000_0000_4000_8000_0000_0000_0000 + n),
                LocalChange::Create {
                    parent_id: uid(ROOT),
                    name: format!("f{n}.txt"),
                    kind: ItemKind::File,
                    content: Some(new_content(&format!("v{n}"), n as u8 + 1, 1)),
                },
            )
        })
        .collect();
    let plan = run(ReconcileMode::Writable, &base, &local, &remote);
    assert_eq!(plan.remote_ops.len(), 25);

    let batches = plan.commit_batches(10, 1000).expect("batches");
    assert_eq!(batches.len(), 3, "25 ops in batches of at most 10");
    let mut seen = Vec::new();
    for (index, batch) in batches.iter().enumerate() {
        assert_eq!(batch.index, index);
        assert!(batch.remote_ops.len() <= 10);
        assert_eq!(batch.changes.len(), batch.remote_ops.len());
        let mut sorted = batch.changes.clone();
        sorted.sort_by_key(|c| c.item_id);
        assert_eq!(batch.changes, sorted, "changes ascend by item id");
        for op_rec in &batch.remote_ops {
            seen.push(op_rec.item_id());
        }
    }
    assert_eq!(seen.len(), 25, "no operation is dropped or duplicated");
    // Prefix property: concatenating batches reproduces the plan order.
    let flat: Vec<_> = batches.iter().flat_map(|b| b.remote_ops.iter()).collect();
    for (a, b) in flat.iter().zip(plan.remote_ops.iter()) {
        assert_eq!(a.item_id(), b.item_id());
    }
    // Invalid bounds are refused instead of silently truncating.
    assert!(plan.commit_batches(0, 1000).is_err());
}

#[test]
fn commit_batches_three_creates_split_at_the_two_two_limits() {
    let base = view(vec![root_state()]);
    let remote = base.clone();
    let local: Vec<LocalIntent> = (0u128..3)
        .map(|n| {
            edit(
                op(0x0001 + n),
                uid(0x1000_0000_0000_4000_8000_0000_0000_0000 + n),
                LocalChange::Create {
                    parent_id: uid(ROOT),
                    name: format!("f{n}.txt"),
                    kind: ItemKind::File,
                    content: Some(new_content(&format!("v{n}"), n as u8 + 1, 1)),
                },
            )
        })
        .collect();
    let plan = run(ReconcileMode::Writable, &base, &local, &remote);
    assert_eq!(plan.remote_ops.len(), 3);

    let batches = plan.commit_batches(2, 2).expect("batches");
    assert_eq!(batches.len(), 2, "three creates split into [2, 1] at the (2, 2) limits");
    assert_eq!(batches[0].index, 0);
    assert_eq!(batches[1].index, 1);
    assert_eq!(batches[0].remote_ops.len(), 2);
    assert_eq!(batches[1].remote_ops.len(), 1);

    // Exact, disjoint id sets: each batch claims only its own records' ids.
    assert_eq!(batches[0].operation_ids, vec![op(0x0001), op(0x0002)]);
    assert_eq!(batches[1].operation_ids, vec![op(0x0003)]);
    for batch in &batches {
        assert_eq!(
            batch.operation_ids,
            batch_ids(batch),
            "ids are recomputed from the batch's own records"
        );
        assert!(batch.operation_ids.len() <= 2, "operation bound preserved");
        assert!(batch.changes.len() <= 2, "change bound preserved");
        assert_eq!(batch.changes.len(), batch.remote_ops.len());
        let mut sorted = batch.changes.clone();
        sorted.sort_by_key(|c| c.item_id);
        assert_eq!(batch.changes, sorted, "changes ascend by item id");
    }
    let mut disjoint = std::collections::BTreeSet::new();
    for batch in &batches {
        for id in &batch.operation_ids {
            assert!(disjoint.insert(*id), "each operation id is claimed by exactly one batch");
        }
    }
    let union: Vec<OperationId> = disjoint.into_iter().collect();
    assert_eq!(union, plan.operation_ids, "the batches claim the realized ids exactly once");

    // Recovery semantics: contiguous prefixes in plan order, no truncation.
    let flat: Vec<_> = batches.iter().flat_map(|b| b.remote_ops.iter()).collect();
    assert_eq!(flat.len(), plan.remote_ops.len());
    for (a, b) in flat.into_iter().zip(plan.remote_ops.iter()) {
        assert_eq!(a, b, "batch concatenation reproduces the plan order");
    }

    // Bounds still refuse unsatisfiable input.
    assert!(plan.commit_batches(0, 2).is_err());
    assert!(plan.commit_batches(2, 0).is_err());
    // Deterministic: re-running produces identical batches.
    assert_eq!(batches, plan.commit_batches(2, 2).expect("batches"));
}

#[test]
fn commit_batches_operation_ids_are_exact_and_disjoint_after_a_split() {
    // A content edit merged with a remote rename emits one record referencing
    // two distinct operation ids; the two creates reference one each. A split
    // must recompute the incoming op's ids against a fresh set instead of
    // retaining the previous batch's ids.
    let base = view(vec![
        root_state(),
        file_state(uid(ITEM_A), uid(ROOT), "old.txt", ver("v0"), digest(0), 10, op(0x2000)),
    ]);
    let remote = view(vec![
        root_state(),
        file_state(uid(ITEM_A), uid(ROOT), "new.txt", ver("v0"), digest(0), 10, op(0x3000)),
    ]);
    let x1 = uid(0x1000_0000_0000_4000_8000_0000_0000_0001);
    let x2 = uid(0x1000_0000_0000_4000_8000_0000_0000_0002);
    let local = vec![
        edit(
            op(0x0001),
            uid(ITEM_A),
            LocalChange::Content { content: new_content("v1", 1, 11) },
        ),
        edit(
            op(0x0002),
            x1,
            LocalChange::Create {
                parent_id: uid(ROOT),
                name: "a.txt".to_owned(),
                kind: ItemKind::File,
                content: Some(new_content("va", 2, 1)),
            },
        ),
        edit(
            op(0x0003),
            x2,
            LocalChange::Create {
                parent_id: uid(ROOT),
                name: "b.txt".to_owned(),
                kind: ItemKind::File,
                content: Some(new_content("vb", 3, 1)),
            },
        ),
    ];
    let plan = run(ReconcileMode::Writable, &base, &local, &remote);
    assert_eq!(plan.remote_ops.len(), 3);

    // The merged edit record references its own content operation and the
    // remote rename operation.
    let edit_op = plan
        .remote_ops
        .iter()
        .find(|o| o.item_id() == uid(ITEM_A))
        .expect("edit upsert");
    assert_eq!(edit_op.record.content_operation, op(0x0001));
    assert_eq!(edit_op.record.location_operation, op(0x3000));

    // Two changes fit, but the edit's second id forces the split.
    let batches = plan.commit_batches(10, 2).expect("batches");
    assert_eq!(batches.len(), 2);
    assert_eq!(batches[0].remote_ops.len(), 2);
    assert_eq!(batches[1].remote_ops.len(), 1);
    assert_eq!(batches[0].operation_ids, vec![op(0x0002), op(0x0003)], "the creates only");
    assert_eq!(
        batches[1].operation_ids,
        vec![op(0x0001), op(0x3000)],
        "the split batch recomputes the incoming op's ids from a fresh set"
    );
    for batch in &batches {
        assert_eq!(batch.operation_ids, batch_ids(batch));
    }
    let mut disjoint = std::collections::BTreeSet::new();
    for batch in &batches {
        for id in &batch.operation_ids {
            assert!(disjoint.insert(*id), "batches claim disjoint id sets");
        }
    }
    let union: Vec<OperationId> = disjoint.into_iter().collect();
    assert_eq!(union, plan.operation_ids);
    assert_eq!(plan.operation_ids.len(), 4);
    // Deterministic: re-running produces identical batches.
    assert_eq!(batches, plan.commit_batches(10, 2).expect("batches"));
}

#[test]
fn commit_batches_split_exactly_at_the_1001_operation_boundary() {
    let build = |count: u128| -> ReconcilePlan {
        let base = view(vec![root_state()]);
        let remote = base.clone();
        let local: Vec<LocalIntent> = (0..count)
            .map(|n| {
                edit(
                    op(0x0001 + n),
                    uid(0x1000_0000_0000_4000_8000_0000_0000_0000 + n),
                    LocalChange::Create {
                        parent_id: uid(ROOT),
                        name: format!("f{n}.txt"),
                        kind: ItemKind::File,
                        content: Some(new_content(&format!("v{n}"), (n % 251) as u8, 1)),
                    },
                )
            })
            .collect();
        run(ReconcileMode::Writable, &base, &local, &remote)
    };

    // Exactly at the v1 commit bound: one batch, no split.
    let at_bound = build(MAX_COMMIT_OPERATIONS as u128);
    assert_eq!(at_bound.remote_ops.len(), MAX_COMMIT_OPERATIONS);
    let one = at_bound
        .commit_batches(MAX_COMMIT_OPERATIONS, MAX_COMMIT_OPERATIONS)
        .expect("batches");
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].remote_ops.len(), MAX_COMMIT_OPERATIONS);
    assert_eq!(one[0].operation_ids.len(), MAX_COMMIT_OPERATIONS);
    assert_eq!(one[0].operation_ids, batch_ids(&one[0]));

    // One past the bound: 1000 + 1, never truncation and never leakage.
    let over = build(MAX_COMMIT_OPERATIONS as u128 + 1);
    assert_eq!(over.remote_ops.len(), MAX_COMMIT_OPERATIONS + 1);
    let batches = over
        .commit_batches(MAX_COMMIT_OPERATIONS, MAX_COMMIT_OPERATIONS)
        .expect("batches");
    assert_eq!(batches.len(), 2);
    assert_eq!(batches[0].remote_ops.len(), MAX_COMMIT_OPERATIONS);
    assert_eq!(batches[1].remote_ops.len(), 1);
    assert_eq!(batches[0].operation_ids.len(), MAX_COMMIT_OPERATIONS);
    assert_eq!(
        batches[1].operation_ids,
        vec![op(0x0001 + MAX_COMMIT_OPERATIONS as u128)],
        "the trailing batch carries only its own operation id"
    );
    for batch in &batches {
        assert_eq!(batch.operation_ids, batch_ids(batch));
        assert!(batch.operation_ids.len() <= MAX_COMMIT_OPERATIONS);
        assert!(batch.changes.len() <= MAX_COMMIT_OPERATIONS);
    }
    let mut disjoint = std::collections::BTreeSet::new();
    for batch in &batches {
        for id in &batch.operation_ids {
            assert!(disjoint.insert(*id), "batches claim disjoint id sets");
        }
    }
    let union: Vec<OperationId> = disjoint.into_iter().collect();
    assert_eq!(union, over.operation_ids);
    assert_eq!(over.operation_ids.len(), MAX_COMMIT_OPERATIONS + 1);

    // Recovery semantics: contiguous prefixes in plan order, no truncation.
    let flat: Vec<_> = batches.iter().flat_map(|b| b.remote_ops.iter()).collect();
    assert_eq!(flat.len(), over.remote_ops.len());
    for (a, b) in flat.into_iter().zip(over.remote_ops.iter()) {
        assert_eq!(a, b, "batch concatenation reproduces the plan order");
    }
}

#[test]
fn commit_batches_relocate_new_children_before_the_999th_tombstone() {
    let directory = dir_state(uid(ITEM_B), uid(ROOT), "docs", op(0x2001));
    let mut base_items = vec![root_state(), directory];
    for n in 0..998u128 {
        base_items.push(file_state(
            uid(0x1000_0000_0000_4000_8000_0000_0000_0000 + n),
            uid(ITEM_B),
            &format!("old-{n}.txt"),
            ver("unchanged"),
            digest(0),
            10,
            op(0x2001),
        ));
    }
    let mut remote_items = base_items.clone();
    remote_items.push(file_state(
        uid(ITEM_A), uid(ITEM_B), "new.txt", ver("new-child"), digest(9), 9, op(0x0002),
    ));
    let base = view(base_items);
    let remote = view(remote_items);
    let local = vec![edit(op(0x0001), uid(ITEM_B), LocalChange::Delete)];
    let plan = run(ReconcileMode::Writable, &base, &local, &remote);
    assert_eq!(plan.remote_ops.len(), 1001);
    let batches = plan.commit_batches(MAX_COMMIT_OPERATIONS, MAX_COMMIT_OPERATIONS).unwrap();
    assert_eq!(batches.iter().map(|batch| batch.remote_ops.len()).collect::<Vec<_>>(), vec![1000, 1]);
    assert_eq!(plan.remote_ops.last().unwrap().item_id(), uid(ITEM_B));
    assert!(plan.remote_ops.last().unwrap().is_tombstone());

    // Formerly the first commit deleted all 999 old items, created recovery,
    // and left new.txt live beneath the tombstoned docs until the next commit.
    let committed = assert_batch_namespaces(
        &remote, &plan, MAX_COMMIT_OPERATIONS, MAX_COMMIT_OPERATIONS,
    );
    // The operation-id limit can split before the survivor even when the
    // change limit has space. It must expose a valid namespace as well.
    assert_batch_namespaces(&remote, &plan, MAX_COMMIT_OPERATIONS, 2);
    let recovery = plan.conflicts.iter()
        .find(|conflict| conflict.kind == ConflictKind::DirectoryDeleteRecovery)
        .unwrap();
    let child = committed.get(uid(ITEM_A)).unwrap();
    assert_eq!(child.parent_id, recovery.preserved_item_id);
    assert_eq!(child.content_sha256, Some(digest(9)));
    assert_eq!(child.content_operation, op(0x0002));
    assert_eq!(child.location_operation, op(0x0001));
    assert_eq!(child.item_revision, op(0x0001));
    assert!(!child.deleted);
    let replay = run(ReconcileMode::Writable, &base, &local, &remote);
    assert_eq!(plan.remote_ops, replay.remote_ops);
    assert_eq!(plan.conflicts, replay.conflicts);
    let settled = run(ReconcileMode::Writable, &base, &local, &committed);
    assert!(settled.remote_ops.is_empty(), "replay does not relocate the recovered child again");
}

#[test]
fn commit_batches_create_tombstone_ancestors_before_unpublished_descendants() {
    let parent = uid(ITEM_B);
    let nested = uid(0xcccc);
    let created = uid(0xdddd);
    let base = view(vec![
        root_state(),
        file_state(uid(ITEM_A), uid(ROOT), "existing.txt", ver("existing"), digest(1), 1, op(0x2000)),
    ]);
    let local = vec![
        edit(op(1), parent, LocalChange::Create {
            parent_id: uid(ROOT), name: "temporary".to_owned(), kind: ItemKind::Directory, content: None,
        }),
        edit(op(2), nested, LocalChange::Create {
            parent_id: parent, name: "nested".to_owned(), kind: ItemKind::Directory, content: None,
        }),
        edit(op(3), created, LocalChange::Create {
            parent_id: nested, name: "created.txt".to_owned(), kind: ItemKind::File,
            content: Some(new_content("ephemeral", 2, 2)),
        }),
        edit(op(4), uid(ITEM_A), LocalChange::Move {
            parent_id: nested, name: "existing.txt".to_owned(),
        }),
        edit(op(5), parent, LocalChange::Delete),
    ];
    let plan = run(ReconcileMode::Writable, &base, &local, &base);
    assert_eq!(plan.remote_ops.len(), 4);
    assert!(plan.remote_ops.iter().all(|operation| operation.is_tombstone()));
    assert_eq!(plan.remote_ops[0].item_id(), parent);
    assert_eq!(plan.remote_ops[1].item_id(), nested);
    let committed = assert_batch_namespaces(&base, &plan, 1, 3);
    assert!(committed.iter().filter(|state| state.item_id != uid(ROOT)).all(|state| state.deleted));
}

#[test]
fn commit_batches_detach_ancestors_before_a_coalesced_move_and_delete() {
    let middle = uid(ITEM_B);
    let destination = uid(0xcccc);
    let base = view(vec![
        root_state(),
        dir_state(uid(ITEM_A), uid(ROOT), "outer", op(0x2000)),
        dir_state(middle, uid(ITEM_A), "middle", op(0x2001)),
        dir_state(destination, middle, "destination", op(0x2002)),
    ]);
    let local = vec![
        edit(op(1), middle, LocalChange::Move {
            parent_id: uid(ROOT), name: "middle".to_owned(),
        }),
        edit(op(2), uid(ITEM_A), LocalChange::Move {
            parent_id: destination, name: "outer".to_owned(),
        }),
        edit(op(3), uid(ITEM_A), LocalChange::Delete),
    ];
    let plan = run(ReconcileMode::Writable, &base, &local, &base);
    assert!(plan.conflicts.is_empty());
    assert_eq!(plan.remote_ops.len(), 2);
    assert_eq!(plan.remote_ops[0].item_id(), middle);
    assert_eq!(plan.remote_ops[1].item_id(), uid(ITEM_A));
    assert!(plan.remote_ops[1].is_tombstone());
    assert_batch_namespaces(&base, &plan, 1, 3);
}

#[test]
fn commit_batches_recover_nested_survivors_before_reusing_a_deleted_name() {
    let survivor = uid(ITEM_A);
    let survivor_file = uid(0xcccc);
    let replacement = uid(0xdddd);
    let local_file = uid(0xeeee);
    let directory = dir_state(uid(ITEM_B), uid(ROOT), "docs", op(0x2001));
    let base = view(vec![root_state(), directory.clone()]);
    let remote = view(vec![
        root_state(), directory,
        dir_state(survivor, uid(ITEM_B), "new-folder", op(0x2002)),
        file_state(survivor_file, survivor, "keep.txt", ver("keep"), digest(4), 4, op(0x2003)),
    ]);
    let local = vec![
        edit(op(1), uid(ITEM_B), LocalChange::Delete),
        edit(op(2), replacement, LocalChange::Create {
            parent_id: uid(ROOT), name: "docs".to_owned(), kind: ItemKind::Directory, content: None,
        }),
        edit(op(3), local_file, LocalChange::Create {
            parent_id: replacement, name: "local.txt".to_owned(), kind: ItemKind::File,
            content: Some(new_content("replacement-child", 5, 5)),
        }),
    ];
    let plan = run(ReconcileMode::Writable, &base, &local, &remote);
    assert_eq!(plan.conflicts.len(), 1);
    assert_eq!(plan.conflicts[0].kind, ConflictKind::DirectoryDeleteRecovery);
    assert_eq!(op_count(&plan, survivor_file), 0, "moving a directory preserves its unchanged subtree");
    let committed = assert_batch_namespaces(&remote, &plan, 1, 2);
    assert_eq!(committed.get(replacement).unwrap().name, "docs");
    assert_eq!(committed.get(local_file).unwrap().parent_id, Some(replacement));
    assert_eq!(committed.get(survivor_file), remote.get(survivor_file));
}

#[test]
fn commit_batches_keep_transient_name_swap_demotion_deterministic() {
    let base = view(vec![
        root_state(),
        dir_state(uid(ITEM_A), uid(ROOT), "a", op(0x2000)),
        dir_state(uid(ITEM_B), uid(ROOT), "b", op(0x2001)),
    ]);
    let local = vec![
        edit(op(1), uid(ITEM_A), LocalChange::Move { parent_id: uid(ROOT), name: "temporary".to_owned() }),
        edit(op(2), uid(ITEM_B), LocalChange::Move { parent_id: uid(ROOT), name: "a".to_owned() }),
        edit(op(3), uid(ITEM_A), LocalChange::Move { parent_id: uid(ROOT), name: "b".to_owned() }),
    ];
    let plan = run(ReconcileMode::Writable, &base, &local, &base);
    let identity = conflict_identity(ws(), ConflictKind::NameCollision, &[uid(ITEM_A)], &[op(3)]);
    assert_eq!(plan.conflicts.len(), 1);
    assert_eq!(plan.conflicts[0].conflict_id, identity.conflict_id);
    let committed = assert_batch_namespaces(&base, &plan, 1, 2);
    assert_eq!(committed.get(uid(ITEM_A)).unwrap().name, conflict_name("b", identity.conflict_id));
    assert_eq!(committed.get(uid(ITEM_B)).unwrap().name, "a");
    let replay = run(ReconcileMode::Writable, &base, &local, &base);
    assert_eq!(plan.remote_ops, replay.remote_ops);
    assert_eq!(plan.conflicts, replay.conflicts);
}

#[test]
fn conflict_names_respect_the_utf16_component_limit() {
    let long = format!("{}.txt", "a".repeat(250));
    let ident = conflict_identity(
        ws(),
        ConflictKind::ContentDivergence,
        &[uid(ITEM_A)],
        &[op(0x0001), op(0x0002)],
    );
    let name = conflict_name(&long, ident.conflict_id);
    assert!(name.encode_utf16().count() <= 255);
    assert!(name.contains("(conflict "), "{}", name);
    assert!(name.ends_with(".txt"), "{}", name);
    // The marker is preserved even when the stem must be truncated.
    let short_stem = conflict_name("\u{1f600}.txt", ident.conflict_id);
    assert!(short_stem.encode_utf16().count() <= 255);
}

#[test]
fn repeated_delete_observations_publish_once_and_converge_on_replay() {
    let file = file_state(uid(ITEM_A), uid(ROOT), "f.txt", ver("v0"), digest(0), 10, op(0x2000));
    let base = view(vec![root_state(), file.clone()]);
    let mut repeated = edit(op(0x0002), uid(ITEM_A), LocalChange::Delete);
    repeated.observed_generation = 2;
    let local = vec![edit(op(0x0001), uid(ITEM_A), LocalChange::Delete), repeated];
    let plan = run(ReconcileMode::Writable, &base, &local, &base);
    assert_eq!(op_count(&plan, uid(ITEM_A)), 1);
    let deleted = &plan.remote_ops[0].record;
    assert!(deleted.deleted);
    assert_eq!(deleted.deletion_operation, Some(op(0x0001)));
    assert_eq!(outcome_of(&plan, op(0x0001)), IntentOutcomeKind::Published);
    assert_eq!(outcome_of(&plan, op(0x0002)), IntentOutcomeKind::Superseded);
    assert!(plan.conflicts.is_empty());

    let committed = view(vec![root_state(), tombstone(&file, op(0x0001))]);
    let replay = run(ReconcileMode::Writable, &committed, &local, &committed);
    assert!(replay.remote_ops.is_empty());
    assert!(replay.local_actions.is_empty());
    for operation in [op(0x0001), op(0x0002)] {
        assert_eq!(outcome_of(&replay, operation), IntentOutcomeKind::Converged);
    }
}

#[test]
fn parent_and_child_delete_observations_preserve_one_subtree_deletion() {
    let directory = dir_state(uid(ITEM_A), uid(ROOT), "folder", op(0x2000));
    let child = file_state(uid(ITEM_B), uid(ITEM_A), "child.txt", ver("child-v0"), digest(1), 10, op(0x2001));
    let base = view(vec![root_state(), directory, child]);
    let local = vec![
        edit(op(0x0001), uid(ITEM_A), LocalChange::Delete),
        edit(op(0x0002), uid(ITEM_B), LocalChange::Delete),
    ];
    let plan = run(ReconcileMode::Writable, &base, &local, &base);
    let deleted: std::collections::BTreeSet<_> = plan.remote_ops.iter().map(|operation| {
        assert!(operation.record.deleted);
        assert_eq!(operation.record.deletion_operation, Some(op(0x0001)));
        operation.record.item_id
    }).collect();
    assert_eq!(deleted, std::collections::BTreeSet::from([uid(ITEM_A), uid(ITEM_B)]));
    assert!(plan.conflicts.is_empty());
    assert_eq!(outcome_of(&plan, op(0x0001)), IntentOutcomeKind::Published);
    assert_eq!(outcome_of(&plan, op(0x0002)), IntentOutcomeKind::Superseded);
}
