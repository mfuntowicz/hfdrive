//! Consumer-visible deterministic regression cases for three-way
//! reconciliation: every race family, conflict retry identity/name
//! stability, incomplete-context refusal, and read-only behaviour.

use hfdrive_core::format::{DisplayMetadata, ItemKind};
use hfdrive_core::ids::{ItemId, OperationId, UploadId, VersionId, WorkspaceId};
use hfdrive_core::reconcile::{
    conflict_identity, conflict_name, reconcile, CatalogView, ConflictKind, ConflictNames,
    ConflictOutcome, DeterministicIds, IntentOutcomeKind, ItemState, LocalActionKind,
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
    let winner = plan
        .remote_ops
        .iter()
        .find(|o| o.item_id() == uid(ITEM_B))
        .expect("winner upsert");
    assert_eq!(winner.record.name, "strasse");
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
