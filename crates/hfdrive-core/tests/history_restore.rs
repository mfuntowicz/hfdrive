//! Bounded paginated history traversal and restore-as-new-mutation planning.

use hfdrive_core::format::{
    ChangeKind, CommitV1, DisplayMetadata, ItemChange, ItemKind, ItemRecord, FORMAT_NAME,
    SCHEMA_VERSION,
};
use hfdrive_core::history::{
    history_page, plan_restore, CommitSource, HistoryCursor, HistoryError, HistoryOptions,
    InvalidCursor, RestoreSpec,
};
use hfdrive_core::ids::{CommitId, ItemId, OperationId, UploadId, VersionId, WorkspaceId};
use hfdrive_core::reconcile::{
    DeterministicIds, IdSource, IntentOutcomeKind, ItemState, LocalActionKind, ReconcileMode,
};
use hfdrive_core::storage::{ObjectRef, PayloadKey, Sha256Digest, XetFileId};
use std::collections::BTreeMap;
use std::convert::Infallible;
use uuid::Uuid;

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    loop {
        match future.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(value) => return value,
            std::task::Poll::Pending => std::thread::yield_now(),
        }
    }
}

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
fn commit_id(n: u128) -> CommitId {
    CommitId::from_uuid(Uuid::from_u128(n)).unwrap()
}
fn ver(n: u128) -> VersionId {
    VersionId::from_uuid(Uuid::from_u128(n)).unwrap()
}

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

fn commit(n: u128, parent: Option<CommitId>, changes: Vec<ItemChange>) -> CommitV1 {
    CommitV1 {
        format: FORMAT_NAME.to_owned(),
        schema_version: SCHEMA_VERSION,
        workspace_id: ws(),
        commit_id: commit_id(n),
        parent_commit_id: parent,
        catalog_root: digest((n & 0xff) as u8),
        operation_ids: vec![op(0x2000 + n)],
        changes,
        device_id: hfdrive_core::ids::DeviceId::from_uuid(Uuid::from_u128(0x5000)).unwrap(),
        created_at: "2026-01-01T00:00:00Z".to_owned(),
    }
}

fn change(item: u128, kind: ChangeKind) -> ItemChange {
    ItemChange {
        item_id: uid(item),
        change: kind,
        old_revision: Some(op(0x2000)),
        new_revision: op(0x2001),
    }
}

struct MemCommits(BTreeMap<CommitId, CommitV1>);

impl CommitSource for MemCommits {
    type Error = Infallible;
    fn load_commit(
        &mut self,
        commit_id: CommitId,
    ) -> impl Future<Output = Result<Option<CommitV1>, Self::Error>> + Send {
        let commit = self.0.get(&commit_id).cloned();
        async move { Ok(commit) }
    }
}

#[test]
fn history_pages_are_bounded_and_resumable() {
    // c1 <- c2 <- ... <- c6; only c2 and c5 touch item A.
    let mut commits = BTreeMap::new();
    let mut parent = None;
    for n in 1u128..=6 {
        let touches_a = n == 2 || n == 5;
        let changes = if touches_a {
            vec![change(0xAAAA, ChangeKind::Content)]
        } else {
            vec![change(0xBBBB, ChangeKind::Create)]
        };
        let c = commit(n, parent, changes);
        parent = Some(c.commit_id);
        commits.insert(c.commit_id, c);
    }
    let mut source = MemCommits(commits);
    let head = Some(commit_id(6));

    // Full walk in pages of two: newest first, cursors resume exactly.
    let options = HistoryOptions { filter: None, page_limit: 2, max_loads_per_page: 1024 };
    let page1 = block_on(history_page(&mut source, head, None, &options)).unwrap();
    assert_eq!(page1.entries.len(), 2);
    assert_eq!(page1.entries[0].commit_id, commit_id(6));
    assert_eq!(page1.entries[1].commit_id, commit_id(5));
    let cursor = page1.next_cursor.expect("more history");
    assert_eq!(cursor.next_commit(), commit_id(4));

    let page2 = block_on(history_page(&mut source, head, Some(cursor), &options)).unwrap();
    assert_eq!(
        page2.entries.iter().map(|c| c.commit_id).collect::<Vec<_>>(),
        vec![commit_id(4), commit_id(3)]
    );
    let page3 = block_on(history_page(&mut source, head, page2.next_cursor, &options)).unwrap();
    assert_eq!(
        page3.entries.iter().map(|c| c.commit_id).collect::<Vec<_>>(),
        vec![commit_id(2), commit_id(1)]
    );
    assert!(page3.next_cursor.is_none(), "the walk ends at the initial commit");

    // Item filter returns only matching commits, still bounded and ordered.
    let options = HistoryOptions {
        filter: Some(uid(0xAAAA)),
        page_limit: 10,
        max_loads_per_page: 1024,
    };
    let page = block_on(history_page(&mut source, head, None, &options)).unwrap();
    assert_eq!(
        page.entries.iter().map(|c| c.commit_id).collect::<Vec<_>>(),
        vec![commit_id(5), commit_id(2)]
    );
    assert!(page.next_cursor.is_none());

    // A tiny load budget returns a resumable cursor even for an empty page.
    let options = HistoryOptions { filter: None, page_limit: 10, max_loads_per_page: 1 };
    let page = block_on(history_page(&mut source, head, None, &options)).unwrap();
    assert_eq!(page.entries.len(), 1, "the first commit is loaded and returned");
    let cursor = page.next_cursor.expect("budget exhausted resumes later");
    let page = block_on(history_page(&mut source, head, Some(cursor), &options)).unwrap();
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].commit_id, commit_id(5));
}

#[test]
fn history_rejects_bad_cursors_missing_commits_and_cycles() {
    // Cursor round-trip and strict validation.
    let cursor = HistoryCursor::decode("h1-00000000-0000-0000-0000-000000000005").unwrap();
    assert_eq!(cursor.encode(), "h1-00000000-0000-0000-0000-000000000005");
    assert!(HistoryCursor::decode("x1-00000000-0000-0000-0000-000000000005").is_err());
    assert!(HistoryCursor::decode("h1-00000000000000000000000000000005").is_err());
    assert!(HistoryCursor::decode("h1-00000000-0000-0000-0000-00000000000A").is_err());
    assert!(matches!(HistoryCursor::decode("h1-zzz"), Err(InvalidCursor)));

    // Missing intermediate commit is an error, never a silent stop.
    let mut source = MemCommits(BTreeMap::new());
    let options = HistoryOptions::default();
    let result = block_on(history_page(&mut source, Some(commit_id(1)), None, &options));
    match result {
        Err(HistoryError::MissingCommit(id)) => assert_eq!(id, commit_id(1)),
        other => panic!("expected MissingCommit, got {other:?}"),
    }

    // A parent cycle is detected instead of walked forever.
    let mut commits = BTreeMap::new();
    let c1 = commit(1, Some(commit_id(2)), vec![change(0xAAAA, ChangeKind::Content)]);
    let c2 = commit(2, Some(commit_id(1)), vec![change(0xAAAA, ChangeKind::Content)]);
    commits.insert(c1.commit_id, c1);
    commits.insert(c2.commit_id, c2);
    let mut source = MemCommits(commits);
    let result = block_on(history_page(&mut source, Some(commit_id(1)), None, &options));
    match result {
        Err(HistoryError::CorruptAncestry(_)) => {}
        other => panic!("expected CorruptAncestry, got {other:?}"),
    }
}

fn current_view(file_state: ItemState) -> hfdrive_core::reconcile::CatalogView {
    let root = ItemState {
        item_id: uid(0x2222),
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
    };
    hfdrive_core::reconcile::CatalogView::new(vec![root, file_state]).unwrap()
}

fn live_file(id: ItemId, name: &str, version: VersionId, rev: OperationId) -> ItemState {
    ItemState {
        item_id: id,
        parent_id: Some(uid(0x2222)),
        name: name.to_owned(),
        kind: ItemKind::File,
        deleted: false,
        item_revision: rev,
        content_version_id: Some(version),
        content_operation: rev,
        location_operation: rev,
        deletion_operation: None,
        content_sha256: Some(digest(2)),
        content_size: Some(22),
    }
}

fn restore_spec(operation: OperationId, item: ItemId, version: VersionId) -> RestoreSpec {
    RestoreSpec {
        operation_id: operation,
        item_id: item,
        version_id: version,
        object: object(1, 11),
        display: DisplayMetadata {
            name: "report.txt".to_owned(),
            modified_at: "2026-01-01T00:00:00Z".to_owned(),
        },
    }
}

#[test]
fn restore_is_a_new_mutation_over_the_latest_state() {
    let current = current_view(live_file(uid(0xAAAA), "report.txt", ver(2), op(0x3000)));
    let mut ids = DeterministicIds::new(NS);
    let plan = plan_restore(
        ws(),
        ReconcileMode::Writable,
        &current,
        &restore_spec(op(0x0001), uid(0xAAAA), ver(1)),
        &mut ids,
    )
    .unwrap();

    // One new mutation against the latest state: no HEAD rewind, no
    // historical rewrite, no payload re-upload, no blob deletion.
    assert_eq!(plan.remote_ops.len(), 1);
    let restore_op = &plan.remote_ops[0];
    assert_eq!(restore_op.change, ChangeKind::Content);
    assert_eq!(restore_op.record.item_id, uid(0xAAAA));
    assert_eq!(restore_op.record.content_version_id, Some(ver(1)));
    assert_eq!(restore_op.record.item_revision, op(0x0001));
    assert_eq!(restore_op.old_revision, Some(op(0x3000)), "the latest revision is superseded, not rewound");
    assert!(plan.versions.is_empty(), "the historical version record already exists");
    assert!(
        plan.operation_ids.contains(&op(0x0001)),
        "the restore operation is searchable in committed ancestry"
    );

    // The local file materializes the restored bytes.
    assert_eq!(plan.local_actions.len(), 1);
    let action = &plan.local_actions[0];
    assert_eq!(action.action, LocalActionKind::UpdatePlaceholder);
    assert_eq!(
        action.target.as_ref().unwrap().content_sha256,
        Some(digest(1)),
        "the restored payload is the historical one"
    );
    assert_eq!(
        plan.intents[0].outcome,
        IntentOutcomeKind::Published
    );

    // Restoring the version already bound is a no-op convergence.
    let plan = plan_restore(
        ws(),
        ReconcileMode::Writable,
        &current,
        &restore_spec(op(0x0002), uid(0xAAAA), ver(2)),
        &mut ids,
    )
    .unwrap();
    assert!(plan.remote_ops.is_empty());
    assert_eq!(plan.intents[0].outcome, IntentOutcomeKind::Converged);
}

#[test]
fn restore_of_deleted_item_with_occupied_name_gets_a_stable_conflict_name() {
    let mut deleted = live_file(uid(0xAAAA), "report.txt", ver(2), op(0x3000));
    deleted.deleted = true;
    deleted.deletion_operation = Some(op(0x3001));
    deleted.item_revision = op(0x3001);
    let occupant = live_file(uid(0xBBBB), "report.txt", ver(3), op(0x3002));
    let current = hfdrive_core::reconcile::CatalogView::new(vec![
        ItemState {
            item_id: uid(0x2222),
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
        },
        deleted,
        occupant,
    ])
    .unwrap();

    let mut ids = DeterministicIds::new(NS);
    let spec = restore_spec(op(0x0001), uid(0xAAAA), ver(1));
    let plan = plan_restore(ws(), ReconcileMode::Writable, &current, &spec, &mut ids).unwrap();

    // The occupant is never overwritten: the revived item takes the
    // deterministic conflict name and the race is recorded.
    let restored = &plan.remote_ops[0];
    assert_eq!(restored.change, ChangeKind::Undelete);
    assert!(!restored.record.deleted);
    assert!(restored.record.name.starts_with("report (conflict "), "{}", restored.record.name);
    assert_eq!(restored.record.content_version_id, Some(ver(1)));
    let collision = plan
        .conflicts
        .iter()
        .find(|c| c.kind == hfdrive_core::reconcile::ConflictKind::NameCollision)
        .expect("name collision record");
    assert_eq!(collision.preserved_item_id, Some(uid(0xAAAA)));

    // Retries recompute the identical name from the identical tuple.
    let mut ids = DeterministicIds::new(NS);
    let again = plan_restore(ws(), ReconcileMode::Writable, &current, &spec, &mut ids).unwrap();
    assert_eq!(again.remote_ops[0].record.name, restored.record.name);
    assert_eq!(again.conflicts[0].conflict_id, plan.conflicts[0].conflict_id);
}

#[test]
fn read_only_restore_is_deferred_without_any_mutation() {
    let current = current_view(live_file(uid(0xAAAA), "report.txt", ver(2), op(0x3000)));
    let mut ids = DeterministicIds::new(NS);
    let plan = plan_restore(
        ws(),
        ReconcileMode::ReadOnly,
        &current,
        &restore_spec(op(0x0001), uid(0xAAAA), ver(1)),
        &mut ids,
    )
    .unwrap();
    assert!(plan.remote_ops.is_empty());
    assert!(plan.local_actions.is_empty());
    assert_eq!(plan.intents[0].outcome, IntentOutcomeKind::Deferred);
}

#[test]
fn restore_rejects_directory_targets() {
    let root = ItemState {
        item_id: uid(0x2222),
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
    };
    let dir = ItemState {
        item_id: uid(0xAAAA),
        parent_id: Some(uid(0x2222)),
        name: "docs".to_owned(),
        kind: ItemKind::Directory,
        deleted: false,
        item_revision: op(0x3000),
        content_version_id: None,
        content_operation: op(0x3000),
        location_operation: op(0x3000),
        deletion_operation: None,
        content_sha256: None,
        content_size: None,
    };
    let current = hfdrive_core::reconcile::CatalogView::new(vec![root, dir]).unwrap();
    let mut ids = DeterministicIds::new(NS);
    let result = plan_restore(
        ws(),
        ReconcileMode::Writable,
        &current,
        &restore_spec(op(0x0001), uid(0xAAAA), ver(1)),
        &mut ids,
    );
    assert!(result.is_err(), "directories do not restore versions");
}
