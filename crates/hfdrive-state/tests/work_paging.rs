//! Durable work evidence for the activity projection: the persisted creation
//! timestamps are the start evidence, keyset pages are bounded and
//! non-overlapping, a recorded failure survives reopen and clears exactly when
//! its work item durably advances, and a capture binds its operation. The
//! active-work listing (K17) and the transactional batch writes (K07/G13) are
//! covered here too: completed work is excluded but preserved, batches are one
//! command and one transaction, and byte-identical rows are never rewritten.

mod common;

use common::*;
use hfdrive_core::ids::{
    ActionId, CommitId, ConnectionId, ItemId, OperationId, SnapshotId, TransferId, VersionId,
};
use hfdrive_state::{
    AccountStore, CommonBaseRecord, ItemKind, ItemRecord, LocalAction, LocalActionKind,
    LocalActionState, OutboxEntry, OutboxState, OutboxTransition, RetryClass, SetupDraft,
    StateError, StatePaths, StateStore, TransferDirection, TransferRecord, TransferState,
    WorkErrorKind, WorkPageCursor,
};
use rusqlite::Connection;

async fn connected(
    store: &StateStore,
    key: hfdrive_core::ids::AccountKey,
) -> hfdrive_core::ids::ConnectionId {
    let draft = SetupDraft {
        operation_id: OperationId::new(),
        account_key: key,
        binding: binding(key),
        initialize: true,
    };
    let reservation = store.reserve_setup(draft).await.unwrap();
    store
        .attach_setup_preview(
            reservation.setup_id,
            preview_json(std::path::Path::new("C:\\hfdrive-root")),
            std::path::PathBuf::from("C:\\hfdrive-root"),
            hfdrive_state::ConnectionMode::Writable,
        )
        .await
        .unwrap();
    store.finalize_setup(reservation.setup_id).await.unwrap().connection_id
}

fn transfer(connection_id: hfdrive_core::ids::ConnectionId) -> TransferRecord {
    TransferRecord {
        connection_id,
        transfer_id: TransferId::new(),
        operation_id: None,
        direction: TransferDirection::Download,
        version_id: None,
        range_start: Some(0),
        range_end: Some(4096),
        state: TransferState::Pending,
        sdk_resume_json: None,
        logical_bytes: 4096,
        wire_bytes: 0,
    }
}

fn local_action(connection_id: hfdrive_core::ids::ConnectionId) -> LocalAction {
    LocalAction {
        connection_id,
        action_id: ActionId::new(),
        item_id: None,
        kind: LocalActionKind::CreatePlaceholder,
        expected_file_id: Some("4612".to_owned()),
        expected_generation: Some(1),
        expected_usn: Some(7),
        old_version: None,
        new_version: None,
        source_path: None,
        target_path: Some(std::path::PathBuf::from("C:\\hfdrive-root\\hello.txt")),
        recovery_path: None,
        state: LocalActionState::Pending,
    }
}

#[tokio::test]
async fn dated_work_rows_are_the_persisted_start_evidence() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let connection_id = connected(&store, key).await;
    let account = store.open_account(key).await.unwrap();

    let op = OperationId::new();
    account
        .record_outbox(OutboxEntry::observed(connection_id, op, None, 0, serde_json::json!({"kind": "content"})))
        .await
        .unwrap();
    let action_id = ActionId::new();
    let mut action = local_action(connection_id);
    action.action_id = action_id;
    account.record_local_action(action).await.unwrap();
    let transfer_id = TransferId::new();
    let mut row_transfer = transfer(connection_id);
    row_transfer.transfer_id = transfer_id;
    account.record_transfer(row_transfer).await.unwrap();

    let outbox = account.list_outbox_rows(connection_id, None, 10).await.unwrap();
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0].entry.operation_id, op);
    assert!(outbox[0].created_at_ms > 0, "the start evidence is the real persisted creation time");

    let actions = account.list_action_rows(connection_id, None, 10).await.unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].action.action_id, action_id);
    assert!(actions[0].created_at_ms > 0);

    let transfers = account.list_transfer_rows(connection_id, None, 10).await.unwrap();
    assert_eq!(transfers.len(), 1);
    assert_eq!(transfers[0].transfer.transfer_id, transfer_id);
    assert!(transfers[0].created_at_ms > 0);

    // The persisted times are row data, not synthesized per call: reading the
    // raw columns yields the same timestamps the projection sees.
    let db_path = tmp.path().join("accounts").join(key.to_string()).join("state.sqlite3");
    let raw = Connection::open(&db_path).unwrap();
    let (raw_outbox, raw_action, raw_transfer): (i64, i64, i64) = raw
        .query_row(
            "SELECT
               (SELECT created_at_ms FROM outbox WHERE operation_id = ?1),
               (SELECT created_at_ms FROM local_actions WHERE action_id = ?2),
               (SELECT created_at_ms FROM transfers WHERE transfer_id = ?3)",
            rusqlite::params![
                op.as_bytes().as_slice(),
                action_id.as_bytes().as_slice(),
                transfer_id.as_bytes().as_slice(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(u64::try_from(raw_outbox).unwrap(), outbox[0].created_at_ms);
    assert_eq!(u64::try_from(raw_action).unwrap(), actions[0].created_at_ms);
    assert_eq!(u64::try_from(raw_transfer).unwrap(), transfers[0].created_at_ms);
    drop(raw);
    store.close().await.unwrap();
}

#[tokio::test]
async fn work_pages_are_bounded_and_non_overlapping() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let connection_id = connected(&store, key).await;
    let account = store.open_account(key).await.unwrap();

    // Five outbox intents, one local action and one transfer.
    let mut ops = Vec::new();
    for _ in 0..5 {
        let op = OperationId::new();
        account
            .record_outbox(OutboxEntry::observed(
                connection_id,
                op,
                None,
                0,
                serde_json::json!({"kind": "content"}),
            ))
            .await
            .unwrap();
        ops.push(op);
    }
    account.record_local_action(local_action(connection_id)).await.unwrap();
    account.record_transfer(transfer(connection_id)).await.unwrap();

    // An out-of-range page limit is refused, never silently widened.
    for limit in [0, 201] {
        let error = account.list_outbox_rows(connection_id, None, limit).await.unwrap_err();
        assert!(
            matches!(error, StateError::InvalidState { .. }),
            "limit {limit} must be refused, found {error:?}"
        );
    }

    // Page 1 carries the limit+1 overflow probe: five rows for limit 2, the
    // caller truncates to two and derives the cursor from its last row.
    let page1 = account.list_outbox_rows(connection_id, None, 2).await.unwrap();
    assert_eq!(page1.len(), 3, "the query reads limit+1 so overflow is detectable");
    let delivered: Vec<_> = page1.into_iter().take(2).collect();
    let cursor = WorkPageCursor {
        created_at_ms: delivered[1].created_at_ms,
        work_id: *delivered[1].entry.operation_id.as_uuid(),
    };

    // Page 2 starts strictly after the cursor and never repeats page 1.
    let page2 = account.list_outbox_rows(connection_id, Some(cursor), 2).await.unwrap();
    let delivered2: Vec<_> = page2.into_iter().take(2).collect();
    assert_eq!(delivered2.len(), 2);
    for row in &delivered {
        for other in &delivered2 {
            assert_ne!(row.entry.operation_id, other.entry.operation_id, "pages must not overlap");
        }
    }
    let cursor2 = WorkPageCursor {
        created_at_ms: delivered2[1].created_at_ms,
        work_id: *delivered2[1].entry.operation_id.as_uuid(),
    };
    let page3 = account.list_outbox_rows(connection_id, Some(cursor2), 2).await.unwrap();
    assert_eq!(page3.len(), 1, "the last page is not overflowed");
    for row in &page3 {
        for other in delivered.iter().chain(delivered2.iter()) {
            assert_ne!(row.entry.operation_id, other.entry.operation_id, "pages must not overlap");
        }
    }

    // The union of pages is exactly the five rows, in durable order.
    let seen: Vec<_> = delivered
        .iter()
        .chain(delivered2.iter())
        .chain(page3.iter())
        .map(|row| row.entry.operation_id)
        .collect();
    assert_eq!(seen.len(), 5);
    for op in &ops {
        assert!(seen.contains(op), "every known unfinished row must be reachable by paging");
    }

    // A second connection on the same account: its rows must never leak into
    // this connection's pages, whatever cursor position is supplied.
    let other_connection = connected(&store, key).await;
    let other_op = OperationId::new();
    account
        .record_outbox(OutboxEntry::observed(
            other_connection,
            other_op,
            None,
            0,
            serde_json::json!({"kind": "content"}),
        ))
        .await
        .unwrap();

    // A cursor is a pure ordered position, not an anchor: the merged
    // projection derives nil/max UUID sentinels for source ranks and those
    // name no stored row. The floor position yields every nonzero id of this
    // connection; the ceiling position yields nothing.
    let at_floor = account
        .list_outbox_rows(
            connection_id,
            Some(WorkPageCursor { created_at_ms: 0, work_id: uuid::Uuid::nil() }),
            200,
        )
        .await
        .unwrap();
    assert_eq!(at_floor.len(), 5, "a nil-UUID position at the floor includes every nonzero id");
    let at_ceiling = account
        .list_outbox_rows(
            connection_id,
            Some(WorkPageCursor { created_at_ms: i64::MAX as u64, work_id: uuid::Uuid::max() }),
            200,
        )
        .await
        .unwrap();
    assert!(at_ceiling.is_empty(), "a max-UUID position at the ceiling excludes everything");
    for row in at_floor.iter().chain(at_ceiling.iter()) {
        assert_eq!(row.entry.connection_id, connection_id, "pages are connection-scoped");
        assert_ne!(row.entry.operation_id, other_op, "another connection's work never leaks in");
    }
    for row in account.list_outbox_rows(other_connection, None, 200).await.unwrap() {
        assert_eq!(row.entry.connection_id, other_connection, "pages are connection-scoped");
    }

    // Actions and transfers page on their own keyset.
    let action_page1 = account.list_action_rows(connection_id, None, 1).await.unwrap();
    assert_eq!(action_page1.len(), 1);
    let action_cursor = WorkPageCursor {
        created_at_ms: action_page1[0].created_at_ms,
        work_id: *action_page1[0].action.action_id.as_uuid(),
    };
    assert!(
        account.list_action_rows(connection_id, Some(action_cursor), 1).await.unwrap().is_empty(),
        "the page strictly after the only row is empty"
    );

    // Deleting the row a position was derived from does not invalidate the
    // position: the page strictly after it is unchanged, with no gap and no
    // repeat, and sentinel positions keep working the same way.
    account.record_transfer(transfer(connection_id)).await.unwrap();
    account.record_transfer(transfer(connection_id)).await.unwrap();
    let transfer_rows = account.list_transfer_rows(connection_id, None, 10).await.unwrap();
    assert_eq!(transfer_rows.len(), 3);
    let anchor = &transfer_rows[0];
    let anchor_cursor = WorkPageCursor {
        created_at_ms: anchor.created_at_ms,
        work_id: *anchor.transfer.transfer_id.as_uuid(),
    };
    let after_anchor = account.list_transfer_rows(connection_id, Some(anchor_cursor), 10).await.unwrap();
    assert_eq!(after_anchor.len(), 2);

    let db_path = tmp.path().join("accounts").join(key.to_string()).join("state.sqlite3");
    let raw = Connection::open(&db_path).unwrap();
    raw.execute(
        "DELETE FROM transfers WHERE connection_id = ?1 AND transfer_id = ?2",
        rusqlite::params![
            connection_id.as_bytes().as_slice(),
            anchor.transfer.transfer_id.as_bytes().as_slice(),
        ],
    )
    .unwrap();
    drop(raw);

    let after_deletion = account.list_transfer_rows(connection_id, Some(anchor_cursor), 10).await.unwrap();
    assert_eq!(after_deletion.len(), 2, "the position is not anchored to the row's existence");
    for (before, after) in after_anchor.iter().zip(after_deletion.iter()) {
        assert_eq!(
            before.transfer.transfer_id, after.transfer.transfer_id,
            "no gap and no repeat after the anchor row is deleted"
        );
    }
    store.close().await.unwrap();
}

#[tokio::test]
async fn work_errors_survive_reopen_and_clear_on_real_progress() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let key = account_key();
    let store = StateStore::open(paths.clone()).await.unwrap();
    store.record_account(account_record(key)).await.unwrap();
    let connection_id = connected(&store, key).await;

    // An outbox operation fails at a real failure site.
    let account = store.open_account(key).await.unwrap();
    let op = OperationId::new();
    account
        .record_outbox(OutboxEntry::observed(connection_id, op, None, 0, serde_json::json!({"kind": "content"})))
        .await
        .unwrap();
    account
        .transition_outbox(
            connection_id,
            op,
            OutboxTransition::MetadataReady {
                candidate_commit: CommitId::new(),
                candidate_head_json: serde_json::json!({"generation": "g1"}),
                expected_etag: "etag-1".to_owned(),
            },
        )
        .await
        .unwrap();
    account
        .transition_outbox(
            connection_id,
            op,
            OutboxTransition::PublishUnknown { retry_class: RetryClass::Backoff, next_attempt_at_ms: Some(10) },
        )
        .await
        .unwrap();
    account
        .record_work_error(
            connection_id,
            WorkErrorKind::Outbox,
            *op.as_uuid(),
            "RemoteContentUnavailable".to_owned(),
            "payload 404 after publication".to_owned(),
        )
        .await
        .unwrap();

    // The error is visible on the row's own page and survives an abrupt drop.
    drop(account);
    drop(store);
    let store = StateStore::open(paths.clone()).await.unwrap();
    let account = store.open_account(key).await.unwrap();
    let error = account.work_error(connection_id, WorkErrorKind::Outbox, *op.as_uuid()).await.unwrap().unwrap();
    assert_eq!(error.error_code, "RemoteContentUnavailable");
    assert_eq!(error.error_detail, "payload 404 after publication");
    assert!(error.updated_at_ms > 0, "the failure carries its real recorded time");
    let page = account.list_outbox_rows(connection_id, None, 10).await.unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(
        account.work_error(connection_id, WorkErrorKind::Outbox, *op.as_uuid()).await.unwrap().unwrap().error_code,
        "RemoteContentUnavailable",
        "the failed work projects with its recorded failure"
    );

    // Real durable progress clears it, transactionally with the state change.
    account
        .transition_outbox(connection_id, op, OutboxTransition::Published)
        .await
        .unwrap();
    assert!(
        account.work_error(connection_id, WorkErrorKind::Outbox, *op.as_uuid()).await.unwrap().is_none(),
        "a durable state advance clears the recorded failure"
    );

    // An explicit clear also works, and a re-record overwrites.
    account
        .record_work_error(connection_id, WorkErrorKind::Outbox, *op.as_uuid(), "DiskFull".to_owned(), "staging full".to_owned())
        .await
        .unwrap();
    account.clear_work_error(connection_id, WorkErrorKind::Outbox, *op.as_uuid()).await.unwrap();
    assert!(account.work_error(connection_id, WorkErrorKind::Outbox, *op.as_uuid()).await.unwrap().is_none());

    // Local actions and transfers clear on their own state advances.
    let action = local_action(connection_id);
    let action_id = action.action_id;
    account.record_local_action(action).await.unwrap();
    account
        .record_work_error(connection_id, WorkErrorKind::Action, *action_id.as_uuid(), "PermissionDenied".to_owned(), "handle denied".to_owned())
        .await
        .unwrap();
    assert!(account.work_error(connection_id, WorkErrorKind::Action, *action_id.as_uuid()).await.unwrap().is_some());
    account.set_local_action_state(connection_id, action_id, LocalActionState::Requeued).await.unwrap();
    assert!(account.work_error(connection_id, WorkErrorKind::Action, *action_id.as_uuid()).await.unwrap().is_none());

    let row_transfer = transfer(connection_id);
    let transfer_id = row_transfer.transfer_id;
    account.record_transfer(row_transfer).await.unwrap();
    account
        .record_work_error(connection_id, WorkErrorKind::Transfer, *transfer_id.as_uuid(), "Cancelled".to_owned(), "range cancelled".to_owned())
        .await
        .unwrap();
    assert!(account.work_error(connection_id, WorkErrorKind::Transfer, *transfer_id.as_uuid()).await.unwrap().is_some());
    account
        .update_transfer(connection_id, transfer_id, TransferState::InProgress, 0, 0, None)
        .await
        .unwrap();
    assert!(account.work_error(connection_id, WorkErrorKind::Transfer, *transfer_id.as_uuid()).await.unwrap().is_none());
    store.close().await.unwrap();
}

#[tokio::test]
async fn snapshot_binding_links_capture_to_its_operation() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let connection_id = connected(&store, key).await;
    let account = store.open_account(key).await.unwrap();

    let snapshot_id = SnapshotId::new();
    // begin_snapshot is unchanged: the capture starts unbound.
    let record = account
        .begin_snapshot(connection_id, snapshot_id, tmp.path().join("staging").join("snap"))
        .await
        .unwrap();
    assert_eq!(record.operation_id, None);

    let op = OperationId::new();
    account
        .record_outbox(OutboxEntry::observed(connection_id, op, None, 0, serde_json::json!({"kind": "content"})))
        .await
        .unwrap();
    account.bind_snapshot_operation(connection_id, snapshot_id, op).await.unwrap();

    // The binding is in the read and list projections.
    assert_eq!(account.snapshot(connection_id, snapshot_id).await.unwrap().unwrap().operation_id, Some(op));
    let listed = account.list_snapshots(connection_id).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].operation_id, Some(op));

    // Idempotent re-bind; a different operation is refused.
    account.bind_snapshot_operation(connection_id, snapshot_id, op).await.unwrap();
    let error = account
        .bind_snapshot_operation(connection_id, snapshot_id, OperationId::new())
        .await
        .unwrap_err();
    assert!(matches!(error, StateError::InvalidState { .. }), "found {error:?}");

    // The binding is durable: it survives reopen with the capture evidence.
    drop(account);
    drop(store);
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let account = store.open_account(key).await.unwrap();
    assert_eq!(account.snapshot(connection_id, snapshot_id).await.unwrap().unwrap().operation_id, Some(op));
    store.close().await.unwrap();
}

#[tokio::test]
async fn item_for_version_resolves_live_item_first() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let connection_id = connected(&store, key).await;
    let account = store.open_account(key).await.unwrap();

    let version_id = VersionId::new();
    let root = ItemId::new();
    let deleted_item = ItemId::new();
    let live_item = ItemId::new();
    for (item_id, parent_id, name, deleted) in [
        (root, None, "", false),
        (deleted_item, Some(root), "old.txt", true),
        (live_item, Some(root), "hello.txt", false),
    ] {
        let mut item = ItemRecord {
            connection_id,
            item_id,
            parent_id,
            name: name.to_owned(),
            name_key: hfdrive_core::names::collision_key(name).iter().map(|byte| format!("{byte:02x}")).collect(),
            kind: ItemKind::File,
            revision: OperationId::new(),
            content_version_id: Some(version_id),
            deleted,
            metadata_json: serde_json::json!({}),
        };
        if item_id == root {
            item.kind = ItemKind::Directory;
            item.content_version_id = None;
        }
        account.upsert_item(item).await.unwrap();
    }

    // The live item wins deterministically over the tombstone, and the lookup
    // is stable across calls (deterministic ordering, not rowid luck).
    for _ in 0..3 {
        let item = account.item_for_version(connection_id, version_id).await.unwrap().unwrap();
        assert_eq!(item.item_id, live_item);
        assert!(!item.deleted);
    }

    // An unbound version resolves to nothing rather than a wrong name.
    assert!(account.item_for_version(connection_id, VersionId::new()).await.unwrap().is_none());
    store.close().await.unwrap();
}

// ---------------------------------------------------------------------------
// K17: active outbox listing (completed history excluded, bounded, ordered)
// ---------------------------------------------------------------------------

/// A deterministic non-nil id: fixture rows whose order must be fixed, not
/// random-UUID luck.
fn fixed_op(value: u128) -> OperationId {
    OperationId::from_uuid(uuid::Uuid::from_u128(value)).unwrap()
}

fn fixed_item(value: u128) -> ItemId {
    ItemId::from_uuid(uuid::Uuid::from_u128(value)).unwrap()
}

fn fixed_commit(value: u128) -> CommitId {
    CommitId::from_uuid(uuid::Uuid::from_u128(value)).unwrap()
}

fn item_record(connection_id: hfdrive_core::ids::ConnectionId, item_id: ItemId, name: &str) -> ItemRecord {
    ItemRecord {
        connection_id,
        item_id,
        parent_id: None,
        name: name.to_owned(),
        name_key: hfdrive_core::names::collision_key(name)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        kind: ItemKind::File,
        revision: OperationId::new(),
        content_version_id: None,
        deleted: false,
        metadata_json: serde_json::json!({"modified_at": "2026-01-01T00:00:00Z"}),
    }
}

fn base_record(
    connection_id: hfdrive_core::ids::ConnectionId,
    commit_id: CommitId,
    item_id: ItemId,
    name: &str,
) -> CommonBaseRecord {
    CommonBaseRecord {
        connection_id,
        item_id,
        commit_id,
        item_json: format!(r#"{{"item_id":"{item_id}","name":"{name}"}}"#),
    }
}

/// Drives one metadata-only intent through its whole publication lifecycle to
/// a durable completion, using only legal evidence edges.
async fn complete_metadata_intent(
    account: &AccountStore,
    connection_id: hfdrive_core::ids::ConnectionId,
    operation: OperationId,
) {
    account
        .transition_outbox(
            connection_id,
            operation,
            OutboxTransition::MetadataReady {
                candidate_commit: CommitId::new(),
                candidate_head_json: serde_json::json!({"generation": "g1"}),
                expected_etag: "etag-1".to_owned(),
            },
        )
        .await
        .unwrap();
    account.transition_outbox(connection_id, operation, OutboxTransition::Published).await.unwrap();
    account
        .transition_outbox(connection_id, operation, OutboxTransition::LocalApplyPending)
        .await
        .unwrap();
    account.complete_outbox(connection_id, operation).await.unwrap();
}

#[tokio::test]
async fn active_outbox_excludes_completed_history_and_orders_oldest_first() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let store = StateStore::open(paths.clone()).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let connection_id = connected(&store, key).await;
    let account = store.open_account(key).await.unwrap();

    // Five intents; two tie on their durable creation time, so the
    // (created_at_ms, operation_id) ordering is observable, and the completed
    // one sits in the middle of the age order.
    let oldest = OperationId::new();
    let completed = OperationId::new();
    let tie_lo = fixed_op(0x0A);
    let tie_hi = fixed_op(0x0B);
    let newest = OperationId::new();
    for op in [oldest, completed, tie_hi, tie_lo, newest] {
        account
            .record_outbox(OutboxEntry::observed(
                connection_id,
                op,
                None,
                0,
                serde_json::json!({"kind": "content"}),
            ))
            .await
            .unwrap();
    }

    // The creation times are row data; the tie rows are inserted newest-id
    // first so only the index order can put tie_lo ahead of tie_hi.
    let raw = Connection::open(&paths.account(key).database()).unwrap();
    for (op, created_at_ms) in [
        (oldest, 1_000i64),
        (completed, 1_001),
        (tie_lo, 1_002),
        (tie_hi, 1_002),
        (newest, 1_003),
    ] {
        raw.execute(
            "UPDATE outbox SET created_at_ms = ?3
              WHERE connection_id = ?1 AND operation_id = ?2",
            rusqlite::params![connection_id.as_bytes().as_slice(), op.as_bytes().as_slice(), created_at_ms],
        )
        .unwrap();
    }
    drop(raw);

    // One intent runs its whole lifecycle to a durable completion. The row
    // stays: complete history is never deleted.
    complete_metadata_intent(&account, connection_id, completed).await;

    // Completed history is excluded in SQL and never scanned by an active
    // pass: exactly the four unfinished rows, oldest first, ties by operation
    // id — the order scheduling rounds drive them in.
    let active = account.list_active_outbox(connection_id, 200).await.unwrap();
    let ids: Vec<OperationId> = active.iter().map(|entry| entry.operation_id).collect();
    assert_eq!(ids, vec![oldest, tie_lo, tie_hi, newest], "oldest-first, ties by operation id");
    assert!(!ids.contains(&completed), "a completed row is never active work");

    // Bounds: `limit` caps the rows in the same durable order; 0 yields none;
    // a limit beyond the active count returns exactly the active rows.
    assert!(account.list_active_outbox(connection_id, 0).await.unwrap().is_empty());
    let head = account.list_active_outbox(connection_id, 2).await.unwrap();
    assert_eq!(
        head.iter().map(|entry| entry.operation_id).collect::<Vec<_>>(),
        vec![oldest, tie_lo],
        "the bound truncates in the same order"
    );
    assert_eq!(account.list_active_outbox(connection_id, 99).await.unwrap().len(), 4);

    // The completed row is history, not garbage: it stays queryable.
    let history = account.list_outbox(connection_id, None, 200).await.unwrap();
    assert_eq!(history.len(), 5, "every recorded intent, complete or not, stays durable");
    assert!(history.iter().any(|entry| entry.operation_id == completed));
    store.close().await.unwrap();
}

#[tokio::test]
async fn active_outbox_listing_survives_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let key = account_key();
    let (connection_id, oldest, completed) = {
        let store = StateStore::open(paths.clone()).await.unwrap();
        store.record_account(account_record(key)).await.unwrap();
        let connection_id = connected(&store, key).await;
        let account = store.open_account(key).await.unwrap();

        let oldest = OperationId::new();
        let completed = OperationId::new();
        for op in [oldest, completed] {
            account
                .record_outbox(OutboxEntry::observed(
                    connection_id,
                    op,
                    None,
                    0,
                    serde_json::json!({"kind": "content"}),
                ))
                .await
                .unwrap();
        }
        complete_metadata_intent(&account, connection_id, completed).await;
        store.close().await.unwrap();
        (connection_id, oldest, completed)
    };

    // Reopened state keeps both the active row and the completed history.
    let store = StateStore::open(paths.clone()).await.unwrap();
    let account = store.open_account(key).await.unwrap();
    let active = account.list_active_outbox(connection_id, 200).await.unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].operation_id, oldest, "the completion state survives reopen");
    assert!(
        active.iter().all(|entry| entry.operation_id != completed),
        "the completed row stays excluded after reopen"
    );
    assert_eq!(
        account.list_outbox(connection_id, None, 200).await.unwrap().len(),
        2,
        "completed history survives reopen"
    );
    store.close().await.unwrap();
}

/// A real v5 account database (the schema before the active-outbox index)
/// migrates forward with a pre-migration backup; the completed history and
/// its rows are untouched, and the active listing works on migrated state.
#[tokio::test]
async fn v5_account_database_gains_the_active_outbox_index_without_losing_rows() {
    use hfdrive_core::ids::WorkspaceId;

    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let key = account_key();

    // Control database fresh; the account database built by hand at exactly
    // schema version 5 with real rows in every state.
    let store = StateStore::open(paths.clone()).await.unwrap();
    store.record_account(account_record(key)).await.unwrap();
    let account_db = paths.account(key).database();
    std::fs::create_dir_all(account_db.parent().unwrap()).unwrap();
    let connection_id = ConnectionId::new();
    let oldest = fixed_op(0x21);
    let completed = fixed_op(0x22);
    let newest = fixed_op(0x23);
    {
        let conn = Connection::open(&account_db).unwrap();
        let application_id: i64 = 0x4846_4441;
        conn.pragma_update(None, "application_id", application_id).unwrap();
        conn.execute_batch(include_str!("../migrations/0001.sql")).unwrap();
        conn.execute_batch(include_str!("../migrations/0002.sql")).unwrap();
        conn.execute_batch(include_str!("../migrations/0003.sql")).unwrap();
        conn.execute_batch(include_str!("../migrations/0004.sql")).unwrap();
        conn.execute_batch(include_str!("../migrations/0005.sql")).unwrap();
        conn.pragma_update(None, "user_version", 5).unwrap();
        conn.execute(
            "INSERT INTO connections
               (connection_id, account_key, workspace_id, owner_kind, owner_id, owner_namespace,
                bucket_id, bucket_name, prefix, root_path, schema_version, mode, config_json,
                created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, 'personal', 'owner-1', 'test-user', 'bucket-1', 'bucket-test-1',
                     'hfdrive/ws', 'C:\\root', 1, 'writable', '{}', 1000, 1000)",
            rusqlite::params![
                connection_id.as_bytes().as_slice(),
                key.as_bytes().as_slice(),
                WorkspaceId::new().as_bytes().as_slice(),
            ],
        )
        .unwrap();
        for (op, state, created_at_ms) in [
            (oldest, "observed", 1_000i64),
            (completed, "complete", 1_001),
            (newest, "metadata_ready", 1_002),
        ] {
            conn.execute(
                "INSERT INTO outbox
                   (connection_id, operation_id, item_id, base_commit, base_json, observed_generation,
                    intent_json, state, snapshot_id, object_ref_json, candidate_commit,
                    candidate_head_json, expected_etag, retry_class, next_attempt_at_ms,
                    created_at_ms, updated_at_ms)
                 VALUES (?1, ?2, NULL, NULL, NULL, 0, '{\"kind\":\"content\"}', ?3,
                         NULL, NULL, NULL, NULL, NULL, 'none', NULL, ?4, ?4)",
                rusqlite::params![connection_id.as_bytes().as_slice(), op.as_bytes().as_slice(), state, created_at_ms],
            )
            .unwrap();
        }
    }

    // Touching the account database runs the forward migration.
    let account = store.open_account(key).await.unwrap();
    let active = account.list_active_outbox(connection_id, 10).await.unwrap();
    store.close().await.unwrap();

    assert_eq!(
        active.iter().map(|entry| entry.operation_id).collect::<Vec<_>>(),
        vec![oldest, newest],
        "migrated state lists exactly the unfinished rows in order"
    );
    assert!(
        active.iter().all(|entry| entry.state != OutboxState::Complete),
        "the migrated index-backed listing never returns completed rows"
    );

    let conn = Connection::open(&account_db).unwrap();
    assert_eq!(
        conn.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0)).unwrap(),
        6,
        "the migration must land on the supported schema"
    );
    let indexed: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'outbox_active_by_creation'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(indexed, 1, "the active-outbox index must exist after the migration");
    let rows: i64 = conn.query_row("SELECT COUNT(*) FROM outbox", [], |row| row.get(0)).unwrap();
    assert_eq!(rows, 3, "no recorded intent may go missing across the migration");
    drop(conn);

    // The pre-migration online backup exists and predates the new index.
    let backup = std::fs::read_dir(account_db.parent().unwrap())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("state.sqlite3.") && n.ends_with(".bak"))
        })
        .expect("a timestamped backup must exist before a forward migration");
    let backup_conn = Connection::open(&backup).unwrap();
    let backup_indexed: i64 = backup_conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'outbox_active_by_creation'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(backup_indexed, 0, "the backup must be the pre-migration database");
    let backup_rows: i64 = backup_conn.query_row("SELECT COUNT(*) FROM outbox", [], |row| row.get(0)).unwrap();
    assert_eq!(backup_rows, 3, "the backup must hold the pre-migration data");
    drop(backup_conn);

    // Reopening migrated state keeps both listings coherent.
    let store = StateStore::open(paths.clone()).await.unwrap();
    let account = store.open_account(key).await.unwrap();
    let active = account.list_active_outbox(connection_id, 10).await.unwrap();
    assert_eq!(active.len(), 2);
    assert_eq!(account.list_outbox(connection_id, None, 10).await.unwrap().len(), 3);
    store.close().await.unwrap();
}

// ---------------------------------------------------------------------------
// K07/G13: transactional batch writes for common bases and the item registry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn batched_common_bases_are_one_transaction_and_skip_identical_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let store = StateStore::open(paths.clone()).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let connection_id = connected(&store, key).await;
    let account = store.open_account(key).await.unwrap();

    let commit = fixed_commit(0x31);
    let items: Vec<ItemId> = (1..=4u128).map(fixed_item).collect();
    let rows: Vec<CommonBaseRecord> = items
        .iter()
        .map(|item_id| base_record(connection_id, commit, *item_id, &format!("name-{item_id}")))
        .collect();

    // A failure at the third row of the batch rolls the whole batch back: one
    // transaction, one durable step. Per-row commits would leave the first two
    // rows behind, so partial namespaces are impossible.
    {
        let raw = Connection::open(&paths.account(key).database()).unwrap();
        raw.execute_batch(&format!(
            "CREATE TRIGGER abort_third_base BEFORE INSERT ON common_bases
               WHEN NEW.item_id = X'{:032x}'
               BEGIN SELECT RAISE(ABORT, 'injected batch failure'); END;",
            items[2].as_uuid().as_u128()
        ))
        .unwrap();
    }
    let error = account.put_common_bases(rows.clone()).await.unwrap_err();
    assert!(
        matches!(error, StateError::Database(_)),
        "the injected failure must surface, found {error:?}"
    );
    assert!(
        account.list_common_bases(connection_id, commit).await.unwrap().is_empty(),
        "an aborted batch leaves no partial namespace behind"
    );
    {
        let raw = Connection::open(&paths.account(key).database()).unwrap();
        raw.execute_batch("DROP TRIGGER abort_third_base").unwrap();
    }

    // The retry lands the whole namespace; every record reports its write.
    let written = account.put_common_bases(rows.clone()).await.unwrap();
    assert_eq!(written, vec![true, true, true, true], "every new row is written once");
    let stored = account.list_common_bases(connection_id, commit).await.unwrap();
    assert_eq!(stored.len(), 4, "no common base may go missing");
    for (expected, row) in rows.iter().zip(stored.iter()) {
        assert_eq!(row, expected, "rows are stored verbatim in item order");
    }

    // Byte-identical rewrites are skipped: the per-record flags report no
    // write, and a trigger that aborts any UPDATE of the table stays silent
    // only if the batch actually rewrites nothing.
    {
        let raw = Connection::open(&paths.account(key).database()).unwrap();
        raw.execute_batch(
            "CREATE TRIGGER refuse_base_rewrite BEFORE UPDATE ON common_bases
             BEGIN SELECT RAISE(ABORT, 'identical row rewritten'); END;",
        )
        .unwrap();
    }
    let written = account.put_common_bases(rows.clone()).await.unwrap();
    assert_eq!(written, vec![false, false, false, false], "an identical row is never rewritten");

    // A genuinely changed row *is* written: the same trigger fires, and the
    // failed batch rolls the change back instead of half-applying it.
    let mut changed = rows.clone();
    changed[0] = base_record(connection_id, commit, items[0], "renamed");
    let error = account.put_common_bases(changed.clone()).await.unwrap_err();
    assert!(matches!(error, StateError::Database(_)), "the changed row must attempt its write");
    let stored = account.list_common_bases(connection_id, commit).await.unwrap();
    assert_eq!(stored[0], rows[0], "the aborted change is rolled back");
    {
        let raw = Connection::open(&paths.account(key).database()).unwrap();
        raw.execute_batch("DROP TRIGGER refuse_base_rewrite").unwrap();
    }
    let written = account.put_common_bases(changed.clone()).await.unwrap();
    assert_eq!(written, vec![true, false, false, false], "only the differing row is written");
    assert_eq!(
        account.get_common_base(connection_id, items[0], commit).await.unwrap().unwrap(),
        changed[0],
        "the changed row is persisted once the guard is gone"
    );

    // Complete history: a later commit's namespace is added, never replacing
    // an earlier commit's rows, and a subset batch removes nothing.
    let later = fixed_commit(0x32);
    let later_rows = vec![
        base_record(connection_id, later, items[0], "later-name"),
        base_record(connection_id, later, items[3], "later-other"),
    ];
    assert_eq!(account.put_common_bases(later_rows.clone()).await.unwrap(), vec![true, true]);
    assert_eq!(
        account.list_common_bases(connection_id, later).await.unwrap(),
        later_rows,
        "the later namespace is complete"
    );
    assert_eq!(
        account.list_common_bases(connection_id, commit).await.unwrap(),
        changed,
        "the earlier sealed namespace is untouched"
    );
    assert_eq!(
        account.put_common_bases(vec![changed[1].clone()]).await.unwrap(),
        vec![false],
        "a replayed subset writes nothing and removes nothing"
    );
    assert_eq!(
        account.list_common_bases(connection_id, commit).await.unwrap(),
        changed,
        "a subset batch never removes remembered rows"
    );
    store.close().await.unwrap();
}

#[tokio::test]
async fn batched_registry_upserts_are_one_transaction_and_skip_identical_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let store = StateStore::open(paths.clone()).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let connection_id = connected(&store, key).await;
    let account = store.open_account(key).await.unwrap();

    // A failure at the third row of the batch rolls the whole batch back.
    let items: Vec<ItemRecord> = (11..=14u128)
        .map(|value| item_record(connection_id, fixed_item(value), &format!("file-{value}")))
        .collect();
    {
        let raw = Connection::open(&paths.account(key).database()).unwrap();
        raw.execute_batch(&format!(
            "CREATE TRIGGER abort_third_item BEFORE INSERT ON items
               WHEN NEW.item_id = X'{:032x}'
               BEGIN SELECT RAISE(ABORT, 'injected batch failure'); END;",
            items[2].item_id.as_uuid().as_u128()
        ))
        .unwrap();
    }
    let error = account.upsert_items(items.clone()).await.unwrap_err();
    assert!(matches!(error, StateError::Database(_)), "the injected failure must surface");
    for item in &items {
        assert!(
            account.item(connection_id, item.item_id).await.unwrap().is_none(),
            "an aborted batch leaves no partial registry write behind"
        );
    }
    {
        let raw = Connection::open(&paths.account(key).database()).unwrap();
        raw.execute_batch("DROP TRIGGER abort_third_item").unwrap();
    }

    // The retry lands every record; every record reports its write.
    let written = account.upsert_items(items.clone()).await.unwrap();
    assert_eq!(written, vec![true, true, true, true], "every new row is written once");
    for item in &items {
        assert_eq!(account.item(connection_id, item.item_id).await.unwrap().unwrap(), *item);
    }

    // Byte-identical rewrites are skipped: the per-record flags report no
    // write, and a trigger that aborts any UPDATE stays silent only if the
    // batch actually rewrites nothing. A changed row *is* written, and the
    // change is rolled back with its batch if the write is refused.
    {
        let raw = Connection::open(&paths.account(key).database()).unwrap();
        raw.execute_batch(
            "CREATE TRIGGER refuse_item_rewrite BEFORE UPDATE ON items
             BEGIN SELECT RAISE(ABORT, 'identical row rewritten'); END;",
        )
        .unwrap();
    }
    let written = account.upsert_items(items.clone()).await.unwrap();
    assert_eq!(written, vec![false, false, false, false], "an identical row is never rewritten");

    let mut changed = items.clone();
    changed[1].name = "renamed.txt".to_owned();
    let error = account.upsert_items(changed.clone()).await.unwrap_err();
    assert!(matches!(error, StateError::Database(_)), "the changed row must attempt its write");
    assert_eq!(
        account.item(connection_id, items[1].item_id).await.unwrap().unwrap(),
        items[1],
        "the aborted change is rolled back"
    );
    {
        let raw = Connection::open(&paths.account(key).database()).unwrap();
        raw.execute_batch("DROP TRIGGER refuse_item_rewrite").unwrap();
    }
    let written = account.upsert_items(changed.clone()).await.unwrap();
    assert_eq!(written, vec![false, true, false, false], "only the differing row is written");
    assert_eq!(
        account.item(connection_id, items[1].item_id).await.unwrap().unwrap(),
        changed[1],
        "the changed row is persisted once the guard is gone"
    );

    // Rows absent from a batch are never removed: the registry keeps every
    // item durable work refers to.
    assert_eq!(
        account.upsert_items(vec![changed[0].clone()]).await.unwrap(),
        vec![false],
        "a replayed subset writes nothing and removes nothing"
    );
    for item in &changed[1..] {
        assert_eq!(
            account.item(connection_id, item.item_id).await.unwrap().unwrap(),
            *item,
            "a subset batch cannot drop registry rows"
        );
    }
    store.close().await.unwrap();
}
