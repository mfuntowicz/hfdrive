//! Durable work evidence for the activity projection: the persisted creation
//! timestamps are the start evidence, keyset pages are bounded and
//! non-overlapping, a recorded failure survives reopen and clears exactly when
//! its work item durably advances, and a capture binds its operation.

mod common;

use common::*;
use hfdrive_core::ids::{ActionId, CommitId, ItemId, OperationId, SnapshotId, TransferId, VersionId};
use hfdrive_state::{
    ItemKind, ItemRecord, LocalAction, LocalActionKind, LocalActionState, OutboxEntry,
    OutboxTransition, RetryClass, SetupDraft, StateError, StatePaths, StateStore,
    TransferDirection, TransferRecord, TransferState, WorkErrorKind, WorkPageCursor,
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
