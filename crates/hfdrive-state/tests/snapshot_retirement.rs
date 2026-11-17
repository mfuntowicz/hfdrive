//! Completion atomicity and capture retirement guarantees.
//!
//! `complete_outbox` commits the outbox completion, the generation-guarded
//! dirty clear and the bound capture's retirement **in one transaction**: an
//! injected failure at any statement rolls all three back together, and a
//! crash between them is impossible. A completed operation with a newer local
//! generation keeps the newer generation dirty and reports
//! `CompletedWithNewerGeneration`. Captured bytes are never deleted by the
//! state layer: `Consumed`/`Released` are lifecycle records (consumer
//! finished / bytes proven gone), and the Free Space dependency scope is
//! exactly the requested item's unfinished work.

mod common;

use common::*;
use hfdrive_core::ids::{CommitId, ItemId, OperationId, SnapshotId, UploadId};
use hfdrive_core::storage::{ObjectRef, PayloadKey, XetFileId};
use hfdrive_state::{
    CompletionOutcome, ConnectionMode, OutboxEntry, OutboxState, OutboxTransition, SetupDraft,
    SnapshotRecord, SnapshotStatus, StateError, StatePaths, StateStore, WorkErrorKind,
};
use std::path::{Path, PathBuf};
use std::time::Duration;

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
            preview_json(Path::new("C:\\hfdrive-root")),
            PathBuf::from("C:\\hfdrive-root"),
            ConnectionMode::Writable,
        )
        .await
        .unwrap();
    store.finalize_setup(reservation.setup_id).await.unwrap().connection_id
}

fn object_ref() -> ObjectRef {
    ObjectRef {
        key: PayloadKey::new(UploadId::new()),
        sha256: digest(b"payload"),
        size: 7,
        xet_file_id: XetFileId::new("ab".repeat(32)).unwrap(),
    }
}

/// One staged capture: row created, bound bytes written to the staging path,
/// `Ready` recorded. The bytes stay on disk for the whole test run.
async fn staged_capture(
    account: &hfdrive_state::AccountStore,
    connection_id: hfdrive_core::ids::ConnectionId,
    staging_dir: &Path,
    name: &str,
) -> (SnapshotId, PathBuf) {
    let snapshot_id = SnapshotId::new();
    let path = staging_dir.join("staging").join(format!("{name}.snap"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"payload").unwrap();
    account.begin_snapshot(connection_id, snapshot_id, path.clone()).await.unwrap();
    account.complete_snapshot(connection_id, snapshot_id, 7, digest(b"payload")).await.unwrap();
    (snapshot_id, path)
}

/// Drives an already-recorded content entry with a staged capture to
/// `LocalApplyPending`, the state from which `complete_outbox` is legal.
async fn drive_to_local_apply(
    account: &hfdrive_state::AccountStore,
    connection_id: hfdrive_core::ids::ConnectionId,
    operation: OperationId,
) {
    account
        .transition_outbox(
            connection_id,
            operation,
            OutboxTransition::PayloadReady { object_ref: object_ref() },
        )
        .await
        .unwrap();
    account
        .transition_outbox(
            connection_id,
            operation,
            OutboxTransition::MetadataReady {
                candidate_commit: CommitId::new(),
                candidate_head_json: serde_json::json!({}),
                expected_etag: "e".to_owned(),
            },
        )
        .await
        .unwrap();
    account.transition_outbox(connection_id, operation, OutboxTransition::Published).await.unwrap();
    account
        .transition_outbox(connection_id, operation, OutboxTransition::LocalApplyPending)
        .await
        .unwrap();
}

/// Records one content intent for `item_id` at `generation` and binds its
/// staged capture through the legal `SnapshotReady` edge.
async fn record_capture_intent(
    account: &hfdrive_state::AccountStore,
    connection_id: hfdrive_core::ids::ConnectionId,
    item_id: ItemId,
    generation: u64,
    snapshot_id: SnapshotId,
) -> OperationId {
    let operation = OperationId::new();
    account
        .record_outbox(OutboxEntry::observed(
            connection_id,
            operation,
            Some(item_id),
            generation,
            serde_json::json!({"kind": "content"}),
        ))
        .await
        .unwrap();
    account
        .transition_outbox(connection_id, operation, OutboxTransition::SnapshotReady { snapshot_id })
        .await
        .unwrap();
    operation
}

fn snapshot_ids(records: Vec<SnapshotRecord>) -> Vec<String> {
    let mut ids: Vec<String> = records.into_iter().map(|record| record.snapshot_id.to_string()).collect();
    ids.sort();
    ids
}

#[tokio::test]
async fn completion_commits_dirty_clear_and_capture_retirement_atomically() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let connection_id = connected(&store, key).await;
    let account = store.open_account(key).await.unwrap();
    let item_id = ItemId::new();

    account.bump_observation(connection_id, item_id, None).await.unwrap();
    let (snapshot_id, staged_path) = staged_capture(&account, connection_id, tmp.path(), "one").await;
    let operation = record_capture_intent(&account, connection_id, item_id, 1, snapshot_id).await;
    drive_to_local_apply(&account, connection_id, operation).await;

    // A recorded failure must clear with the state advance, not before it.
    account
        .record_work_error(
            connection_id,
            WorkErrorKind::Outbox,
            *operation.as_uuid(),
            "capture-failed".to_owned(),
            "transient".to_owned(),
        )
        .await
        .unwrap();

    let outcome = account.complete_outbox(connection_id, operation).await.unwrap();
    assert!(
        matches!(outcome, CompletionOutcome::Completed { generation: 1 }),
        "found {outcome:?}"
    );

    // Completion, dirty clear and retirement landed together.
    let entry = account.outbox_entry(connection_id, operation).await.unwrap().unwrap();
    assert_eq!(entry.state, OutboxState::Complete);
    let observation = account.observation(connection_id, item_id).await.unwrap().unwrap();
    assert!(!observation.dirty, "the matching generation is clean");
    assert_eq!(observation.generation, 1);
    let snapshot = account.snapshot(connection_id, snapshot_id).await.unwrap().unwrap();
    assert_eq!(
        snapshot.status,
        SnapshotStatus::Consumed,
        "the capture retires after its durable consumer finished"
    );
    assert!(
        account
            .work_error(connection_id, WorkErrorKind::Outbox, *operation.as_uuid())
            .await
            .unwrap()
            .is_none(),
        "the failure clears in the same durable step"
    );

    // Retirement records a lifecycle state; it never deletes bytes.
    assert!(staged_path.is_file(), "retirement must not delete the staged bytes");
    assert_eq!(std::fs::read(&staged_path).unwrap(), b"payload");
    store.close().await.unwrap();
}

#[tokio::test]
async fn completion_with_newer_generation_preserves_dirty_and_retires_capture() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let connection_id = connected(&store, key).await;
    let account = store.open_account(key).await.unwrap();
    let item_id = ItemId::new();

    account.bump_observation(connection_id, item_id, None).await.unwrap();
    let (snapshot_id, _) = staged_capture(&account, connection_id, tmp.path(), "newer").await;
    let operation = record_capture_intent(&account, connection_id, item_id, 1, snapshot_id).await;
    // A newer local save lands while the operation is still in flight.
    account.bump_observation(connection_id, item_id, None).await.unwrap();
    drive_to_local_apply(&account, connection_id, operation).await;

    let outcome = account.complete_outbox(connection_id, operation).await.unwrap();
    assert!(
        matches!(
            outcome,
            CompletionOutcome::CompletedWithNewerGeneration {
                operation_generation: 1,
                current_generation: 2,
            }
        ),
        "found {outcome:?}"
    );

    // The entry is complete but the newer generation stays dirty; its own
    // operation will publish it later.
    let entry = account.outbox_entry(connection_id, operation).await.unwrap().unwrap();
    assert_eq!(entry.state, OutboxState::Complete);
    let observation = account.observation(connection_id, item_id).await.unwrap().unwrap();
    assert!(observation.dirty, "the newer generation stays dirty");
    assert_eq!(observation.generation, 2);

    // This operation's consumer finished, so its capture still retires: the
    // newer generation needs its own capture, not this one.
    let snapshot = account.snapshot(connection_id, snapshot_id).await.unwrap().unwrap();
    assert_eq!(snapshot.status, SnapshotStatus::Consumed);
    store.close().await.unwrap();
}

#[tokio::test]
async fn completion_failure_rolls_back_every_change_together() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let store = StateStore::open(paths.clone()).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let connection_id = connected(&store, key).await;
    let account = store.open_account(key).await.unwrap();
    let item_id = ItemId::new();

    account.bump_observation(connection_id, item_id, None).await.unwrap();
    let (snapshot_id, _) = staged_capture(&account, connection_id, tmp.path(), "atomic").await;
    let operation = record_capture_intent(&account, connection_id, item_id, 1, snapshot_id).await;
    drive_to_local_apply(&account, connection_id, operation).await;
    account
        .record_work_error(
            connection_id,
            WorkErrorKind::Outbox,
            *operation.as_uuid(),
            "capture-failed".to_owned(),
            "transient".to_owned(),
        )
        .await
        .unwrap();

    // Deterministic failure injection at each statement of the completion
    // transaction, through a second connection to the same database.
    let raw = rusqlite::Connection::open(paths.account(key).database()).unwrap();
    raw.busy_timeout(Duration::from_secs(5)).unwrap();

    // Failure point 1: the dirty clear itself aborts. Nothing may advance.
    raw.execute_batch(
        "CREATE TRIGGER fail_observation_update BEFORE UPDATE ON local_observations
         BEGIN SELECT RAISE(ABORT, 'injected observation failure'); END;",
    )
    .unwrap();
    let error = account.complete_outbox(connection_id, operation).await.unwrap_err();
    assert!(matches!(error, StateError::Database(_)), "found {error:?}");
    raw.execute_batch("DROP TRIGGER fail_observation_update;").unwrap();

    let entry = account.outbox_entry(connection_id, operation).await.unwrap().unwrap();
    assert_eq!(entry.state, OutboxState::LocalApplyPending, "the outbox row rolls back with the failure");
    assert!(account.observation(connection_id, item_id).await.unwrap().unwrap().dirty);
    assert_eq!(
        account.snapshot(connection_id, snapshot_id).await.unwrap().unwrap().status,
        SnapshotStatus::Ready
    );
    assert!(
        account
            .work_error(connection_id, WorkErrorKind::Outbox, *operation.as_uuid())
            .await
            .unwrap()
            .is_some(),
        "the failure record survives with the uncompleted work"
    );

    // Failure point 2: the capture retirement aborts *after* the dirty clear
    // ran. The dirty clear must roll back with it: a file can never be marked
    // clean by a completion that did not durably complete.
    raw.execute_batch(
        "CREATE TRIGGER fail_snapshot_update BEFORE UPDATE ON snapshots
         BEGIN SELECT RAISE(ABORT, 'injected snapshot failure'); END;",
    )
    .unwrap();
    let error = account.complete_outbox(connection_id, operation).await.unwrap_err();
    assert!(matches!(error, StateError::Database(_)), "found {error:?}");
    raw.execute_batch("DROP TRIGGER fail_snapshot_update;").unwrap();

    let entry = account.outbox_entry(connection_id, operation).await.unwrap().unwrap();
    assert_eq!(entry.state, OutboxState::LocalApplyPending);
    assert!(
        account.observation(connection_id, item_id).await.unwrap().unwrap().dirty,
        "the dirty clear rolls back with the failed completion"
    );
    assert_eq!(
        account.snapshot(connection_id, snapshot_id).await.unwrap().unwrap().status,
        SnapshotStatus::Ready
    );

    // Without the injected failures the whole transaction commits at once.
    let outcome = account.complete_outbox(connection_id, operation).await.unwrap();
    assert!(matches!(outcome, CompletionOutcome::Completed { generation: 1 }), "found {outcome:?}");
    let entry = account.outbox_entry(connection_id, operation).await.unwrap().unwrap();
    assert_eq!(entry.state, OutboxState::Complete);
    assert!(!account.observation(connection_id, item_id).await.unwrap().unwrap().dirty);
    assert_eq!(
        account.snapshot(connection_id, snapshot_id).await.unwrap().unwrap().status,
        SnapshotStatus::Consumed
    );
    store.close().await.unwrap();
}

#[tokio::test]
async fn completion_and_retirement_survive_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let key = account_key();
    let clean_item = ItemId::new();
    let dirty_item = ItemId::new();

    let (connection_id, clean_operation, dirty_operation) = {
        // Abrupt drop (no `close`): every completed command is already
        // committed, so the restart sees exactly the durable picture below.
        let store = StateStore::open(paths.clone()).await.unwrap();
        store.record_account(account_record(key)).await.unwrap();
        let connection = connected(&store, key).await;
        let account = store.open_account(key).await.unwrap();

        // One operation completes cleanly; one completes with a newer
        // generation and must stay dirty across the restart.
        account.bump_observation(connection, clean_item, None).await.unwrap();
        account.bump_observation(connection, dirty_item, None).await.unwrap();

        let (clean_snapshot, _) = staged_capture(&account, connection, tmp.path(), "clean").await;
        let clean_operation = record_capture_intent(&account, connection, clean_item, 1, clean_snapshot).await;
        drive_to_local_apply(&account, connection, clean_operation).await;
        let outcome = account.complete_outbox(connection, clean_operation).await.unwrap();
        assert!(matches!(outcome, CompletionOutcome::Completed { generation: 1 }));

        let (dirty_snapshot, _) = staged_capture(&account, connection, tmp.path(), "dirty").await;
        let dirty_operation = record_capture_intent(&account, connection, dirty_item, 1, dirty_snapshot).await;
        account.bump_observation(connection, dirty_item, None).await.unwrap();
        drive_to_local_apply(&account, connection, dirty_operation).await;
        let outcome = account.complete_outbox(connection, dirty_operation).await.unwrap();
        assert!(
            matches!(
                outcome,
                CompletionOutcome::CompletedWithNewerGeneration {
                    operation_generation: 1,
                    current_generation: 2,
                }
            ),
            "found {outcome:?}"
        );
        (connection, clean_operation, dirty_operation)
    };

    let store = StateStore::open(paths).await.unwrap();
    let account = store.open_account(key).await.unwrap();

    let clean_entry = account.outbox_entry(connection_id, clean_operation).await.unwrap().unwrap();
    assert_eq!(clean_entry.state, OutboxState::Complete, "completion is durable");
    let dirty_entry = account.outbox_entry(connection_id, dirty_operation).await.unwrap().unwrap();
    assert_eq!(dirty_entry.state, OutboxState::Complete, "completion is durable");

    let clean_observation = account.observation(connection_id, clean_item).await.unwrap().unwrap();
    assert!(!clean_observation.dirty, "the matching generation is still clean");
    let dirty_observation = account.observation(connection_id, dirty_item).await.unwrap().unwrap();
    assert!(dirty_observation.dirty, "the newer generation is still dirty after reopen");
    assert_eq!(dirty_observation.generation, 2);

    // Both captures' retirement state is durable; the rows still exist.
    for operation in [clean_operation, dirty_operation] {
        let snapshot_id = account
            .outbox_entry(connection_id, operation)
            .await
            .unwrap()
            .unwrap()
            .snapshot_id
            .expect("content operations carry their capture binding");
        let snapshot = account.snapshot(connection_id, snapshot_id).await.unwrap().unwrap();
        assert_eq!(snapshot.status, SnapshotStatus::Consumed);
    }
    store.close().await.unwrap();
}

#[tokio::test]
async fn snapshot_dependencies_scope_only_unfinished_work_of_the_item() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let connection_id = connected(&store, key).await;
    let account = store.open_account(key).await.unwrap();
    let item_a = ItemId::new();
    let item_b = ItemId::new();

    account.bump_observation(connection_id, item_a, None).await.unwrap();
    account.bump_observation(connection_id, item_b, None).await.unwrap();

    // Item A's own staged capture, consumed by its unfinished work.
    let (snapshot_a, _) = staged_capture(&account, connection_id, tmp.path(), "a").await;
    let operation_a = record_capture_intent(&account, connection_id, item_a, 1, snapshot_a).await;

    // Item B's unrelated staged capture with its own unfinished work.
    let (snapshot_b, _) = staged_capture(&account, connection_id, tmp.path(), "b").await;
    let _operation_b = record_capture_intent(&account, connection_id, item_b, 1, snapshot_b).await;

    // A retained capture nobody references (a finished/abandoned consumer):
    // it must never block anyone.
    let (orphan, _) = staged_capture(&account, connection_id, tmp.path(), "orphan").await;

    // A capture still in flight, referenced through its operation binding
    // before its outbox entry binds the snapshot id.
    let capturing = SnapshotId::new();
    account
        .begin_snapshot(connection_id, capturing, tmp.path().join("staging").join("c.snap"))
        .await
        .unwrap();
    let capturing_operation = OperationId::new();
    account.bind_snapshot_operation(connection_id, capturing, capturing_operation).await.unwrap();
    account
        .record_outbox(OutboxEntry::observed(
            connection_id,
            capturing_operation,
            Some(item_a),
            1,
            serde_json::json!({"kind": "content"}),
        ))
        .await
        .unwrap();

    // Scope is exactly the requested item's unfinished work.
    let mut expected_a = snapshot_ids(vec![
        account.snapshot(connection_id, snapshot_a).await.unwrap().unwrap(),
        account.snapshot(connection_id, capturing).await.unwrap().unwrap(),
    ]);
    expected_a.sort();
    assert_eq!(
        snapshot_ids(account.snapshot_dependencies(connection_id, item_a).await.unwrap()),
        expected_a,
        "only this item's unfinished consumers count"
    );
    assert_eq!(
        snapshot_ids(account.snapshot_dependencies(connection_id, item_b).await.unwrap()),
        snapshot_ids(vec![account.snapshot(connection_id, snapshot_b).await.unwrap().unwrap()]),
    );
    // The retained orphan is nobody's dependency.
    for item in [item_a, item_b] {
        assert!(
            !snapshot_ids(account.snapshot_dependencies(connection_id, item).await.unwrap())
                .contains(&orphan.to_string()),
            "an unreferenced retained capture never blocks free space"
        );
    }

    // A's work finishes: its capture retires and stops being a dependency,
    // while B's unrelated capture keeps blocking only B.
    drive_to_local_apply(&account, connection_id, operation_a).await;
    account.complete_outbox(connection_id, operation_a).await.unwrap();
    assert_eq!(
        snapshot_ids(account.snapshot_dependencies(connection_id, item_a).await.unwrap()),
        snapshot_ids(vec![account.snapshot(connection_id, capturing).await.unwrap().unwrap()]),
        "only the in-flight capture is still A's dependency"
    );
    assert_eq!(
        account.snapshot(connection_id, snapshot_a).await.unwrap().unwrap().status,
        SnapshotStatus::Consumed
    );
    assert_eq!(
        snapshot_ids(account.snapshot_dependencies(connection_id, item_b).await.unwrap()),
        snapshot_ids(vec![account.snapshot(connection_id, snapshot_b).await.unwrap().unwrap()]),
        "another item's retained capture never blocks this one"
    );
    store.close().await.unwrap();
}

#[tokio::test]
async fn retirement_ladder_keeps_rows_and_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let connection_id = connected(&store, key).await;
    let account = store.open_account(key).await.unwrap();
    let item_id = ItemId::new();

    account.bump_observation(connection_id, item_id, None).await.unwrap();
    let (snapshot_id, staged_path) = staged_capture(&account, connection_id, tmp.path(), "retire").await;
    let operation = record_capture_intent(&account, connection_id, item_id, 1, snapshot_id).await;

    // Unfinished consumers block every retirement step, through either API.
    let error = account.retire_snapshot_consumed(connection_id, snapshot_id).await.unwrap_err();
    assert!(
        matches!(error, StateError::InvalidState { .. }),
        "unfinished consumers must block retirement, found {error:?}"
    );
    let error = account.retire_snapshot_released(connection_id, snapshot_id).await.unwrap_err();
    assert!(
        matches!(error, StateError::InvalidState { .. }),
        "unfinished consumers must block retirement, found {error:?}"
    );
    let error = account
        .set_snapshot_status(connection_id, snapshot_id, SnapshotStatus::Released)
        .await
        .unwrap_err();
    assert!(
        matches!(error, StateError::InvalidState { .. }),
        "the status setter must not bypass the retirement guard, found {error:?}"
    );
    assert_eq!(
        account.snapshot(connection_id, snapshot_id).await.unwrap().unwrap().status,
        SnapshotStatus::Ready
    );

    // A capture still in flight can never retire.
    let capturing = SnapshotId::new();
    account
        .begin_snapshot(connection_id, capturing, tmp.path().join("staging").join("c.snap"))
        .await
        .unwrap();
    let error = account.retire_snapshot_consumed(connection_id, capturing).await.unwrap_err();
    assert!(matches!(error, StateError::InvalidState { .. }), "found {error:?}");

    // Completion retires the capture to Consumed; the explicit call is then
    // idempotent and the ladder only moves forward.
    drive_to_local_apply(&account, connection_id, operation).await;
    account.complete_outbox(connection_id, operation).await.unwrap();
    let record = account.retire_snapshot_consumed(connection_id, snapshot_id).await.unwrap();
    assert_eq!(record.status, SnapshotStatus::Consumed, "idempotent retirement");
    let record = account.retire_snapshot_released(connection_id, snapshot_id).await.unwrap();
    assert_eq!(record.status, SnapshotStatus::Released, "bytes proven gone");
    // Monotonic: the ladder never moves backwards and never errors on repeat.
    let record = account.retire_snapshot_released(connection_id, snapshot_id).await.unwrap();
    assert_eq!(record.status, SnapshotStatus::Released);
    let record = account.retire_snapshot_consumed(connection_id, snapshot_id).await.unwrap();
    assert_eq!(record.status, SnapshotStatus::Released, "a released capture never goes back");

    // Rows and bytes survive every retirement step.
    let record = account.snapshot(connection_id, snapshot_id).await.unwrap().unwrap();
    assert_eq!(record.status, SnapshotStatus::Released);
    assert!(staged_path.is_file(), "retirement records must never delete the staged bytes");
    assert_eq!(std::fs::read(&staged_path).unwrap(), b"payload");
    store.close().await.unwrap();
}
