//! Generation and outbox state-machine guarantees: the eight durable states
//! only move along their legal edges with their evidence, completion is guarded
//! by the observed generation, signed integer conversions are checked, and the
//! applied baseline never runs ahead of durable local actions.

mod common;

use common::*;
use hfdrive_core::ids::{
    ActionId, CommitId, ConflictId, ItemId, OperationId, SnapshotId, TransferId, UploadId, VersionId,
};
use hfdrive_core::storage::{ObjectRef, PayloadKey, XetFileId};
use hfdrive_state::{
    BaselineKind, ConflictRecord, ConflictResolution, ConnectionMode, ItemKind, ItemRecord,
    LocalAction, LocalActionKind, LocalActionState, OutboxEntry, OutboxState, OutboxTransition,
    RetryClass, SetupDraft, StateError, StatePaths, StateStore, TransferDirection, TransferRecord,
    TransferState,
};

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

#[tokio::test]
async fn outbox_only_moves_along_legal_edges_with_evidence() {
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

    // Skipping the snapshot evidence is refused.
    let error = account
        .transition_outbox(connection_id, op, OutboxTransition::PayloadReady { object_ref: object_ref() })
        .await
        .unwrap_err();
    assert!(matches!(error, StateError::IllegalOutboxTransition { .. }), "found {error:?}");

    // A capturing snapshot is not yet evidence.
    let snapshot_id = SnapshotId::new();
    account
        .begin_snapshot(connection_id, snapshot_id, tmp.path().join("staging").join("s1"))
        .await
        .unwrap();
    let error = account
        .transition_outbox(connection_id, op, OutboxTransition::SnapshotReady { snapshot_id })
        .await
        .unwrap_err();
    assert!(
        matches!(error, StateError::InvalidState { .. }),
        "a capturing snapshot cannot satisfy SnapshotReady, found {error:?}"
    );

    // The full content chain, each step with its evidence.
    account
        .complete_snapshot(connection_id, snapshot_id, 7, digest(b"payload"))
        .await
        .unwrap();
    let entry = account
        .transition_outbox(connection_id, op, OutboxTransition::SnapshotReady { snapshot_id })
        .await
        .unwrap();
    assert_eq!(entry.state, OutboxState::SnapshotReady);

    let entry = account
        .transition_outbox(connection_id, op, OutboxTransition::PayloadReady { object_ref: object_ref() })
        .await
        .unwrap();
    assert_eq!(entry.state, OutboxState::PayloadReady);
    assert!(entry.object_ref.is_some());

    let candidate = CommitId::new();
    let entry = account
        .transition_outbox(
            connection_id,
            op,
            OutboxTransition::MetadataReady {
                candidate_commit: candidate,
                candidate_head_json: serde_json::json!({"generation": "g1"}),
                expected_etag: "etag-1".to_owned(),
            },
        )
        .await
        .unwrap();
    assert_eq!(entry.state, OutboxState::MetadataReady);
    assert_eq!(entry.expected_etag.as_deref(), Some("etag-1"));

    // An ambiguous conditional write parks in PublishUnknown with its retry
    // classification instead of claiming success.
    let entry = account
        .transition_outbox(
            connection_id,
            op,
            OutboxTransition::PublishUnknown { retry_class: RetryClass::Backoff, next_attempt_at_ms: Some(5_000) },
        )
        .await
        .unwrap();
    assert_eq!(entry.state, OutboxState::PublishUnknown);
    assert_eq!(entry.retry_class, RetryClass::Backoff);

    // Reconciliation proved our commit landed: Published, then the guarded
    // local apply, then Complete.
    let entry = account.transition_outbox(connection_id, op, OutboxTransition::Published).await.unwrap();
    assert_eq!(entry.state, OutboxState::Published);
    let entry = account
        .transition_outbox(connection_id, op, OutboxTransition::LocalApplyPending)
        .await
        .unwrap();
    assert_eq!(entry.state, OutboxState::LocalApplyPending);
    let outcome = account.complete_outbox(connection_id, op).await.unwrap();
    assert!(
        matches!(outcome, hfdrive_state::CompletionOutcome::Completed { generation: 0 }),
        "found {outcome:?}"
    );

    // Complete is terminal.
    let error = account
        .transition_outbox(connection_id, op, OutboxTransition::LocalApplyPending)
        .await
        .unwrap_err();
    assert!(matches!(error, StateError::IllegalOutboxTransition { .. }));
    store.close().await.unwrap();
}

#[tokio::test]
async fn metadata_only_intent_skips_content_states() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let connection_id = connected(&store, key).await;
    let account = store.open_account(key).await.unwrap();

    let op = OperationId::new();
    account
        .record_outbox(OutboxEntry::observed(connection_id, op, None, 0, serde_json::json!({"kind": "rename"})))
        .await
        .unwrap();
    let entry = account
        .transition_outbox(
            connection_id,
            op,
            OutboxTransition::MetadataReady {
                candidate_commit: CommitId::new(),
                candidate_head_json: serde_json::json!({"generation": "g1"}),
                expected_etag: "etag-2".to_owned(),
            },
        )
        .await
        .unwrap();
    assert_eq!(entry.state, OutboxState::MetadataReady, "metadata-only intents go straight to MetadataReady");
    store.close().await.unwrap();
}

#[tokio::test]
async fn completion_only_clears_the_matching_generation() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let connection_id = connected(&store, key).await;
    let account = store.open_account(key).await.unwrap();
    let item_id = ItemId::new();

    account.bump_observation(connection_id, item_id, None).await.unwrap();
    let op1 = OperationId::new();
    account
        .record_outbox(OutboxEntry::observed(connection_id, op1, Some(item_id), 1, serde_json::json!({"kind": "content"})))
        .await
        .unwrap();
    // A newer local save lands while op1 is still in flight.
    account.bump_observation(connection_id, item_id, None).await.unwrap();

    // Drive op1 to LocalApplyPending via the metadata-only edge.
    account
        .transition_outbox(
            connection_id,
            op1,
            OutboxTransition::MetadataReady {
                candidate_commit: CommitId::new(),
                candidate_head_json: serde_json::json!({}),
                expected_etag: "e".to_owned(),
            },
        )
        .await
        .unwrap();
    account.transition_outbox(connection_id, op1, OutboxTransition::Published).await.unwrap();
    account
        .transition_outbox(connection_id, op1, OutboxTransition::LocalApplyPending)
        .await
        .unwrap();

    let outcome = account.complete_outbox(connection_id, op1).await.unwrap();
    assert!(
        matches!(
            outcome,
            hfdrive_state::CompletionOutcome::CompletedWithNewerGeneration {
                operation_generation: 1,
                current_generation: 2,
            }
        ),
        "found {outcome:?}"
    );
    let obs = account.observation(connection_id, item_id).await.unwrap().unwrap();
    assert!(obs.dirty, "the newer generation stays dirty for its own operation");
    assert_eq!(obs.generation, 2);

    // The newer generation completes cleanly.
    let op2 = OperationId::new();
    account
        .record_outbox(OutboxEntry::observed(connection_id, op2, Some(item_id), 2, serde_json::json!({"kind": "content"})))
        .await
        .unwrap();
    account
        .transition_outbox(
            connection_id,
            op2,
            OutboxTransition::MetadataReady {
                candidate_commit: CommitId::new(),
                candidate_head_json: serde_json::json!({}),
                expected_etag: "e2".to_owned(),
            },
        )
        .await
        .unwrap();
    account.transition_outbox(connection_id, op2, OutboxTransition::Published).await.unwrap();
    account
        .transition_outbox(connection_id, op2, OutboxTransition::LocalApplyPending)
        .await
        .unwrap();
    let outcome = account.complete_outbox(connection_id, op2).await.unwrap();
    assert!(matches!(outcome, hfdrive_state::CompletionOutcome::Completed { generation: 2 }), "found {outcome:?}");
    let obs = account.observation(connection_id, item_id).await.unwrap().unwrap();
    assert!(!obs.dirty, "clean only for the matching generation");
    store.close().await.unwrap();
}

#[tokio::test]
async fn signed_integer_conversions_are_checked() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let connection_id = connected(&store, key).await;
    let account = store.open_account(key).await.unwrap();

    // A size beyond i64 cannot be silently wrapped into a SQLite column.
    let snapshot_id = SnapshotId::new();
    account
        .begin_snapshot(connection_id, snapshot_id, tmp.path().join("staging").join("big"))
        .await
        .unwrap();
    let error = account
        .complete_snapshot(connection_id, snapshot_id, u64::MAX, digest(b"x"))
        .await
        .unwrap_err();
    assert!(
        matches!(error, StateError::IntegerOutOfRange { value } if value == u64::MAX),
        "found {error:?}"
    );

    let error = account
        .record_transfer(TransferRecord {
            connection_id,
            transfer_id: TransferId::new(),
            operation_id: None,
            direction: TransferDirection::Download,
            version_id: None,
            range_start: Some(0),
            range_end: Some(4096),
            state: TransferState::Pending,
            sdk_resume_json: None,
            logical_bytes: u64::MAX,
            wire_bytes: 0,
        })
        .await
        .unwrap_err();
    assert!(matches!(error, StateError::IntegerOutOfRange { .. }), "found {error:?}");
    store.close().await.unwrap();
}

#[tokio::test]
async fn applied_baseline_waits_for_durable_local_actions() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let connection_id = connected(&store, key).await;
    let account = store.open_account(key).await.unwrap();

    let action_id = ActionId::new();
    account
        .record_local_action(LocalAction {
            connection_id,
            action_id,
            item_id: None,
            kind: LocalActionKind::UpdatePlaceholder,
            expected_file_id: Some("4612".to_owned()),
            expected_generation: Some(3),
            expected_usn: Some(99),
            old_version: None,
            new_version: None,
            source_path: None,
            target_path: Some(std::path::PathBuf::from("C:\\hfdrive-root\\hello.txt")),
            recovery_path: None,
            state: LocalActionState::Pending,
        })
        .await
        .unwrap();

    let commit = CommitId::new();
    let error = account
        .set_baseline(connection_id, BaselineKind::Applied, Some(commit))
        .await
        .unwrap_err();
    assert!(
        matches!(error, StateError::InvalidState { .. }),
        "applied must not run ahead of pending local actions, found {error:?}"
    );

    // Once the local action has a durable outcome the baseline may advance.
    account
        .set_local_action_state(connection_id, action_id, LocalActionState::Applied)
        .await
        .unwrap();
    let baseline = account
        .set_baseline(connection_id, BaselineKind::Applied, Some(commit))
        .await
        .unwrap();
    assert_eq!(baseline.applied_commit, Some(commit));

    // Observed/published baselines track independently.
    let baseline = account
        .set_baseline(connection_id, BaselineKind::Observed, Some(CommitId::new()))
        .await
        .unwrap();
    assert!(baseline.observed_commit.is_some());
    assert_eq!(baseline.applied_commit, Some(commit));
    store.close().await.unwrap();
}

#[tokio::test]
async fn snapshot_reservations_track_unfinished_work() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let connection_id = connected(&store, key).await;
    let account = store.open_account(key).await.unwrap();

    let snapshot_id = SnapshotId::new();
    account
        .begin_snapshot(connection_id, snapshot_id, tmp.path().join("staging").join("s"))
        .await
        .unwrap();
    account
        .complete_snapshot(connection_id, snapshot_id, 3, digest(b"abc"))
        .await
        .unwrap();

    let op = OperationId::new();
    account
        .record_outbox(OutboxEntry::observed(connection_id, op, None, 0, serde_json::json!({})))
        .await
        .unwrap();
    account
        .transition_outbox(connection_id, op, OutboxTransition::SnapshotReady { snapshot_id })
        .await
        .unwrap();

    let retention = account.retention_snapshot(connection_id).await.unwrap();
    assert_eq!(retention.epoch, 0);
    assert_eq!(retention.pending_upload_reservations, 1, "the snapshot is reserved by unfinished work");

    // Completing the work releases the reservation without any refcount.
    account
        .transition_outbox(connection_id, op, OutboxTransition::PayloadReady { object_ref: object_ref() })
        .await
        .unwrap();
    account
        .transition_outbox(
            connection_id,
            op,
            OutboxTransition::MetadataReady {
                candidate_commit: CommitId::new(),
                candidate_head_json: serde_json::json!({}),
                expected_etag: "e".to_owned(),
            },
        )
        .await
        .unwrap();
    account.transition_outbox(connection_id, op, OutboxTransition::Published).await.unwrap();
    account
        .transition_outbox(connection_id, op, OutboxTransition::LocalApplyPending)
        .await
        .unwrap();
    account.complete_outbox(connection_id, op).await.unwrap();
    let retention = account.retention_snapshot(connection_id).await.unwrap();
    assert_eq!(retention.pending_upload_reservations, 0);
    store.close().await.unwrap();
}

#[tokio::test]
async fn work_counts_measure_distinct_dirty_files_without_materializing_registry() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let connection_id = connected(&store, key).await;
    let account = store.open_account(key).await.unwrap();
    let root = ItemId::new();
    let file_a = ItemId::new();
    let file_b = ItemId::new();
    let directory = ItemId::new();
    for (item_id, parent_id, name, kind) in [
        (root, None, "", ItemKind::Directory),
        (file_a, Some(root), "a.txt", ItemKind::File),
        (file_b, Some(root), "b.txt", ItemKind::File),
        (directory, Some(root), "dir", ItemKind::Directory),
    ] {
        account.upsert_item(ItemRecord {
            connection_id,
            item_id,
            parent_id,
            name: name.to_owned(),
            name_key: hfdrive_core::names::collision_key(name).iter().map(|byte| format!("{byte:02x}")).collect(),
            kind,
            revision: OperationId::new(),
            content_version_id: (kind == ItemKind::File).then(VersionId::new),
            deleted: false,
            metadata_json: serde_json::json!({}),
        }).await.unwrap();
    }
    for item_id in [file_a, file_b, directory] {
        account.bump_observation(connection_id, item_id, None).await.unwrap();
    }
    for item_id in [file_a, file_a, file_b, directory] {
        account.record_outbox(OutboxEntry::observed(
            connection_id,
            OperationId::new(),
            Some(item_id),
            1,
            serde_json::json!({"intent": "content"}),
        )).await.unwrap();
    }
    let conflict = account.record_conflict(ConflictRecord {
        connection_id,
        conflict_id: ConflictId::new(),
        item_id: file_a,
        competing_ops: vec![OperationId::new(), OperationId::new()],
        revisions_json: serde_json::json!({}),
        original_names: vec!["a.txt".to_owned()],
        resolution_state: ConflictResolution::Unresolved,
        detected_at_ms: None,
    }).await.unwrap();

    let counts = account.work_counts(connection_id).await.unwrap();
    assert_eq!(counts.pending_files, 2, "two operations for one file are still one pending file");
    assert_eq!(counts.dirty_files, 2, "the dirty directory is not a dirty file");
    assert_eq!(counts.conflict_files, 1);
    assert!(conflict.detected_at_ms.is_some());
    assert_eq!(account.list_all_items(connection_id, true).await.unwrap().len(), 4,
        "maintenance traversal includes nested items, not only root children");
    store.close().await.unwrap();
}
