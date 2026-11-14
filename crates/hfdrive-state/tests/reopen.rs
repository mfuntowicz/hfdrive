//! Restart durability: everything the durable boundary promises survives a
//! clean close/reopen and an abrupt drop/reopen.

mod common;

use common::*;
use hfdrive_core::ids::{CommitId, ItemId, OperationId, SnapshotId};
use hfdrive_state::{
    BeginOperationRequest, CommonBaseRecord, ConnectionMode, EffectClass, OutboxEntry,
    OutboxState, OutboxTransition, SetupDraft, StateError, StatePaths, StateStore,
};
use std::path::PathBuf;

fn staging(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("staging").join("snap-1")
}

#[tokio::test]
async fn state_survives_clean_close_and_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let key = account_key();
    let binding = binding(key);

    let store = StateStore::open(paths.clone()).await.unwrap();
    store.record_account(account_record(key)).await.unwrap();
    store.select_account(key).await.unwrap();
    assert_eq!(store.selected_account().await.unwrap(), Some(key));

    let draft = SetupDraft {
        operation_id: OperationId::new(),
        account_key: key,
        binding: binding.clone(),
        initialize: true,
    };
    let reservation = store.reserve_setup(draft).await.unwrap();
    store
        .attach_setup_preview(
            reservation.setup_id,
            preview_json(&tmp.path().join("root")),
            tmp.path().join("root"),
            ConnectionMode::Writable,
        )
        .await
        .unwrap();
    let setup = store.finalize_setup(reservation.setup_id).await.unwrap();
    let connection_id = setup.connection_id;

    let account = store.open_account(key).await.unwrap();
    let item_id = ItemId::new();
    account
        .bump_observation(connection_id, item_id, Some(42))
        .await
        .unwrap();

    let op = OperationId::new();
    let entry = OutboxEntry::observed(
        connection_id,
        op,
        Some(item_id),
        1,
        serde_json::json!({"kind": "content"}),
    );
    account.record_outbox(entry).await.unwrap();

    let snapshot_id = SnapshotId::new();
    account
        .begin_snapshot(connection_id, snapshot_id, staging(&tmp))
        .await
        .unwrap();
    account
        .complete_snapshot(connection_id, snapshot_id, 7, digest(b"payload"))
        .await
        .unwrap();
    account
        .transition_outbox(connection_id, op, OutboxTransition::SnapshotReady { snapshot_id })
        .await
        .unwrap();

    let settings = store
        .set_settings("global".to_owned(), serde_json::json!({"upload": 1}), None)
        .await
        .unwrap();
    assert_eq!(settings.revision, 1);

    store.close().await.unwrap();

    // Reopen and verify every durable fact.
    let store = StateStore::open(paths).await.unwrap();
    assert_eq!(store.selected_account().await.unwrap(), Some(key));
    let setup2 = store.get_setup(reservation.setup_id).await.unwrap().unwrap();
    assert_eq!(setup2.connection_id, connection_id);
    assert!(setup2.initialize, "explicit initialization intent is immutable");
    assert_eq!(setup2.phase, hfdrive_state::SetupPhase::Connected);
    assert_eq!(
        store.get_setup_by_connection(connection_id).await.unwrap().unwrap().setup_id,
        reservation.setup_id
    );

    let account = store.open_account(key).await.unwrap();
    let conn = account.get_connection(connection_id).await.unwrap().unwrap();
    assert_eq!(conn.mode, ConnectionMode::Writable);
    assert_eq!(conn.account_key, key);

    let obs = account.observation(connection_id, item_id).await.unwrap().unwrap();
    assert_eq!(obs.generation, 1);
    assert_eq!(obs.observed_usn, Some(42));
    assert!(obs.dirty);

    let row = account.outbox_entry(connection_id, op).await.unwrap().unwrap();
    assert_eq!(row.state, OutboxState::SnapshotReady);
    assert_eq!(row.snapshot_id, Some(snapshot_id));
    assert_eq!(row.observed_generation, 1);

    let snap = account.snapshot(connection_id, snapshot_id).await.unwrap().unwrap();
    assert_eq!(snap.size, Some(7));
    assert_eq!(snap.sha256, Some(digest(b"payload")));

    let settings2 = store.settings("global".to_owned()).await.unwrap().unwrap();
    assert_eq!(settings2.revision, 1);

    store.close().await.unwrap();
}

#[tokio::test]
async fn canonical_item_bytes_round_trip_verbatim() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let key = account_key();
    let binding = binding(key);

    let store = StateStore::open(paths.clone()).await.unwrap();
    store.record_account(account_record(key)).await.unwrap();
    let draft = SetupDraft {
        operation_id: OperationId::new(),
        account_key: key,
        binding: binding.clone(),
        initialize: true,
    };
    let reservation = store.reserve_setup(draft).await.unwrap();
    store
        .attach_setup_preview(
            reservation.setup_id,
            preview_json(&tmp.path().join("root")),
            tmp.path().join("root"),
            ConnectionMode::Writable,
        )
        .await
        .unwrap();
    let connection_id = store.finalize_setup(reservation.setup_id).await.unwrap().connection_id;
    let account = store.open_account(key).await.unwrap();

    // Opaque item-record bytes in deliberately non-canonical member order with
    // non-ASCII content: the state layer stores exactly what it is given and
    // must never re-spell it (canonical validity is the catalog decoder's
    // gate, not ours), so byte identity survives restart.
    let item_id = ItemId::new();
    let commit_id = CommitId::new();
    let canonical = format!(
        r#"{{"zeta":1,"alpha":2,"item_id":"{item_id}","name":"résumé 日本語"}}"#
    );
    account
        .put_common_base(CommonBaseRecord {
            connection_id,
            item_id,
            commit_id,
            item_json: canonical.clone(),
        })
        .await
        .unwrap();

    // The outbox base field gets the same verbatim treatment.
    let op = OperationId::new();
    let mut entry =
        OutboxEntry::observed(connection_id, op, Some(item_id), 1, serde_json::json!({"kind": "content"}));
    entry.base_json = Some(canonical.clone());
    account.record_outbox(entry).await.unwrap();

    store.close().await.unwrap();

    let store = StateStore::open(paths).await.unwrap();
    let account = store.open_account(key).await.unwrap();
    let base = account.get_common_base(connection_id, item_id, commit_id).await.unwrap().unwrap();
    assert_eq!(base.item_json, canonical, "format bytes must survive restart byte-for-byte");
    let row = account.outbox_entry(connection_id, op).await.unwrap().unwrap();
    assert_eq!(row.base_json.as_deref(), Some(canonical.as_str()));

    // Garbage that is not JSON is refused instead of silently persisted.
    let error = account
        .put_common_base(hfdrive_state::CommonBaseRecord {
            connection_id,
            item_id,
            commit_id: hfdrive_core::ids::CommitId::new(),
            item_json: "{not json".to_owned(),
        })
        .await
        .unwrap_err();
    assert!(matches!(error, StateError::InvalidState { .. }), "found {error:?}");
    store.close().await.unwrap();
}

#[tokio::test]
async fn durable_rows_survive_abrupt_drop() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let key = account_key();

    {
        let store = StateStore::open(paths.clone()).await.unwrap();
        store.record_account(account_record(key)).await.unwrap();
        let account = store.open_account(key).await.unwrap();
        let draft = SetupDraft {
            operation_id: OperationId::new(),
            account_key: key,
            binding: binding(key),
            initialize: false,
        };
        let reservation = store.reserve_setup(draft).await.unwrap();
        store.attach_setup_preview(
            reservation.setup_id,
            preview_json(&tmp.path().join("root")),
            tmp.path().join("root"),
            ConnectionMode::ReadOnly,
        ).await.unwrap();
        store.finalize_setup(reservation.setup_id).await.unwrap();
        let op = OperationId::new();
        account
            .record_outbox(OutboxEntry::observed(
                reservation.connection_id,
                op,
                None,
                0,
                serde_json::json!({"kind": "metadata"}),
            ))
            .await
            .unwrap();
        // No close(): the worker drains and checkpoints on its own.
    }

    let store = StateStore::open(paths).await.unwrap();
    let account = store.open_account(key).await.unwrap();
    let setups = store.list_setups(None).await.unwrap();
    assert_eq!(setups.len(), 1);
    assert!(!setups[0].initialize);
    let rows = account
        .list_outbox(setups[0].connection_id, None, 200)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, OutboxState::Observed);
    store.close().await.unwrap();
}

#[tokio::test]
async fn process_exit_child() {
    if std::env::var_os("HFDRIVE_PROCESS_EXIT_CHILD").is_none() {
        return;
    }
    let dir = std::env::var("HFDRIVE_PROCESS_EXIT_DIR").unwrap();
    let store = StateStore::open(StatePaths::new(PathBuf::from(dir))).await.unwrap();
    let operation = crash_operation();
    store.begin_operation(operation.clone()).await.unwrap();
    store.mark_dispatched(operation.operation_id).await.unwrap();
    // Intentionally terminate without close, Drop, or any user-mode cleanup.
    std::process::exit(0);
}

#[tokio::test]
async fn externally_pending_operation_survives_process_exit_without_reexecution() {
    let tmp = tempfile::tempdir().unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("process_exit_child")
        .arg("--nocapture")
        .env("HFDRIVE_PROCESS_EXIT_CHILD", "1")
        .env("HFDRIVE_PROCESS_EXIT_DIR", tmp.path())
        .status()
        .unwrap();
    assert!(child.success(), "crash fixture exited unexpectedly: {child:?}");

    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let operation = crash_operation();
    let pending = store.pending_external_operations().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].operation_id, operation.operation_id);
    match store.begin_operation(operation).await {
        Err(StateError::OperationNotReplayable { state, .. }) => {
            assert_eq!(state, hfdrive_state::OperationState::ExternalPending);
        }
        other => panic!("externally pending operation was re-executed: {other:?}"),
    }
    store.close().await.unwrap();
}

fn crash_operation() -> BeginOperationRequest {
    let operation_id = OperationId::from_uuid(uuid::Uuid::from_u128(0xdead_beef)).unwrap();
    BeginOperationRequest {
        operation_id,
        kind: "start_login".to_owned(),
        request: serde_json::json!({"operation_id": operation_id.to_string()}),
        effect_class: EffectClass::External,
        account_key: None,
        connection_id: None,
        bucket_creation_operation_id: None,
    }
}
