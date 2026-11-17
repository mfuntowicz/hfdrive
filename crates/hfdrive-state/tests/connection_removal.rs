//! Connection removal (unlink) durability: the account-local connection row
//! and its work metadata are deleted with the setup intent abandoned in one
//! account transaction, the control-side connection mirror and setup registry
//! follow afterwards, and a crash in between leaves only control residue that
//! `reconcile_connections` repairs. Unknown ids stay `UnknownConnection`, and
//! physical snapshots/recovery files are never touched.

mod common;

use common::*;
use hfdrive_core::ids::{
    AccountKey, ActionId, CommitId, ConflictId, ConnectionId, GenerationId, ItemId, OperationId,
    SnapshotId, TransferId, VersionId,
};
use hfdrive_state::{
    AccountRecord, AccountStatus, CommitRecord, CommitStatus, CommonBaseRecord, ConflictRecord,
    ConflictResolution, ConnectionMode, CredentialRef, ItemKind, ItemRecord, LocalAction,
    LocalActionKind, LocalActionState, OutboxEntry, ProbeKeyRecord, ProbeKeyState, SetupDraft,
    SetupStatus, StateError, StatePaths, StateStore, TransferDirection, TransferRecord,
    TransferState,
};
use rusqlite::{params, Connection};

/// Reserves, previews and finalizes one writable connection.
async fn connected(store: &StateStore, key: AccountKey) -> ConnectionId {
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

/// One row per connection-scoped work table, so the cascade can be asserted
/// table by table instead of "something happened".
async fn seed_work(
    account: &hfdrive_state::AccountStore,
    connection_id: ConnectionId,
    item_id: ItemId,
    name: &str,
) -> (OperationId, SnapshotId, TransferId, CommitId, GenerationId) {
    let operation_id = OperationId::new();
    account
        .upsert_item(ItemRecord {
            connection_id,
            item_id,
            parent_id: None,
            name: name.to_owned(),
            name_key: hfdrive_core::names::collision_key(name)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            kind: ItemKind::File,
            revision: operation_id,
            content_version_id: Some(VersionId::new()),
            deleted: false,
            metadata_json: serde_json::json!({"name": name}),
        })
        .await
        .unwrap();
    account.bump_observation(connection_id, item_id, Some(7)).await.unwrap();
    account
        .record_outbox(OutboxEntry::observed(
            connection_id,
            operation_id,
            Some(item_id),
            1,
            serde_json::json!({"kind": "content"}),
        ))
        .await
        .unwrap();

    let snapshot_id = SnapshotId::new();
    account
        .begin_snapshot(connection_id, snapshot_id, std::path::PathBuf::from("C:\\staging\\s.bin"))
        .await
        .unwrap();
    account.complete_snapshot(connection_id, snapshot_id, 4, digest(b"data")).await.unwrap();

    let transfer_id = TransferId::new();
    account
        .record_transfer(TransferRecord {
            connection_id,
            transfer_id,
            operation_id: Some(operation_id),
            direction: TransferDirection::Upload,
            version_id: None,
            range_start: Some(0),
            range_end: Some(4),
            state: TransferState::InProgress,
            sdk_resume_json: None,
            logical_bytes: 4,
            wire_bytes: 8,
        })
        .await
        .unwrap();

    let commit_id = CommitId::new();
    account
        .record_commit(CommitRecord {
            connection_id,
            commit_id,
            parent_id: None,
            catalog_root: Some(digest(b"catalog")),
            operation_ids: vec![operation_id],
            status: CommitStatus::Committed,
        })
        .await
        .unwrap();
    account
        .put_common_base(CommonBaseRecord {
            connection_id,
            item_id,
            commit_id,
            item_json: "{\"name\":\"hello.txt\"}".to_owned(),
        })
        .await
        .unwrap();

    account
        .record_conflict(ConflictRecord {
            connection_id,
            conflict_id: ConflictId::new(),
            item_id,
            competing_ops: vec![operation_id, OperationId::new()],
            revisions_json: serde_json::json!({}),
            original_names: vec![name.to_owned()],
            resolution_state: ConflictResolution::Unresolved,
            detected_at_ms: None,
        })
        .await
        .unwrap();
    account
        .record_local_action(LocalAction {
            connection_id,
            action_id: ActionId::new(),
            item_id: Some(item_id),
            kind: LocalActionKind::UpdatePlaceholder,
            expected_file_id: Some("4612".to_owned()),
            expected_generation: Some(1),
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

    // The probe created-key journal has no foreign key to the connection on
    // purpose: its rows are the only evidence for remote key cleanup and must
    // survive an unlink.
    let run_id = GenerationId::new();
    account
        .reserve_probe_key(ProbeKeyRecord {
            run_id,
            connection_id,
            setup_id: None,
            key: format!("hfdrive-probe/{run_id}/a.bin"),
            state: ProbeKeyState::Reserved,
        })
        .await
        .unwrap();
    (operation_id, snapshot_id, transfer_id, commit_id, run_id)
}

/// The control-side registry mirror of a connection/setup pair, read straight
/// from the control database.
fn control_rows(paths: &StatePaths, connection_id: ConnectionId) -> (bool, Option<String>) {
    let control = Connection::open(paths.control_database()).unwrap();
    let mirrors: i64 = control
        .query_row(
            "SELECT COUNT(*) FROM connections WHERE connection_id = ?1",
            params![connection_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let registry_status = control
        .query_row(
            "SELECT status FROM setup_registry WHERE connection_id = ?1",
            params![connection_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .ok();
    (mirrors == 1, registry_status)
}

#[tokio::test]
async fn removal_deletes_the_row_and_cascades_work_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let store = StateStore::open(paths.clone()).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();

    let connection_id = connected(&store, key).await;
    let account = store.open_account(key).await.unwrap();
    let item_id = ItemId::new();
    let (operation_id, snapshot_id, transfer_id, commit_id, run_id) =
        seed_work(&account, connection_id, item_id, "hello.txt").await;

    // Every connection-scoped table holds its row before the removal.
    assert_eq!(account.list_outbox(connection_id, None, 10).await.unwrap().len(), 1);
    assert_eq!(account.list_snapshots(connection_id).await.unwrap().len(), 1);
    assert!(account.transfer(connection_id, transfer_id).await.unwrap().is_some());
    assert!(account.commit(connection_id, commit_id).await.unwrap().is_some());
    assert!(account.item(connection_id, item_id).await.unwrap().is_some());
    assert!(account.observation(connection_id, item_id).await.unwrap().is_some());
    assert!(account.get_common_base(connection_id, item_id, commit_id).await.unwrap().is_some());
    assert_eq!(account.list_conflicts(connection_id).await.unwrap().len(), 1);
    assert_eq!(account.list_local_actions(connection_id, None).await.unwrap().len(), 1);
    assert!(account.scan_state(connection_id).await.unwrap().is_some());

    account.remove_connection(connection_id).await.unwrap();

    assert!(account.get_connection(connection_id).await.unwrap().is_none());
    assert!(account.list_connections().await.unwrap().is_empty());
    assert!(account.list_outbox(connection_id, None, 10).await.unwrap().is_empty());
    assert!(account.outbox_entry(connection_id, operation_id).await.unwrap().is_none());
    assert!(account.list_snapshots(connection_id).await.unwrap().is_empty());
    assert!(account.snapshot(connection_id, snapshot_id).await.unwrap().is_none());
    assert!(account.transfer(connection_id, transfer_id).await.unwrap().is_none());
    assert!(account.commit(connection_id, commit_id).await.unwrap().is_none());
    assert!(account.list_ancestry(connection_id, None, None, 10).await.unwrap().is_empty());
    assert!(account.item(connection_id, item_id).await.unwrap().is_none());
    assert!(account.list_all_items(connection_id, true).await.unwrap().is_empty());
    assert!(account.observation(connection_id, item_id).await.unwrap().is_none());
    assert!(account.get_common_base(connection_id, item_id, commit_id).await.unwrap().is_none());
    assert!(account.list_conflicts(connection_id).await.unwrap().is_empty());
    assert!(account.list_local_actions(connection_id, None).await.unwrap().is_empty());
    assert!(account.scan_state(connection_id).await.unwrap().is_none());
    assert!(
        matches!(account.baseline(connection_id).await.unwrap_err(), StateError::UnknownConnection(_)),
        "the removed connection is gone, not merely deregistered"
    );

    // The probe created-key journal survives: it is the only cleanup evidence
    // for keys that may already exist in remote storage.
    assert_eq!(account.probe_keys(connection_id, run_id).await.unwrap().len(), 1);

    // A second connection of the same account is untouched by the cascade.
    let survivor = connected(&store, key).await;
    assert!(account.get_connection(survivor).await.unwrap().is_some());
    let survivor_item = ItemId::new();
    seed_work(&account, survivor, survivor_item, "kept.txt").await;
    account.remove_connection(connection_id).await.unwrap_err(); // already gone
    assert!(account.item(survivor, survivor_item).await.unwrap().is_some());
    store.close().await.unwrap();
}

#[tokio::test]
async fn removal_abandons_the_setup_intent_and_control_registry() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let store = StateStore::open(paths.clone()).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();

    let connection_id = connected(&store, key).await;
    let account = store.open_account(key).await.unwrap();
    account.remove_connection(connection_id).await.unwrap();

    // The setup intent is abandoned in the same account transaction that
    // removed the connection row; the row itself is kept as journal history.
    let setup = store.get_setup_by_connection(connection_id).await.unwrap().expect("setup journal row");
    assert_eq!(setup.status, SetupStatus::Abandoned);
    assert_eq!(setup.failure_reason.as_deref(), Some("connection unlinked"));
    assert!(setup.control_committed, "the control mirror is caught up");
    store.close().await.unwrap();

    // Control side: the connection mirror is gone and the registry row is
    // abandoned rather than deleted.
    let (mirror, registry_status) = control_rows(&paths, connection_id);
    assert!(!mirror, "the control connection mirror must be deleted");
    assert_eq!(registry_status.as_deref(), Some("abandoned"), "the registry row stays as history");
}

#[tokio::test]
async fn removal_requires_a_known_connection() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();

    // Unknown ids are UnknownConnection, never UnknownSetup or NotFound.
    let account = store.open_account(key).await.unwrap();
    let unknown = ConnectionId::new();
    let error = account.remove_connection(unknown).await.unwrap_err();
    assert!(matches!(error, StateError::UnknownConnection(id) if id == unknown), "found {error:?}");

    // A connection belonging to another account is unknown to this account.
    let other_key = AccountKey::from_subject(ISSUER, "test-subject-2");
    store
        .record_account(AccountRecord {
            account_key: other_key,
            issuer: ISSUER.to_owned(),
            subject: "test-subject-2".to_owned(),
            namespace: "test-user-2".to_owned(),
            credential_ref: CredentialRef("credentials/oauth-2.cred".to_owned()),
            auth_epoch: 0,
            status: AccountStatus::Active,
        })
        .await
        .unwrap();
    let connection_id = connected(&store, key).await;
    let other = store.open_account(other_key).await.unwrap();
    let error = other.remove_connection(connection_id).await.unwrap_err();
    assert!(matches!(error, StateError::UnknownConnection(id) if id == connection_id), "found {error:?}");
    assert!(account.get_connection(connection_id).await.unwrap().is_some(), "a foreign removal must not mutate");

    // Unknown removals leave the registry untouched.
    assert_eq!(account.list_connections().await.unwrap().len(), 1);
    assert!(store.reconcile_connections().await.unwrap().len() >= 1);
    store.close().await.unwrap();
}

#[tokio::test]
async fn reconcile_repairs_control_residue_of_an_interrupted_removal() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let store = StateStore::open(paths.clone()).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let connection_id = connected(&store, key).await;
    store.close().await.unwrap();

    // Simulate a crash after the account commit of `remove_connection` but
    // before its control cleanup: the account transaction landed exactly as
    // remove_connection writes it, and the control databases still hold the
    // pre-removal rows.
    {
        let account_db = Connection::open(paths.account(key).database()).unwrap();
        let tx = account_db.unchecked_transaction().unwrap();
        let deleted = tx
            .execute(
                "DELETE FROM connections WHERE connection_id = ?1",
                params![connection_id.as_bytes().as_slice()],
            )
            .unwrap();
        assert_eq!(deleted, 1);
        tx.execute(
            "UPDATE setup_intents
                SET status = 'abandoned', failure_reason = 'connection unlinked', control_committed = 0
              WHERE connection_id = ?1",
            params![connection_id.as_bytes().as_slice()],
        )
        .unwrap();
        tx.commit().unwrap();
    }
    let (mirror, registry_status) = control_rows(&paths, connection_id);
    assert!(mirror, "the interrupted removal left a stale control mirror");
    assert_eq!(registry_status.as_deref(), Some("connected"), "the registry row is stale too");

    // Reconciliation repairs the residue from the account-side journals: the
    // stale mirror is deleted and the registry row becomes abandoned. The
    // account row is never resurrected.
    let store = StateStore::open(paths.clone()).await.unwrap();
    let reconciled = store.reconcile_connections().await.unwrap();
    assert!(
        reconciled.iter().all(|record| record.connection_id != connection_id),
        "the removed connection must not be re-registered"
    );
    let account = store.open_account(key).await.unwrap();
    assert!(account.get_connection(connection_id).await.unwrap().is_none());
    let setup = store.get_setup_by_connection(connection_id).await.unwrap().expect("setup journal row");
    assert_eq!(setup.status, SetupStatus::Abandoned);
    assert!(setup.control_committed);

    // The repair is idempotent.
    store.reconcile_connections().await.unwrap();
    store.close().await.unwrap();

    let (mirror, registry_status) = control_rows(&paths, connection_id);
    assert!(!mirror, "the stale control mirror must be deleted");
    assert_eq!(registry_status.as_deref(), Some("abandoned"));
}

#[tokio::test]
async fn removal_never_touches_physical_snapshot_and_recovery_files() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let store = StateStore::open(paths.clone()).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();

    let draft = SetupDraft {
        operation_id: OperationId::new(),
        account_key: key,
        binding: binding(key),
        initialize: true,
    };
    let reservation = store.reserve_setup(draft).await.unwrap();
    let workspace = reservation.binding.workspace_id;
    store
        .attach_setup_preview(
            reservation.setup_id,
            preview_json(std::path::Path::new("C:\\hfdrive-root")),
            std::path::PathBuf::from("C:\\hfdrive-root"),
            ConnectionMode::Writable,
        )
        .await
        .unwrap();
    let connection_id = store.finalize_setup(reservation.setup_id).await.unwrap().connection_id;

    // Physical artifacts outside the databases: staged snapshots and recovered
    // dirty bytes. Removal deletes state rows only.
    let snapshots = paths.account(key).drive(workspace).snapshots();
    std::fs::create_dir_all(&snapshots).unwrap();
    std::fs::write(snapshots.join("s.bin"), b"snapshot-bytes").unwrap();
    let recovery = paths.account(key).recovery();
    std::fs::create_dir_all(&recovery).unwrap();
    std::fs::write(recovery.join("r.bin"), b"recovered-bytes").unwrap();

    let account = store.open_account(key).await.unwrap();
    account.remove_connection(connection_id).await.unwrap();

    assert_eq!(std::fs::read(snapshots.join("s.bin")).unwrap(), b"snapshot-bytes");
    assert_eq!(std::fs::read(recovery.join("r.bin")).unwrap(), b"recovered-bytes");
    store.close().await.unwrap();
}
