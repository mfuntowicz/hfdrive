//! The guarded storage-repair commit: one account transaction moves the
//! connected connection's supplemental credential reference and the fresh
//! capability evidence together, guarded by the previously observed reference.
//! Root, workspace, mode, pending work and local observations are preserved,
//! and a lost guard race commits nothing.

mod common;

use common::*;
use hfdrive_core::ids::{ItemId, OperationId};
use hfdrive_state::{
    ConnectionMode, CredentialRef, OutboxEntry, OutboxState, RetryClass, SetupDraft, StatePaths,
    StateStore,
};

/// Builds one connected connection whose config carries `root_item_id`.
async fn connected_connection(store: &StateStore, key: hfdrive_core::ids::AccountKey, s3_ref: &str) -> (
    hfdrive_core::ids::ConnectionId,
    serde_json::Value,
) {
    let setup = store
        .reserve_setup(SetupDraft {
            operation_id: OperationId::new(),
            account_key: key,
            binding: binding(key),
            initialize: false,
        })
        .await
        .unwrap();
    store
        .record_setup_credentials(setup.setup_id, CredentialRef(s3_ref.to_owned()))
        .await
        .unwrap();
    let root_item = ItemId::new();
    store
        .attach_setup_preview(
            setup.setup_id,
            serde_json::json!({ "root_item_id": root_item.to_string(), "fixture": true }),
            std::path::PathBuf::from("C:\\hfdrive-repair-target"),
            ConnectionMode::Writable,
        )
        .await
        .unwrap();
    store.finalize_setup(setup.setup_id).await.unwrap();
    (setup.connection_id, serde_json::json!({ "root_item_id": root_item.to_string() }))
}

fn evidence(connection: hfdrive_core::ids::ConnectionId, marker: &str) -> serde_json::Value {
    serde_json::json!({
        "connection_id": connection.to_string(),
        "mode": "full",
        "marker": marker,
    })
}

#[tokio::test]
async fn guarded_commit_moves_reference_and_evidence_together() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let (connection, root_config) = connected_connection(&store, key, "s3-old.hfdcred").await;
    let account = store.open_account(key).await.unwrap();

    // Pending work and local observations are part of what a repair must keep.
    // The observed item and the queued item are the same item: the dirty
    // observation is the pending work's own local state.
    let dirty_item = ItemId::new();
    account
        .record_outbox(OutboxEntry {
            connection_id: connection,
            operation_id: OperationId::new(),
            item_id: Some(dirty_item),
            base_commit: None,
            base_json: None,
            observed_generation: 3,
            intent_json: serde_json::json!({"fixture": true}),
            state: OutboxState::Observed,
            snapshot_id: None,
            object_ref: None,
            candidate_commit: None,
            candidate_head_json: None,
            expected_etag: None,
            retry_class: RetryClass::None,
            next_attempt_at_ms: None,
        })
        .await
        .unwrap();
    account.bump_observation(connection, dirty_item, Some(7)).await.unwrap();

    let fresh = evidence(connection, "fresh");
    let updated = store
        .commit_storage_repair(
            connection,
            Some(CredentialRef("s3-old.hfdcred".to_owned())),
            CredentialRef("s3-repair-1".to_owned()),
            fresh.clone(),
        )
        .await
        .unwrap()
        .expect("the guarded commit must succeed against the observed reference");

    assert_eq!(updated.credential_ref, Some(CredentialRef("s3-repair-1".to_owned())));
    assert_eq!(updated.probe_evidence_json, Some(fresh));
    let record = account.get_connection(connection).await.unwrap().unwrap();
    assert_eq!(record.s3_ref, Some(CredentialRef("s3-repair-1".to_owned())));
    // Root, workspace, mode and config are never part of a credential repair.
    assert_eq!(record.root_path, std::path::PathBuf::from("C:\\hfdrive-repair-target"));
    assert_eq!(record.mode, ConnectionMode::Writable);
    assert_eq!(record.config_json.get("root_item_id"), root_config.get("root_item_id"));
    // Pending work and dirty observations survive untouched.
    let pending = account.list_outbox(connection, None, 10).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].item_id, Some(dirty_item));
    assert!(account.observation(connection, dirty_item).await.unwrap().unwrap().dirty);
    store.close().await.unwrap();
}

#[tokio::test]
async fn lost_guard_race_commits_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();
    let (connection, _) = connected_connection(&store, key, "s3-old.hfdcred").await;

    // A concurrent credential commit wins the race and lands first.
    let winner = store
        .commit_storage_repair(
            connection,
            Some(CredentialRef("s3-old.hfdcred".to_owned())),
            CredentialRef("s3-concurrent.hfdcred".to_owned()),
            evidence(connection, "concurrent"),
        )
        .await
        .unwrap();
    assert!(winner.is_some());

    // The loser still believes the old reference is current: it must change
    // nothing at all.
    let loser = store
        .commit_storage_repair(
            connection,
            Some(CredentialRef("s3-old.hfdcred".to_owned())),
            CredentialRef("s3-repair-loser.hfdcred".to_owned()),
            evidence(connection, "loser"),
        )
        .await
        .unwrap();
    assert!(loser.is_none(), "the lost race must report itself, not commit");
    let account = store.open_account(key).await.unwrap();
    let record = account.get_connection(connection).await.unwrap().unwrap();
    assert_eq!(record.s3_ref, Some(CredentialRef("s3-concurrent.hfdcred".to_owned())));
    let setup = store.get_setup_by_connection(connection).await.unwrap().unwrap();
    assert_eq!(setup.credential_ref, Some(CredentialRef("s3-concurrent.hfdcred".to_owned())));
    assert_eq!(setup.probe_evidence_json, Some(evidence(connection, "concurrent")));
    store.close().await.unwrap();
}

#[tokio::test]
async fn repair_commit_survives_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let key = account_key();
    {
        let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
        store.record_account(account_record(key)).await.unwrap();
        let (connection, _) = connected_connection(&store, key, "s3-old.hfdcred").await;
        store
            .commit_storage_repair(
                connection,
                Some(CredentialRef("s3-old.hfdcred".to_owned())),
                CredentialRef("s3-repair-1".to_owned()),
                evidence(connection, "fresh"),
            )
            .await
            .unwrap();
        store.close().await.unwrap();
    }
    let reopened = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let account = reopened.open_account(key).await.unwrap();
    let connections = account.list_connections().await.unwrap();
    let record = account.get_connection(connections[0].connection_id).await.unwrap().unwrap();
    assert_eq!(record.s3_ref, Some(CredentialRef("s3-repair-1".to_owned())));
    let setup = reopened
        .get_setup_by_connection(record.connection_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(setup.probe_evidence_json, Some(evidence(record.connection_id, "fresh")));
    reopened.close().await.unwrap();
}
