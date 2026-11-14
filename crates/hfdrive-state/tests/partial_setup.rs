//! Draft setup reservations: explicit, immutable initialization intent; no
//! draft ever appears as a connected Explorer root; read-only setups reach
//! Connected without credentials or write probes; created resources survive
//! failure; replacing credentials invalidates stale evidence; registry commits
//! reconcile idempotently after a crash.

mod common;

use common::*;
use hfdrive_core::ids::{ConnectionId, OperationId};
use hfdrive_state::{
    ConnectionMode, CreatedResource, CredentialRef, SetupDraft, SetupPhase, SetupStatus, StateError,
    StatePaths, StateStore,
};

#[tokio::test]
async fn draft_setup_is_not_a_registered_connection() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();

    let draft = SetupDraft {
        operation_id: OperationId::new(),
        account_key: key,
        binding: binding(key),
        initialize: true,
    };
    let reservation = store.reserve_setup(draft).await.unwrap();

    let account = store.open_account(key).await.unwrap();
    assert!(
        account.list_connections().await.unwrap().is_empty(),
        "a draft must not appear as a registered connection"
    );
    assert!(
        store.reconcile_connections().await.unwrap().is_empty(),
        "a draft must not appear in the reconciled registry"
    );

    // It is discoverable as a draft.
    let setup = store.get_setup_by_connection(reservation.connection_id).await.unwrap().unwrap();
    assert_eq!(setup.phase, SetupPhase::Reserved);
    assert!(setup.initialize);
    assert_eq!(setup.status, SetupStatus::Active);
    store.close().await.unwrap();
}

#[tokio::test]
async fn readonly_setup_connects_without_credentials_or_probes() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();

    let draft = SetupDraft {
        operation_id: OperationId::new(),
        account_key: key,
        binding: binding(key),
        initialize: false,
    };
    let reservation = store.reserve_setup(draft).await.unwrap();

    // Read-only setups skip credentials and probes: the forward-only chain
    // must not categorically require them.
    let setup = store
        .advance_setup(reservation.setup_id, SetupPhase::PreviewReady)
        .await
        .unwrap();
    assert_eq!(setup.phase, SetupPhase::PreviewReady);

    // Backward transitions stay refused.
    let error = store
        .advance_setup(reservation.setup_id, SetupPhase::Reserved)
        .await
        .unwrap_err();
    assert!(matches!(error, StateError::IllegalSetupTransition { .. }), "found {error:?}");

    store
        .attach_setup_preview(
            reservation.setup_id,
            preview_json(std::path::Path::new("C:\\hfdrive-ro")),
            std::path::PathBuf::from("C:\\hfdrive-ro"),
            ConnectionMode::ReadOnly,
        )
        .await
        .unwrap();
    let setup = store.finalize_setup(reservation.setup_id).await.unwrap();
    assert_eq!(setup.phase, SetupPhase::Connected);
    assert_eq!(setup.status, SetupStatus::Connected);

    let account = store.open_account(key).await.unwrap();
    let conn = account.get_connection(setup.connection_id).await.unwrap().unwrap();
    assert_eq!(conn.mode, ConnectionMode::ReadOnly);
    assert!(conn.s3_ref.is_none(), "no publication credentials are required for read-only");
    assert_eq!(conn.oauth_ref, Some(CredentialRef("credentials/oauth.cred".to_owned())));
    store.close().await.unwrap();
}

#[tokio::test]
async fn writable_flow_preserves_created_resources_through_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();

    let draft = SetupDraft {
        operation_id: OperationId::new(),
        account_key: key,
        binding: binding(key),
        initialize: true,
    };
    let reservation = store.reserve_setup(draft).await.unwrap();

    let setup = store
        .record_setup_credentials(reservation.setup_id, CredentialRef("credentials/s3-1.cred".to_owned()))
        .await
        .unwrap();
    assert_eq!(setup.phase, SetupPhase::CredentialsRecorded);
    let setup = store
        .record_probe_evidence(reservation.setup_id, serde_json::json!({"writable": true}))
        .await
        .unwrap();
    assert_eq!(setup.phase, SetupPhase::Probed);
    store
        .attach_setup_preview(
            reservation.setup_id,
            preview_json(std::path::Path::new("C:\\hfdrive-root")),
            std::path::PathBuf::from("C:\\hfdrive-root"),
            ConnectionMode::Writable,
        )
        .await
        .unwrap();

    // A resource created for this setup is journaled before a partial failure.
    store
        .record_created_resources(
            reservation.setup_id,
            vec![
                CreatedResource {
                    kind: "bucket".to_owned(),
                    identity: "bucket-stable-1".to_owned(),
                    note: Some("created by operation 1".to_owned()),
                },
                CreatedResource {
                    kind: "prefix".to_owned(),
                    identity: "hfdrive/test-ws".to_owned(),
                    note: None,
                },
            ],
        )
        .await
        .unwrap();

    let failed = store
        .fail_setup(reservation.setup_id, "probe failed: write check timed out".to_owned())
        .await
        .unwrap();
    assert_eq!(failed.status, SetupStatus::Failed);
    assert_eq!(
        failed.failure_reason.as_deref(),
        Some("probe failed: write check timed out")
    );
    assert_eq!(failed.created_resources.len(), 2, "created resources stay visible on failure");

    // Explicit resume keeps everything and reaches Connected.
    let resumed = store.resume_setup(reservation.setup_id).await.unwrap();
    assert_eq!(resumed.status, SetupStatus::Active);
    assert_eq!(resumed.created_resources.len(), 2);
    let connected = store.finalize_setup(reservation.setup_id).await.unwrap();
    assert_eq!(connected.phase, SetupPhase::Connected);
    let account = store.open_account(key).await.unwrap();
    assert_eq!(account.list_connections().await.unwrap().len(), 1);
    store.close().await.unwrap();
}

#[tokio::test]
async fn replacing_credentials_invalidates_stale_probe_and_preview_evidence() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();

    let draft = SetupDraft {
        operation_id: OperationId::new(),
        account_key: key,
        binding: binding(key),
        initialize: true,
    };
    let reservation = store.reserve_setup(draft).await.unwrap();
    store
        .record_setup_credentials(reservation.setup_id, CredentialRef("credentials/s3-1.cred".to_owned()))
        .await
        .unwrap();
    store
        .record_probe_evidence(reservation.setup_id, serde_json::json!({"writable": true}))
        .await
        .unwrap();
    store
        .attach_setup_preview(
            reservation.setup_id,
            preview_json(std::path::Path::new("C:\\hfdrive-root")),
            std::path::PathBuf::from("C:\\hfdrive-root"),
            ConnectionMode::Writable,
        )
        .await
        .unwrap();
    let before = store.get_setup(reservation.setup_id).await.unwrap().unwrap();
    assert!(before.probe_evidence_json.is_some());
    assert!(before.preview_json.is_some());

    // Replacing the credential must invalidate the evidence collected under
    // the old one before any writable resume can rely on it.
    let after = store
        .record_setup_credentials(reservation.setup_id, CredentialRef("credentials/s3-2.cred".to_owned()))
        .await
        .unwrap();
    assert!(
        after.probe_evidence_json.is_none(),
        "probe evidence from replaced credentials must be invalidated"
    );
    assert!(
        after.preview_json.is_none(),
        "preview evidence from replaced credentials must be invalidated"
    );
    assert_eq!(after.evidence_generation, before.evidence_generation + 1);
    assert_eq!(after.credential_ref, Some(CredentialRef("credentials/s3-2.cred".to_owned())));
    store.close().await.unwrap();
}

#[tokio::test]
async fn finalize_is_idempotent_and_registry_reconciles() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let key = account_key();
    let store = StateStore::open(paths.clone()).await.unwrap();
    store.record_account(account_record(key)).await.unwrap();

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
    let first = store.finalize_setup(reservation.setup_id).await.unwrap();
    let second = store.finalize_setup(reservation.setup_id).await.unwrap();
    assert_eq!(first.connection_id, second.connection_id, "finalize is idempotent");
    let account = store.open_account(key).await.unwrap();
    assert_eq!(account.list_connections().await.unwrap().len(), 1, "no duplicate registrations");
    store.close().await.unwrap();

    // Simulate the crash window: the control-side registry row is missing
    // while the account-side registration committed.
    let control = paths.control_database();
    {
        let conn = rusqlite::Connection::open(&control).unwrap();
        conn.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
        conn.execute("DELETE FROM connections", []).unwrap();
    }

    let store = StateStore::open(paths).await.unwrap();
    let registry = store.reconcile_connections().await.unwrap();
    assert_eq!(registry.len(), 1, "reconciliation restores the missing registry row");
    assert_eq!(registry[0].connection_id, first.connection_id);
    // Running it again is a no-op: reconciliation is idempotent.
    let registry = store.reconcile_connections().await.unwrap();
    assert_eq!(registry.len(), 1);
    store.close().await.unwrap();
}

#[tokio::test]
async fn setup_journal_reconciles_the_missing_control_side() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let key = account_key();
    let store = StateStore::open(paths.clone()).await.unwrap();
    store.record_account(account_record(key)).await.unwrap();

    let draft = SetupDraft {
        operation_id: OperationId::new(),
        account_key: key,
        binding: binding(key),
        initialize: true,
    };
    let reservation = store.reserve_setup(draft).await.unwrap();
    store.close().await.unwrap();

    // Simulate a crash between the account commit and the control mirror.
    let control = paths.control_database();
    {
        let conn = rusqlite::Connection::open(&control).unwrap();
        conn.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
        conn.execute("DELETE FROM setup_registry", []).unwrap();
    }

    let store = StateStore::open(paths).await.unwrap();
    let setup = store
        .reconcile_setup_commits(reservation.setup_id)
        .await
        .unwrap();
    assert!(setup.control_committed, "the missing mirror side is completed");
    let again = store.reconcile_setup_commits(reservation.setup_id).await.unwrap();
    assert!(again.control_committed);
    let conn_id: ConnectionId = reservation.connection_id;
    assert!(store.get_setup_by_connection(conn_id).await.unwrap().is_some());
    store.close().await.unwrap();
}
