//! Scan safety: a disappearance is deletion evidence only after a fully
//! completed, still-valid metadata scan. Overflow, reset, denial, or an
//! incomplete enumeration invalidate it. The durable event/scan bookkeeping
//! row is registered in the connection's finalization transaction and
//! repaired by normal open/reconciliation: an existing row is never reset,
//! and unknown scan evidence stays unknown and deletion-ineligible.

mod common;

use common::*;
use hfdrive_core::ids::OperationId;
use hfdrive_state::{ConnectionMode, SetupDraft, StatePaths, StateStore};

async fn connect(store: &StateStore) -> hfdrive_core::ids::ConnectionId {
    connect_reserved(store).await.connection_id
}

/// Reserves, previews and finalizes one read-only setup, returning the full
/// reservation so tests can exercise finalization boundaries again.
async fn connect_reserved(store: &StateStore) -> hfdrive_state::SetupReservation {
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
        .attach_setup_preview(
            reservation.setup_id,
            preview_json(std::path::Path::new("C:\\hfdrive-root")),
            std::path::PathBuf::from("C:\\hfdrive-root"),
            ConnectionMode::ReadOnly,
        )
        .await
        .unwrap();
    store.finalize_setup(reservation.setup_id).await.unwrap();
    reservation
}

#[tokio::test]
async fn finalize_registers_event_bookkeeping_before_the_first_invalidation() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let store = StateStore::open(paths.clone()).await.unwrap();
    let connection_id = connect(&store).await;
    let account = store.open_account(account_key()).await.unwrap();

    // Finalization itself registers the durable event/scan bookkeeping row;
    // no caller has to initialize it, and it claims no evidence yet.
    let initial = account
        .scan_state(connection_id)
        .await
        .unwrap()
        .expect("finalization registers the event row");
    assert_eq!(initial.cursor, None, "no cursor is fabricated at finalization");
    assert!(!initial.pending_head_refresh, "no HEAD refresh is fabricated at finalization");
    assert!(!initial.scan_complete && !initial.scan_invalidated, "scan evidence stays unknown");
    assert!(!initial.may_infer_deletion(), "unknown scan evidence stays deletion-ineligible");

    // The first notification lands without any manual initialization.
    let state = account
        .record_head_invalidation(connection_id, Some("cursor-1".to_owned()))
        .await
        .unwrap();
    assert!(state.pending_head_refresh, "the first invalidation is durable");
    assert_eq!(state.cursor.as_deref(), Some("cursor-1"));
    store.close().await.unwrap();

    // The pending refresh and its cursor survive reopen.
    let store = StateStore::open(paths).await.unwrap();
    let account = store.open_account(account_key()).await.unwrap();
    let state = account.scan_state(connection_id).await.unwrap().unwrap();
    assert!(state.pending_head_refresh, "the pending refresh is durable");
    assert_eq!(state.cursor.as_deref(), Some("cursor-1"), "the cursor is durable");
    store.close().await.unwrap();
}

#[tokio::test]
async fn connected_connection_without_event_state_is_repaired_on_open() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let key = account_key();
    let store = StateStore::open(paths.clone()).await.unwrap();
    let connection_id = connect(&store).await;

    // The provider's durable registration identity, recorded exactly as
    // `registry::persist_registration` records it.
    let volume_guid = "\\\\?\\Volume{11111111-2222-3333-4444-555555555555}\\";
    let account = store.open_account(key).await.unwrap();
    account
        .set_settings(
            format!("connection/{connection_id}/registration"),
            serde_json::json!({
                "sync_root_id": format!("HFDrive!S-1-5-21-1!{connection_id}"),
                "volume_guid": volume_guid,
                "volume_serial": 2747303275u32,
                "registered": true,
            }),
            None,
        )
        .await
        .unwrap();
    store.close().await.unwrap();

    // Simulate a connection finalized before event bookkeeping existed: the
    // registry row is real, the event row is missing.
    {
        let conn = rusqlite::Connection::open(paths.account(key).database()).unwrap();
        conn.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
        let deleted = conn
            .execute(
                "DELETE FROM event_cursors WHERE connection_id = ?1",
                rusqlite::params![connection_id.as_bytes().as_slice()],
            )
            .unwrap();
        assert_eq!(deleted, 1, "the fixture must remove exactly the event row");
    }

    // The normal open/reconciliation path repairs it: no SQL from the user,
    // no new remote setup, and no fabricated scan evidence.
    let store = StateStore::open(paths).await.unwrap();
    let registry = store.reconcile_connections().await.unwrap();
    assert_eq!(registry.len(), 1, "the registered connection reconciles");
    let account = store.open_account(key).await.unwrap();
    let repaired = account
        .scan_state(connection_id)
        .await
        .unwrap()
        .expect("the missing event row is repaired by reconciliation");
    assert_eq!(repaired.volume_id, volume_guid, "the repair reuses the recorded volume identity");
    assert_eq!(repaired.cursor, None, "the repair fabricates no cursor");
    assert!(!repaired.pending_head_refresh, "the repair fabricates no HEAD refresh");
    assert!(!repaired.scan_complete && !repaired.scan_invalidated);
    assert!(!repaired.may_infer_deletion(), "repaired bookkeeping is never scan evidence");

    // And the first notification lands on the repaired connection.
    let state = account.record_head_invalidation(connection_id, None).await.unwrap();
    assert!(state.pending_head_refresh);
    store.close().await.unwrap();
}

#[tokio::test]
async fn cursor_and_scan_evidence_survive_repeated_reconciliation() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let key = account_key();
    let connection_id;
    {
        let store = StateStore::open(paths.clone()).await.unwrap();
        let reservation = connect_reserved(&store).await;
        connection_id = reservation.connection_id;
        let account = store.open_account(key).await.unwrap();

        account
            .init_event_cursor(connection_id, "volume-1".to_owned(), "journal-1".to_owned())
            .await
            .unwrap();
        account.begin_scan(connection_id, "volume-1".to_owned(), "journal-1".to_owned()).await.unwrap();
        account.complete_scan(connection_id, Some(77)).await.unwrap();
        let recorded = account
            .record_head_invalidation(connection_id, Some("cursor-9".to_owned()))
            .await
            .unwrap();
        assert!(recorded.may_infer_deletion());
        assert!(recorded.pending_head_refresh);

        // Duplicate finalization and repeated reconciliation are no-ops for
        // recorded bookkeeping.
        for _ in 0..2 {
            store.finalize_setup(reservation.setup_id).await.unwrap();
            store.reconcile_setup_commits(reservation.setup_id).await.unwrap();
            store.reconcile_connections().await.unwrap();
        }
        // No close(): the store ends here as a reconnect/crash boundary.
    }

    // The normal open/reconciliation path preserves every recorded fact.
    let store = StateStore::open(paths).await.unwrap();
    store.reconcile_connections().await.unwrap();
    let account = store.open_account(key).await.unwrap();
    let state = account.scan_state(connection_id).await.unwrap().unwrap();
    assert_eq!(state.cursor.as_deref(), Some("cursor-9"), "the cursor survives");
    assert!(state.pending_head_refresh, "the unacknowledged refresh survives");
    assert!(state.scan_complete && !state.scan_invalidated, "the scan evidence survives");
    assert!(state.may_infer_deletion(), "deletion evidence survives reconciliation");
    assert_eq!(state.usn_cursor, Some(77), "the USN cursor survives");
    assert_eq!(state.scan_epoch, 1, "the scan epoch is never reset");
    assert_eq!(state.volume_id, "volume-1", "the observed volume identity survives");
    assert_eq!(state.journal_id, "journal-1", "the observed journal identity survives");
    store.close().await.unwrap();
}

#[tokio::test]
async fn deletion_evidence_requires_a_completed_scan() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let connection_id = connect(&store).await;
    let account = store.open_account(account_key()).await.unwrap();

    let cursor = account
        .init_event_cursor(connection_id, "volume-1".to_owned(), "journal-1".to_owned())
        .await
        .unwrap();
    assert!(!cursor.may_infer_deletion(), "no scan has completed yet");

    let scanning = account
        .begin_scan(connection_id, "volume-1".to_owned(), "journal-1".to_owned())
        .await
        .unwrap();
    assert_eq!(scanning.scan_epoch, 1);
    assert!(!scanning.may_infer_deletion(), "an in-flight scan is not evidence");

    let done = account.complete_scan(connection_id, Some(10_000)).await.unwrap();
    assert!(done.scan_complete);
    assert!(done.may_infer_deletion(), "only a fully completed scan may infer deletion");
    assert_eq!(done.usn_cursor, Some(10_000));

    // A fresh scan supersedes the old evidence while it is running.
    let next = account.begin_scan(connection_id, "volume-1".to_owned(), "journal-1".to_owned()).await.unwrap();
    assert_eq!(next.scan_epoch, 2);
    assert!(!next.may_infer_deletion(), "the new incomplete scan cannot infer deletion");
    store.close().await.unwrap();
}

#[tokio::test]
async fn invalidation_revokes_deletion_evidence() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let connection_id = connect(&store).await;
    let account = store.open_account(account_key()).await.unwrap();

    account
        .init_event_cursor(connection_id, "volume-1".to_owned(), "journal-1".to_owned())
        .await
        .unwrap();
    account.begin_scan(connection_id, "volume-1".to_owned(), "journal-1".to_owned()).await.unwrap();
    let done = account.complete_scan(connection_id, Some(5)).await.unwrap();
    assert!(done.may_infer_deletion());

    // Watcher overflow / USN reset / denied enumeration: evidence is revoked
    // and the disappearance cannot be treated as deletion.
    let invalidated = account.invalidate_scan(connection_id).await.unwrap();
    assert!(invalidated.scan_invalidated);
    assert!(!invalidated.may_infer_deletion(), "an invalidated scan is never deletion evidence");

    // Only a fresh completed scan restores it.
    account.begin_scan(connection_id, "volume-2".to_owned(), "journal-2".to_owned()).await.unwrap();
    let restored = account.complete_scan(connection_id, Some(1)).await.unwrap();
    assert!(restored.may_infer_deletion());
    assert_eq!(restored.volume_id, "volume-2");
    assert_eq!(restored.journal_id, "journal-2");
    store.close().await.unwrap();
}

#[tokio::test]
async fn head_invalidation_is_persisted_before_the_cursor_advances() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let connection_id = connect(&store).await;
    let account = store.open_account(account_key()).await.unwrap();
    account
        .init_event_cursor(connection_id, "volume-1".to_owned(), "journal-1".to_owned())
        .await
        .unwrap();

    // The invalidation and the opaque cursor land together: the cursor never
    // advances past an unpersisted invalidation.
    let state = account
        .record_head_invalidation(connection_id, Some("cursor-1".to_owned()))
        .await
        .unwrap();
    assert!(state.pending_head_refresh);
    assert_eq!(state.cursor.as_deref(), Some("cursor-1"));

    // The applied head refresh clears the flag only after processing.
    let state = account.ack_head_refresh(connection_id).await.unwrap();
    assert!(!state.pending_head_refresh);
    assert_eq!(state.cursor.as_deref(), Some("cursor-1"), "the cursor is retained for reconnect");

    let state = account
        .record_head_invalidation(connection_id, Some("cursor-2".to_owned()))
        .await
        .unwrap();
    assert!(state.pending_head_refresh);
    assert_eq!(state.cursor.as_deref(), Some("cursor-2"));
    store.close().await.unwrap();
}

#[tokio::test]
async fn scan_state_survives_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let store = StateStore::open(paths.clone()).await.unwrap();
    let connection_id = connect(&store).await;
    let account = store.open_account(account_key()).await.unwrap();
    account
        .init_event_cursor(connection_id, "volume-1".to_owned(), "journal-1".to_owned())
        .await
        .unwrap();
    account.begin_scan(connection_id, "volume-1".to_owned(), "journal-1".to_owned()).await.unwrap();
    account.complete_scan(connection_id, Some(77)).await.unwrap();
    account.record_head_invalidation(connection_id, Some("cursor-9".to_owned())).await.unwrap();
    store.close().await.unwrap();

    let store = StateStore::open(paths).await.unwrap();
    let account = store.open_account(account_key()).await.unwrap();
    let state = account.scan_state(connection_id).await.unwrap().unwrap();
    assert!(state.may_infer_deletion(), "completed scan evidence survives restart");
    assert!(state.pending_head_refresh, "an unacknowledged HEAD refresh survives restart");
    assert_eq!(state.usn_cursor, Some(77));
    store.close().await.unwrap();
}
