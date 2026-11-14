//! The public state API.
//!
//! `StateStore` owns the control database and the single worker thread; an
//! `AccountStore` handle scopes every call to one account database. All calls
//! are async only because they queue to the worker — the worker itself never
//! awaits on I/O beyond SQLite.

use crate::error::StateError;
use crate::model::*;
use crate::store::{CompletionOutcome, Db, ObservationFlags, OperationResolution, OutboxTransition};
use crate::worker::{Queue, Worker};
use hfdrive_core::ids::{
    AccountKey, ActionId, CommitId, ConflictId, ConnectionId, GenerationId, ItemId, OperationId,
    SetupId, SnapshotId, TransferId,
};
use hfdrive_core::storage::Sha256Digest;
use std::path::{Path, PathBuf};


/// Entry point: opens (or creates) the control database and starts the single
/// database worker thread.
pub struct StateStore {
    worker: Worker,
}

impl StateStore {
    /// Opens the state store rooted at `paths`. Refuses foreign/newer/corrupt
    /// databases instead of recreating them.
    pub async fn open(paths: crate::StatePaths) -> Result<Self, StateError> {
        let (worker, init) = Worker::spawn(paths)?;
        init.await.map_err(|_| StateError::WorkerStopped)??;
        Ok(Self { worker })
    }

    fn queue(&self) -> Queue {
        self.worker.queue()
    }

    // ---- accounts and selection ---------------------------------

    pub async fn record_account(&self, record: AccountRecord) -> Result<(), StateError> {
        self.queue().call(move |db| db.record_account(&record)).await
    }

    pub async fn get_account(&self, account: AccountKey) -> Result<Option<AccountRecord>, StateError> {
        self.queue().call(move |db| db.get_account(account)).await
    }

    pub async fn list_accounts(&self) -> Result<Vec<AccountRecord>, StateError> {
        self.queue().call(move |db| db.list_accounts()).await
    }

    pub async fn set_account_status(&self, account: AccountKey, status: AccountStatus) -> Result<(), StateError> {
        self.queue()
            .call(move |db| db.set_account_status(account, status))
            .await
    }

    /// The explicitly selected account, if one is recorded and selected.
    pub async fn selected_account(&self) -> Result<Option<AccountKey>, StateError> {
        self.queue().call(move |db| db.selected_account()).await
    }

    pub async fn select_account(&self, account: AccountKey) -> Result<(), StateError> {
        self.queue().call(move |db| db.select_account(account)).await
    }

    /// Clears the selection on sign-out. Local work stays intact.
    pub async fn clear_selected_account(&self) -> Result<(), StateError> {
        self.queue().call(move |db| db.clear_selected_account()).await
    }

    /// A handle for account-scoped persistence. The account must already be
    /// recorded; the handle never scans for credentials or databases.
    pub async fn open_account(&self, account: AccountKey) -> Result<AccountStore, StateError> {
        if self.get_account(account).await?.is_none() {
            return Err(StateError::UnknownAccount(account));
        }
        Ok(AccountStore { account, queue: self.queue() })
    }

    // ---- setup journal ------------------------------------------

    /// Reserves a durable draft setup bound to an account and exact binding.
    /// Idempotent on the operation id; the same operation with a different
    /// request is a conflict. Drafts are not registered connections.
    pub async fn reserve_setup(&self, draft: SetupDraft) -> Result<SetupReservation, StateError> {
        self.queue().call(move |db| db.reserve_setup(&draft)).await
    }

    pub async fn get_setup(&self, setup_id: SetupId) -> Result<Option<SetupRecord>, StateError> {
        self.queue().call(move |db| db.get_setup(setup_id)).await
    }

    pub async fn get_setup_by_connection(
        &self,
        connection_id: ConnectionId,
    ) -> Result<Option<SetupRecord>, StateError> {
        self.queue()
            .call(move |db| db.get_setup_by_connection(connection_id))
            .await
    }

    pub async fn list_setups(&self, account: Option<AccountKey>) -> Result<Vec<SetupRecord>, StateError> {
        self.queue().call(move |db| db.list_setups(account)).await
    }

    /// Advances a draft through its phase chain (forward only).
    pub async fn advance_setup(&self, setup_id: SetupId, phase: SetupPhase) -> Result<SetupRecord, StateError> {
        self.queue().call(move |db| db.advance_setup(setup_id, phase)).await
    }

    /// Records the setup's publication-credential file reference. Replacing it
    /// invalidates prior probe and preview evidence.
    pub async fn record_setup_credentials(
        &self,
        setup_id: SetupId,
        credential_ref: CredentialRef,
    ) -> Result<SetupRecord, StateError> {
        self.queue()
            .call(move |db| db.record_setup_credentials(setup_id, credential_ref))
            .await
    }

    pub async fn record_probe_evidence(
        &self,
        setup_id: SetupId,
        evidence: serde_json::Value,
    ) -> Result<SetupRecord, StateError> {
        self.queue()
            .call(move |db| db.record_probe_evidence(setup_id, evidence))
            .await
    }

    /// Attaches the local-root proof and access mode selected at preview time.
    pub async fn attach_setup_preview(
        &self,
        setup_id: SetupId,
        preview: serde_json::Value,
        root_path: PathBuf,
        mode: ConnectionMode,
    ) -> Result<SetupRecord, StateError> {
        self.queue()
            .call(move |db| db.attach_setup_preview(setup_id, preview, root_path, mode))
            .await
    }

    pub async fn record_created_resources(
        &self,
        setup_id: SetupId,
        resources: Vec<CreatedResource>,
    ) -> Result<SetupRecord, StateError> {
        self.queue()
            .call(move |db| db.record_created_resources(setup_id, resources))
            .await
    }

    pub async fn fail_setup(&self, setup_id: SetupId, reason: String) -> Result<SetupRecord, StateError> {
        self.queue().call(move |db| db.fail_setup(setup_id, reason)).await
    }

    /// Explicitly re-activates a failed setup and completes whichever journal
    /// side is missing. Never automatic.
    pub async fn resume_setup(&self, setup_id: SetupId) -> Result<SetupRecord, StateError> {
        self.queue().call(move |db| db.resume_setup(setup_id)).await
    }

    /// Commits a setup to the connection registry in both databases,
    /// idempotently and in separate journal commits.
    pub async fn finalize_setup(&self, setup_id: SetupId) -> Result<SetupRecord, StateError> {
        self.queue().call(move |db| db.finalize_setup(setup_id)).await
    }

    pub async fn reconcile_setup_commits(&self, setup_id: SetupId) -> Result<SetupRecord, StateError> {
        self.queue()
            .call(move |db| db.reconcile_setup_commits(setup_id))
            .await
    }

    /// Reconciles the connection registry after a crash or restart.
    pub async fn reconcile_connections(&self) -> Result<Vec<ConnectionRecord>, StateError> {
        self.queue().call(move |db| db.reconcile_connections()).await
    }

    // ---- operation ledger ---------------------------------------

    /// Reserves one operation id for one exact request. A repeat of the same
    /// request replays the persisted record; a different request conflicts. An
    /// interrupted external operation is never replayed automatically.
    pub async fn begin_operation(&self, request: BeginOperationRequest) -> Result<BeginOutcome, StateError> {
        self.queue().call(move |db| db.begin_operation(&request)).await
    }

    pub async fn get_operation(&self, operation_id: OperationId) -> Result<Option<OperationRecord>, StateError> {
        self.queue().call(move |db| db.get_operation(operation_id)).await
    }

    /// Records that the operation's external effect may now be in flight.
    pub async fn mark_dispatched(&self, operation_id: OperationId) -> Result<OperationRecord, StateError> {
        self.queue().call(move |db| db.mark_dispatched(operation_id)).await
    }

    pub async fn finish_operation(
        &self,
        operation_id: OperationId,
        result: serde_json::Value,
    ) -> Result<OperationRecord, StateError> {
        self.queue()
            .call(move |db| db.finish_operation(operation_id, &result))
            .await
    }

    pub async fn fail_operation(
        &self,
        operation_id: OperationId,
        error_code: String,
    ) -> Result<OperationRecord, StateError> {
        self.queue()
            .call(move |db| db.fail_operation(operation_id, &error_code))
            .await
    }

    pub async fn abandon_operation(&self, operation_id: OperationId) -> Result<OperationRecord, StateError> {
        self.queue().call(move |db| db.abandon_operation(operation_id)).await
    }

    /// Resolves an interrupted external operation after the caller recovered
    /// the truth about its effect. Explicit, never automatic.
    pub async fn reconcile_operation(
        &self,
        operation_id: OperationId,
        resolution: OperationResolution,
    ) -> Result<OperationRecord, StateError> {
        self.queue()
            .call(move |db| db.reconcile_operation(operation_id, resolution))
            .await
    }

    pub async fn pending_external_operations(&self) -> Result<Vec<OperationRecord>, StateError> {
        self.queue().call(move |db| db.pending_external_operations()).await
    }

    // ---- global settings ----------------------------------------

    pub async fn set_settings(
        &self,
        scope_id: String,
        value: serde_json::Value,
        expected_revision: Option<u64>,
    ) -> Result<SettingsRow, StateError> {
        self.queue()
            .call(move |db| db.set_settings(None, &scope_id, &value, expected_revision))
            .await
    }

    pub async fn settings(&self, scope_id: String) -> Result<Option<SettingsRow>, StateError> {
        self.queue().call(move |db| db.settings(None, &scope_id)).await
    }

    // ---- lifetime -----------------------------------------------

    /// Checkpoints the WAL of every open database.
    pub async fn checkpoint(&self) -> Result<(), StateError> {
        self.queue().call(move |db: &mut Db| db.checkpoint()).await
    }

    /// Drains the queued commands, checkpoints the WAL of every open database,
    /// and stops the worker thread before returning.
    pub async fn close(mut self) -> Result<(), StateError> {
        self.worker.shutdown().await?;
        self.worker.join().await
    }
}

/// Account-scoped persistence. Clonable; every method queues one command on
/// the shared worker.
#[derive(Clone)]
pub struct AccountStore {
    account: AccountKey,
    queue: Queue,
}

impl AccountStore {
    pub fn account_key(&self) -> AccountKey {
        self.account
    }

    // ---- connections and baselines ------------------------------

    pub async fn get_connection(&self, connection_id: ConnectionId) -> Result<Option<ConnectionRecord>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.get_connection(account, connection_id)).await
    }

    pub async fn list_connections(&self) -> Result<Vec<ConnectionRecord>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.list_connections(account)).await
    }

    pub async fn set_connection_root(
        &self,
        connection_id: ConnectionId,
        root_path: PathBuf,
    ) -> Result<(), StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.set_connection_root(account, connection_id, Path::new(&root_path)))
            .await
    }

    pub async fn baseline(&self, connection_id: ConnectionId) -> Result<PublicationBaseline, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.baseline(account, connection_id)).await
    }

    /// Advances one publication baseline. `Applied` is refused while local
    /// actions are still pending.
    pub async fn set_baseline(
        &self,
        connection_id: ConnectionId,
        kind: BaselineKind,
        commit: Option<CommitId>,
    ) -> Result<PublicationBaseline, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.set_baseline(account, connection_id, kind, commit))
            .await
    }

    // ---- outbox -------------------------------------------------

    pub async fn record_outbox(&self, entry: OutboxEntry) -> Result<OutboxEntry, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.record_outbox(account, &entry)).await
    }

    pub async fn outbox_entry(
        &self,
        connection_id: ConnectionId,
        operation_id: OperationId,
    ) -> Result<Option<OutboxEntry>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.outbox_entry(account, connection_id, operation_id))
            .await
    }

    pub async fn list_outbox(
        &self,
        connection_id: ConnectionId,
        state: Option<OutboxState>,
        limit: u32,
    ) -> Result<Vec<OutboxEntry>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.list_outbox(account, connection_id, state, limit))
            .await
    }

    pub async fn work_counts(
        &self,
        connection_id: ConnectionId,
    ) -> Result<ConnectionWorkCounts, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.work_counts(account, connection_id)).await
    }

    pub async fn storage_counts(
        &self,
        connection_id: ConnectionId,
    ) -> Result<ConnectionStorageCounts, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.storage_counts(account, connection_id)).await
    }

    pub async fn transition_outbox(
        &self,
        connection_id: ConnectionId,
        operation_id: OperationId,
        transition: OutboxTransition,
    ) -> Result<OutboxEntry, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.transition_outbox(account, connection_id, operation_id, transition))
            .await
    }

    pub async fn complete_outbox(
        &self,
        connection_id: ConnectionId,
        operation_id: OperationId,
    ) -> Result<CompletionOutcome, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.complete_outbox(account, connection_id, operation_id))
            .await
    }

    // ---- snapshots ----------------------------------------------

    pub async fn begin_snapshot(
        &self,
        connection_id: ConnectionId,
        snapshot_id: SnapshotId,
        path: PathBuf,
    ) -> Result<SnapshotRecord, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.begin_snapshot(account, connection_id, snapshot_id, Path::new(&path)))
            .await
    }

    pub async fn complete_snapshot(
        &self,
        connection_id: ConnectionId,
        snapshot_id: SnapshotId,
        size: u64,
        sha256: Sha256Digest,
    ) -> Result<SnapshotRecord, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.complete_snapshot(account, connection_id, snapshot_id, size, sha256))
            .await
    }

    pub async fn set_snapshot_status(
        &self,
        connection_id: ConnectionId,
        snapshot_id: SnapshotId,
        status: SnapshotStatus,
    ) -> Result<SnapshotRecord, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.set_snapshot_status(account, connection_id, snapshot_id, status))
            .await
    }

    pub async fn snapshot(
        &self,
        connection_id: ConnectionId,
        snapshot_id: SnapshotId,
    ) -> Result<Option<SnapshotRecord>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.snapshot(account, connection_id, snapshot_id))
            .await
    }

    pub async fn list_snapshots(&self, connection_id: ConnectionId) -> Result<Vec<SnapshotRecord>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.list_snapshots(account, connection_id)).await
    }

    // ---- transfers ----------------------------------------------

    pub async fn record_transfer(&self, transfer: TransferRecord) -> Result<TransferRecord, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.record_transfer(account, &transfer)).await
    }

    pub async fn update_transfer(
        &self,
        connection_id: ConnectionId,
        transfer_id: TransferId,
        state: TransferState,
        logical_bytes: u64,
        wire_bytes: u64,
        sdk_resume_json: Option<serde_json::Value>,
    ) -> Result<TransferRecord, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| {
                db.update_transfer(
                    account,
                    connection_id,
                    transfer_id,
                    state,
                    logical_bytes,
                    wire_bytes,
                    sdk_resume_json.as_ref(),
                )
            })
            .await
    }

    pub async fn transfer(
        &self,
        connection_id: ConnectionId,
        transfer_id: TransferId,
    ) -> Result<Option<TransferRecord>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.transfer(account, connection_id, transfer_id))
            .await
    }

    // ---- commits and history ------------------------------------

    pub async fn record_commit(&self, commit: CommitRecord) -> Result<CommitRecord, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.record_commit(account, &commit)).await
    }

    pub async fn set_commit_status(
        &self,
        connection_id: ConnectionId,
        commit_id: CommitId,
        status: CommitStatus,
    ) -> Result<CommitRecord, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.set_commit_status(account, connection_id, commit_id, status))
            .await
    }

    pub async fn commit(
        &self,
        connection_id: ConnectionId,
        commit_id: CommitId,
    ) -> Result<Option<CommitRecord>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.commit(account, connection_id, commit_id)).await
    }

    /// Walks retained committed ancestry; resumable through `after`.
    pub async fn list_ancestry(
        &self,
        connection_id: ConnectionId,
        from: Option<CommitId>,
        after: Option<CommitId>,
        limit: u32,
    ) -> Result<Vec<CommitRecord>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.list_ancestry(account, connection_id, from, after, limit))
            .await
    }

    // ---- event cursors and scan safety --------------------------

    pub async fn init_event_cursor(
        &self,
        connection_id: ConnectionId,
        volume_id: String,
        journal_id: String,
    ) -> Result<ScanState, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.init_event_cursor(account, connection_id, &volume_id, &journal_id))
            .await
    }

    /// Durable HEAD invalidation; the invalidation lands before the cursor.
    pub async fn record_head_invalidation(
        &self,
        connection_id: ConnectionId,
        cursor: Option<String>,
    ) -> Result<ScanState, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.record_head_invalidation(account, connection_id, cursor.as_deref()))
            .await
    }

    pub async fn ack_head_refresh(&self, connection_id: ConnectionId) -> Result<ScanState, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.ack_head_refresh(account, connection_id)).await
    }

    pub async fn begin_scan(
        &self,
        connection_id: ConnectionId,
        volume_id: String,
        journal_id: String,
    ) -> Result<ScanState, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.begin_scan(account, connection_id, &volume_id, &journal_id))
            .await
    }

    pub async fn complete_scan(
        &self,
        connection_id: ConnectionId,
        usn_cursor: Option<u64>,
    ) -> Result<ScanState, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.complete_scan(account, connection_id, usn_cursor))
            .await
    }

    /// Overflow, reset, denial, or unavailable volume: deletion evidence is
    /// invalid until a fresh completed scan.
    pub async fn invalidate_scan(&self, connection_id: ConnectionId) -> Result<ScanState, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.invalidate_scan(account, connection_id)).await
    }

    pub async fn scan_state(&self, connection_id: ConnectionId) -> Result<Option<ScanState>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.scan_state(account, connection_id)).await
    }

    // ---- conflicts ----------------------------------------------

    pub async fn record_conflict(&self, conflict: ConflictRecord) -> Result<ConflictRecord, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.record_conflict(account, &conflict)).await
    }

    pub async fn resolve_conflict(
        &self,
        connection_id: ConnectionId,
        conflict_id: ConflictId,
        resolution: ConflictResolution,
    ) -> Result<ConflictRecord, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.resolve_conflict(account, connection_id, conflict_id, resolution))
            .await
    }

    pub async fn conflict(
        &self,
        connection_id: ConnectionId,
        conflict_id: ConflictId,
    ) -> Result<Option<ConflictRecord>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.conflict(account, connection_id, conflict_id))
            .await
    }

    pub async fn list_conflicts(&self, connection_id: ConnectionId) -> Result<Vec<ConflictRecord>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.list_conflicts(account, connection_id)).await
    }

    // ---- local actions ------------------------------------------

    pub async fn record_local_action(&self, action: LocalAction) -> Result<LocalAction, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.record_local_action(account, &action)).await
    }

    pub async fn set_local_action_state(
        &self,
        connection_id: ConnectionId,
        action_id: ActionId,
        state: LocalActionState,
    ) -> Result<LocalAction, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.set_local_action_state(account, connection_id, action_id, state))
            .await
    }

    pub async fn local_action(
        &self,
        connection_id: ConnectionId,
        action_id: ActionId,
    ) -> Result<Option<LocalAction>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.local_action(account, connection_id, action_id))
            .await
    }

    pub async fn list_local_actions(
        &self,
        connection_id: ConnectionId,
        state: Option<LocalActionState>,
    ) -> Result<Vec<LocalAction>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.list_local_actions(account, connection_id, state))
            .await
    }

    pub async fn pending_local_actions(&self, connection_id: ConnectionId) -> Result<Vec<LocalAction>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.pending_local_actions(account, connection_id))
            .await
    }

    // ---- observations -------------------------------------------

    /// Records a local observation: a new durable generation, dirty set.
    pub async fn bump_observation(
        &self,
        connection_id: ConnectionId,
        item_id: ItemId,
        observed_usn: Option<u64>,
    ) -> Result<LocalObservation, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.bump_observation(account, connection_id, item_id, observed_usn))
            .await
    }

    pub async fn set_observation_flags(
        &self,
        connection_id: ConnectionId,
        item_id: ItemId,
        flags: ObservationFlags,
    ) -> Result<LocalObservation, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.set_observation_flags(account, connection_id, item_id, flags))
            .await
    }

    pub async fn observation(
        &self,
        connection_id: ConnectionId,
        item_id: ItemId,
    ) -> Result<Option<LocalObservation>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.observation(account, connection_id, item_id))
            .await
    }

    // ---- common bases -------------------------------------------

    /// Stores the remembered base item record verbatim: `item_json` holds
    /// canonical format bytes and is never re-serialized by the state layer.
    pub async fn put_common_base(&self, record: CommonBaseRecord) -> Result<CommonBaseRecord, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.put_common_base(account, &record)).await
    }

    pub async fn get_common_base(
        &self,
        connection_id: ConnectionId,
        item_id: ItemId,
        commit_id: CommitId,
    ) -> Result<Option<CommonBaseRecord>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.get_common_base(account, connection_id, item_id, commit_id))
            .await
    }

    pub async fn list_common_bases(&self, connection_id: ConnectionId) -> Result<Vec<CommonBaseRecord>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.list_common_bases(account, connection_id)).await
    }

    // ---- items --------------------------------------------------

    pub async fn upsert_item(&self, item: ItemRecord) -> Result<ItemRecord, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.upsert_item(account, &item)).await
    }

    pub async fn excluded_observations(
        &self,
        connection_id: ConnectionId,
    ) -> Result<Vec<LocalObservation>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.excluded_observations(account, connection_id)).await
    }

    /// Complete connection traversal for maintenance operations such as
    /// preservation-proven unlink. Not used by health polling.
    pub async fn list_all_items(
        &self,
        connection_id: ConnectionId,
        include_deleted: bool,
    ) -> Result<Vec<ItemRecord>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.list_all_items(account, connection_id, include_deleted)).await
    }

    pub async fn item(
        &self,
        connection_id: ConnectionId,
        item_id: ItemId,
    ) -> Result<Option<ItemRecord>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.item(account, connection_id, item_id)).await
    }

    pub async fn list_children(
        &self,
        connection_id: ConnectionId,
        parent_id: Option<ItemId>,
        include_deleted: bool,
    ) -> Result<Vec<ItemRecord>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.list_children(account, connection_id, parent_id, include_deleted))
            .await
    }

    // ---- probe created-key journal ------------------------------

    /// Reserves the exact key a probe run may create, before any external
    /// create effect.
    pub async fn reserve_probe_key(&self, record: ProbeKeyRecord) -> Result<ProbeKeyRecord, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.reserve_probe_key(account, &record)).await
    }

    pub async fn set_probe_key_state(
        &self,
        connection_id: ConnectionId,
        run_id: GenerationId,
        key: String,
        state: ProbeKeyState,
    ) -> Result<ProbeKeyRecord, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.set_probe_key_state(account, connection_id, run_id, &key, state))
            .await
    }

    pub async fn probe_key(
        &self,
        connection_id: ConnectionId,
        run_id: GenerationId,
        key: String,
    ) -> Result<Option<ProbeKeyRecord>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.probe_key(account, connection_id, run_id, &key))
            .await
    }

    /// Every key reserved by exactly this run.
    pub async fn probe_keys(
        &self,
        connection_id: ConnectionId,
        run_id: GenerationId,
    ) -> Result<Vec<ProbeKeyRecord>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.probe_keys(account, connection_id, run_id))
            .await
    }

    /// The exact confirmed-created keys of this run: the only deletable set.
    pub async fn probe_cleanup_candidates(
        &self,
        connection_id: ConnectionId,
        run_id: GenerationId,
    ) -> Result<Vec<ProbeKeyRecord>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.probe_cleanup_candidates(account, connection_id, run_id))
            .await
    }

    // ---- settings and retention ---------------------------------

    pub async fn set_settings(
        &self,
        scope_id: String,
        value: serde_json::Value,
        expected_revision: Option<u64>,
    ) -> Result<SettingsRow, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.set_settings(Some(account), &scope_id, &value, expected_revision))
            .await
    }

    pub async fn settings(&self, scope_id: String) -> Result<Option<SettingsRow>, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue.call(move |db| db.settings(Some(account), &scope_id)).await
    }

    /// Read-only retained reference accounting; no deletion method exists.
    pub async fn retention_snapshot(&self, connection_id: ConnectionId) -> Result<RetentionSnapshot, StateError> {
        let (account, queue) = (self.account, self.queue.clone());
        queue
            .call(move |db| db.retention_snapshot(account, connection_id))
            .await
    }
}

// Convenience constructors used by tests and callers.
impl ProbeKeyRecord {
    pub fn reserved(run_id: GenerationId, connection_id: ConnectionId, setup_id: Option<SetupId>, key: String) -> Self {
        Self { run_id, connection_id, setup_id, key, state: ProbeKeyState::Reserved }
    }
}

impl OutboxEntry {
    /// A new durable intent, starting at `Observed`.
    pub fn observed(
        connection_id: ConnectionId,
        operation_id: OperationId,
        item_id: Option<ItemId>,
        observed_generation: u64,
        intent_json: serde_json::Value,
    ) -> Self {
        Self {
            connection_id,
            operation_id,
            item_id,
            base_commit: None,
            base_json: None,
            observed_generation,
            intent_json,
            state: OutboxState::Observed,
            snapshot_id: None,
            object_ref: None,
            candidate_commit: None,
            candidate_head_json: None,
            expected_etag: None,
            retry_class: RetryClass::None,
            next_attempt_at_ms: None,
        }
    }
}
