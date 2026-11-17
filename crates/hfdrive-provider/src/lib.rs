use hfdrive_auth::AuthManager;
use hfdrive_core::ids::{AccountKey, ConnectionId};
use hfdrive_protocol::{
    AuthenticationState, Envelope, Event, ExitProviderResult, GetStatusResult, HelloRequest,
    HelloResult, ProtocolError, ProtocolErrorCode, Request, ResponseResult, StatusChangedEvent,
    StatusSnapshot,
};
use hfdrive_state::{StatePaths, StateStore};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc, watch};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

mod account;
mod account_runtime;
mod activity;
mod conflicts;
mod connect;
mod controls;
mod diagnostics;
mod history;
mod import;
mod import_menu;
mod inspect;
mod operations;
mod probe;
mod repair;
mod requests;
pub mod scheduler;
pub mod remote_watch;
mod session;
mod settings;
mod setup;
mod status;
mod storage;
pub mod sync;
mod tokens;
use operations::{AfterReply, DispatchReply, Operations, error, internal};
use tokens::DurableTokens;
pub use requests::MAX_CLIENTS;
pub use session::serve;

pub(crate) struct OutgoingEnvelope {
    envelope: Envelope,
    after: AfterReply,
}

impl OutgoingEnvelope {
    fn new(envelope: Envelope) -> Self {
        Self { envelope, after: AfterReply::default() }
    }
}

/// How an account-runtime failure changes the published session state.
pub(crate) enum AccountFailure {
    /// The token epoch is gone: the session needs a new interactive grant.
    SignInRequired,
    /// The session is intact; only its restoration failed.
    Restore,
}

pub struct Provider {
    pub shutdown: CancellationToken,
    #[cfg(any(test, feature = "provider-test-support"))]
    pub state: Arc<StateStore>,
    #[cfg(not(any(test, feature = "provider-test-support")))]
    state: Arc<StateStore>,
    paths: StatePaths,
    auth: AuthManager,
    tokens: Arc<DurableTokens>,
    operations: Arc<Operations>,
    pub(crate) scheduler: scheduler::Scheduler,
    engine: Option<Arc<sync::SyncEngine<sync::remote::LiveRemote<tokens::DurableTokens, hfdrive_publication::S3Transport>>>>,
    user_sid: String,
    device_id: hfdrive_core::ids::DeviceId,
    account_revision: Mutex<u64>,
    engine_account: Mutex<Option<AccountKey>>,
    status: watch::Sender<StatusSnapshot>,
}

impl Provider {
    /// Open preserved state before accepting IPC. A corrupt or foreign database is never replaced.
    pub async fn open(paths: StatePaths, user_sid: String) -> Result<Arc<Self>, hfdrive_state::StateError> {
        let auth = AuthManager::new(
            hfdrive_auth::AuthConfig::production(),
            paths.base().to_path_buf(),
            None,
        );
        Self::open_with_auth(paths, user_sid, auth).await
    }

    async fn open_with_auth(
        paths: StatePaths,
        user_sid: String,
        auth: AuthManager,
    ) -> Result<Arc<Self>, hfdrive_state::StateError> {
        let engine_state_dir = paths.base().to_path_buf();
        let state = Arc::new(StateStore::open(paths.clone()).await?);
        let selected = state.selected_account().await?;
        state.reconcile_connections().await?;
        if user_sid.is_empty() { return Err(hfdrive_state::StateError::WorkerStopped); }
        let device_id = match state.settings("device_id".to_owned()).await? {
            Some(row) => serde_json::from_value::<String>(row.value_json)
                .ok()
                .and_then(|text| text.parse::<hfdrive_core::ids::DeviceId>().ok())
                .ok_or_else(|| hfdrive_state::StateError::Corrupt {
                    detail: "settings device_id is not a valid nonzero device UUID".to_owned(),
                })?,
            None => {
                let device_id = hfdrive_core::ids::DeviceId::new();
                state.set_settings(
                    "device_id".to_owned(),
                    serde_json::Value::String(device_id.to_string()),
                    None,
                ).await?;
                device_id
            }
        };
        // K11: startup honors the persisted account status. An account whose
        // durable status recorded a rejected credential (`NeedsSignIn`) is
        // restored for display/recovery only and is never reactivated into a
        // usable token epoch — its envelope is preserved but its bearer and
        // refresh secrets are dropped and the authorization epoch stays
        // disabled. Any other status (including an absent record) restores
        // normally; restore failure stays non-fatal and surfaces as the
        // sign-in-required state below. The retained selection survives for
        // display/recovery either way.
        if let Some(selected_account) = selected {
            let rejected = state
                .get_account(selected_account)
                .await?
                .is_some_and(|record| record.status == hfdrive_state::AccountStatus::NeedsSignIn);
            let _ = if rejected {
                auth.restore_rejected_account(selected_account)
            } else {
                auth.restore_account(selected_account)
            };
        }
        let tokens = Arc::new(DurableTokens::new(auth.clone()));
        let (status, _) = watch::channel(StatusSnapshot {
            sequence: 0,
            account: account::status(&auth.snapshot()).unwrap_or_default(),
            connections: Vec::new(),
        });
        let shutdown = CancellationToken::new();
        let scheduler = scheduler::Scheduler::new(Default::default());
        let global_settings = match state.settings("global".to_owned()).await? {
            Some(row) => row.value_json,
            None => {
                let value = settings::default_global_settings();
                state.set_settings("global".to_owned(), value.clone(), None).await?;
                value
            }
        };
        settings::apply_global_settings(&scheduler, &global_settings)
            .map_err(|detail| hfdrive_state::StateError::Corrupt { detail: detail.to_owned() })?;
        let engine = Arc::new(sync::SyncEngine::new(
            sync::EngineConfig {
                state_dir: engine_state_dir,
                user_sid: user_sid.clone(),
                device_id,
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            state.clone(),
            Arc::new(scheduler.clone()),
            shutdown.child_token(),
        ));
        let provider = Arc::new(Self {
            shutdown,
            state,
            paths,
            auth,
            tokens,
            operations: Arc::new(Operations::new()),
            scheduler,
            account_revision: Mutex::new(0),
            engine_account: Mutex::new(None),
            status,
            engine: Some(engine),
            user_sid,
            device_id,
        });
        // A selected credential envelope does not establish a usable token epoch until
        // its public identity and account binding have been persisted in this provider.
        // Root restoration runs in observe_accounts after the host binds IPC;
        // network or inaccessible storage must not block Hello/GetStatus.
        if let Err(error) = provider.synchronize_account().await {
            let _ = provider.publish_account_error(AccountFailure::SignInRequired, error);
        }
        Ok(provider)
    }

    #[cfg(any(test, feature = "provider-test-support"))]
    pub fn new(initial_status: StatusSnapshot) -> Self {
        let directory = tempfile::tempdir().expect("test state");
        Self::open_for_test(directory, initial_status)
    }

    #[cfg(any(test, feature = "provider-test-support"))]
    fn open_for_test(directory: tempfile::TempDir, initial_status: StatusSnapshot) -> Self {
        let paths = StatePaths::new(directory.keep());
        // The state worker runs on its own OS thread, so its open future does
        // not need a Tokio reactor or `block_in_place` (which panics on the
        // current-thread test runtime). Poll it directly until the worker
        // answers; no additional async-runtime feature is required.
        let mut open = std::pin::pin!(StateStore::open(paths.clone()));
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        let state = loop {
            match open.as_mut().poll(&mut context) {
                std::task::Poll::Ready(result) => break result.expect("test state database"),
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        };
        let auth = AuthManager::new(hfdrive_auth::AuthConfig::default(), paths.base().to_path_buf(), None);
        let tokens = Arc::new(DurableTokens::new(auth.clone()));
        let (status, _) = watch::channel(initial_status);
        Self {
            shutdown: CancellationToken::new(), state: Arc::new(state), paths, auth, tokens,
            operations: Arc::new(Operations::new()), scheduler: scheduler::Scheduler::new(Default::default()), account_revision: Mutex::new(0),
            engine_account: Mutex::new(None),
            status,
            engine: None,
            user_sid: "test-user".to_owned(),
            device_id: hfdrive_core::ids::DeviceId::new(),
        }
    }

    pub async fn drain(&self) -> Result<(), sync::EngineError> {
        self.operations.cancellation.cancel();
        let result = match &self.engine {
            Some(engine) => engine.drain().await,
            None => Ok(()),
        };
        self.operations.drain().await;
        result
    }

    fn hello(&self, _request: HelloRequest) -> ResponseResult {
        ResponseResult::Hello(HelloResult {
            protocol_major: 1,
            protocol_minor: 0,
            provider_version: env!("CARGO_PKG_VERSION").to_owned(),
            supported_features: ["get_status", "subscribe_status", "cancel_request", "start_login", "cancel_login", "sign_out", "list_owners", "list_buckets", "create_bucket", "inspect_drive", "list_conflicts", "resolve_conflict", "list_history", "restore", "begin_setup", "set_publication_credentials", "preview_connect", "connect", "probe_storage", "repair_storage", "pause", "resume", "set_pin", "free_space", "set_selective_sync", "export_diagnostics", "prepare_unlink", "unlink", "update_settings", "list_activity", "prepare_upgrade", "exit_provider", "import"]
                .into_iter().map(str::to_owned).collect(),
            supported_min_protocol_minor: 0,
        })
    }

    fn subscribe(&self) -> (StatusSnapshot, watch::Receiver<StatusSnapshot>) {
        let mut receiver = self.status.subscribe();
        let snapshot = receiver.borrow_and_update().clone();
        (snapshot, receiver)
    }

    /// The one account-status error publication boundary, shared by startup and
    /// the account observer. It publishes through the same watch/sequence path
    /// as every other account status change — never a parallel status writer —
    /// and never holds a watch read guard across the write.
    ///
    /// [`AccountFailure::SignInRequired`] marks the session as needing a new
    /// interactive grant because its token epoch is gone; [`AccountFailure::Restore`]
    /// only annotates a session that remains intact. Both preserve the projected
    /// account profile and the retained connection records.
    pub(crate) fn publish_account_error(
        &self,
        failure: AccountFailure,
        error: ProtocolError,
    ) -> Result<(), ProtocolError> {
        let mut account = self.status.borrow().account.clone();
        if matches!(failure, AccountFailure::SignInRequired) {
            account.state = AuthenticationState::NeedsSignIn;
        }
        account.last_error = Some(error);
        self.publish_account(account)
    }

    async fn dispatch(self: &Arc<Self>, request: Request, cancellation: CancellationToken) -> DispatchReply {
        if cancellation.is_cancelled() {
            return Err(error(ProtocolErrorCode::Cancelled, "Request cancelled")).into();
        }
        match request {
            Request::GetStatus(_) => {
                let connections = match self.connection_statuses().await {
                    Ok(connections) => connections,
                    Err(error) => return Err(error).into(),
                };
                let status = self.status.borrow();
                Ok(ResponseResult::GetStatus(GetStatusResult {
                    event_sequence: status.sequence,
                    account: status.account.clone(),
                    connections,
                })).into()
            }
            Request::ListOwners(request) => self.list_owners(request).await.map(ResponseResult::ListOwners).into(),
            Request::ListBuckets(request) => self.list_buckets(request).await.map(ResponseResult::ListBuckets).into(),
            Request::InspectDrive(request) => self.inspect_drive(request).await.map(ResponseResult::InspectDrive).into(),
            Request::ListConflicts(request) => self.list_conflicts(request).await.map(ResponseResult::ListConflicts).into(),
            Request::ListActivity(request) => self.list_activity(request).await.map(ResponseResult::ListActivity).into(),
            Request::ListHistory(request) => self.list_history(request).await.map(ResponseResult::ListHistory).into(),
            request => self.dispatch_mutation(request, cancellation).await,
        }
    }

    async fn execute_mutation_action(self: &Arc<Self>, request: Request) -> operations::MutationOutcome {
        match request {
            Request::Import(request) => {
                let outcome = self.import(request).await;
                let uncertain = self.operations.cancellation.is_cancelled()
                    || outcome.as_ref().is_err_and(|error| matches!(error.code,
                        ProtocolErrorCode::Cancelled | ProtocolErrorCode::Timeout | ProtocolErrorCode::Internal));
                operations::MutationOutcome {
                    reply: outcome.map(ResponseResult::Import).into(), uncertain,
                }
            }
            Request::StartLogin(request) => self.start_login(request).await.map(ResponseResult::StartLogin).into(),
            Request::CancelLogin(request) => self.cancel_login(request.session_id).await.map(ResponseResult::CancelLogin).into(),
            Request::SignOut(_) => self.sign_out().await.map(ResponseResult::SignOut).into(),
            Request::CreateBucket(request) => {
                let outcome = self.create_bucket(request).await;
                let uncertain = self.operations.cancellation.is_cancelled()
                    || outcome.as_ref().is_err_and(|error| matches!(error.code,
                        ProtocolErrorCode::Cancelled | ProtocolErrorCode::Timeout | ProtocolErrorCode::Internal));
                operations::MutationOutcome {
                    reply: outcome.map(ResponseResult::CreateBucket).into(), uncertain,
                }
            }
            Request::BeginSetup(request) => self.begin_setup(request).await.map(ResponseResult::BeginSetup).into(),
            Request::SetPublicationCredentials(request) => self.set_publication_credentials(request).await.map(ResponseResult::SetPublicationCredentials).into(),
            Request::PreviewConnect(request) => self.preview_connect(request).await.map(ResponseResult::PreviewConnect).into(),
            Request::Connect(request) => {
                let outcome = self.connect(request).await;
                let uncertain = self.operations.cancellation.is_cancelled()
                    || outcome.as_ref().is_err_and(|error| matches!(error.code,
                        ProtocolErrorCode::Cancelled | ProtocolErrorCode::Timeout | ProtocolErrorCode::Internal));
                operations::MutationOutcome {
                    reply: outcome.map(ResponseResult::Connect).into(),
                    uncertain,
                }
            }
            Request::ProbeStorage(request) => {
                let outcome = self.probe_storage(request).await;
                let uncertain = self.operations.cancellation.is_cancelled()
                    || outcome.as_ref().is_err_and(|error| matches!(error.code,
                        ProtocolErrorCode::Cancelled | ProtocolErrorCode::Timeout | ProtocolErrorCode::Internal));
                operations::MutationOutcome {
                    reply: outcome.map(ResponseResult::ProbeStorage).into(),
                    uncertain,
                }
            }
            Request::RepairStorage(request) => {
                let outcome = self.repair_storage(request).await;
                let uncertain = self.operations.cancellation.is_cancelled()
                    || outcome.as_ref().is_err_and(|error| matches!(error.code,
                        ProtocolErrorCode::Cancelled | ProtocolErrorCode::Timeout | ProtocolErrorCode::Internal));
                operations::MutationOutcome {
                    reply: outcome.map(ResponseResult::RepairStorage).into(),
                    uncertain,
                }
            }
            Request::Pause(request) => self.set_connections_paused(request.connection_id, true).await
                .map(|paused_connection_ids| ResponseResult::Pause(hfdrive_protocol::PauseResult { paused_connection_ids })).into(),
            Request::Resume(request) => self.set_connections_paused(request.connection_id, false).await
                .map(|resumed_connection_ids| ResponseResult::Resume(hfdrive_protocol::ResumeResult { resumed_connection_ids })).into(),
            Request::SetPin(request) => self.set_pin(request).await.map(ResponseResult::SetPin).into(),
            Request::FreeSpace(request) => self.free_space(request).await.map(ResponseResult::FreeSpace).into(),
            Request::SetSelectiveSync(request) => self.set_selective_sync(request).await.map(ResponseResult::SetSelectiveSync).into(),
            Request::ExportDiagnostics(request) => self.export_diagnostics(request).await.map(ResponseResult::ExportDiagnostics).into(),
            Request::PrepareUnlink(request) => self.prepare_unlink(request).await.map(ResponseResult::PrepareUnlink).into(),
            Request::Unlink(request) => {
                let outcome = self.unlink(request).await;
                let uncertain = self.operations.cancellation.is_cancelled()
                    || outcome.as_ref().is_err_and(|error| matches!(error.code,
                        ProtocolErrorCode::Cancelled | ProtocolErrorCode::Timeout | ProtocolErrorCode::Internal));
                operations::MutationOutcome {
                    reply: outcome.map(ResponseResult::Unlink).into(),
                    uncertain,
                }
            }
            Request::UpdateSettings(request) => self.update_settings(request).await.map(ResponseResult::UpdateSettings).into(),
            Request::Restore(request) => {
                let outcome = self.restore(request).await;
                let uncertain = self.operations.cancellation.is_cancelled()
                    || outcome.as_ref().is_err_and(|error| matches!(error.code,
                        ProtocolErrorCode::Cancelled | ProtocolErrorCode::Timeout | ProtocolErrorCode::Internal));
                operations::MutationOutcome {
                    reply: outcome.map(ResponseResult::Restore).into(),
                    uncertain,
                }
            }
            Request::ResolveConflict(request) => {
                let outcome = self.resolve_conflict(request).await;
                let uncertain = self.operations.cancellation.is_cancelled()
                    || outcome.as_ref().is_err_and(|error| matches!(error.code,
                        ProtocolErrorCode::Cancelled | ProtocolErrorCode::Timeout | ProtocolErrorCode::Internal));
                operations::MutationOutcome {
                    reply: outcome.map(ResponseResult::ResolveConflict).into(),
                    uncertain,
                }
            }
            Request::PrepareUpgrade(_) => self.prepare_upgrade(false).await.into(),
            Request::ExitProvider(_) => self.prepare_upgrade(true).await.into(),
            _ => Err(ProtocolError {
                code: ProtocolErrorCode::UnsupportedProtocol,
                message: "Requested provider operation is not advertised".into(), retry_after_ms: None,
            }).into(),
        }
    }

    async fn operation_scope(&self, request: &Request) -> Result<(Option<AccountKey>, Option<ConnectionId>), ProtocolError> {
        fn connection(id: Uuid) -> Result<ConnectionId, ProtocolError> {
            ConnectionId::from_uuid(id).map_err(|_| error(ProtocolErrorCode::InvalidRequest, "A nonzero connection identifier is required"))
        }
        match request {
            Request::StartLogin(_)
            | Request::CancelLogin(_)
            | Request::SignOut(_)
            | Request::UpdateSettings(_)
            | Request::PrepareUpgrade(_)
            | Request::ExitProvider(_) => Ok((None, None)),
            _ => {
                let account = self.auth.active_profile().ok_or_else(|| error(ProtocolErrorCode::NeedsSignIn, "An authenticated account is required"))?.account_key;
                let id = match request {
                    Request::Import(_) => None,
                    Request::SetPublicationCredentials(r) => Some(connection(r.connection_id)?),
                    Request::ProbeStorage(r) => Some(connection(r.connection_id)?),
                    Request::RepairStorage(r) => Some(connection(r.connection_id)?),
                    Request::PreviewConnect(r) => Some(connection(r.connection_id)?),
                    Request::Pause(r) => r.connection_id.map(&connection).transpose()?,
                    Request::Resume(r) => r.connection_id.map(&connection).transpose()?,
                    Request::SetPin(r) => Some(connection(r.connection_id)?),
                    Request::FreeSpace(r) => Some(connection(r.connection_id)?),
                    Request::SetSelectiveSync(r) => Some(connection(r.connection_id)?),
                    Request::Restore(r) => Some(connection(r.connection_id)?),
                    Request::ResolveConflict(r) => Some(connection(r.connection_id)?),
                    Request::ExportDiagnostics(r) => r.connection_id.map(&connection).transpose()?,
                    Request::PrepareUnlink(r) => Some(connection(r.connection_id)?),
                    Request::Unlink(r) => Some(connection(r.connection_id)?),
                    _ => None,
                };
                Ok((Some(account), id))
            }
        }
    }

    async fn prepare_upgrade(self: &Arc<Self>, exit: bool) -> operations::MutationOutcome {
        self.operations.cancellation.cancel();
        if self.tokens.clear().is_err() { return Err(internal()).into(); }
        if let Err(error) = self.operations.quiesce_from_mutation().await { return Err(error).into(); }
        let checkpointed = if let Some(engine) = &self.engine {
            match engine.drain().await {
                Ok(()) => true,
                Err(_) => return operations::MutationOutcome { reply: Err(internal()).into(), uncertain: true },
            }
        } else {
            match self.state.checkpoint().await {
                Ok(()) => true,
                Err(error) => return operations::MutationOutcome { reply: Err(operations::state_error(error)).into(), uncertain: true },
            }
        };
        let pending = match self.state.pending_external_operations().await {
            Ok(records) => match u32::try_from(records.len()) { Ok(value) => value, Err(_) => return Err(internal()).into() },
            Err(error) => return operations::MutationOutcome { reply: Err(operations::state_error(error)).into(), uncertain: true },
        };
        if exit {
            operations::MutationOutcome {
                reply: DispatchReply {
                    result: Ok(ResponseResult::ExitProvider(ExitProviderResult { accepted: true })),
                    after: AfterReply::shutdown(self.shutdown.clone()),
                },
                uncertain: false,
            }
        } else {
            DispatchReply {
                result: Ok(ResponseResult::PrepareUpgrade(hfdrive_protocol::PrepareUpgradeResult {
                    checkpointed, pending_operations: pending,
                })),
                after: AfterReply::shutdown(self.shutdown.clone()),
            }.into()
        }
    }
}

async fn stream_status(
    mut receiver: watch::Receiver<StatusSnapshot>,
    cancellation: CancellationToken,
    outgoing: mpsc::Sender<OutgoingEnvelope>,
) {
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            changed = receiver.changed() => if changed.is_err() { break; },
        }
        let snapshot = receiver.borrow_and_update().clone();
        // A coalesced watch update is always a complete snapshot: skipped revisions
        // cannot be mistaken for a complete stream of deltas.
        let event = Envelope::event(Uuid::new_v4(), Event::StatusChanged(StatusChangedEvent {
            sequence: snapshot.sequence,
            snapshot: true,
            account: snapshot.account,
            changes: snapshot.connections,
            removed_connection_ids: Vec::new(),
        }));
        tokio::select! {
            _ = cancellation.cancelled() => break,
            sent = outgoing.send(OutgoingEnvelope::new(event)) => if sent.is_err() { break; },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hfdrive_protocol::{
        AccountProfile, AccountStatus, Body, Bucket, CapabilityState, ConnectionMode,
        ConnectionState, ConnectionStatus, GetStatusRequest, HydrationState, Owner, OwnerKind,
        PinState, Visibility,
    };

    mod selective_sync_dispatch {
        use super::*;
        use hfdrive_core::{
            format::{ItemKind, ItemRecord},
            ids::{CommitId, ItemId, OperationId, VersionId},
            reconcile::{CatalogView, ItemState, ReconcileMode},
            storage::Sha256Digest,
        };
        use hfdrive_state::{ObservationFlags, OperationState};
        use std::collections::{BTreeSet, HashMap};

        type LiveRuntime = sync::controller::ConnectionRuntime<
            sync::remote::LiveRemote<DurableTokens, hfdrive_publication::S3Transport>,
        >;

        struct Fixture {
            _directory: tempfile::TempDir,
            provider: Arc<Provider>,
            runtime: Arc<LiveRuntime>,
            account: hfdrive_state::AccountStore,
            connection: ConnectionId,
            workspace: hfdrive_core::ids::WorkspaceId,
            root: std::path::PathBuf,
            records: Vec<ItemRecord>,
            commit: CommitId,
            selected: ItemId,
            nested: ItemId,
            leaf: ItemId,
            other: ItemId,
        }

        impl Fixture {
            async fn new() -> Self {
                let fixture = sync::test_support::connection_fixture().await;
                let paths = StatePaths::new(fixture.directory.path().join("state"));
                let key = fixture.account.account_key();
                let mut envelope = rejected_envelope("sync-fixture");
                envelope.namespace = "test-user".to_owned();
                envelope.access_token = "selective-sync-fixture-not-a-live-token".to_owned();
                envelope.refresh_token = None;
                hfdrive_auth::AccountCredentialStore::open(paths.account(key).credentials(), key)
                    .unwrap().save(&envelope).unwrap();
                fixture.state.select_account(key).await.unwrap();
                fixture.state.close().await.unwrap();
                let provider = Provider::open(paths, "S-1-5-21-fixture".to_owned()).await.unwrap();
                let account = provider.state.open_account(key).await.unwrap();
                let [selected, nested, leaf, other] = std::array::from_fn(|_| ItemId::new());
                let revision = OperationId::new();
                let root = ItemRecord {
                    item_id: fixture.root_item, parent_id: None, name: String::new(),
                    kind: ItemKind::Directory, item_revision: revision, content_version_id: None,
                    deleted: false, content_operation: revision, location_operation: revision,
                    deletion_operation: None,
                };
                let records = vec![
                    root.clone(),
                    ItemRecord { item_id: selected, parent_id: Some(fixture.root_item), name: "selected".to_owned(), ..root.clone() },
                    ItemRecord { item_id: nested, parent_id: Some(selected), name: "nested".to_owned(), ..root.clone() },
                    ItemRecord {
                        item_id: leaf, parent_id: Some(nested), name: "leaf.txt".to_owned(),
                        kind: ItemKind::File, content_version_id: Some(VersionId::new()), ..root.clone()
                    },
                    ItemRecord { item_id: other, parent_id: Some(fixture.root_item), name: "other".to_owned(), ..root },
                ];
                for item in &records {
                    let content = item.content_version_id.map(|_| (Sha256Digest::of(b"committed"), 9));
                    account.upsert_item(sync::plan::registry_item(
                        fixture.connection, item, content.map(|(digest, _)| digest),
                        content.map(|(_, size)| size), None,
                    )).await.unwrap();
                    account.bump_observation(fixture.connection, item.item_id, Some(91)).await.unwrap();
                    account.set_observation_flags(fixture.connection, item.item_id, ObservationFlags {
                        dirty: Some(false), ..Default::default()
                    }).await.unwrap();
                }
                let commit = CommitId::new();
                sync::plan::record_common_bases(&account, fixture.connection, commit, &records).await.unwrap();
                account.set_baseline(fixture.connection, hfdrive_state::BaselineKind::Applied, Some(commit)).await.unwrap();
                let record = provider.state.reconcile_connections().await.unwrap().into_iter()
                    .find(|record| record.connection_id == fixture.connection).unwrap();
                // Construction only: the runtime stays paused, with no CFAPI
                // registration, observer or remote task. Dispatch and state are real.
                let remote = provider.remote_for(&record, &provider.current_account().unwrap()).unwrap();
                let cancel = provider.shutdown.child_token();
                let (_notifications, receiver) = mpsc::channel(1);
                let runtime = sync::controller::ConnectionRuntime::start(
                    sync::controller::ConnectionConfig {
                        connection_id: fixture.connection, workspace: fixture.workspace,
                        root_item_id: fixture.root_item, device_id: provider.device_id,
                        root: fixture.root.clone(), staging_dir: fixture.directory.path().join("snapshots"),
                        recovery_dir: fixture.directory.path().join("recovery"),
                        mode: hfdrive_state::ConnectionMode::Writable, start_paused: true,
                    },
                    account.clone(), remote, Arc::new(provider.scheduler.clone()),
                    Arc::new(sync::activity::ActivityRegistry::new()), cancel.clone(), receiver,
                );
                provider.engine.as_ref().unwrap().insert_runtime_for_test(runtime.clone(), cancel).await;
                Self {
                    _directory: fixture.directory, provider, runtime, account,
                    connection: fixture.connection, workspace: fixture.workspace, root: fixture.root,
                    records, commit, selected, nested, leaf, other,
                }
            }

            fn request(&self, roots: &[ItemId]) -> Request {
                Request::SetSelectiveSync(hfdrive_protocol::SetSelectiveSyncRequest {
                    operation_id: Uuid::new_v4(), connection_id: *self.connection.as_uuid(),
                    exclude_item_ids: roots.iter().map(|item| *item.as_uuid()).collect(),
                })
            }

            async fn apply(&self, roots: &[ItemId]) -> hfdrive_protocol::SetSelectiveSyncResult {
                let reply = self.provider.dispatch(self.request(roots), CancellationToken::new()).await;
                let ResponseResult::SetSelectiveSync(result) = reply.result.unwrap() else {
                    panic!("selective sync result");
                };
                assert!(result.retained_dirty_item_ids.is_empty());
                result
            }

            async fn observation(&self, item: ItemId) -> hfdrive_state::LocalObservation {
                self.account.observation(self.connection, item).await.unwrap().unwrap()
            }

            async fn close(self) {
                self.provider.drain().await.unwrap();
                let Fixture { _directory, provider, runtime, account, .. } = self;
                drop(runtime);
                drop(account);
                drop(provider);
                _directory.close().unwrap();
            }
        }

        #[tokio::test]
        async fn selective_sync_dispatch_refuses_dirty_and_pinned_descendants_durably() {
            for pinned in [false, true] {
                let fixture = Fixture::new().await;
                let guarded = fixture.account.set_observation_flags(fixture.connection, fixture.leaf, ObservationFlags {
                    dirty: Some(!pinned), pin_requested: Some(pinned), ..Default::default()
                }).await.unwrap();
                let request = fixture.request(&[fixture.selected]);
                let operation = OperationId::from_uuid(request.operation_id().unwrap()).unwrap();
                let reply = fixture.provider.dispatch(request.clone(), CancellationToken::new()).await;
                assert_eq!(reply.result.unwrap_err().code, ProtocolErrorCode::Conflict);
                assert_eq!(fixture.observation(fixture.leaf).await, guarded);
                assert!(fixture.account.excluded_observations(fixture.connection).await.unwrap().is_empty());
                let receipt = fixture.provider.state.get_operation(operation).await.unwrap().unwrap();
                assert_eq!(receipt.state, OperationState::Failed);
                assert_eq!(receipt.error_code.as_deref(), Some(ProtocolErrorCode::Conflict.wire()));
                fixture.account.set_observation_flags(fixture.connection, fixture.leaf, ObservationFlags {
                    dirty: Some(false), pin_requested: Some(false), ..Default::default()
                }).await.unwrap();
                let replay = fixture.provider.dispatch(request, CancellationToken::new()).await;
                assert_eq!(replay.result.unwrap_err().code, ProtocolErrorCode::Conflict);
                assert!(fixture.account.excluded_observations(fixture.connection).await.unwrap().is_empty());
                assert!(fixture.account.list_outbox(fixture.connection, None, 100).await.unwrap().is_empty());
                fixture.close().await;
            }
        }

        #[tokio::test]
        async fn selective_sync_dispatch_reincludes_only_removed_subtrees_and_validates_before_mutation() {
            let fixture = Fixture::new().await;
            let excluded = fixture.apply(&[fixture.selected, fixture.other]).await;
            assert_eq!(
                excluded.excluded_item_ids.into_iter().collect::<BTreeSet<_>>(),
                [fixture.selected, fixture.nested, fixture.leaf, fixture.other].map(|id| *id.as_uuid()).into_iter().collect(),
            );
            let retained = fixture.observation(fixture.leaf).await;
            let other = fixture.observation(fixture.other).await;
            fixture.apply(&[fixture.selected, fixture.nested, fixture.other, fixture.selected]).await;
            assert_eq!(fixture.observation(fixture.leaf).await, retained, "retained descendants must not be toggled through inclusion");
            fixture.apply(&[fixture.nested, fixture.other]).await;
            assert!(!fixture.observation(fixture.selected).await.excluded);
            for item in [fixture.nested, fixture.leaf] {
                let observation = fixture.observation(item).await;
                assert!(observation.excluded);
                assert_eq!(observation.generation, 0);
                assert_eq!(observation.observed_usn, None);
            }
            assert_eq!(fixture.observation(fixture.other).await, other, "independent retained roots keep their evidence");
            fixture.apply(&[fixture.other]).await;
            for item in [fixture.selected, fixture.nested, fixture.leaf] {
                let observation = fixture.observation(item).await;
                assert!(!observation.excluded);
                assert_eq!(observation.generation, 0);
                assert_eq!(observation.observed_usn, None);
            }
            for (id, code) in [
                (Uuid::nil(), ProtocolErrorCode::InvalidRequest),
                (Uuid::new_v4(), ProtocolErrorCode::NotFound),
            ] {
                let request = Request::SetSelectiveSync(hfdrive_protocol::SetSelectiveSyncRequest {
                    operation_id: Uuid::new_v4(), connection_id: *fixture.connection.as_uuid(),
                    exclude_item_ids: vec![id],
                });
                let reply = fixture.provider.dispatch(request, CancellationToken::new()).await;
                assert_eq!(reply.result.unwrap_err().code, code);
                assert_eq!(fixture.observation(fixture.other).await, other);
            }
            assert!(fixture.account.list_outbox(fixture.connection, None, 100).await.unwrap().is_empty());
            fixture.close().await;
        }

        #[tokio::test]
        async fn selective_sync_dispatch_absence_materializes_after_reinclusion_never_deletes() {
            use sync::observe::{ObservationBatch, RawObservation};
            use hfdrive_windows::filesystem::WatchAction;
            let fixture = Fixture::new().await;
            let sealed = fixture.account.list_common_bases(fixture.connection, fixture.commit).await.unwrap();
            fixture.apply(&[fixture.selected, fixture.other]).await;
            fixture.account.begin_scan(fixture.connection, "fixture-volume".to_owned(), "fixture-journal".to_owned()).await.unwrap();
            fixture.account.complete_scan(fixture.connection, None).await.unwrap();
            fixture.runtime.ingest_observations(ObservationBatch {
                observations: ["selected", "selected/nested", "selected/nested/leaf.txt", "other"]
                    .into_iter().map(|path| RawObservation {
                        relative_path: path.into(), action: WatchAction::Removed,
                    }).collect(),
                rescan_required: false,
            }).await.unwrap();
            assert!(fixture.account.scan_state(fixture.connection).await.unwrap().unwrap().may_infer_deletion());
            assert!(fixture.account.list_outbox(fixture.connection, None, 100).await.unwrap().is_empty());
            assert!(sync::plan::missing_materializations(&fixture.account, fixture.connection, &fixture.root).await.unwrap().is_empty());

            let included = fixture.apply(&[]).await;
            assert!(included.excluded_item_ids.is_empty());
            let missing = sync::plan::missing_materializations(&fixture.account, fixture.connection, &fixture.root).await.unwrap();
            assert_eq!(missing.len(), 4, "reincluded absence schedules materialization, not local deletion");
            for item in &missing {
                let observation = fixture.observation(*item).await;
                assert!(!observation.excluded && !observation.dirty);
                assert_eq!(observation.generation, 0);
                assert_eq!(observation.observed_usn, None);
            }
            let remote = Arc::new(CatalogView::new(fixture.records.iter().map(|record| {
                let content = record.content_version_id.map(|_| (Sha256Digest::of(b"committed"), 9));
                ItemState::from_record(record, content.map(|(digest, _)| digest), content.map(|(_, size)| size)).unwrap()
            }).collect()).unwrap());
            let sources = sync::plan::PlanSources {
                base: sync::plan::materialization_base(remote.clone(), missing).unwrap(),
                remote, intents: Vec::new(),
            };
            let planned = sync::plan::plan_round(
                &fixture.account, fixture.connection, fixture.workspace, ReconcileMode::Writable, &sources,
            ).await.unwrap();
            assert!(planned.plan.remote_ops.is_empty());
            assert_eq!(planned.plan.local_actions.len(), 4);
            let mut facts = HashMap::new();
            for action in &planned.plan.local_actions {
                assert_eq!(action.action, hfdrive_core::reconcile::LocalActionKind::CreatePlaceholder);
                facts.insert(action.action_id, sync::plan::ActionFacts {
                    source_path: None,
                    target_path: Some(sync::controller::registry_path(&fixture.account, fixture.connection, action.item_id).await.unwrap()),
                    expected_file_id: None, expected_generation: None, expected_usn: None,
                });
            }
            sync::plan::persist_plan_records(&fixture.account, fixture.connection, &planned.plan, &facts).await.unwrap();
            let actions = fixture.account.pending_local_actions(fixture.connection).await.unwrap();
            assert_eq!(actions.len(), 4);
            assert!(actions.iter().all(|action| action.kind == hfdrive_state::LocalActionKind::CreatePlaceholder));
            assert_eq!(fixture.account.list_common_bases(fixture.connection, fixture.commit).await.unwrap(), sealed);
            assert!(fixture.account.list_outbox(fixture.connection, None, 100).await.unwrap().is_empty());
            fixture.close().await;
        }
    }

    #[tokio::test]
    async fn missing_root_projects_offline_status_instead_of_failing_status() {
        let fixture = sync::test_support::connection_fixture().await;
        let paths = StatePaths::new(fixture.directory.path().join("state"));
        let key = fixture.account.account_key();
        let mut envelope = rejected_envelope("sync-fixture");
        envelope.namespace = "test-user".to_owned();
        envelope.access_token = "missing-root-fixture-not-a-live-token".to_owned();
        hfdrive_auth::AccountCredentialStore::open(paths.account(key).credentials(), key)
            .unwrap().save(&envelope).unwrap();
        fixture.state.select_account(key).await.unwrap();
        fixture.state.close().await.unwrap();
        std::fs::remove_dir(&fixture.root).unwrap();

        let mut provider = Provider::open(paths.clone(), "S-1-5-21-fixture".to_owned()).await.unwrap();
        let auth = hfdrive_auth::AuthManager::new(
            hfdrive_auth::AuthConfig::production(), paths.base().to_path_buf(), None,
        );
        auth.restore_account(key).unwrap();
        let mutable = Arc::get_mut(&mut provider).unwrap();
        mutable.tokens = Arc::new(crate::tokens::DurableTokens::new(auth.clone()));
        mutable.auth = auth;
        let raw = rusqlite::Connection::open(paths.account(key).database()).unwrap();
        assert_eq!(raw.execute(
            "UPDATE connections SET config_json = json_set(config_json, '$.visibility', 'private') WHERE connection_id = ?1",
            rusqlite::params![fixture.connection.as_bytes().as_slice()],
        ).unwrap(), 1);
        drop(raw);
        let record = provider.state.reconcile_connections().await.unwrap().pop().unwrap();
        assert_eq!(record.config_json.get("visibility").and_then(serde_json::Value::as_str), Some("private"));
        let statuses = provider.connection_statuses().await.unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, hfdrive_protocol::ConnectionState::Offline);
        let error = statuses[0].last_error.as_ref().unwrap();
        assert_eq!(error.code, hfdrive_protocol::ProtocolErrorCode::LocalRootInvalid);
        assert!(error.message.contains("unavailable"));
        assert_eq!(statuses[0].hydration, hfdrive_protocol::HydrationState::OnlineOnly);
        provider.drain().await.unwrap();
        drop(provider);
        fixture.directory.close().unwrap();
    }

    fn account() -> AccountStatus {
        AccountStatus {
            state: AuthenticationState::SignedIn,
            profile: Some(AccountProfile {
                account_key: "fixture-account-key".to_owned(),
                issuer: "https://huggingface.co".to_owned(),
                subject: "fixture-subject".to_owned(),
                namespace: "fixture-person".to_owned(),
                display_name: "fixture-person".to_owned(),
                avatar_url: Some("https://cdn-avatars.huggingface.co/v1/production/uploads/test-avatar.jpeg".to_owned()),
                granted_scopes: Some(vec!["openid".to_owned()]),
            }),
            login: None,
            last_error: None,
        }
    }

    fn connection() -> ConnectionStatus {
        ConnectionStatus {
            connection_id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            owner: Owner {
                owner_kind: OwnerKind::Personal,
                owner_id: "stable-owner".to_owned(),
                namespace: Some("fixture-person".to_owned()),
                display_name: "fixture-person".to_owned(),
                role: None,
                restrictions: Vec::new(),
                can_create: false,
            },
            bucket: Bucket {
                bucket_id: "bucket-01".to_owned(),
                name: "fixture-bucket".to_owned(),
                namespace: "fixture-person".to_owned(),
                visibility: Visibility::Private,
            },
            prefix: "hfdrive/fixture".to_owned(),
            root_path: "C:\\fixture-root".to_owned(),
            mode: ConnectionMode::ReadOnly,
            capability: CapabilityState::ReadOnly,
            state: ConnectionState::UpToDate,
            pin: PinState::Unpinned,
            hydration: HydrationState::OnlineOnly,
            observed_commit: None,
            published_commit: None,
            applied_commit: None,
            observed_generation: Some(9),
            pending_files: 0,
            dirty_files: 0,
            conflict_files: 0,
            online_only_files: 2,
            pinned_files: 0,
            pending_upload_bytes: 0,
            local_bytes: 4096,
            staging_used_bytes: 0,
            range_cache_used_bytes: 0,
            transfer_memory_used_bytes: 0,
            last_error: None,
            updated_at: "2026-01-01T00:00:00Z".to_owned(),
        }
    }

    /// The startup/observer failure path must reach the real status consumer
    /// without blocking on the watch (the former borrow-into-write deadlock)
    /// and without rewriting any account field but the error.
    #[tokio::test]
    async fn restore_failure_reaches_the_status_stream_and_get_status() {
        let provider = Arc::new(Provider::new(StatusSnapshot {
            sequence: 11,
            account: account(),
            connections: Vec::new(),
        }));
        let (snapshot, receiver) = provider.subscribe();
        assert_eq!(snapshot.sequence, 11);
        let (outgoing, mut incoming) = mpsc::channel(4);
        let cancellation = CancellationToken::new();
        let _stream_task = tokio::spawn(stream_status(receiver, cancellation.clone(), outgoing));

        provider
            .publish_account_error(
                AccountFailure::Restore,
                error(ProtocolErrorCode::Timeout, "the persisted root could not be restored"),
            )
            .unwrap();

        // The same watch consumer that serves subscribed IPC clients observes
        // the failure as an ordinary status event, promptly and exactly once.
        let envelope = tokio::time::timeout(std::time::Duration::from_secs(5), incoming.recv())
            .await
            .expect("the status event is delivered promptly")
            .expect("the status stream stays open");
        let Body::Event(Event::StatusChanged(event)) = envelope.envelope.body else {
            panic!("the status stream emits status events");
        };
        assert!(event.snapshot);
        assert_eq!(event.sequence, 12, "the published change advances the sequence exactly once");
        assert_eq!(event.account.state, AuthenticationState::SignedIn, "a restore failure does not require sign-in");
        assert_eq!(event.account.profile, account().profile, "the profile is retained");
        assert_eq!(event.account.last_error.as_ref().map(|failure| failure.code), Some(ProtocolErrorCode::Timeout));
        assert!(event.changes.is_empty());

        // GetStatus answers with the same published account and sequence; the
        // failure changed nothing else and did not block the request path.
        let reply = provider
            .dispatch(Request::GetStatus(GetStatusRequest {}), CancellationToken::new())
            .await;
        let ResponseResult::GetStatus(status) = reply.result.expect("status reply") else {
            panic!("get_status answers");
        };
        assert_eq!(status.event_sequence, 12);
        assert_eq!(status.account.state, AuthenticationState::SignedIn);
        assert_eq!(status.account.profile, account().profile);
        assert_eq!(status.account.last_error.as_ref().map(|failure| failure.code), Some(ProtocolErrorCode::Timeout));
        cancellation.cancel();
    }

    /// Account error publication must retain the existing snapshot even when
    /// no consumer is attached: existing account and connection data survive,
    /// the sequence stays monotonic, and a later subscriber sees the changes.
    #[tokio::test]
    async fn error_publication_retains_snapshots_without_current_subscribers() {
        let connection = connection();
        let provider = Provider::new(StatusSnapshot {
            sequence: 40,
            account: account(),
            connections: vec![connection.clone()],
        });

        // No subscriber exists; both observer failure kinds are published
        // through the same account-status path.
        provider
            .publish_account_error(
                AccountFailure::Restore,
                error(ProtocolErrorCode::Timeout, "the persisted root could not be restored"),
            )
            .unwrap();
        provider
            .publish_account_error(
                AccountFailure::SignInRequired,
                error(ProtocolErrorCode::NeedsSignIn, "the account must sign in again"),
            )
            .unwrap();

        let mut receiver = provider.status.subscribe();
        {
            let snapshot = receiver.borrow_and_update().clone();
            assert_eq!(snapshot.sequence, 42, "each published change advances the sequence exactly once");
            assert_eq!(snapshot.account.state, AuthenticationState::NeedsSignIn);
            assert_eq!(
                snapshot.account.last_error.as_ref().map(|failure| failure.code),
                Some(ProtocolErrorCode::NeedsSignIn)
            );
            assert_eq!(snapshot.account.profile, account().profile);
            assert_eq!(snapshot.connections, vec![connection.clone()], "connection rows survive account error publication");
        }
        assert!(!receiver.has_changed().expect("watch stays open"), "the late subscriber already owns the retained snapshot");

        // The watch remains responsive for that subscriber afterwards.
        provider
            .publish_account_error(
                AccountFailure::Restore,
                error(ProtocolErrorCode::Timeout, "restoration failed again"),
            )
            .unwrap();
        assert!(receiver.has_changed().expect("watch stays open"));
        let snapshot = receiver.borrow_and_update().clone();
        assert_eq!(snapshot.sequence, 43);
        assert_eq!(snapshot.account.state, AuthenticationState::NeedsSignIn, "a restore failure never relaxes an established state");
        assert_eq!(snapshot.account.profile, account().profile);
        assert_eq!(snapshot.connections, vec![connection]);
    }

    // ---- bounded startup over unusable selected credentials (K11/G06) ----

    /// The preserved envelope of a rejected session. It still carries
    /// usable-looking secrets on purpose: only the persisted
    /// [`hfdrive_state::AccountStatus::NeedsSignIn`] record keeps startup from
    /// reactivating it.
    fn rejected_envelope(subject: &str) -> hfdrive_auth::CredentialEnvelope {
        hfdrive_auth::CredentialEnvelope {
            schema: hfdrive_auth::store::ENVELOPE_SCHEMA,
            issuer: "https://huggingface.co".to_owned(),
            subject: subject.to_owned(),
            namespace: "fixture-person".to_owned(),
            avatar_url: None,
            orgs: Vec::new(),
            granted_scopes: Some(vec!["openid".to_owned(), "profile".to_owned()]),
            covered_purpose: hfdrive_auth::LoginPurpose::WriteStorage,
            login_flow: hfdrive_auth::LoginFlow::Pkce,
            generation: 1,
            authorization_epoch: 1,
            lifetime_secs: 3_600,
            expires_at: 4_000_000_000,
            access_token: "HFDRIVE-REJECTED-SECRET-do-not-render".to_owned(),
            refresh_token: Some("HFDRIVE-REJECTED-REFRESH-do-not-render".to_owned()),
        }
    }

    /// Records and selects one account in the control database, then releases
    /// the state worker so the provider reopens the same database as a restart.
    async fn select_account(
        paths: &StatePaths,
        subject: &str,
        status: hfdrive_state::AccountStatus,
    ) -> AccountKey {
        let account = AccountKey::from_subject("https://huggingface.co", subject);
        let state = StateStore::open(paths.clone()).await.expect("state database");
        state.record_account(hfdrive_state::AccountRecord {
            account_key: account,
            issuer: "https://huggingface.co".to_owned(),
            subject: subject.to_owned(),
            namespace: "fixture-person".to_owned(),
            credential_ref: hfdrive_state::CredentialRef("oauth.hfdcred".to_owned()),
            auth_epoch: 1,
            status,
        }).await.expect("record account");
        state.select_account(account).await.expect("select account");
        drop(state);
        account
    }

    /// The common sign-in-required assertions: a bounded open, the exact
    /// usable NeedsSignIn state, a retained selection for display/recovery, and
    /// a fresh login still permitted without a usable session (G06).
    async fn assert_sign_in_required_startup(provider: &Arc<Provider>, account: AccountKey) {
        let account_status = provider.status.borrow().account.clone();
        assert_eq!(account_status.state, AuthenticationState::NeedsSignIn);
        assert_eq!(
            account_status.last_error.as_ref().map(|failure| failure.code),
            Some(ProtocolErrorCode::NeedsSignIn)
        );
        assert_eq!(
            provider.state.selected_account().await.expect("selection"),
            Some(account),
            "the retained selection survives startup for display and recovery"
        );
        assert_eq!(
            provider.state.get_account(account).await.expect("account row")
                .expect("account row persists").status,
            hfdrive_state::AccountStatus::NeedsSignIn,
            "the rejection is durably persisted"
        );
        // No usable token epoch is admitted: account-scoped remote work fails
        // closed at the credential boundary.
        assert!(hfdrive_auth::TokenSource::access_token(&*provider.tokens, account).await.is_err());
        assert!(hfdrive_auth::TokenSource::authorization_lease(&*provider.tokens, account).is_err());
        // A fresh login is permitted without a usable session (G06).
        let login = Request::StartLogin(hfdrive_protocol::StartLoginRequest {
            operation_id: Uuid::new_v4(),
            flow: hfdrive_protocol::LoginFlow::Pkce,
            purpose: hfdrive_protocol::LoginPurpose::Signin,
            organization_id: None,
        });
        assert_eq!(provider.operation_scope(&login).await, Ok((None, None)));
        // GetStatus still answers the sign-in-required state promptly.
        let reply = provider
            .dispatch(Request::GetStatus(GetStatusRequest {}), CancellationToken::new())
            .await;
        let ResponseResult::GetStatus(status) = reply.result.expect("status reply") else {
            panic!("get_status answers");
        };
        assert_eq!(status.account.state, AuthenticationState::NeedsSignIn);
    }

    /// G06: with no active profile and a retained selection, startup persists
    /// and publishes NeedsSignIn exactly once instead of spinning on
    /// selected-account equality with `None`.
    #[tokio::test]
    async fn startup_with_missing_selected_credentials_is_bounded_and_needs_sign_in() {
        let directory = tempfile::tempdir().expect("tempdir");
        let paths = StatePaths::new(directory.path().to_path_buf());
        // A stale `active` row whose credential record is missing.
        let account = select_account(&paths, "missing-fixture-subject", hfdrive_state::AccountStatus::Active).await;
        let provider = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            Provider::open(paths, "S-1-5-21-fixture".to_owned()),
        )
        .await
        .expect("startup stays bounded with missing selected credentials")
        .expect("provider opens");
        assert_sign_in_required_startup(&provider, account).await;
        // A repeat synchronization is a no-op: the state was persisted and
        // published once, not rewritten on every observation.
        let sequence = provider.status.borrow().sequence;
        provider.synchronize_account().await.expect("synchronize");
        assert_eq!(provider.status.borrow().sequence, sequence, "NeedsSignIn is published once");
    }

    /// K11: an unreadable selected credential record keeps startup bounded,
    /// honors the recorded rejection, and is preserved untouched.
    #[tokio::test]
    async fn startup_with_corrupt_selected_credentials_preserves_the_record() {
        let directory = tempfile::tempdir().expect("tempdir");
        let paths = StatePaths::new(directory.path().to_path_buf());
        let account = select_account(&paths, "corrupt-fixture-subject", hfdrive_state::AccountStatus::NeedsSignIn).await;
        let record_path = paths
            .account(account)
            .credentials()
            .join(hfdrive_auth::AccountCredentialStore::record_file_name());
        std::fs::create_dir_all(record_path.parent().expect("credentials dir")).expect("credentials dir");
        std::fs::write(&record_path, b"NOT-HFDCRED1-corrupt-record").expect("corrupt record");
        let before = std::fs::read(&record_path).expect("corrupt record");
        let provider = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            Provider::open(paths, "S-1-5-21-fixture".to_owned()),
        )
        .await
        .expect("startup stays bounded with corrupt selected credentials")
        .expect("provider opens");
        assert_eq!(
            std::fs::read(&record_path).expect("corrupt record"),
            before,
            "an unreadable credential record is preserved untouched"
        );
        assert_sign_in_required_startup(&provider, account).await;
    }

    /// K11: startup honors the persisted `NeedsSignIn` rejection and never
    /// reactivates the rejected envelope — even though the preserved record
    /// still carries an unexpired bearer and a refresh token that the
    /// permissive restore path would otherwise accept.
    #[tokio::test]
    async fn startup_honors_recorded_rejection_and_never_reactivates_the_envelope() {
        let directory = tempfile::tempdir().expect("tempdir");
        let paths = StatePaths::new(directory.path().to_path_buf());
        let subject = "rejected-fixture-subject";
        let account = select_account(&paths, subject, hfdrive_state::AccountStatus::NeedsSignIn).await;
        let store = hfdrive_auth::AccountCredentialStore::open(paths.account(account).credentials(), account)
            .expect("credential store");
        store.save(&rejected_envelope(subject)).expect("persist rejected envelope");
        let provider = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            Provider::open(paths, "S-1-5-21-fixture".to_owned()),
        )
        .await
        .expect("startup stays bounded over a rejected credential envelope")
        .expect("provider opens");
        // The verified identity is retained for display and recovery.
        let profile = provider.status.borrow().account.profile.clone().expect("display identity");
        assert_eq!(profile.subject, subject);
        assert_sign_in_required_startup(&provider, account).await;
        // The rejected envelope's replayable secrets are neutralized durably:
        // no later restore path can reactivate them.
        let saved = store.load().expect("preserved record");
        assert!(saved.access_token.is_empty(), "a rejected bearer must not survive startup");
        assert!(saved.refresh_token.is_none(), "a rejected refresh token must not survive startup");
        assert_eq!(saved.expires_at, 0);
        assert_eq!(saved.generation, 1, "generation bookkeeping stays monotonic for the replacement login");
        assert_eq!(saved.subject, subject);
    }

    struct DeniedLoginFixture {
        issuer: String,
        discovery_url: String,
    }

    impl DeniedLoginFixture {
        async fn start() -> Self {
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .expect("OIDC fixture listener");
            let port = listener.local_addr().expect("OIDC fixture address").port();
            let issuer = format!("http://127.0.0.1:{port}");
            let discovery_url = format!("{issuer}/.well-known/openid-configuration");
            let server_issuer = issuer.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else { return };
                    let issuer = server_issuer.clone();
                    tokio::spawn(serve_oidc_connection(stream, issuer));
                }
            });
            Self { issuer, discovery_url }
        }

        fn auth_manager(&self, state_base: &std::path::Path) -> AuthManager {
            let manager = AuthManager::with_settings_and_launcher(
                hfdrive_auth::AuthConfig::with_client_id(Some("fixture-client".to_owned())),
                hfdrive_auth::OidcSettings::fixture(
                    &self.issuer,
                    &self.discovery_url,
                    "127.0.0.1",
                    300,
                ),
                state_base.to_path_buf(),
                None,
                Arc::new(|_: &str| Ok(())),
            );
            // The record remains readable, but its neutralizing replacement
            // fails at the persistence boundary. This preserves the original
            // unexpired bearer/refresh material across the whole regression.
            manager.fail_rejection_replacement_for_test(true);
            manager
        }
    }

    async fn serve_oidc_connection(mut stream: tokio::net::TcpStream, issuer: String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut request = Vec::new();
        let mut chunk = [0u8; 2048];
        loop {
            let Ok(read) = stream.read(&mut chunk).await else { return };
            if read == 0 { return; }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") { break; }
            if request.len() > 64 * 1024 { return; }
        }
        let request = String::from_utf8_lossy(&request);
        let target = request.split_whitespace().nth(1).unwrap_or("");
        let path = target.split('?').next().unwrap_or(target);
        let (status, body) = match path {
            "/.well-known/openid-configuration" => (
                "200 OK",
                serde_json::json!({
                    "issuer": issuer,
                    "authorization_endpoint": format!("{issuer}/authorize"),
                    "token_endpoint": format!("{issuer}/token"),
                    "userinfo_endpoint": format!("{issuer}/userinfo"),
                    "jwks_uri": format!("{issuer}/jwks"),
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                })
                .to_string(),
            ),
            // Discovery requires one RSA key, but a denied authorization never
            // exchanges a code or verifies an ID-token signature.
            "/jwks" => (
                "200 OK",
                serde_json::json!({"keys": [{
                    "kty": "RSA", "use": "sig", "kid": "fixture-key",
                    "alg": "RS256", "n": "AQAB", "e": "AQAB"
                }]})
                .to_string(),
            ),
            _ => ("404 Not Found", "{\"error\":\"not_found\"}".to_owned()),
        };
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.flush().await;
    }

    fn query_parameter<'a>(url: &'a str, name: &str) -> &'a str {
        url.split_once('?')
            .and_then(|(_, query)| {
                query.split('&').find_map(|pair| {
                    let (candidate, value) = pair.split_once('=')?;
                    (candidate == name).then_some(value)
                })
            })
            .expect("authorization URL query parameter")
    }

    fn decode_query_component(value: &str) -> String {
        let input = value.as_bytes();
        let mut decoded = Vec::with_capacity(input.len());
        let mut index = 0;
        while index < input.len() {
            if input[index] == b'%' && index + 2 < input.len() {
                let high = (input[index + 1] as char).to_digit(16);
                let low = (input[index + 2] as char).to_digit(16);
                if let (Some(high), Some(low)) = (high, low) {
                    decoded.push((high * 16 + low) as u8);
                    index += 3;
                    continue;
                }
            }
            decoded.push(input[index]);
            index += 1;
        }
        String::from_utf8(decoded).expect("decoded callback URL is UTF-8")
    }

    async fn deny_login(authorization_url: &str) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let state = decode_query_component(query_parameter(authorization_url, "state"));
        let redirect = decode_query_component(query_parameter(authorization_url, "redirect_uri"));
        let rest = redirect.strip_prefix("http://").expect("loopback callback");
        let (authority, path) = rest.split_once('/').expect("callback path");
        let mut stream = tokio::net::TcpStream::connect(authority)
            .await
            .expect("connect to login callback");
        let request = format!(
            "GET /{path}?error=access_denied&state={state} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.expect("write denial");
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response).await;
        assert!(
            String::from_utf8_lossy(&response).contains("400"),
            "the valid denial consumes the login attempt"
        );
    }

    /// K11 exact recovery regression: the rejected record loads, neutralizing
    /// replacement fails, a denied re-login replaces only `last_error`, and a
    /// restart still selects rejected restoration over the intact envelope.
    #[tokio::test]
    async fn rejected_envelope_survives_failed_replacement_denied_relogin_and_restart() {
        let directory = tempfile::tempdir().expect("tempdir");
        let paths = StatePaths::new(directory.path().to_path_buf());
        let subject = "nonreplaceable-rejected-subject";
        let account = select_account(
            &paths,
            subject,
            hfdrive_state::AccountStatus::NeedsSignIn,
        )
        .await;
        let store = hfdrive_auth::AccountCredentialStore::open(
            paths.account(account).credentials(),
            account,
        )
        .expect("credential store");
        store.save(&rejected_envelope(subject)).expect("persist original envelope");
        assert!(!store.load().expect("record remains readable").access_token.is_empty());

        let fixture = DeniedLoginFixture::start().await;
        let provider = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            Provider::open_with_auth(
                paths.clone(),
                "S-1-5-21-fixture".to_owned(),
                fixture.auth_manager(paths.base()),
            ),
        )
        .await
        .expect("bounded startup over nonreplaceable rejected envelope")
        .expect("provider opens");
        assert_eq!(provider.auth.snapshot().rejected, Some(account));
        assert_eq!(
            provider.status.borrow().account.state,
            AuthenticationState::NeedsSignIn
        );
        assert!(
            !store.load().expect("original record remains readable").access_token.is_empty(),
            "failed neutralization leaves the original bearer in the record"
        );

        let login = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            provider.start_login(hfdrive_protocol::StartLoginRequest {
                operation_id: Uuid::new_v4(),
                flow: hfdrive_protocol::LoginFlow::Pkce,
                purpose: hfdrive_protocol::LoginPurpose::Signin,
                organization_id: None,
            }),
        )
        .await
        .expect("denied login reaches its authorization instructions")
        .expect("start denied re-login");
        deny_login(login.authorization_url.as_deref().expect("authorization URL")).await;
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                provider.auth.wait_for_login(login.session_id),
            )
            .await
            .expect("denied login finishes"),
            Err(hfdrive_auth::AuthError::Denied)
        );
        provider.synchronize_account().await.expect("persist denied-login snapshot");

        let snapshot = provider.auth.snapshot();
        assert_eq!(snapshot.last_error, Some(hfdrive_auth::AuthError::Denied));
        assert_eq!(
            snapshot.rejected,
            Some(account),
            "a later denial cannot clear the account-scoped rejection"
        );
        assert_eq!(provider.status.borrow().account.state, AuthenticationState::NeedsSignIn);
        assert_eq!(
            provider.state.get_account(account).await.expect("account row")
                .expect("account row persists").status,
            hfdrive_state::AccountStatus::NeedsSignIn,
            "Denied is not persisted as an Active account"
        );
        assert!(hfdrive_auth::TokenSource::access_token(&*provider.tokens, account).await.is_err());
        assert!(hfdrive_auth::TokenSource::authorization_lease(&*provider.tokens, account).is_err());
        assert!(!store.load().expect("original record survives denial").access_token.is_empty());

        drop(provider);
        let restarted = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            Provider::open_with_auth(
                paths.clone(),
                "S-1-5-21-fixture".to_owned(),
                fixture.auth_manager(paths.base()),
            ),
        )
        .await
        .expect("bounded restart over the original rejected envelope")
        .expect("provider restarts");
        assert_sign_in_required_startup(&restarted, account).await;
        assert_eq!(restarted.auth.snapshot().rejected, Some(account));
        assert!(
            !store.load().expect("original envelope survives restart").access_token.is_empty(),
            "the restart denied token and lease even though the original bearer remained"
        );
    }
}
