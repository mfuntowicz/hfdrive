use hfdrive_auth::AuthManager;
use hfdrive_core::ids::{AccountKey, ConnectionId};
use hfdrive_protocol::{
    Envelope, Event, ExitProviderResult, GetStatusResult, HelloRequest, HelloResult,
    ProtocolError, ProtocolErrorCode, Request, ResponseResult, StatusChangedEvent, StatusSnapshot,
};
use hfdrive_state::{StatePaths, StateStore};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc, watch};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

mod account;
mod account_runtime;
mod conflicts;
mod connect;
mod controls;
mod diagnostics;
mod history;
mod inspect;
mod operations;
mod probe;
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
    pub async fn open(paths: StatePaths, client_id: Option<String>, user_sid: String) -> Result<Arc<Self>, hfdrive_state::StateError> {
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
        let auth = AuthManager::new(hfdrive_auth::AuthConfig::with_client_id(client_id), paths.base().to_path_buf(), selected);
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
        let startup = match provider.synchronize_account().await {
            Ok(_) => provider.restore_connections().await.map(|_| ()),
            Err(error) => Err(error),
        };
        if let Err(error) = startup {
            let mut status = provider.status.borrow().account.clone();
            status.last_error = Some(error);
            provider.status.send_replace(StatusSnapshot { account: status, ..provider.status.borrow().clone() });
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
            supported_features: ["get_status", "subscribe_status", "cancel_request", "start_login", "cancel_login", "sign_out", "list_owners", "list_buckets", "create_bucket", "inspect_drive", "list_conflicts", "resolve_conflict", "list_history", "restore", "begin_setup", "set_publication_credentials", "preview_connect", "connect", "probe_storage", "pause", "resume", "set_pin", "free_space", "set_selective_sync", "export_diagnostics", "prepare_unlink", "unlink", "update_settings", "prepare_upgrade", "exit_provider"]
                .into_iter().map(str::to_owned).collect(),
            supported_min_protocol_minor: 0,
        })
    }

    fn subscribe(&self) -> (StatusSnapshot, watch::Receiver<StatusSnapshot>) {
        let mut receiver = self.status.subscribe();
        let snapshot = receiver.borrow_and_update().clone();
        (snapshot, receiver)
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
            Request::ListHistory(request) => self.list_history(request).await.map(ResponseResult::ListHistory).into(),
            request => self.dispatch_mutation(request, cancellation).await,
        }
    }

    async fn execute_mutation_action(self: &Arc<Self>, request: Request) -> operations::MutationOutcome {
        match request {
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
                    Request::SetPublicationCredentials(r) => Some(connection(r.connection_id)?),
                    Request::ProbeStorage(r) => Some(connection(r.connection_id)?),
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
