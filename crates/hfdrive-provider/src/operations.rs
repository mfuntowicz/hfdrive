//! IPC waiters do not own accepted mutations. Only this provider owns their lifetime.
use crate::{Provider, account};
use hfdrive_core::ids::OperationId;
use hfdrive_protocol::{ProtocolError, ProtocolErrorCode, Request, ResponseResult, StartLoginResult};
use hfdrive_state::{BeginOperationRequest, BeginOutcome, EffectClass, OperationRecord, OperationState, StateError};
use std::sync::{Arc, Mutex};
use tokio::sync::{Semaphore, oneshot};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const MAX_MUTATIONS: u32 = 64;

pub(crate) struct Operations {
    pub(crate) cancellation: CancellationToken,
    accepting: Mutex<bool>,
    permits: Arc<Semaphore>,
    tasks: TaskTracker,
}

impl Operations {
    pub(crate) fn new() -> Self {
        Self { cancellation: CancellationToken::new(), accepting: Mutex::new(true), permits: Arc::new(Semaphore::new(MAX_MUTATIONS as usize)), tasks: TaskTracker::new() }
    }

    /// Exactly one exit/upgrade may drain. Competing requests release their permit.
    pub(crate) async fn quiesce_from_mutation(&self) -> Result<(), ProtocolError> {
        {
            let mut accepting = self.accepting.lock().map_err(|_| internal())?;
            if !*accepting { return Err(error(ProtocolErrorCode::Busy, "Provider shutdown is already in progress")); }
            *accepting = false;
        }
        // The calling mutation owns the one remaining permit. Admission is closed.
        let others = self.permits.clone().acquire_many_owned(MAX_MUTATIONS - 1).await.map_err(|_| internal())?;
        drop(others);
        // Exit closes only the provider service, not its accepted mutation tracker;
        // the current task must remain alive to persist its exit receipt and reply.
        Ok(())
    }

    pub(crate) async fn drain(&self) {
        if let Ok(mut accepting) = self.accepting.lock() { *accepting = false; }
        self.tasks.close();
        self.tasks.wait().await;
    }
}

/// Moving or dropping a reply transfers its post-reply action, not the mutation.
/// A disconnected waiter cannot leave an accepted shutdown stranded indefinitely.
#[derive(Default)]
pub(crate) struct AfterReply(pub(crate) Option<CancellationToken>);

impl AfterReply {
    pub(crate) fn shutdown(token: CancellationToken) -> Self { Self(Some(token)) }
}

impl Drop for AfterReply {
    fn drop(&mut self) {
        if let Some(token) = &self.0 { token.cancel(); }
    }
}

pub(crate) struct DispatchReply {
    pub(crate) result: Result<ResponseResult, ProtocolError>,
    pub(crate) after: AfterReply,
}

impl From<Result<ResponseResult, ProtocolError>> for DispatchReply {
    fn from(result: Result<ResponseResult, ProtocolError>) -> Self {
        Self { result, after: AfterReply::default() }
    }
}

pub(crate) struct MutationOutcome {
    pub(crate) reply: DispatchReply,
    /// An external effect may have happened: preserve the pending journal, never fail/replay it.
    pub(crate) uncertain: bool,
}

impl From<Result<ResponseResult, ProtocolError>> for MutationOutcome {
    fn from(result: Result<ResponseResult, ProtocolError>) -> Self {
        Self { reply: result.into(), uncertain: false }
    }
}

impl From<DispatchReply> for MutationOutcome {
    fn from(reply: DispatchReply) -> Self {
        Self { reply, uncertain: false }
    }
}

impl Provider {
    pub(crate) async fn dispatch_mutation(self: &Arc<Self>, request: Request, cancellation: CancellationToken) -> DispatchReply {
        let (send, receive) = oneshot::channel();
        {
            let accepting = match self.operations.accepting.lock() {
                Ok(guard) => guard,
                Err(_) => return Err(internal()).into(),
            };
            if !*accepting || self.shutdown.is_cancelled() {
                return Err(error(ProtocolErrorCode::Busy, "Provider is draining accepted work")).into();
            }
            let permit = match self.operations.permits.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => return Err(error(ProtocolErrorCode::Busy, "Provider mutation capacity is occupied")).into(),
            };
            let provider = self.clone();
            let before_admission = cancellation.clone();
            self.operations.tasks.spawn(async move {
                let _permit = permit;
                let reply = if before_admission.is_cancelled() {
                    Err(error(ProtocolErrorCode::Cancelled, "Request cancelled before admission")).into()
                } else {
                    provider.execute_mutation(request).await
                };
                // On send failure, dropping the owned reply still runs its post-reply action.
                let _ = send.send(reply);
            });
        }
        tokio::select! {
            reply = receive => reply.unwrap_or_else(|_| Err(internal()).into()),
            _ = cancellation.cancelled() => Err(error(ProtocolErrorCode::Cancelled,
                "Stopped waiting; an admitted operation may still complete. Inspect its operation ID before retrying")).into(),
        }
    }

    async fn execute_mutation(self: &Arc<Self>, request: Request) -> DispatchReply {
        let Some(id) = request.operation_id() else { return Err(internal()).into(); };
        let operation_id = match OperationId::from_uuid(id) {
            Ok(id) => id,
            Err(_) => return Err(error(ProtocolErrorCode::InvalidRequest, "A nonzero operation identifier is required")).into(),
        };
        let request_value = match serde_json::to_value(&request) {
            Ok(value) => value,
            Err(_) => return Err(internal()).into(),
        };
        let effect_class = match &request {
            Request::StartLogin(_)
            | Request::CreateBucket(_)
            | Request::ProbeStorage(_)
            | Request::Restore(_)
            | Request::ResolveConflict(_)
            | Request::Connect(_) => EffectClass::External,
            _ => EffectClass::Local,
        };
        let bucket_creation_operation_id = match &request {
            Request::BeginSetup(request) => match request.bucket_creation_operation_id {
                Some(id) => match OperationId::from_uuid(id) {
                    Ok(id) => Some(id),
                    Err(_) => return Err(error(ProtocolErrorCode::InvalidRequest, "A nonzero bucket-creation operation identifier is required")).into(),
                },
                None => None,
            },
            _ => None,
        };
        let (account_key, connection_id) = match self.operation_scope(&request).await {
            Ok(scope) => scope,
            Err(error) => return Err(error).into(),
        };
        let reservation = BeginOperationRequest {
            operation_id, kind: request.method().to_owned(), request: request_value,
            effect_class, account_key, connection_id, bucket_creation_operation_id,
        };
        let (record, replayed) = match self.state.begin_operation(reservation).await {
            Ok(BeginOutcome::Replayed(record)) => (record, true),
            Ok(BeginOutcome::Fresh(record)) => (record, false),
            Err(StateError::OperationNotReplayable { .. }) => match self.state.get_operation(operation_id).await {
                Ok(Some(record)) => (record, true),
                Ok(None) => return Err(internal()).into(),
                Err(error) => return Err(state_error(error)).into(),
            },
            Err(error) => return Err(state_error(error)).into(),
        };
        if replayed || record.state != OperationState::Pending {
            return self.replay_operation(record).await.into();
        }
        if effect_class == EffectClass::External {
            if let Err(error) = self.state.mark_dispatched(operation_id).await {
                return Err(state_error(error)).into();
            }
        }
        let mut outcome = self.execute_mutation_action(request).await;
        let persistence = match &outcome.reply.result {
            Ok(result) => match durable_result(result) {
                Ok(value) => self.state.finish_operation(operation_id, value).await.map(|_| ()),
                Err(error) => {
                    outcome.reply.result = Err(error);
                    return outcome.reply;
                }
            },
            Err(error) if !outcome.uncertain => self.state.fail_operation(operation_id, error.code.wire().to_owned()).await.map(|_| ()),
            Err(_) => Ok(()),
        };
        if let Err(error) = persistence { outcome.reply.result = Err(state_error(error)); }
        outcome.reply
    }

    async fn replay_operation(&self, record: OperationRecord) -> Result<ResponseResult, ProtocolError> {
        match record.state {
            OperationState::Committed => {
                let value = record.result_json.ok_or_else(internal)?;
                let result = ResponseResult::from_body(&record.kind, value).map_err(|_| internal())?;
                if let ResponseResult::StartLogin(receipt) = result {
                    let snapshot = self.auth.snapshot();
                    let session = snapshot.active_login.as_ref().filter(|session| session.session_id == receipt.session_id)
                        .ok_or_else(|| error(ProtocolErrorCode::Conflict, "Login instructions are no longer available; start a new login operation"))?;
                    return account::login_result(session).map(ResponseResult::StartLogin);
                }
                // In particular, replaying an old exit receipt cannot stop a new provider instance.
                Ok(result)
            }
            OperationState::Failed => {
                let code = record.error_code.as_deref().and_then(ProtocolErrorCode::from_wire).unwrap_or(ProtocolErrorCode::Internal);
                Err(error(code, "This operation previously failed; a deliberate new attempt needs a new operation ID"))
            }
            OperationState::Abandoned => Err(error(ProtocolErrorCode::Conflict, "This operation was abandoned and cannot be executed again")),
            OperationState::Pending | OperationState::ExternalPending => Err(error(ProtocolErrorCode::Busy,
                "This operation is pending or requires reconciliation; it was not executed again")),
        }
    }
}

fn durable_result(result: &ResponseResult) -> Result<serde_json::Value, ProtocolError> {
    match result {
        ResponseResult::StartLogin(session) => serde_json::to_value(StartLoginResult {
            session_id: session.session_id, expires_at: session.expires_at.clone(),
            authorization_url: None, user_code: None, verification_uri: None,
        }),
        _ => serde_json::to_value(result),
    }.map_err(|_| internal())
}

pub(crate) fn error(code: ProtocolErrorCode, message: &'static str) -> ProtocolError {
    ProtocolError { code, message: message.to_owned(), retry_after_ms: None }
}

pub(crate) fn internal() -> ProtocolError {
    error(ProtocolErrorCode::Internal, "Provider state could not complete this operation; existing data was preserved")
}

pub(crate) fn state_error(error_value: StateError) -> ProtocolError {
    use ProtocolErrorCode as Code;
    let code = match error_value {
        StateError::OperationConflict { .. } | StateError::RevisionMismatch { .. } | StateError::StaleEvidence { .. } => Code::Conflict,
        StateError::NotFound { .. } | StateError::UnknownAccount(_) | StateError::UnknownConnection(_) | StateError::UnknownSetup(_) => Code::NotFound,
        StateError::OperationNotReplayable { .. } => Code::Conflict,
        StateError::OperationNotMutable { .. } => Code::Busy,
        _ => Code::Internal,
    };
    error(code, "Durable state could not complete this operation; existing data was preserved")
}
