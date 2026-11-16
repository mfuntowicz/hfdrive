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
        let import_cursor = match &request {
            Request::Import(request) => Some(request.files_cursor.clone()),
            _ => None,
        };
        let mut request_value = match serde_json::to_value(&request) {
            Ok(value) => value,
            Err(_) => return Err(internal()).into(),
        };
        // Receipt cursors select a page of the same committed operation; they
        // are not mutation identity and must not change its request digest.
        if matches!(&import_cursor, Some(Some(_))) {
            let Some(cursor) = request_value.get_mut("files_cursor") else { return Err(internal()).into(); };
            *cursor = serde_json::Value::Null;
        }
        let effect_class = match &request {
            Request::StartLogin(_)
            | Request::Import(_)
            | Request::CreateBucket(_)
            | Request::ProbeStorage(_)
            | Request::RepairStorage(_)
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
        let (mut record, mut replayed) = match self.state.begin_operation(reservation).await {
            Ok(BeginOutcome::Replayed(record)) => (record, true),
            Ok(BeginOutcome::Fresh(record)) => (record, false),
            Err(StateError::OperationNotReplayable { .. }) => match self.state.get_operation(operation_id).await {
                Ok(Some(record)) => (record, true),
                Ok(None) => return Err(internal()).into(),
                Err(error) => return Err(state_error(error)).into(),
            },
            Err(error) => return Err(state_error(error)).into(),
        };
        if !replayed && matches!(&import_cursor, Some(Some(_))) {
            if let Err(error) = self.state.fail_operation(operation_id, ProtocolErrorCode::InvalidRequest.wire().to_owned()).await {
                return Err(state_error(error)).into();
            }
            return Err(error(ProtocolErrorCode::InvalidRequest, "An import receipt cursor requires an existing committed operation")).into();
        }
        if replayed
            && matches!(&import_cursor, Some(None))
            && matches!(record.state, OperationState::Pending | OperationState::ExternalPending)
        {
            let Request::Import(import) = &request else { return Err(internal()).into(); };
            if let Err(error) = crate::import::validate_import_resume(self, import) {
                return Err(error).into();
            }
            if record.state == OperationState::ExternalPending {
                record = match self.state.reconcile_operation(operation_id, hfdrive_state::OperationResolution::ResumeVerified).await {
                    Ok(record) => record,
                    Err(error) => return Err(state_error(error)).into(),
                };
            }
            // mark_dispatched below is the atomic execution claim. A competing
            // retry either loses that transition or remains a read-only replay.
            replayed = false;
        }
        if replayed || record.state != OperationState::Pending {
            let result = self.replay_operation(record).await;
            return match (result, import_cursor) {
                (Ok(ResponseResult::Import(result)), Some(cursor)) => {
                    crate::import::page_import_result(result, cursor.as_deref()).map(ResponseResult::Import).into()
                }
                (result, _) => result.into(),
            };
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
        if let (Some(cursor), Ok(ResponseResult::Import(result))) = (import_cursor, &outcome.reply.result) {
            outcome.reply.result = crate::import::page_import_result_ref(result, cursor.as_deref()).map(ResponseResult::Import);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use hfdrive_protocol::{ImportFileResult, ImportResult, ImportTarget, OwnerKind, StatusSnapshot, Visibility};
    use uuid::Uuid;

    fn import_request(operation_id: Uuid, import_id: Uuid) -> Request {
        Request::Import(hfdrive_protocol::ImportRequest {
            operation_id,
            import_id,
            target: ImportTarget {
                owner_kind: OwnerKind::Personal,
                owner_id: "owner-id".to_owned(),
                owner_namespace: "alice".to_owned(),
                bucket_id: "bucket-id".to_owned(),
                bucket_name: "data".to_owned(),
                visibility: Visibility::Private,
            },
            sources: vec![r"C:\fixture\hello.txt".to_owned()],
            files_cursor: None,
        })
    }

    async fn signed_in_provider() -> (Arc<Provider>, hfdrive_core::ids::AccountKey) {
        let provider = Arc::new(Provider::new(StatusSnapshot {
            sequence: 0,
            account: Default::default(),
            connections: Vec::new(),
        }));
        let account_key = hfdrive_core::ids::AccountKey::from_subject("https://huggingface.co", "import-replay-subject");
        let store = hfdrive_auth::AccountCredentialStore::open(provider.paths.account(account_key).credentials(), account_key).unwrap();
        store.save(&hfdrive_auth::CredentialEnvelope {
            schema: hfdrive_auth::store::ENVELOPE_SCHEMA,
            issuer: "https://huggingface.co".to_owned(),
            subject: "import-replay-subject".to_owned(),
            namespace: "alice".to_owned(),
            avatar_url: None,
            orgs: Vec::new(),
            granted_scopes: Some(vec!["openid".to_owned()]),
            covered_purpose: hfdrive_auth::LoginPurpose::WriteStorage,
            login_flow: hfdrive_auth::LoginFlow::Pkce,
            generation: 1,
            authorization_epoch: 1,
            lifetime_secs: 3_600,
            expires_at: 4_000_000_000,
            access_token: "fixture-not-a-live-token".to_owned(),
            refresh_token: None,
        }).unwrap();
        provider.auth.restore_account(account_key).unwrap();
        provider.state.record_account(hfdrive_state::AccountRecord {
            account_key,
            issuer: "https://huggingface.co".to_owned(),
            subject: "import-replay-subject".to_owned(),
            namespace: "alice".to_owned(),
            credential_ref: hfdrive_state::CredentialRef("oauth.hfdcred".to_owned()),
            auth_epoch: 1,
            status: hfdrive_state::AccountStatus::Active,
        }).await.unwrap();
        (provider, account_key)
    }

    #[tokio::test]
    async fn import_cursor_replays_the_requested_committed_page() {
        let (provider, account_key) = signed_in_provider().await;
        let operation_id = Uuid::new_v4();
        let import_id = Uuid::new_v4();
        let request = import_request(operation_id, import_id);
        let operation = hfdrive_core::ids::OperationId::from_uuid(operation_id).unwrap();
        provider.state.begin_operation(BeginOperationRequest {
            operation_id: operation,
            kind: "import".to_owned(),
            request: serde_json::to_value(&request).unwrap(),
            effect_class: EffectClass::External,
            account_key: Some(account_key),
            connection_id: None,
            bucket_creation_operation_id: None,
        }).await.unwrap();
        let full = ImportResult {
            import_id,
            prefix: format!("hfdrive-imports/{import_id}"),
            files: (0..205).map(|index| ImportFileResult {
                key: format!("hfdrive-imports/{import_id}/file-{index}"),
                size: 1,
                sha256: "ab".repeat(32),
                xet_file_id: "cd".repeat(32),
            }).collect(),
            next_cursor: None,
            file_count: 205,
            total_bytes: 205,
            empty_directory_count: 0,
        };
        provider.state.finish_operation(operation, serde_json::to_value(&full).unwrap()).await.unwrap();

        let first = provider.dispatch_mutation(request.clone(), CancellationToken::new()).await.result.unwrap();
        let ResponseResult::Import(first) = first else { panic!("wrong response") };
        assert_eq!(first.files.len(), 200);
        let cursor = first.next_cursor.unwrap();
        let Request::Import(continuation) = request else { unreachable!() };
        let second = provider.dispatch_mutation(Request::Import(hfdrive_protocol::ImportRequest {
            files_cursor: Some(cursor),
            ..continuation
        }), CancellationToken::new()).await.result.unwrap();
        let ResponseResult::Import(second) = second else { panic!("wrong response") };
        assert_eq!(second.files.len(), 5);
        assert_eq!(second.files[0].key, format!("hfdrive-imports/{import_id}/file-200"));
        assert_eq!(second.file_count, 205);
        assert_eq!(second.total_bytes, 205);
        assert!(second.next_cursor.is_none());
    }

    #[tokio::test]
    async fn external_pending_import_uses_the_verified_resume_transition() {
        let (provider, account_key) = signed_in_provider().await;
        let operation_id = Uuid::new_v4();
        let import_id = Uuid::new_v4();
        let Request::Import(mut import) = import_request(operation_id, import_id) else { unreachable!() };
        // Once resume reaches execute_import, this fails before any native call.
        import.target.owner_id.clear();
        let request = Request::Import(import);
        let operation = hfdrive_core::ids::OperationId::from_uuid(operation_id).unwrap();
        provider.state.begin_operation(BeginOperationRequest {
            operation_id: operation,
            kind: "import".to_owned(),
            request: serde_json::to_value(&request).unwrap(),
            effect_class: EffectClass::External,
            account_key: Some(account_key),
            connection_id: None,
            bucket_creation_operation_id: None,
        }).await.unwrap();
        provider.state.mark_dispatched(operation).await.unwrap();

        let reply = provider.dispatch_mutation(request, CancellationToken::new()).await;
        let error = reply.result.unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::InvalidRequest);
        let record = provider.state.get_operation(operation).await.unwrap().unwrap();
        assert_eq!(record.state, OperationState::Failed);
    }

    #[tokio::test]
    async fn fresh_import_cursor_is_rejected_without_starting_work() {
        let (provider, _account_key) = signed_in_provider().await;
        let operation_id = Uuid::new_v4();
        let import_id = Uuid::new_v4();
        let Request::Import(request) = import_request(operation_id, import_id) else { unreachable!() };
        let reply = provider.dispatch_mutation(Request::Import(hfdrive_protocol::ImportRequest {
            files_cursor: Some(format!("import-files-v1:{import_id}:0")),
            ..request
        }), CancellationToken::new()).await;
        let error = reply.result.unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::InvalidRequest);
        let record = provider.state.get_operation(hfdrive_core::ids::OperationId::from_uuid(operation_id).unwrap()).await.unwrap().unwrap();
        assert_eq!(record.state, OperationState::Failed);
        assert!(record.result_json.is_none());
    }
}
