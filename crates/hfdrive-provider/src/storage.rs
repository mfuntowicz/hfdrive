//! Every native read and mutation is bound to the currently admitted account epoch.
use crate::{Provider, operations::error};
use hfdrive_core::storage::{BucketId, BucketName, Namespace, OwnerId, OwnerKind};
use hfdrive_hf::{BucketSummary, CreateBucket, NativeApi, NativeConfig, NativeControl, NativeError, OwnerLocator};
use hfdrive_protocol as wire;

pub(crate) struct NativePublicationParts {
    pub control: NativeControl<crate::tokens::DurableTokens>,
    pub binding: Option<hfdrive_publication::PublicationBinding>,
    pub transport: Option<hfdrive_publication::S3Transport>,
}

impl Provider {
    pub(crate) fn native_control(&self, account: hfdrive_core::ids::AccountKey) -> NativeControl<crate::tokens::DurableTokens> {
        let config = NativeConfig { endpoint: "https://huggingface.co".to_owned(), ..Default::default() };
        // Static construction cannot fail for this fixed endpoint and does not touch the network.
        let api = NativeApi::new_with_budget(self.tokens.clone(), account, config.endpoint.clone(), self.scheduler.wire_budget().clone())
            .unwrap_or_else(|_| unreachable!("fixed HF endpoint"));
        NativeControl::new(api, config)
    }

    pub(crate) fn native_parts(
        &self,
        connection: &hfdrive_state::ConnectionRecord,
        profile: &hfdrive_auth::AccountProfile,
    ) -> Result<NativePublicationParts, wire::ProtocolError> {
        if connection.account_key != profile.account_key || connection.binding.account_key != profile.account_key {
            return Err(error(wire::ProtocolErrorCode::PermissionDenied, "The connection belongs to a different account"));
        }
        let config = NativeConfig {
            endpoint: "https://huggingface.co".to_owned(),
            xet_cache_dir: self.paths.account(profile.account_key).drive(connection.binding.workspace_id).xet_cache(),
            ..Default::default()
        };
        let api = NativeApi::new_with_budget(
            self.tokens.clone(),
            profile.account_key,
            config.endpoint.clone(),
            self.scheduler.wire_budget().clone(),
        ).unwrap_or_else(|_| unreachable!("fixed HF endpoint"));
        let control = NativeControl::new(api, config);
        let (binding, transport) = if connection.mode == hfdrive_state::ConnectionMode::ReadOnly {
            (None, None)
        } else {
            match &connection.s3_ref {
                None => (None, None),
                Some(reference) => {
                    let identity = hfdrive_publication::AccountIdentity {
                        issuer: &profile.issuer,
                        subject: &profile.subject,
                    };
                    let binding = hfdrive_publication::PublicationBinding::new(&connection.binding, &identity)
                        .map_err(|_| error(wire::ProtocolErrorCode::StorageSetupRequired, "Publication identity does not match the connection"))?;
                    let context = binding.protection_context(*connection.connection_id.as_uuid());
                    let entropy = context.entropy(*connection.connection_id.as_uuid())
                        .map_err(|_| internal_credential())?;
                    let name = hfdrive_windows::credentials::RecordName::new(&reference.0)
                        .map_err(|_| internal_credential())?;
                    let store = hfdrive_windows::credentials::CredentialStore::open(
                        self.paths.account(profile.account_key).credentials().to_path_buf(),
                    ).map_err(|_| internal_credential())?;
                    let plaintext = store.load_record(&name, Some(&entropy)).map_err(|_| {
                        error(wire::ProtocolErrorCode::StorageSetupRequired, "Stored publication credentials must be configured again")
                    })?;
                    let record = hfdrive_publication::SupplementalCredentialRecord::decode(plaintext.expose())
                        .map_err(|_| internal_credential())?;
                    let transport = hfdrive_publication::S3Transport::bind(
                        &connection.binding,
                        &identity,
                        &record,
                        self.scheduler.wire_budget().clone(),
                    ).map_err(|_| internal_credential())?;
                    (Some(binding), Some(transport))
                }
            }
        };
        Ok(NativePublicationParts { control, binding, transport })
    }

    pub(crate) fn remote_for(
        &self,
        connection: &hfdrive_state::ConnectionRecord,
        profile: &hfdrive_auth::AccountProfile,
    ) -> Result<crate::sync::remote::LiveRemote<crate::tokens::DurableTokens, hfdrive_publication::S3Transport>, wire::ProtocolError> {
        let parts = self.native_parts(connection, profile)?;
        let native = parts.control.open_store(connection.binding.clone()).map_err(native_failure)?;
        let publication = match (parts.binding, parts.transport) {
            (Some(binding), Some(transport)) => Some(
                hfdrive_publication::coordinator::PublicationCoordinator::new(
                    binding,
                    native.clone(),
                    transport,
                ).map_err(|_| internal_credential())?
            ),
            _ => None,
        };
        Ok(crate::sync::remote::LiveRemote::new(native, parts.control, publication))
    }

    /// Connects one restored connection entry with remote services freshly
    /// built from its durable binding and credentials. Shared by startup
    /// restore and storage repair so a reconnect never forks the
    /// config/services construction. `replace` drains any existing runtime
    /// first — required when the remote services themselves must change;
    /// without it an already active runtime keeps driving untouched.
    pub(crate) async fn connect_restored_entry(
        &self,
        engine: &crate::sync::SyncEngine<
            crate::sync::remote::LiveRemote<crate::tokens::DurableTokens, hfdrive_publication::S3Transport>,
        >,
        entry: &crate::sync::registry::RestoredConnection,
        profile: &hfdrive_auth::AccountProfile,
        replace: bool,
    ) -> Result<(), wire::ProtocolError> {
        let remote = self.remote_for(&entry.record, profile)?;
        let account = self.state.open_account(profile.account_key).await.map_err(crate::operations::state_error)?;
        let drive = self.paths.account(profile.account_key).drive(entry.record.binding.workspace_id);
        let config = crate::sync::ConnectionConfig {
            connection_id: entry.record.connection_id,
            workspace: entry.record.binding.workspace_id,
            root_item_id: entry.root_item_id,
            device_id: self.device_id,
            root: entry.record.root_path.clone(),
            staging_dir: drive.snapshots(),
            recovery_dir: self.paths.account(profile.account_key).recovery(),
            mode: entry.record.mode,
            start_paused: false,
        };
        let services = crate::sync::ConnectionServices { remote, root_item_id: entry.root_item_id };
        let connected = if replace {
            engine.reconnect(config, services, &entry.validated, account).await
        } else {
            engine.connect(config, services, &entry.validated, account).await
        };
        connected.map_err(engine_failure)?;
        Ok(())
    }

    /// Restores only the currently admitted account. Other accounts retain
    /// their registrations and work but cannot borrow this account's token epoch.
    pub async fn restore_connections(&self) -> Result<Vec<hfdrive_core::ids::ConnectionId>, wire::ProtocolError> {
        let Some(engine) = &self.engine else { return Ok(Vec::new()); };
        let Some(profile) = self.auth.active_profile() else { return Ok(Vec::new()); };
        let mut engine_account = self.engine_account.lock().await;
        if *engine_account != Some(profile.account_key) {
            engine.disconnect_all().await.map_err(engine_failure)?;
            *engine_account = Some(profile.account_key);
        }
        let connections = self.state.reconcile_connections().await.map_err(crate::operations::state_error)?
            .into_iter()
            .filter(|record| record.account_key == profile.account_key)
            .collect::<Vec<_>>();
        let restored = crate::sync::registry::restore_all_account_connections(
            &self.state,
            &connections,
            self.paths.base(),
            &self.user_sid,
        ).await.map_err(|_| error(wire::ProtocolErrorCode::Conflict, "A persisted connection could not be restored safely"))?;
        let mut ids = Vec::new();
        let mut first_error = None;
        for entry in restored {
            let connection_id = entry.record.connection_id;
            // A registry entry is not running unless its CFAPI runtime is
            // actually driving the root: a stale (missing, cancelled or
            // finished) entry is reconnected from its durable binding below.
            if engine
                .health(connection_id)
                .await
                .map(|health| health.runtime.is_active())
                .unwrap_or(false)
            {
                ids.push(connection_id);
                continue;
            }
            let result = self.connect_restored_entry(engine, &entry, &profile, false).await;
            match result {
                Ok(()) => ids.push(connection_id),
                Err(error) => if first_error.is_none() { first_error = Some(error); },
            }
        }
        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(ids)
        }
    }

    pub(crate) async fn set_connections_paused(
        &self,
        connection: Option<uuid::Uuid>,
        paused: bool,
    ) -> Result<Vec<uuid::Uuid>, wire::ProtocolError> {
        let profile = self.current_account()?;
        let requested = connection
            .map(|id| hfdrive_core::ids::ConnectionId::from_uuid(id).map_err(|_| invalid("A nonzero connection identifier is required")))
            .transpose()?;
        let records = self.state.reconcile_connections().await.map_err(crate::operations::state_error)?
            .into_iter()
            .filter(|record| record.account_key == profile.account_key && requested.is_none_or(|id| id == record.connection_id))
            .collect::<Vec<_>>();
        if requested.is_some() && records.is_empty() {
            return Err(error(wire::ProtocolErrorCode::NotFound, "The connection does not exist for this account"));
        }
        let account = self.state.open_account(profile.account_key).await.map_err(crate::operations::state_error)?;
        let mut first_error = None;
        if paused {
            // Pause intent is durable before any runtime is touched: an
            // unavailable root keeps the intent without failing the request.
            for record in &records {
                account.set_settings(
                    format!("connection/{}/paused", record.connection_id),
                    serde_json::Value::Bool(true),
                    None,
                ).await.map_err(crate::operations::state_error)?;
                let Some(engine) = &self.engine else { continue; };
                match engine.pause(record.connection_id).await {
                    Ok(()) | Err(crate::sync::EngineError::UnknownConnection) => {}
                    Err(error) => if first_error.is_none() { first_error = Some(engine_failure(error)); },
                }
            }
            if let Some(error) = first_error {
                return Err(error);
            }
            return Ok(records.into_iter().map(|record| *record.connection_id.as_uuid()).collect());
        }
        // Resume clears the durable pause intent only after the connection
        // actually resumed: restore the existing bindings through the normal
        // restore path first, then resume, then persist. A failed resume keeps
        // the pause intent and returns the real error — never a reported or
        // persisted success.
        let mut resumed_ids = Vec::with_capacity(records.len());
        for record in &records {
            self.restore_connections().await?;
            let resumed = match &self.engine {
                None => false,
                Some(engine) => match engine.resume(record.connection_id).await {
                    Ok(()) => true,
                    Err(crate::sync::EngineError::UnknownConnection) => false,
                    Err(error) => {
                        if first_error.is_none() { first_error = Some(engine_failure(error)); }
                        false
                    }
                },
            };
            if !resumed {
                return Err(first_error.take().unwrap_or_else(|| engine_failure(crate::sync::EngineError::UnknownConnection)));
            }
            account.set_settings(
                format!("connection/{}/paused", record.connection_id),
                serde_json::Value::Bool(false),
                None,
            ).await.map_err(crate::operations::state_error)?;
            resumed_ids.push(*record.connection_id.as_uuid());
        }
        Ok(resumed_ids)
    }

    pub(crate) fn current_account(&self) -> Result<hfdrive_auth::AccountProfile, wire::ProtocolError> {
        self.auth.active_profile().ok_or_else(|| error(wire::ProtocolErrorCode::NeedsSignIn, "An authenticated account is required"))
    }

    pub(crate) fn typed_binding(&self, binding: &wire::RemoteBinding) -> Result<hfdrive_core::storage::DriveBinding, wire::ProtocolError> {
        let account = self.current_account()?;
        let account_key = account.account_key;
        Ok(hfdrive_core::storage::DriveBinding {
            account_key,
            workspace_id: hfdrive_core::ids::WorkspaceId::from_uuid(binding.workspace_id).map_err(|_| invalid("A nonzero workspace identifier is required"))?,
            bucket: hfdrive_core::storage::BucketBinding {
                owner_namespace: Namespace::new(binding.owner_namespace.clone()).map_err(|_| invalid("Invalid canonical owner namespace"))?,
                owner_id: OwnerId::new(binding.owner_id.clone()).map_err(|_| invalid("Invalid stable owner identifier"))?,
                owner_kind: match binding.owner_kind { wire::OwnerKind::Personal => OwnerKind::Personal, wire::OwnerKind::Organization => OwnerKind::Organization },
                bucket_name: BucketName::new(binding.bucket.clone()).map_err(|_| invalid("Invalid bucket name"))?,
                bucket_id: BucketId::new(binding.bucket_id.clone()).map_err(|_| invalid("Invalid stable bucket identifier"))?,
            },
            prefix: hfdrive_core::storage::RemotePrefix::new(binding.prefix.clone()).map_err(|_| invalid("Invalid managed storage prefix"))?,
        })
    }

    pub(crate) fn public_binding(binding: &hfdrive_core::storage::DriveBinding) -> wire::RemoteBinding {
        wire::RemoteBinding {
            owner_namespace: binding.bucket.owner_namespace.as_str().to_owned(), owner_id: binding.bucket.owner_id.as_str().to_owned(),
            owner_kind: match binding.bucket.owner_kind { OwnerKind::Personal => wire::OwnerKind::Personal, OwnerKind::Organization => wire::OwnerKind::Organization },
            bucket: binding.bucket.bucket_name.as_str().to_owned(), bucket_id: binding.bucket.bucket_id.as_str().to_owned(),
            prefix: binding.prefix.as_str().to_owned(), workspace_id: *binding.workspace_id.as_uuid(),
        }
    }

    fn locator(kind: wire::OwnerKind, id: &str, namespace: &str) -> Result<OwnerLocator, wire::ProtocolError> {
        Ok(OwnerLocator {
            owner_id: OwnerId::new(id.to_owned()).map_err(|_| invalid("Invalid stable owner identifier"))?,
            owner_kind: match kind { wire::OwnerKind::Personal => OwnerKind::Personal, wire::OwnerKind::Organization => OwnerKind::Organization },
            claimed_namespace: Some(Namespace::new(namespace.to_owned()).map_err(|_| invalid("Owner has no verified canonical namespace"))?),
        })
    }

    pub(crate) async fn list_owners(&self, request: wire::ListOwnersRequest) -> Result<wire::ListOwnersResult, wire::ProtocolError> {
        if !(1..=200).contains(&request.limit) { return Err(invalid("Owner page size must be between 1 and 200")); }
        let profile = self.current_account()?;
        let control = self.native_control(profile.account_key);
        let lease = control.capture_lease().map_err(native_failure)?;
        let resolved = control.whoami_owners(&lease, &self.operations.cancellation).await.map_err(native_failure)?;
        let mut items = Vec::with_capacity(resolved.len());
        for owner in resolved {
            items.push(wire::Owner {
                owner_kind: match owner.owner_kind { OwnerKind::Personal => wire::OwnerKind::Personal, OwnerKind::Organization => wire::OwnerKind::Organization },
                owner_id: owner.owner_id.as_str().to_owned(),
                namespace: owner.namespace.as_ref().map(|ns| ns.as_str().to_owned()),
                display_name: owner.display_name,
                role: None,
                restrictions: Vec::new(),
                can_create: owner.namespace.is_some(),
            });
        }
        crate::account::owners(&profile, self.auth.snapshot().revision, &request, &items)
    }

    pub(crate) async fn list_buckets(&self, request: wire::ListBucketsRequest) -> Result<wire::ListBucketsResult, wire::ProtocolError> {
        if !(1..=200).contains(&request.limit) { return Err(invalid("Bucket page size must be between 1 and 200")); }
        let account = self.current_account()?;
        let control = self.native_control(account.account_key);
        let lease = control.capture_lease().map_err(native_failure)?;
        let owner = self.resolve_namespace_owner(&control, &lease, &request.owner_namespace).await?;
        let buckets = control.list_buckets(&lease, &owner.owner_ref(), &self.operations.cancellation).await.map_err(native_failure)?;
        let start = bucket_cursor(&request.cursor, account.account_key, request.owner_namespace.as_bytes(), buckets.len())?;
        let end = start.saturating_add(request.limit as usize).min(buckets.len());
        let items = buckets.get(start..end).ok_or_else(|| invalid("Invalid bucket continuation cursor"))?.iter().map(public_bucket).collect();
        let next_cursor = (end < buckets.len()).then(|| bucket_cursor_value(account.account_key, request.owner_namespace.as_bytes(), end));
        Ok(wire::ListBucketsResult { items, next_cursor })
    }

    pub(crate) async fn create_bucket(&self, request: wire::CreateBucketRequest) -> Result<wire::CreateBucketResult, wire::ProtocolError> {
        let account = self.current_account()?;
        let control = self.native_control(account.account_key);
        let lease = control.capture_lease().map_err(native_failure)?;
        let locator = Self::locator(request.owner_kind, &request.owner_id, &request.owner_namespace)?;
        let owner = control.verify_owner(&lease, &locator, &self.operations.cancellation).await.map_err(native_failure)?;
        let name = BucketName::new(request.bucket_name.clone()).map_err(|_| invalid("Invalid bucket name"))?;
        let region = request.region.as_deref().map(|region| match region {
            "us" => Ok(hfdrive_hf::BucketRegion::Us),
            "eu" => Ok(hfdrive_hf::BucketRegion::Eu),
            _ => Err(invalid("Unsupported bucket region")),
        }).transpose()?;
        let summary = control.create_bucket(&lease, &owner, &name, &CreateBucket { region, ..Default::default() }, &self.operations.cancellation)
            .await.map_err(native_failure)?;
        if let Some(binding) = self.pending_creation_binding(&request, &summary).await? {
            let Some(record) = self.state.get_setup(binding).await.map_err(crate::operations::state_error)? else {
                return Err(error(wire::ProtocolErrorCode::NotFound, "The setup awaiting bucket creation is no longer present"));
            };
            self.state.record_created_resources(record.setup_id, vec![hfdrive_state::CreatedResource {
                kind: "bucket".to_owned(), identity: summary.binding.bucket_id.to_string(),
                note: Some(summary.binding.bucket_name.as_str().to_owned()),
            }]).await.map_err(crate::operations::state_error)?;
        }
        Ok(wire::CreateBucketResult { bucket: public_bucket(&summary), completed: true })
    }

    async fn pending_creation_binding(&self, request: &wire::CreateBucketRequest, summary: &BucketSummary) -> Result<Option<hfdrive_core::ids::SetupId>, wire::ProtocolError> {
        let setups = self.state.list_setups(Some(self.current_account()?.account_key)).await.map_err(crate::operations::state_error)?;
        for setup in setups {
            if setup.bucket_creation_operation_id.as_ref().map(|id| *id.as_uuid()) == Some(request.operation_id)
                && setup.status == hfdrive_state::SetupStatus::Active
                && setup.binding.bucket.owner_id.as_str() == summary.binding.owner_id.as_str()
                && setup.binding.bucket.bucket_name.as_str() == summary.binding.bucket_name.as_str() {
                return Ok(Some(setup.setup_id));
            }
        }
        Ok(None)
    }

    async fn resolve_namespace_owner(&self, control: &NativeControl<crate::tokens::DurableTokens>, lease: &hfdrive_hf::NativeLease, namespace: &str) -> Result<hfdrive_hf::VerifiedOwner, wire::ProtocolError> {
        let owners = control.whoami_owners(lease, &self.operations.cancellation).await.map_err(native_failure)?;
        let mut matching = owners.into_iter().filter(|owner| owner.namespace.as_ref().is_some_and(|ns| ns.as_str() == namespace));
        let owner = matching.next().ok_or_else(|| error(wire::ProtocolErrorCode::PermissionDenied, "The namespace is not a canonical owner of this account"))?;
        if matching.next().is_some() { return Err(error(wire::ProtocolErrorCode::Conflict, "The namespace has ambiguous stable owner identities")); }
        control.verify_owner(lease, &OwnerLocator {
            owner_id: owner.owner_id, owner_kind: owner.owner_kind, claimed_namespace: owner.namespace,
        }, &self.operations.cancellation).await.map_err(native_failure)
    }
}

pub(crate) fn public_bucket(summary: &BucketSummary) -> wire::Bucket {
    wire::Bucket {
        bucket_id: summary.binding.bucket_id.as_str().to_owned(), name: summary.binding.bucket_name.as_str().to_owned(),
        namespace: summary.binding.owner_namespace.as_str().to_owned(),
        visibility: if summary.private { wire::Visibility::Private } else { wire::Visibility::Public },
    }
}

fn bucket_cursor_value(account: hfdrive_core::ids::AccountKey, namespace: &[u8], offset: usize) -> String {
    format!("buckets-v1:{account}:{}:{offset}", hex::encode(namespace))
}

fn bucket_cursor(cursor: &Option<String>, account: hfdrive_core::ids::AccountKey, namespace: &[u8], total: usize) -> Result<usize, wire::ProtocolError> {
    let Some(cursor) = cursor else { return Ok(0); };
    let mut parts = cursor.split(':');
    if parts.next() != Some("buckets-v1") || parts.next() != Some(account.to_string().as_str())
        || parts.next() != Some(hex::encode(namespace).as_str()) { return Err(invalid("Bucket continuation cursor is not bound to this owner/account")); }
    let offset = parts.next().and_then(|value| value.parse::<usize>().ok()).filter(|_| parts.next().is_none()).ok_or_else(|| invalid("Invalid bucket continuation cursor"))?;
    if offset > total { return Err(error(wire::ProtocolErrorCode::Conflict, "Bucket listing changed; reload the first page")); }
    Ok(offset)
}

pub(crate) fn invalid(message: &'static str) -> wire::ProtocolError { error(wire::ProtocolErrorCode::InvalidRequest, message) }

pub(crate) fn engine_failure(error_value: crate::sync::EngineError) -> wire::ProtocolError {
    use crate::sync::{EngineError, registry::AdmissionError};
    match error_value {
        EngineError::UnknownConnection => error(wire::ProtocolErrorCode::NotFound, "The connection is not running"),
        EngineError::UnknownConflict => error(wire::ProtocolErrorCode::NotFound, "The conflict or its preserved evidence is unavailable"),
        EngineError::InvalidResolution => error(wire::ProtocolErrorCode::InvalidRequest, "The requested conflict resolution is not valid for this item"),
        EngineError::Admission(AdmissionError::LocalRoot(reason)) => wire::ProtocolError {
            code: wire::ProtocolErrorCode::LocalRootInvalid,
            message: reason,
            retry_after_ms: None,
        },
        EngineError::Admission(AdmissionError::State(error)) | EngineError::State(error) => crate::operations::state_error(error),
        EngineError::Admission(_) => error(wire::ProtocolErrorCode::Conflict, "The connection root or registration conflicts with its persisted identity"),
        EngineError::NeedsSignIn => error(wire::ProtocolErrorCode::NeedsSignIn, "Sign-in is required"),
        EngineError::ReadOnly => error(wire::ProtocolErrorCode::ReadOnly, "The connection is read-only"),
        EngineError::UnlinkBlocked(_) => error(wire::ProtocolErrorCode::Conflict, "Unlink is blocked until local content is preserved"),
        EngineError::Disconnect(_) => crate::operations::internal(),
        EngineError::Publish(_) => crate::operations::internal(),
    }
}

pub(crate) fn remote_failure(error_value: crate::sync::RemoteError) -> wire::ProtocolError {
    use crate::sync::RemoteError;
    let (code, message) = match error_value {
        RemoteError::NeedsSignIn => (wire::ProtocolErrorCode::NeedsSignIn, "Sign-in is required"),
        RemoteError::PermissionDenied => (wire::ProtocolErrorCode::PermissionDenied, "Remote access was denied"),
        RemoteError::StorageSetupRequired => (wire::ProtocolErrorCode::StorageSetupRequired, "Supplemental publication setup is required"),
        RemoteError::ReadOnly => (wire::ProtocolErrorCode::ReadOnly, "The connection is read-only"),
        RemoteError::UnsupportedFormat => (wire::ProtocolErrorCode::UnsupportedFormat, "The remote format is unsupported"),
        RemoteError::RemoteContentUnavailable => (wire::ProtocolErrorCode::RemoteContentUnavailable, "A referenced remote object is unavailable"),
        RemoteError::Transport | RemoteError::SearchIncomplete => (wire::ProtocolErrorCode::Timeout, "Remote transport failed; inspect before retrying"),
        RemoteError::RateLimited { retry_after_seconds } => {
            return wire::ProtocolError {
                code: wire::ProtocolErrorCode::Busy,
                message: "Remote storage is rate limited".to_owned(),
                retry_after_ms: retry_after_seconds.and_then(|value| value.checked_mul(1000)),
            };
        }
        RemoteError::Cancelled => (wire::ProtocolErrorCode::Cancelled, "The remote operation was cancelled"),
        RemoteError::SourceChanged => (wire::ProtocolErrorCode::Conflict, "The staged source changed"),
        RemoteError::Rejected { .. } | RemoteError::InvalidResponse => (wire::ProtocolErrorCode::Internal, "The remote service rejected or invalidated the operation"),
    };
    error(code, message)
}

fn internal_credential() -> wire::ProtocolError {
    error(wire::ProtocolErrorCode::StorageSetupRequired, "Publication credentials are not valid for this connection")
}

pub(crate) fn native_failure(error_value: NativeError) -> wire::ProtocolError {
    use wire::ProtocolErrorCode as Code;
    let (code, message) = match error_value {
        NativeError::NeedsSignIn => (Code::NeedsSignIn, "Sign-in is required"),
        NativeError::PermissionDenied => (Code::PermissionDenied, "Storage access was denied"),
        NativeError::RemoteContentUnavailable => (Code::RemoteContentUnavailable, "Remote content is unavailable"),
        NativeError::XetRequired => (Code::UnsupportedFormat, "Native Xet content is required"),
        NativeError::InvalidRange | NativeError::InvalidRequest { .. } => (Code::InvalidRequest, "The native storage request was rejected"),
        NativeError::Cancelled => (Code::Cancelled, "The native operation was cancelled"),
        NativeError::RateLimited { retry_after_seconds } => {
            return wire::ProtocolError { code: Code::Busy, message: "Native storage was rate limited".to_owned(), retry_after_ms: retry_after_seconds.and_then(|value| value.checked_mul(1000)) };
        }
        NativeError::Transport => (Code::Timeout, "Native transport failed; inspect the operation before retrying"),
        NativeError::InvalidResponse | NativeError::TooManyEntries => (Code::Internal, "The native service response was invalid or exceeded its bound"),
        NativeError::AlreadyExists => (Code::Conflict, "The bucket already exists; it was not adopted"),
        NativeError::IdentityMismatch => (Code::Conflict, "The selected identity no longer matches the native service"),
        NativeError::SourceChanged => (Code::Conflict, "The staged source changed; recapture is required"),
    };
    error(code, message)
}
