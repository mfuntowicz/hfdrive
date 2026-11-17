//! Pin, free-space and selective-sync controls over durable registry state.

use std::collections::{BTreeSet, HashMap};

use hfdrive_core::ids::{ConnectionId, ItemId, OperationId};
use hfdrive_core::storage::{BucketName, Sha256Digest};
use hfdrive_hf::OwnerLocator;
use hfdrive_protocol as wire;
use hfdrive_protocol::RequestMethod;
use hfdrive_state::OperationState;

use crate::{Provider, operations::error, storage::{engine_failure, invalid}};

/// `affected_files` is producer-bounded: the reviewed preview never grows past
/// this many entries even when the connection holds more unavailable files.
const AFFECTED_FILE_LIMIT: usize = 200;

impl Provider {
    /// Reviews an unlink without mutating anything. The preview id **is** this
    /// mutation's operation id: its committed operation receipt is the durable
    /// preview that `unlink` must later accept.
    ///
    /// `RemoveUnavailable` is the explicit deleted-bucket mode. It may only
    /// preview while the connection's exact stable bucket is gone, and it must
    /// name every byte it would abandon.
    pub(crate) async fn prepare_unlink(
        &self,
        request: wire::PrepareUnlinkRequest,
    ) -> Result<wire::PrepareUnlinkResult, wire::ProtocolError> {
        let connection = ConnectionId::from_uuid(request.connection_id)
            .map_err(|_| invalid("A nonzero connection identifier is required"))?;
        let preview_id = OperationId::from_uuid(request.operation_id)
            .map_err(|_| invalid("A nonzero operation identifier is required"))?;
        let (profile, record) = self.unlink_connection(connection).await?;
        if request.mode == wire::UnlinkMode::RemoveUnavailable {
            self.require_bucket_gone(&profile, &record).await?;
        }
        let engine = self.engine.as_ref().ok_or_else(crate::operations::internal)?;
        let plan = engine.prepare_unlink(connection, engine_mode(request.mode)).await.map_err(engine_failure)?;
        let mut blocking_reasons = plan.blockers.clone();
        // `RemoveUnavailable` abandons bytes instead of preserving them, so
        // everything it cannot abandon cleanly blocks that mode outright.
        if request.mode == wire::UnlinkMode::RemoveUnavailable {
            for (count, reason) in [
                (plan.partial_files, "files are only partially resident"),
                (plan.dirty_files, "files retain unsynchronized local changes"),
                (plan.conflict_files, "files have unresolved conflicts"),
            ] {
                if count > 0 {
                    let reason = format!("{count} {reason}");
                    if !blocking_reasons.contains(&reason) {
                        blocking_reasons.push(reason);
                    }
                }
            }
        }
        let safe_to_unlink = match request.mode {
            wire::UnlinkMode::DisconnectKeepRegistration => true,
            wire::UnlinkMode::SafeRemove => plan.blockers.is_empty(),
            wire::UnlinkMode::RemoveUnavailable => blocking_reasons.is_empty(),
        };
        Ok(wire::PrepareUnlinkResult {
            safe_to_unlink,
            online_only_files: plan.online_only_files,
            partial_files: plan.partial_files,
            dirty_files: plan.dirty_files,
            conflict_files: plan.conflict_files,
            required_export_bytes: plan.required_export_bytes,
            blocking_reasons,
            preview_id: *preview_id.as_uuid(),
            // Engine fingerprint over the full reviewed plan, including the
            // exact affected identities; any change rotates consent.
            preview_fingerprint: plan.preview_fingerprint(),
            // Only abandonment destroys bytes that exist solely in managed
            // storage; safe removal hydrates/exports them first.
            online_only_data_loss: request.mode == wire::UnlinkMode::RemoveUnavailable && !plan.abandon.is_empty(),
            // The reviewed identities the unlink touches as files: managed
            // directories carry no bytes (`version_id: None` in the engine's
            // record) and are covered by the counts/reasons above.
            affected_files: plan.abandon.iter()
                .filter(|file| file.version_id.is_some())
                .take(AFFECTED_FILE_LIMIT)
                .map(|file| wire::UnlinkFileResult {
                    path: record.root_path.join(&file.path).to_string_lossy().into_owned(),
                    size: file.size,
                    partial: file.partial,
                }).collect(),
        })
    }

    /// Accepts one reviewed preview and executes the unlink. The committed
    /// `prepare_unlink` receipt binds the connection and the previewed mode;
    /// the engine fingerprint must still match the current plan and file
    /// identities before anything is removed. A wrong, stale or missing
    /// preview is [`wire::ProtocolErrorCode::PreviewChanged`] — the caller
    /// reviews a fresh preview, never a guess.
    pub(crate) async fn unlink(
        &self,
        request: wire::UnlinkRequest,
    ) -> Result<wire::UnlinkResult, wire::ProtocolError> {
        let connection = ConnectionId::from_uuid(request.connection_id)
            .map_err(|_| invalid("A nonzero connection identifier is required"))?;
        let operation_id = OperationId::from_uuid(request.operation_id)
            .map_err(|_| invalid("A nonzero operation identifier is required"))?;
        let preview_id = OperationId::from_uuid(request.preview_id)
            .map_err(|_| invalid("A nonzero preview identifier is required"))?;
        if operation_id == preview_id {
            return Err(invalid("The unlink mutation needs a fresh operation identifier; the preview identifier cannot become the mutation"));
        }
        let (profile, record) = self.unlink_connection(connection).await?;
        let receipt = self.load_unlink_preview(&profile, connection, preview_id, request.mode).await?;
        let engine = self.engine.as_ref().ok_or_else(crate::operations::internal)?;
        let plan = engine.prepare_unlink(connection, engine_mode(request.mode)).await.map_err(engine_failure)?;
        if plan.preview_fingerprint() != receipt.preview_fingerprint {
            return Err(error(wire::ProtocolErrorCode::PreviewChanged,
                "Preview inputs changed; review the refreshed preview before removing anything"));
        }
        // Mode-specific safety decisions are explicit here, not implied by the
        // engine's internals. `RemoveUnavailable` only abandons clean
        // zero-residency entries; anything partially resident, dirty or
        // conflicted is refused up front with the safe reason instead of
        // surfacing later as a generic engine conflict.
        if request.mode == wire::UnlinkMode::RemoveUnavailable {
            let mut reasons = Vec::new();
            for (count, reason) in [
                (plan.partial_files, "partially resident files cannot be abandoned; hydrate, export or resolve them first"),
                (plan.dirty_files, "files with unsynchronized local changes must be preserved before removal"),
                (plan.conflict_files, "unresolved conflicts must be resolved before removal"),
            ] {
                if count > 0 {
                    reasons.push(format!("{count}: {reason}"));
                }
            }
            if !reasons.is_empty() {
                let mut message = String::from("This removal would lose unsynchronized content: ");
                message.push_str(&reasons.join("; "));
                return Err(wire::ProtocolError {
                    code: wire::ProtocolErrorCode::Conflict,
                    message,
                    retry_after_ms: None,
                });
            }
        }
        // Consent is required exactly when proceeding would destroy bytes that
        // exist only in managed storage — judged from both the reviewed
        // receipt and the current plan (the fingerprint match binds them, but
        // the requirement is enforced independently of that agreement).
        if (receipt.online_only_data_loss || plan.requires_abandon_consent()) && !request.accept_online_only_data_loss {
            return Err(invalid("Accepting this preview discards online-only bytes and requires explicit online-only data-loss consent"));
        }
        // Execute re-checks the deleted-bucket gate on the same identities: a
        // recreated or still-live bucket can never authorize abandonment.
        if request.mode == wire::UnlinkMode::RemoveUnavailable {
            self.require_bucket_gone(&profile, &record).await?;
        }
        let outcome = engine.execute_unlink(connection, &plan, engine_mode(request.mode)).await.map_err(engine_failure)?;
        // The engine owns durable removal: it unregisters, verifies
        // registration absence and drops the connection rows itself (removal
        // modes only). Disconnect-keep-registration deliberately retains all
        // state for explicit recovery.
        Ok(wire::UnlinkResult {
            connection_id: request.connection_id,
            unregistered: outcome == crate::sync::UnlinkOutcome::Unlinked,
            retained_for_recovery: outcome == crate::sync::UnlinkOutcome::DisconnectedKeptRegistration,
        })
    }

    /// The current account and its connection record on one admitted identity.
    /// Unlink never acts on a connection record owned by another account.
    async fn unlink_connection(
        &self,
        connection: ConnectionId,
    ) -> Result<(hfdrive_auth::AccountProfile, hfdrive_state::ConnectionRecord), wire::ProtocolError> {
        let profile = self.current_account()?;
        let record = self.state.reconcile_connections().await.map_err(crate::operations::state_error)?
            .into_iter()
            .find(|record| record.connection_id == connection && record.account_key == profile.account_key)
            .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The connection does not exist for this account"))?;
        Ok((profile, record))
    }

    /// `RemoveUnavailable` gate: the connection's exact stable bucket must be
    /// **gone** (`resolve_bucket` yields `None`) before any bytes may be
    /// abandoned. A live bucket — even a recreated one — is a conflict; every
    /// other resolution error (sign-in, denial, transport) propagates and can
    /// never authorize abandonment.
    async fn require_bucket_gone(
        &self,
        profile: &hfdrive_auth::AccountProfile,
        record: &hfdrive_state::ConnectionRecord,
    ) -> Result<(), wire::ProtocolError> {
        let control = self.native_control(profile.account_key);
        let lease = control.capture_lease().map_err(crate::storage::native_failure)?;
        let bucket = &record.binding.bucket;
        let owner = control.verify_owner(&lease, &OwnerLocator {
            owner_id: bucket.owner_id.clone(),
            owner_kind: bucket.owner_kind,
            claimed_namespace: Some(bucket.owner_namespace.clone()),
        }, &self.operations.cancellation).await.map_err(crate::storage::native_failure)?;
        let name = BucketName::new(bucket.bucket_name.as_str().to_owned())
            .map_err(|_| invalid("Invalid bucket name"))?;
        let live = control.resolve_bucket(
            &lease,
            &owner.owner_ref(),
            &name,
            Some(&bucket.bucket_id),
            &self.operations.cancellation,
        ).await.map_err(crate::storage::native_failure)?;
        if live.is_some() {
            return Err(error(wire::ProtocolErrorCode::Conflict,
                "The exact bucket still exists; this mode only applies to a deleted bucket and never removes live storage"));
        }
        Ok(())
    }

    /// Loads the committed `prepare_unlink` receipt for one reviewed preview.
    /// The receipt binds the connection **and** the previewed mode through the
    /// persisted request digest; anything wrong, stale or missing surfaces as
    /// [`wire::ProtocolErrorCode::PreviewChanged`] so the caller reviews a
    /// fresh preview instead of guessing.
    async fn load_unlink_preview(
        &self,
        profile: &hfdrive_auth::AccountProfile,
        connection: ConnectionId,
        preview_id: OperationId,
        mode: wire::UnlinkMode,
    ) -> Result<UnlinkPreviewReceipt, wire::ProtocolError> {
        let changed = |message: &'static str| error(wire::ProtocolErrorCode::PreviewChanged, message);
        let record = self.state.get_operation(preview_id).await.map_err(crate::operations::state_error)?
            .ok_or_else(|| changed("The reviewed preview is missing; prepare and review a fresh one"))?;
        if record.state != OperationState::Committed
            || record.kind != wire::PrepareUnlinkRequest::METHOD
            || record.connection_id != Some(connection)
            || record.account_key != Some(profile.account_key)
        {
            return Err(changed("The preview is stale or belongs to another connection; prepare and review a fresh one"));
        }
        // The ledger keeps only the request digest, so re-derive it from the
        // identity the caller now claims: the same `PrepareUnlinkRequest`
        // (preview id == operation id, connection, mode) must hash identically.
        let previewed = wire::PrepareUnlinkRequest {
            operation_id: *preview_id.as_uuid(),
            connection_id: *connection.as_uuid(),
            mode,
        };
        let body = serde_json::to_value(&previewed).map_err(|_| crate::operations::internal())?;
        let mut material = Vec::new();
        material.extend_from_slice(wire::PrepareUnlinkRequest::METHOD.as_bytes());
        material.push(0);
        material.extend_from_slice(body.to_string().as_bytes());
        if Sha256Digest::of(&material) != record.request_digest {
            return Err(changed("The preview was prepared for another mode or connection; prepare and review a fresh one"));
        }
        let result: wire::PrepareUnlinkResult = serde_json::from_value(
            record.result_json.ok_or_else(|| changed("The preview receipt carries no reviewed result"))?,
        ).map_err(|_| changed("The preview receipt is not a reviewed unlink preview"))?;
        if result.preview_id != *preview_id.as_uuid() {
            return Err(changed("The preview receipt does not match this preview"));
        }
        Ok(UnlinkPreviewReceipt {
            preview_fingerprint: result.preview_fingerprint,
            online_only_data_loss: result.online_only_data_loss,
        })
    }

    pub(crate) async fn set_pin(
        &self,
        request: wire::SetPinRequest,
    ) -> Result<wire::SetPinResult, wire::ProtocolError> {
        let connection = ConnectionId::from_uuid(request.connection_id)
            .map_err(|_| invalid("A nonzero connection identifier is required"))?;
        let account = self.account_connection(connection).await?;
        let pin = request.mode == wire::PinMode::Pin;
        let targets = target_items(&account, connection, request.item_id).await?;
        let engine = self.engine.as_ref().ok_or_else(crate::operations::internal)?;
        for item in targets {
            engine.set_pin(connection, item, pin).await.map_err(engine_failure)?;
        }
        let counts = account.storage_counts(connection).await.map_err(crate::operations::state_error)?;
        Ok(wire::SetPinResult {
            pin_state: if counts.pin_requests == 0 {
                wire::PinState::Unpinned
            } else if counts.pinned_files < counts.pin_requests {
                wire::PinState::Partial
            } else {
                wire::PinState::Pinned
            },
            pinned_files: counts.pinned_files,
        })
    }

    pub(crate) async fn free_space(
        &self,
        request: wire::FreeSpaceRequest,
    ) -> Result<wire::FreeSpaceResult, wire::ProtocolError> {
        let connection = ConnectionId::from_uuid(request.connection_id)
            .map_err(|_| invalid("A nonzero connection identifier is required"))?;
        let account = self.account_connection(connection).await?;
        let targets = target_items(&account, connection, request.item_id).await?;
        let engine = self.engine.as_ref().ok_or_else(crate::operations::internal)?;
        // The connection root is resolved once per request: it does not vary by
        // item, and re-resolving it per item would rerun the whole connection
        // reconciliation for every dehydrated file.
        let root = self.connection_root(connection).await?;
        let mut freed_bytes = 0u64;
        let mut dehydrated_files = 0u32;
        for item in targets {
            let observation = account.observation(connection, item).await.map_err(crate::operations::state_error)?;
            if request.mode == wire::FreeSpaceMode::ExceptPinned
                && observation.as_ref().is_some_and(|observation| observation.pin_requested)
            {
                continue;
            }
            if request.mode == wire::FreeSpaceMode::All
                && observation.as_ref().is_some_and(|observation| observation.pin_requested)
            {
                engine.set_pin(connection, item, false).await.map_err(engine_failure)?;
            }
            let path = crate::sync::controller::registry_path(&account, connection, item).await
                .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The item has no local path"))?;
            let live = hfdrive_windows::filesystem::volume::query_file_state(&root.join(&path))
                .map_err(|_| error(wire::ProtocolErrorCode::LocalRootInvalid, "The local file state is unavailable"))?;
            engine.free_space(connection, item).await.map_err(engine_failure)?;
            freed_bytes = freed_bytes.checked_add(live.size)
                .ok_or_else(|| error(wire::ProtocolErrorCode::Internal, "Released-byte total overflowed"))?;
            dehydrated_files = dehydrated_files.checked_add(1)
                .ok_or_else(|| error(wire::ProtocolErrorCode::Internal, "Released-file total overflowed"))?;
        }
        Ok(wire::FreeSpaceResult { freed_bytes, dehydrated_files })
    }

    pub(crate) async fn set_selective_sync(
        &self,
        request: wire::SetSelectiveSyncRequest,
    ) -> Result<wire::SetSelectiveSyncResult, wire::ProtocolError> {
        let connection = ConnectionId::from_uuid(request.connection_id)
            .map_err(|_| invalid("A nonzero connection identifier is required"))?;
        let account = self.account_connection(connection).await?;
        let requested = request.exclude_item_ids.into_iter().map(|id| {
            ItemId::from_uuid(id).map_err(|_| invalid("A nonzero excluded item identifier is required"))
        }).collect::<Result<BTreeSet<_>, _>>()?;
        let engine = self.engine.as_ref().ok_or_else(crate::operations::internal)?;
        let parents: HashMap<_, _> = account.list_all_items(connection, true).await
            .map_err(crate::operations::state_error)?
            .into_iter().map(|item| (item.item_id, item.parent_id)).collect();
        if requested.iter().any(|item| !parents.contains_key(item)) {
            return Err(error(wire::ProtocolErrorCode::NotFound, "An excluded item does not exist"));
        }
        let existing = account.excluded_observations(connection).await.map_err(crate::operations::state_error)?;
        // Stored flags cover descendants too. Keeping an excluded ancestor must
        // not spuriously reinclude its children and erase their presence evidence.
        let included: BTreeSet<_> = existing.into_iter()
            .map(|observation| observation.item_id)
            .filter(|item| !selection_contains(Some(*item), &requested, &parents))
            .collect();
        for item in &included {
            if !selection_contains(parents.get(item).copied().flatten(), &included, &parents) {
                engine.set_excluded(connection, *item, false).await.map_err(selective_sync_failure)?;
            }
        }
        // Inclusion precedes exclusion when an old selected ancestor is replaced
        // by a narrower subtree. Every transition uses the runtime's serialized,
        // durable subtree guard, generation reset and rescan/reconcile scheduling.
        for item in &requested {
            if !selection_contains(parents.get(item).copied().flatten(), &requested, &parents) {
                engine.set_excluded(connection, *item, true).await.map_err(selective_sync_failure)?;
            }
        }
        let effective = account.excluded_observations(connection).await.map_err(crate::operations::state_error)?;
        Ok(wire::SetSelectiveSyncResult {
            excluded_item_ids: effective.into_iter().map(|observation| *observation.item_id.as_uuid()).collect(),
            retained_dirty_item_ids: Vec::new(),
        })
    }

    async fn account_connection(
        &self,
        connection: ConnectionId,
    ) -> Result<hfdrive_state::AccountStore, wire::ProtocolError> {
        let profile = self.current_account()?;
        self.state.reconcile_connections().await.map_err(crate::operations::state_error)?
            .into_iter()
            .find(|record| record.connection_id == connection && record.account_key == profile.account_key)
            .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The connection does not exist for this account"))?;
        self.state.open_account(profile.account_key).await.map_err(crate::operations::state_error)
    }

    async fn connection_root(&self, connection: ConnectionId) -> Result<std::path::PathBuf, wire::ProtocolError> {
        self.state.reconcile_connections().await.map_err(crate::operations::state_error)?
            .into_iter()
            .find(|record| record.connection_id == connection)
            .map(|record| record.root_path)
            .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The connection does not exist"))
    }
}

fn selection_contains(
    mut item: Option<ItemId>,
    selected: &BTreeSet<ItemId>,
    parents: &HashMap<ItemId, Option<ItemId>>,
) -> bool {
    // The catalog is acyclic; the bound also prevents damaged local ancestry
    // from hanging an IPC request.
    for _ in 0..=parents.len() {
        let Some(current) = item else { return false; };
        if selected.contains(&current) { return true; }
        item = parents.get(&current).copied().flatten();
    }
    false
}

fn selective_sync_failure(failure: crate::sync::EngineError) -> wire::ProtocolError {
    match failure {
        crate::sync::EngineError::Publish(crate::sync::publish::PublishError::LocalApply(reason)) =>
            error(wire::ProtocolErrorCode::Conflict, reason),
        crate::sync::EngineError::Publish(crate::sync::publish::PublishError::State(failure)) =>
            crate::operations::state_error(failure),
        failure => engine_failure(failure),
    }
}

/// Committed preview identity re-derived from the `prepare_unlink` receipt.
struct UnlinkPreviewReceipt {
    preview_fingerprint: String,
    online_only_data_loss: bool,
}

/// The engine's internal removal mode mirrors the wire mode: removal keeps the
/// selected policy (safe preservation versus explicit abandonment), and only
/// `DisconnectKeepRegistration` disconnects without unregistering. The accept
/// path calls `execute_unlink(connection, plan, mode)`, never a
/// keep-registration boolean.
fn engine_mode(mode: wire::UnlinkMode) -> crate::sync::UnlinkMode {
    match mode {
        wire::UnlinkMode::SafeRemove => crate::sync::UnlinkMode::SafeRemove,
        wire::UnlinkMode::RemoveUnavailable => crate::sync::UnlinkMode::RemoveUnavailable,
        wire::UnlinkMode::DisconnectKeepRegistration => crate::sync::UnlinkMode::DisconnectKeepRegistration,
    }
}

async fn target_items(
    account: &hfdrive_state::AccountStore,
    connection: ConnectionId,
    target: Option<uuid::Uuid>,
) -> Result<Vec<ItemId>, wire::ProtocolError> {
    let target = match target {
        Some(id) => ItemId::from_uuid(id).map_err(|_| invalid("A nonzero target item identifier is required"))?,
        None => {
            let record = account.list_connections().await.map_err(crate::operations::state_error)?
                .into_iter()
                .find(|record| record.connection_id == connection)
                .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The connection does not exist"))?;
            record.config_json.get("root_item_id").and_then(serde_json::Value::as_str)
                .and_then(|value| value.parse::<ItemId>().ok())
                .ok_or_else(|| error(wire::ProtocolErrorCode::UnsupportedFormat, "The connection lacks durable root identity"))?
        }
    };
    let all = account.list_all_items(connection, false).await.map_err(crate::operations::state_error)?;
    if !all.iter().any(|item| item.item_id == target) {
        return Err(error(wire::ProtocolErrorCode::NotFound, "The target item does not exist"));
    }
    let parents: HashMap<ItemId, Option<ItemId>> = all.iter().map(|item| (item.item_id, item.parent_id)).collect();
    Ok(all.into_iter().filter(|item| {
        item.kind == hfdrive_state::ItemKind::File && {
            let mut current = Some(item.item_id);
            let mut included = false;
            while let Some(id) = current {
                if id == target {
                    included = true;
                    break;
                }
                let Some(parent) = parents.get(&id).copied().flatten() else { break; };
                current = Some(parent);
            }
            included
        }
    }).map(|item| item.item_id).collect())
}
