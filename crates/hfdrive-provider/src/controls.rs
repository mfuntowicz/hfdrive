//! Pin, free-space and selective-sync controls over durable registry state.

use std::collections::{BTreeSet, HashMap};

use hfdrive_core::ids::{ConnectionId, ItemId};
use hfdrive_protocol as wire;

use crate::{Provider, operations::error, storage::{engine_failure, invalid}};

impl Provider {
    pub(crate) async fn prepare_unlink(
        &self,
        request: wire::PrepareUnlinkRequest,
    ) -> Result<wire::PrepareUnlinkResult, wire::ProtocolError> {
        let connection = ConnectionId::from_uuid(request.connection_id)
            .map_err(|_| invalid("A nonzero connection identifier is required"))?;
        let engine = self.engine.as_ref().ok_or_else(crate::operations::internal)?;
        let plan = engine.prepare_unlink(connection).await.map_err(engine_failure)?;
        let keep_registration = request.mode == wire::UnlinkMode::DisconnectKeepRegistration;
        Ok(wire::PrepareUnlinkResult {
            safe_to_unlink: keep_registration || plan.blockers.is_empty(),
            online_only_files: plan.online_only_files,
            partial_files: plan.partial_files,
            dirty_files: plan.dirty_files,
            conflict_files: plan.conflict_files,
            required_export_bytes: plan.required_export_bytes,
            blocking_reasons: plan.blockers,
        })
    }

    pub(crate) async fn unlink(
        &self,
        request: wire::UnlinkRequest,
    ) -> Result<wire::UnlinkResult, wire::ProtocolError> {
        let connection = ConnectionId::from_uuid(request.connection_id)
            .map_err(|_| invalid("A nonzero connection identifier is required"))?;
        let keep_registration = request.mode == wire::UnlinkMode::DisconnectKeepRegistration;
        let engine = self.engine.as_ref().ok_or_else(crate::operations::internal)?;
        let plan = engine.prepare_unlink(connection).await.map_err(engine_failure)?;
        let outcome = engine.execute_unlink(connection, &plan, keep_registration).await.map_err(engine_failure)?;
        Ok(wire::UnlinkResult {
            connection_id: request.connection_id,
            unregistered: outcome == crate::sync::UnlinkOutcome::Unlinked,
            retained_for_recovery: outcome == crate::sync::UnlinkOutcome::DisconnectedKeptRegistration,
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
            let root = self.connection_root(connection).await?;
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
        let existing = account.excluded_observations(connection).await.map_err(crate::operations::state_error)?;
        let mut retained_dirty_item_ids = Vec::new();
        for observation in existing {
            if !requested.contains(&observation.item_id) {
                account.set_observation_flags(
                    connection,
                    observation.item_id,
                    hfdrive_state::ObservationFlags { excluded: Some(false), ..Default::default() },
                ).await.map_err(crate::operations::state_error)?;
            }
        }
        for item in requested {
            let observation = account.observation(connection, item).await.map_err(crate::operations::state_error)?;
            let busy = observation.as_ref().is_some_and(|observation| observation.dirty || observation.pin_requested);
            if busy {
                if observation.as_ref().is_some_and(|observation| observation.dirty) {
                    retained_dirty_item_ids.push(*item.as_uuid());
                }
                continue;
            }
            account.set_observation_flags(
                connection,
                item,
                hfdrive_state::ObservationFlags { excluded: Some(true), ..Default::default() },
            ).await.map_err(crate::operations::state_error)?;
        }
        let effective = account.excluded_observations(connection).await.map_err(crate::operations::state_error)?;
        Ok(wire::SetSelectiveSyncResult {
            excluded_item_ids: effective.into_iter().map(|observation| *observation.item_id.as_uuid()).collect(),
            retained_dirty_item_ids,
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
