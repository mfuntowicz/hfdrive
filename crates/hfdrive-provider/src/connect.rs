//! Finalize an exact persisted preview. Connect re-runs preview generation,
//! compares the complete durable plan and identities, then starts the runtime
//! paused until any explicit initialization is complete.

use hfdrive_core::ids::{ConnectionId, ItemId, OperationId, SetupId};
use hfdrive_protocol as wire;

use crate::{Provider, operations::error, storage::{engine_failure, invalid}};

impl Provider {
    pub(crate) async fn connect(
        &self,
        request: wire::ConnectRequest,
    ) -> Result<wire::ConnectResult, wire::ProtocolError> {
        let profile = self.current_account()?;
        let preview_id = SetupId::from_uuid(request.preview_id)
            .map_err(|_| invalid("A nonzero preview identifier is required"))?;
        let (setup_id, connection, old_preview) = self.find_preview(profile.account_key, preview_id).await?;
        let setup = self.state.get_setup(setup_id).await.map_err(crate::operations::state_error)?
            .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The setup reservation does not exist"))?;
        if setup.status != hfdrive_state::SetupStatus::Active {
            return Err(error(wire::ProtocolErrorCode::Conflict, "The setup reservation is not active"));
        }
        if setup.phase == hfdrive_state::SetupPhase::Connected {
            return Ok(wire::ConnectResult {
                connection_id: *connection.as_uuid(),
                status: self.connection_status(connection).await?,
            });
        }
        let root = setup.root_path.clone().ok_or_else(|| error(wire::ProtocolErrorCode::PreviewChanged, "The preview has no local root"))?;
        let root_text = root.to_str().ok_or_else(|| error(wire::ProtocolErrorCode::LocalRootInvalid, "The local root is not valid UTF-8"))?.to_owned();
        let mode = setup.mode.ok_or_else(|| error(wire::ProtocolErrorCode::PreviewChanged, "The preview has no access mode"))?;
        // This is a fresh internal preview, not a new external bucket/workspace
        // mutation. It replaces the durable preview so a changed result is ready
        // for the user to review before a deliberate retry.
        let refreshed = self.preview_connect(wire::PreviewConnectRequest {
            operation_id: *OperationId::new().as_uuid(),
            connection_id: *connection.as_uuid(),
            root_path: root_text,
            mode: match mode {
                hfdrive_state::ConnectionMode::ReadOnly => wire::ConnectionMode::ReadOnly,
                hfdrive_state::ConnectionMode::Writable => wire::ConnectionMode::Writable,
            },
        }).await?;
        if refreshed.head_generation.map(|id| id.to_string()) != old_preview.get("head_generation").and_then(serde_json::Value::as_str).map(|value| value.to_owned())
            || Some(refreshed.local_scan_generation) != old_preview.get("local_scan_generation").and_then(serde_json::Value::as_u64)
        {
            return Err(error(wire::ProtocolErrorCode::PreviewChanged, "Preview inputs changed; review the refreshed preview"));
        }
        let setup_after = self.state.get_setup(setup_id).await.map_err(crate::operations::state_error)?
            .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The setup reservation does not exist"))?;
        let new_preview = setup_after.preview_json.as_ref().ok_or_else(|| error(wire::ProtocolErrorCode::PreviewChanged, "The refreshed preview was not persisted"))?;
        for key in [
            "binding",
            "evidence_fingerprint",
            "mode",
            "visibility",
            "initialize",
            "root_item_id",
            "head_commit_id",
            "local_fingerprint",
            "local_scan_complete",
            "entries",
        ] {
            if old_preview.get(key) != new_preview.get(key) {
                return Err(error(wire::ProtocolErrorCode::PreviewChanged, "Preview inputs changed; review the refreshed preview"));
            }
        }
        if Some(setup_after.evidence_generation) != old_preview.get("evidence_generation").and_then(serde_json::Value::as_u64) {
            return Err(error(wire::ProtocolErrorCode::PreviewChanged, "Preview credentials or evidence changed"));
        }
        let initialize = new_preview.get("initialize").and_then(serde_json::Value::as_bool)
            .ok_or_else(|| error(wire::ProtocolErrorCode::PreviewChanged, "The preview lacks initialization intent"))?;
        let root_item_id = new_preview.get("root_item_id").and_then(serde_json::Value::as_str)
            .and_then(|value| value.parse::<ItemId>().ok())
            .ok_or_else(|| error(wire::ProtocolErrorCode::PreviewChanged, "The preview lacks durable root identity"))?;
        let engine = self.engine.as_ref().ok_or_else(crate::operations::internal)?;
        let evidence = engine.admit(connection, &root, &setup_after.binding).await.map_err(engine_failure)?;
        // Finalization writes both registry sides before any CFAPI/remote work.
        self.state.finalize_setup(setup_id).await.map_err(crate::operations::state_error)?;
        let record = self.state.reconcile_connections().await.map_err(crate::operations::state_error)?
            .into_iter()
            .find(|record| record.connection_id == connection && record.account_key == profile.account_key)
            .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The finalized connection is missing"))?;
        let remote = self.remote_for(&record, &profile)?;
        let account = self.state.open_account(profile.account_key).await.map_err(crate::operations::state_error)?;
        let drive = self.paths.account(profile.account_key).drive(record.binding.workspace_id);
        engine.connect(
            crate::sync::ConnectionConfig {
                connection_id: connection,
                workspace: record.binding.workspace_id,
                root_item_id,
                device_id: self.device_id,
                root,
                staging_dir: drive.snapshots(),
                recovery_dir: self.paths.account(profile.account_key).recovery(),
                mode: record.mode,
                start_paused: initialize,
            },
            crate::sync::ConnectionServices { remote, root_item_id },
            &evidence.validated,
            account,
        ).await.map_err(engine_failure)?;
        if initialize {
            engine.initialize(connection).await.map_err(engine_failure)?;
        }
        engine.resume(connection).await.map_err(engine_failure)?;
        Ok(wire::ConnectResult {
            connection_id: *connection.as_uuid(),
            status: self.connection_status(connection).await?,
        })
    }

    async fn find_preview(
        &self,
        account: hfdrive_core::ids::AccountKey,
        preview_id: SetupId,
    ) -> Result<(SetupId, ConnectionId, serde_json::Value), wire::ProtocolError> {
        for setup in self.state.list_setups(Some(account)).await.map_err(crate::operations::state_error)? {
            let Some(preview) = &setup.preview_json else { continue; };
            if preview.get("preview_id").and_then(serde_json::Value::as_str) == Some(preview_id.to_string().as_str()) {
                return Ok((setup.setup_id, setup.connection_id, preview.clone()));
            }
        }
        Err(error(wire::ProtocolErrorCode::NotFound, "The preview does not exist for this account"))
    }
}
