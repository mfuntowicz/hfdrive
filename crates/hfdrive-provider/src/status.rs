//! Connection status built from durable state, live runtime health and real
//! on-disk residency. No zero-filled substitutes for unknown evidence.

use hfdrive_core::ids::ConnectionId;
use hfdrive_core::storage::{BucketName, OwnerKind};
use hfdrive_hf::OwnerLocator;
use hfdrive_protocol as wire;

use crate::{Provider, operations::error};

impl Provider {
    pub(crate) async fn connection_status(
        &self,
        connection: ConnectionId,
    ) -> Result<wire::ConnectionStatus, wire::ProtocolError> {
        let profile = self.current_account()?;
        let record = self.state.reconcile_connections().await.map_err(crate::operations::state_error)?
            .into_iter()
            .find(|record| record.connection_id == connection && record.account_key == profile.account_key)
            .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The connection does not exist for this account"))?;
        self.project_connection(record).await
    }

    pub(crate) async fn connection_statuses(&self) -> Result<Vec<wire::ConnectionStatus>, wire::ProtocolError> {
        let Some(profile) = self.auth.active_profile() else {
            self.publish_connections(Vec::new())?;
            return Ok(Vec::new());
        };
        let records = self.state.reconcile_connections().await.map_err(crate::operations::state_error)?
            .into_iter()
            .filter(|record| record.account_key == profile.account_key)
            .collect::<Vec<_>>();
        let mut statuses = Vec::with_capacity(records.len());
        for record in records {
            statuses.push(self.project_connection(record).await?);
        }
        self.publish_connections(statuses.clone())?;
        Ok(statuses)
    }

    fn publish_connections(&self, connections: Vec<wire::ConnectionStatus>) -> Result<(), wire::ProtocolError> {
        let mut exhausted = false;
        self.status.send_if_modified(|snapshot| {
            if snapshot.connections == connections {
                return false;
            }
            let Some(sequence) = snapshot.sequence.checked_add(1) else {
                exhausted = true;
                return false;
            };
            snapshot.sequence = sequence;
            snapshot.connections = connections;
            true
        });
        if exhausted { Err(crate::operations::internal()) } else { Ok(()) }
    }

    async fn project_connection(
        &self,
        record: hfdrive_state::ConnectionRecord,
    ) -> Result<wire::ConnectionStatus, wire::ProtocolError> {
        let connection = record.connection_id;
        let account = self.state.open_account(record.account_key).await.map_err(crate::operations::state_error)?;
        let health = match &self.engine {
            Some(engine) => engine.health(connection).await.ok(),
            None => None,
        };
        let paused = account.settings(format!("connection/{connection}/paused")).await
            .map_err(crate::operations::state_error)?
            .is_some_and(|row| row.value_json.as_bool() == Some(true))
            || health.as_ref().is_some_and(|health| health.paused);
        let counts = account.work_counts(connection).await.map_err(crate::operations::state_error)?;
        let storage = account.storage_counts(connection).await.map_err(crate::operations::state_error)?;
        let baseline = account.baseline(connection).await.map_err(crate::operations::state_error)?;
        let scan = account.scan_state(connection).await.map_err(crate::operations::state_error)?;
        let disk = residency(&record.root_path).await?;
        let visibility = match record.config_json.get("visibility").and_then(serde_json::Value::as_str) {
            Some("private") => wire::Visibility::Private,
            Some("public") => wire::Visibility::Public,
            _ => self.live_visibility(&record).await?,
        };
        let capability = capability_for(&self.state, &record, paused).await?;
        let last_error = health.as_ref().and_then(|health| health.last_error.clone()).map(|message| {
            wire::ErrorObject { code: wire::ProtocolErrorCode::Timeout, message, retry_after_ms: None }
        });
        let state = if last_error.is_some() {
            wire::ConnectionState::Offline
        } else if paused {
            wire::ConnectionState::WriteSyncPaused
        } else if capability == wire::CapabilityState::StorageSetupRequired {
            wire::ConnectionState::StorageSetupRequired
        } else if counts.conflict_files > 0 {
            wire::ConnectionState::Conflict
        } else if counts.pending_files > 0 || counts.dirty_files > 0 {
            wire::ConnectionState::PendingUpload
        } else {
            wire::ConnectionState::UpToDate
        };
        let pin = if storage.pin_requests == 0 {
            wire::PinState::Unpinned
        } else if storage.pinned_files < storage.pin_requests {
            wire::PinState::Partial
        } else {
            wire::PinState::Pinned
        };
        let hydration = if disk.partial_files > 0 {
            wire::HydrationState::Partial
        } else if disk.online_only_files > 0 {
            wire::HydrationState::OnlineOnly
        } else {
            wire::HydrationState::Full
        };
        let scheduler = self.scheduler.stats();
        Ok(wire::ConnectionStatus {
            connection_id: *connection.as_uuid(),
            workspace_id: *record.binding.workspace_id.as_uuid(),
            owner: wire::Owner {
                owner_kind: match record.binding.bucket.owner_kind {
                    OwnerKind::Personal => wire::OwnerKind::Personal,
                    OwnerKind::Organization => wire::OwnerKind::Organization,
                },
                owner_id: record.binding.bucket.owner_id.as_str().to_owned(),
                namespace: Some(record.binding.bucket.owner_namespace.as_str().to_owned()),
                display_name: record.binding.bucket.owner_namespace.as_str().to_owned(),
                role: None,
                restrictions: Vec::new(),
                can_create: false,
            },
            bucket: wire::Bucket {
                bucket_id: record.binding.bucket.bucket_id.as_str().to_owned(),
                name: record.binding.bucket.bucket_name.as_str().to_owned(),
                namespace: record.binding.bucket.owner_namespace.as_str().to_owned(),
                visibility,
            },
            prefix: record.binding.prefix.as_str().to_owned(),
            root_path: record.root_path.to_str().ok_or_else(|| error(wire::ProtocolErrorCode::LocalRootInvalid, "The local root is not valid UTF-8"))?.to_owned(),
            mode: match record.mode {
                hfdrive_state::ConnectionMode::ReadOnly => wire::ConnectionMode::ReadOnly,
                hfdrive_state::ConnectionMode::Writable => wire::ConnectionMode::Writable,
            },
            capability,
            state,
            pin,
            hydration,
            observed_commit: baseline.observed_commit.map(|id| *id.as_uuid()),
            published_commit: baseline.published_commit.map(|id| *id.as_uuid()),
            applied_commit: baseline.applied_commit.map(|id| *id.as_uuid()),
            observed_generation: scan.map(|state| state.scan_epoch),
            pending_files: health.as_ref().map_or(counts.pending_files, |health| health.pending_files),
            dirty_files: health.as_ref().map_or(counts.dirty_files, |health| health.dirty_files),
            conflict_files: health.as_ref().map_or(counts.conflict_files, |health| health.conflict_files),
            online_only_files: disk.online_only_files,
            pinned_files: storage.pinned_files,
            pending_upload_bytes: storage.pending_upload_bytes,
            local_bytes: disk.local_bytes,
            staging_used_bytes: scheduler.staging_used_bytes,
            range_cache_used_bytes: scheduler.range_cache_used_bytes,
            transfer_memory_used_bytes: scheduler.transfer_memory_used_bytes,
            last_error,
            updated_at: display_now(),
        })
    }

    pub(crate) async fn live_visibility(
        &self,
        record: &hfdrive_state::ConnectionRecord,
    ) -> Result<wire::Visibility, wire::ProtocolError> {
        let control = self.native_control(record.account_key);
        let lease = control.capture_lease().map_err(crate::storage::native_failure)?;
        let bucket = &record.binding.bucket;
        let owner = control.verify_owner(&lease, &OwnerLocator {
            owner_id: bucket.owner_id.clone(),
            owner_kind: bucket.owner_kind,
            claimed_namespace: Some(bucket.owner_namespace.clone()),
        }, &self.operations.cancellation).await.map_err(crate::storage::native_failure)?;
        let summary = control.resolve_bucket(
            &lease,
            &owner.owner_ref(),
            &BucketName::new(bucket.bucket_name.as_str().to_owned()).map_err(|_| crate::storage::invalid("Invalid bucket name"))?,
            Some(&bucket.bucket_id),
            &self.operations.cancellation,
        ).await.map_err(crate::storage::native_failure)?
            .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The selected bucket no longer exists"))?;
        Ok(if summary.private { wire::Visibility::Private } else { wire::Visibility::Public })
    }
}

async fn capability_for(
    state: &hfdrive_state::StateStore,
    record: &hfdrive_state::ConnectionRecord,
    paused: bool,
) -> Result<wire::CapabilityState, wire::ProtocolError> {
    if record.mode == hfdrive_state::ConnectionMode::ReadOnly {
        return Ok(wire::CapabilityState::ReadOnly);
    }
    if paused {
        return Ok(wire::CapabilityState::WriteSyncPaused);
    }
    let Some(setup) = state.get_setup_by_connection(record.connection_id).await.map_err(crate::operations::state_error)? else {
        return Ok(wire::CapabilityState::StorageSetupRequired);
    };
    let Some(evidence) = setup.probe_evidence_json else {
        return Ok(wire::CapabilityState::StorageSetupRequired);
    };
    let checks = evidence.get("checks").and_then(serde_json::Value::as_array);
    let capabilities = evidence.get("capabilities");
    let proven = record.s3_ref.is_some()
        && checks.is_some_and(|checks| !checks.is_empty() && checks.iter().all(|check| {
            check.get("outcome").and_then(serde_json::Value::as_str) == Some("passed")
        }))
        && capabilities.is_some_and(|capabilities| {
            ["native_write", "xet_upload", "xet_range", "s3_read", "conditional_create", "conditional_replace", "strong_etag"]
                .iter().all(|key| capabilities.get(*key).and_then(serde_json::Value::as_bool) == Some(true))
        });
    Ok(if proven { wire::CapabilityState::Writable } else { wire::CapabilityState::StorageSetupRequired })
}

#[derive(Default)]
struct Residency {
    online_only_files: u32,
    partial_files: u32,
    local_bytes: u64,
}

async fn residency(root: &std::path::Path) -> Result<Residency, wire::ProtocolError> {
    let root = root.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut result = Residency::default();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut failed = false;
        let report = hfdrive_windows::filesystem::scan_metadata(
            &root,
            &hfdrive_windows::filesystem::ScanBudget::default(),
            &cancel,
            &mut |entry| {
                if entry.is_directory {
                    return hfdrive_windows::filesystem::VisitFlow::Continue;
                }
                if entry.identity.may_not_be_materialized() {
                    let placeholder = hfdrive_windows::filesystem::volume::placeholder_state(
                        entry.identity.attributes,
                        entry.identity.reparse_tag,
                    );
                    if placeholder.is_partially_on_disk() {
                        result.partial_files += 1;
                    } else {
                        result.online_only_files += 1;
                    }
                    let absolute = root.join(&entry.relative_path);
                    match hfdrive_windows::cfapi::ops::resident_bytes(&absolute, entry.size) {
                        Ok(bytes) => result.local_bytes = result.local_bytes.saturating_add(bytes),
                        Err(_) => {
                            failed = true;
                            return hfdrive_windows::filesystem::VisitFlow::Stop;
                        }
                    }
                } else {
                    result.local_bytes = result.local_bytes.saturating_add(entry.size);
                }
                hfdrive_windows::filesystem::VisitFlow::Continue
            },
        ).map_err(|_| error(wire::ProtocolErrorCode::LocalRootInvalid, "The local root could not be scanned"))?;
        if failed || !report.complete {
            return Err(error(wire::ProtocolErrorCode::LocalRootInvalid, "The local residency scan is incomplete"));
        }
        Ok(result)
    }).await.map_err(|_| crate::operations::internal())?
}

fn display_now() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}
