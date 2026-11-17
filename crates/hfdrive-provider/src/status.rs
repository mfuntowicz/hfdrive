//! Connection status built from durable state, live runtime health and real
//! on-disk residency. No zero-filled substitutes for unknown evidence.

use hfdrive_core::ids::ConnectionId;
use hfdrive_core::storage::{BucketName, OwnerKind};
use hfdrive_hf::OwnerLocator;
use hfdrive_protocol as wire;

use crate::sync::{RuntimeState, WatchFailure};
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
        let root_available = disk.is_some();
        // A missing root has no accessible entries. These zero counts are not
        // a completed scan or a claim about recoverable data elsewhere; the
        // explicit offline error below is the availability signal.
        let disk = disk.unwrap_or_default();
        let visibility = match record.config_json.get("visibility").and_then(serde_json::Value::as_str) {
            Some("private") => wire::Visibility::Private,
            Some("public") => wire::Visibility::Public,
            _ => self.live_visibility(&record).await?,
        };
        let capability = capability_for(&self.state, &record, paused).await?;
        // Durable counts are the authoritative work evidence; live health
        // contributes runtime liveness, its recorded work error and the watch
        // outcome. A stale snapshot is never projected as zeroed work and a
        // missing, cancelled or finished runtime is never projected as
        // synchronized.
        let projection = if root_available {
            decide_projection(
                health.as_ref().map_or(RuntimeState::Missing, |health| health.runtime),
                paused,
                capability,
                &baseline,
                WorkCounts {
                    pending_files: counts.pending_files,
                    dirty_files: counts.dirty_files,
                    conflict_files: counts.conflict_files,
                },
                health.as_ref().and_then(|health| health.watch_error),
                health.as_ref().and_then(|health| health.last_error.as_deref()),
            )
        } else {
            Projection::offline(
                wire::ProtocolErrorCode::LocalRootInvalid,
                "The local folder or volume is unavailable; restore it to resume synchronization",
            )
        };
        let Projection { state, last_error } = projection;
        let pin = if storage.pin_requests == 0 {
            wire::PinState::Unpinned
        } else if storage.pinned_files < storage.pin_requests {
            wire::PinState::Partial
        } else {
            wire::PinState::Pinned
        };
        let hydration = if !root_available {
            wire::HydrationState::OnlineOnly
        } else if disk.partial_files > 0 {
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
            pending_files: counts.pending_files,
            dirty_files: counts.dirty_files,
            conflict_files: counts.conflict_files,
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

/// Durable work evidence for the projection decision.
#[derive(Clone, Copy)]
struct WorkCounts {
    pending_files: u32,
    dirty_files: u32,
    conflict_files: u32,
}

/// The projected display state plus its nonsecret actionable explanation.
struct Projection {
    state: wire::ConnectionState,
    last_error: Option<wire::ErrorObject>,
}

impl Projection {
    fn state(state: wire::ConnectionState) -> Self {
        Self { state, last_error: None }
    }

    fn offline(code: wire::ProtocolErrorCode, message: impl Into<String>) -> Self {
        Self {
            state: wire::ConnectionState::Offline,
            last_error: Some(wire::ErrorObject { code, message: message.into(), retry_after_ms: None }),
        }
    }
}

/// True only when the durable baseline proves reconciliation: an applied
/// commit is known and no newer observed commit is waiting to be absorbed.
/// An initialized-but-quiet connection (no observed commit) is reconciled at
/// its applied commit; an unknown or moved baseline is never presented as a
/// successful sync.
fn baseline_reconciled(baseline: &hfdrive_state::PublicationBaseline) -> bool {
    match (baseline.observed_commit, baseline.applied_commit) {
        (_, None) => false,
        (Some(observed), Some(applied)) => observed == applied,
        (None, Some(_)) => true,
    }
}

/// The one status decision, isolated so it is testable without a live runtime.
///
/// Order is the contract: an inactive CFAPI runtime drives nothing and is
/// never synchronized; for an active runtime the existing
/// pause/capability/conflict/pending precedence is preserved; only a proven
/// reconciliation with no recorded work and no unresolved persistence
/// failure projects `UpToDate`. A stream-only watch issue is deliberately not
/// folded in: the independent HEAD poll keeps reconciling and a proven
/// healthy reconciliation is never erased by the event feed's condition.
fn decide_projection(
    runtime: RuntimeState,
    paused: bool,
    capability: wire::CapabilityState,
    baseline: &hfdrive_state::PublicationBaseline,
    counts: WorkCounts,
    watch: Option<WatchFailure>,
    work_error: Option<&str>,
) -> Projection {
    if !runtime.is_active() {
        let code = match runtime {
            RuntimeState::Cancelled => wire::ProtocolErrorCode::Cancelled,
            _ => wire::ProtocolErrorCode::NotFound,
        };
        return Projection::offline(code, runtime.describe());
    }
    if paused {
        // Paused intent is authoritative even with a recorded work error: the
        // consumer must be able to resume. The error is retained so the
        // issue stays visible; the drive is not presented as synchronized.
        return Projection {
            state: wire::ConnectionState::WriteSyncPaused,
            last_error: work_error.map(|message| wire::ErrorObject {
                code: wire::ProtocolErrorCode::Timeout,
                message: message.to_owned(),
                retry_after_ms: None,
            }),
        };
    }
    if let Some(message) = work_error {
        return Projection::offline(wire::ProtocolErrorCode::Timeout, message);
    }
    if capability == wire::CapabilityState::StorageSetupRequired {
        return Projection::state(wire::ConnectionState::StorageSetupRequired);
    }
    if counts.conflict_files > 0 {
        return Projection::state(wire::ConnectionState::Conflict);
    }
    if counts.pending_files > 0 || counts.dirty_files > 0 {
        return Projection::state(wire::ConnectionState::PendingUpload);
    }
    if !baseline_reconciled(baseline) {
        return Projection::offline(
            wire::ProtocolErrorCode::Busy,
            "synchronization has not been reconciled with the remote yet; local files are preserved and reconnect resumes synchronization",
        );
    }
    if matches!(watch, Some(WatchFailure::Persistence)) {
        return Projection::offline(wire::ProtocolErrorCode::Internal, WatchFailure::Persistence.describe());
    }
    Projection::state(wire::ConnectionState::UpToDate)
}

#[derive(Default)]
struct Residency {
    online_only_files: u32,
    partial_files: u32,
    local_bytes: u64,
}

async fn residency(root: &std::path::Path) -> Result<Option<Residency>, wire::ProtocolError> {
    let root = root.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut result = Residency::default();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut failed = false;
        let report = match hfdrive_windows::filesystem::scan_metadata(
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
        ) {
            Ok(report) => report,
            Err(hfdrive_windows::filesystem::FsError::NotFound { .. }) => return Ok(None),
            Err(_) => {
                return Err(error(wire::ProtocolErrorCode::LocalRootInvalid, "The local root could not be scanned"));
            }
        };
        if !report.complete
            && matches!(std::fs::symlink_metadata(&root), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        {
            return Ok(None);
        }
        if failed || !report.complete {
            return Err(error(wire::ProtocolErrorCode::LocalRootInvalid, "The local residency scan is incomplete"));
        }
        Ok(Some(result))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn commit(byte: u8) -> hfdrive_core::ids::CommitId {
        hfdrive_core::ids::CommitId::from_uuid(uuid::Uuid::from_bytes([byte; 16])).expect("nonzero commit id")
    }

    fn baseline(observed: Option<u8>, applied: Option<u8>) -> hfdrive_state::PublicationBaseline {
        hfdrive_state::PublicationBaseline {
            observed_commit: observed.map(commit),
            published_commit: None,
            applied_commit: applied.map(commit),
        }
    }

    fn reconciled() -> hfdrive_state::PublicationBaseline {
        baseline(Some(1), Some(1))
    }

    fn quiet() -> hfdrive_state::PublicationBaseline {
        baseline(None, Some(1))
    }

    fn clean() -> WorkCounts {
        WorkCounts { pending_files: 0, dirty_files: 0, conflict_files: 0 }
    }

    #[tokio::test]
    async fn missing_root_returns_no_residency_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing");
        assert!(residency(&missing).await.unwrap().is_none());
    }

    fn active(
        paused: bool,
        capability: wire::CapabilityState,
        baseline: &hfdrive_state::PublicationBaseline,
    ) -> Projection {
        decide_projection(RuntimeState::Active, paused, capability, baseline, clean(), None, None)
    }

    #[test]
    fn absent_cancelled_or_finished_runtime_is_never_up_to_date() {
        for runtime in [RuntimeState::Missing, RuntimeState::Cancelled, RuntimeState::Finished] {
            let projection = decide_projection(
                runtime,
                false,
                wire::CapabilityState::Writable,
                &reconciled(),
                clean(),
                None,
                None,
            );
            assert_ne!(
                projection.state,
                wire::ConnectionState::UpToDate,
                "{runtime:?} drives nothing and must never report a successful sync"
            );
            assert_eq!(projection.state, wire::ConnectionState::Offline);
            let message = projection.last_error.expect("actionable explanation");
            assert_eq!(message.message, runtime.describe());
        }
    }

    #[test]
    fn cancelled_runtime_reports_the_cancelled_code() {
        let projection = decide_projection(
            RuntimeState::Cancelled,
            false,
            wire::CapabilityState::Writable,
            &reconciled(),
            clean(),
            None,
            None,
        );
        assert_eq!(
            projection.last_error.expect("explanation").code,
            wire::ProtocolErrorCode::Cancelled
        );
    }

    #[test]
    fn active_runtime_keeps_pause_capability_conflict_pending_precedence() {
        let paused = decide_projection(
            RuntimeState::Active,
            true,
            wire::CapabilityState::WriteSyncPaused,
            &reconciled(),
            WorkCounts { pending_files: 3, dirty_files: 2, conflict_files: 1 },
            None,
            None,
        );
        assert_eq!(paused.state, wire::ConnectionState::WriteSyncPaused);

        let setup = active(false, wire::CapabilityState::StorageSetupRequired, &reconciled());
        assert_eq!(setup.state, wire::ConnectionState::StorageSetupRequired);

        let conflict = decide_projection(
            RuntimeState::Active,
            false,
            wire::CapabilityState::Writable,
            &reconciled(),
            WorkCounts { pending_files: 2, dirty_files: 1, conflict_files: 1 },
            None,
            None,
        );
        assert_eq!(conflict.state, wire::ConnectionState::Conflict);

        let pending = decide_projection(
            RuntimeState::Active,
            false,
            wire::CapabilityState::Writable,
            &reconciled(),
            WorkCounts { pending_files: 1, dirty_files: 0, conflict_files: 0 },
            None,
            None,
        );
        assert_eq!(pending.state, wire::ConnectionState::PendingUpload);

        let dirty = decide_projection(
            RuntimeState::Active,
            false,
            wire::CapabilityState::Writable,
            &reconciled(),
            WorkCounts { pending_files: 0, dirty_files: 1, conflict_files: 0 },
            None,
            None,
        );
        assert_eq!(dirty.state, wire::ConnectionState::PendingUpload);

        let clean_run = active(false, wire::CapabilityState::Writable, &reconciled());
        assert_eq!(clean_run.state, wire::ConnectionState::UpToDate);
    }

    #[test]
    fn unknown_or_unreconciled_baseline_is_never_up_to_date() {
        let unknown = active(false, wire::CapabilityState::Writable, &baseline(None, None));
        assert_eq!(unknown.state, wire::ConnectionState::Offline);
        assert!(unknown.last_error.is_some());

        let applied_only = active(false, wire::CapabilityState::Writable, &baseline(None, Some(1)));
        assert_eq!(
            applied_only.state,
            wire::ConnectionState::UpToDate,
            "an initialized but quiet connection is reconciled at its applied commit"
        );

        let moved = active(false, wire::CapabilityState::Writable, &baseline(Some(2), Some(1)));
        assert_eq!(moved.state, wire::ConnectionState::Offline);
        assert!(moved.last_error.is_some(), "a newer observed commit waiting to be absorbed is not a completed sync");

        let applied_without_observation = active(false, wire::CapabilityState::Writable, &quiet());
        assert_eq!(applied_without_observation.state, wire::ConnectionState::UpToDate);
    }

    #[test]
    fn persistence_watch_failure_blocks_up_to_date_but_stream_issue_does_not() {
        let persistence = decide_projection(
            RuntimeState::Active,
            false,
            wire::CapabilityState::Writable,
            &reconciled(),
            clean(),
            Some(WatchFailure::Persistence),
            None,
        );
        assert_ne!(persistence.state, wire::ConnectionState::UpToDate);
        assert_eq!(persistence.state, wire::ConnectionState::Offline);
        let message = persistence.last_error.expect("explanation");
        assert_eq!(message.message, WatchFailure::Persistence.describe());

        // An SSE-only stream issue never erases a proven healthy independent
        // HEAD reconciliation.
        let stream = decide_projection(
            RuntimeState::Active,
            false,
            wire::CapabilityState::Writable,
            &reconciled(),
            clean(),
            Some(WatchFailure::Stream(crate::remote_watch::WatchIssue::Transport)),
            None,
        );
        assert_eq!(stream.state, wire::ConnectionState::UpToDate);
        assert!(stream.last_error.is_none());
    }

    #[test]
    fn recorded_work_error_is_offline_with_its_message() {
        let projection = decide_projection(
            RuntimeState::Active,
            false,
            wire::CapabilityState::Writable,
            &reconciled(),
            clean(),
            None,
            Some("the round failed and was recorded"),
        );
        assert_eq!(projection.state, wire::ConnectionState::Offline);
        let message = projection.last_error.expect("explanation");
        assert_eq!(message.message, "the round failed and was recorded");
        assert_eq!(message.code, wire::ProtocolErrorCode::Timeout);
    }

    #[test]
    fn read_only_and_writable_capabilities_project_up_to_date_when_clean() {
        for capability in [wire::CapabilityState::ReadOnly, wire::CapabilityState::Writable] {
            let projection = active(false, capability, &reconciled());
            assert_eq!(projection.state, wire::ConnectionState::UpToDate);
        }
    }

    #[test]
    fn baseline_reconciliation_is_exact() {
        assert!(!baseline_reconciled(&baseline(None, None)));
        assert!(baseline_reconciled(&baseline(None, Some(1))));
        assert!(baseline_reconciled(&baseline(Some(1), Some(1))));
        assert!(!baseline_reconciled(&baseline(Some(2), Some(1))));
        assert!(!baseline_reconciled(&baseline(Some(1), None)));
    }

    #[test]
    fn paused_with_recorded_work_error_stays_resumable_and_retains_error() {
        // An errored paused drive must project WriteSyncPaused (so the
        // consumer can resume), must not claim UpToDate, and must retain the
        // recorded error so the issue stays visible.
        let projection = decide_projection(
            RuntimeState::Active,
            true,
            wire::CapabilityState::Writable,
            &reconciled(),
            clean(),
            None,
            Some("the round failed and was recorded"),
        );
        assert_eq!(projection.state, wire::ConnectionState::WriteSyncPaused);
        assert_ne!(projection.state, wire::ConnectionState::UpToDate);
        let message = projection.last_error.expect("the recorded work error is retained");
        assert_eq!(message.message, "the round failed and was recorded");
        assert_eq!(message.code, wire::ProtocolErrorCode::Timeout);

        // A paused drive without a recorded error still has no last_error.
        let quiet = decide_projection(
            RuntimeState::Active,
            true,
            wire::CapabilityState::Writable,
            &reconciled(),
            clean(),
            None,
            None,
        );
        assert_eq!(quiet.state, wire::ConnectionState::WriteSyncPaused);
        assert!(quiet.last_error.is_none());

        // Inactive runtime still projects Offline even when paused with an
        // error: nothing is driving the root.
        let inactive = decide_projection(
            RuntimeState::Missing,
            true,
            wire::CapabilityState::Writable,
            &reconciled(),
            clean(),
            None,
            Some("the round failed and was recorded"),
        );
        assert_eq!(inactive.state, wire::ConnectionState::Offline);
    }
}
