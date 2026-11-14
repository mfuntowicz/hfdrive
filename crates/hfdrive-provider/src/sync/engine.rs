//! The global synchronization engine: connection registry and the
//! parent-facing control API.
//!
//! One `SyncEngine` per provider owns the shared `StateStore` (behind `Arc`),
//! the shared provider-wide [`Scheduler`] (never per connection) and the
//! running [`ConnectionRuntime`]s. Per-connection remote services arrive
//! through the [`ConnectionServices`] factory so account/drive-bound native
//! stores and the optional publication transport (read-only connections have
//! none) stay typed.
//!
//! Lifecycle boundaries:
//!
//! * **pause/resume** stop and revalidate remote scheduling per connection;
//! * **provider drain** (exit/upgrade) checkpoints state and disconnects the
//!   CFAPI runtime callbacks while retaining registration, state and data;
//! * **unlink** hydrates or durably exports every required placeholder and
//!   dirty snapshot, converts and unregisters only after preservation is
//!   proven, blocks unsafe removal, and offers the explicit
//!   disconnect-keep-registration alternative.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hfdrive_core::ids::{ConnectionId, ItemId, OperationId};
use hfdrive_core::storage::{DriveBinding, ObjectRef};
use hfdrive_state::{
    AccountStore, SnapshotStatus, StateStore,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::scheduler::Scheduler;
use crate::sync::controller::{ConnectionConfig, ConnectionHealth, ConnectionRuntime};
use crate::sync::publish::{PublishError, initialize_workspace, RoundContext};
use crate::sync::registry::{self, AdmissionError, AdmissionEvidence};
use crate::sync::remote::RemoteOps;

/// Global engine configuration.
pub struct EngineConfig {
    /// Physical per-user state root (`%LOCALAPPDATA%\HFDrive`).
    pub state_dir: PathBuf,
    /// The Windows user SID for sync-root identities.
    pub user_sid: String,
    /// This device's stable identity for commit provenance.
    pub device_id: hfdrive_core::ids::DeviceId,
    /// Provider build version (Explorer display).
    pub version: String,
}

/// Account/drive-bound remote services for one connection. `publication` is
/// `None` for read-only connections and for writable connections whose
/// supplemental authorization is not recorded yet: native reads keep working
/// and mutation reports [`RemoteError::StorageSetupRequired`].
pub struct ConnectionServices<R: RemoteOps> {
    pub remote: R,
    pub root_item_id: ItemId,
}

/// The parent-facing plan of a safe unlink.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnlinkPlan {
    pub connection_id: ConnectionId,
    pub online_only_files: u32,
    pub partial_files: u32,
    pub dirty_files: u32,
    pub conflict_files: u32,
    pub required_export_bytes: u64,
    /// Empty when safe removal may proceed; otherwise the blocking reasons.
    pub blockers: Vec<String>,
    /// True when every required item is already fully resident.
    pub all_resident: bool,
}

/// How an unlink was carried out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlinkOutcome {
    /// Content preserved, root converted, registration removed.
    Unlinked,
    /// The binding disconnected; registration and references retained for
    /// recovery. Explicit alternative, never silently chosen.
    DisconnectedKeptRegistration,
}

/// Errors surfaced to the parent's RPC layer (non-secret, classifiable).
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("unknown connection")]
    UnknownConnection,
    #[error("unknown or invalid conflict evidence")]
    UnknownConflict,
    #[error("the requested conflict resolution is not valid for this item")]
    InvalidResolution,
    #[error("admission refused the root: {0}")]
    Admission(#[from] AdmissionError),
    #[error("publication work failed: {0}")]
    Publish(#[from] PublishError),
    #[error("durable state failed: {0}")]
    State(#[from] hfdrive_state::StateError),
    #[error("unlink is blocked: {0}")]
    UnlinkBlocked(#[from] crate::sync::controller::UnlinkBlocked),
    #[error("connection disconnect failed: {0}")]
    Disconnect(#[from] crate::sync::controller::DisconnectError),
    #[error("the operation requires sign-in")]
    NeedsSignIn,
    #[error("the connection is read-only for this operation")]
    ReadOnly,
}

/// True when the item has local unsynchronized changes (its durable
/// generation is dirty).
async fn entry_dirty(
    account: &AccountStore,
    connection_id: ConnectionId,
    item_id: ItemId,
) -> bool {
    account
        .observation(connection_id, item_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|observation| observation.dirty)
}

struct ResolutionSide {
    operation_id: OperationId,
    parent_id: Option<ItemId>,
    name: String,
    content_version_id: Option<hfdrive_core::ids::VersionId>,
}

fn resolution_sides(value: &serde_json::Value) -> Option<Vec<ResolutionSide>> {
    let sides = value.get("sides")?.as_array()?;
    if sides.len() != 2 {
        return None;
    }
    sides.iter().map(|side| {
        Some(ResolutionSide {
            operation_id: side.get("operation_id")?.as_str()?.parse().ok()?,
            parent_id: side.get("parent_id")?
                .as_str()
                .map(|value| value.parse::<ItemId>())
                .transpose()
                .ok()?,
            name: side.get("name")?.as_str()?.to_owned(),
            content_version_id: side.get("content_version_id")?
                .as_str()
                .map(|value| value.parse::<hfdrive_core::ids::VersionId>())
                .transpose()
                .ok()?,
        })
    }).collect()
}

/// One registered connection entry. The remote services live inside the
/// runtime; the registry keeps the runtime handle and mode.
struct Registered<R: RemoteOps> {
    runtime: Arc<ConnectionRuntime<R>>,
    cancel: CancellationToken,
    watch_task: Option<tokio::task::JoinHandle<()>>,
}

/// The global connection registry.
pub struct SyncEngine<R: RemoteOps> {
    config: EngineConfig,
    state: Arc<StateStore>,
    scheduler: Arc<Scheduler>,
    running: Mutex<HashMap<ConnectionId, Registered<R>>>,
    cancel: CancellationToken,
}

impl<R: RemoteOps> SyncEngine<R> {
    /// Builds the engine over the provider-owned state worker and scheduler.
    pub fn new(
        config: EngineConfig,
        state: Arc<StateStore>,
        scheduler: Arc<Scheduler>,
        cancel: CancellationToken,
    ) -> Self {
        Self { config, state, scheduler, running: Mutex::new(HashMap::new()), cancel }
    }

    /// The shared scheduler (provider-wide, never per connection).
    pub fn scheduler(&self) -> &Arc<Scheduler> {
        &self.scheduler
    }

    /// Admission evidence for a candidate connection. Pure validation: no
    /// registration, no mutation.
    pub async fn admit(
        &self,
        connection: ConnectionId,
        root: &Path,
        binding: &DriveBinding,
    ) -> Result<AdmissionEvidence, EngineError> {
        let account = self.state.open_account(binding.account_key).await?;
        let configured = account
            .list_connections()
            .await?
            .into_iter()
            .map(|record| (record.root_path, record.binding))
            .collect::<Vec<_>>();
        Ok(registry::admit_root(
            connection,
            root,
            binding,
            &self.config.state_dir,
            &configured,
            &self.config.user_sid,
        )?)
    }

    /// Registers, connects and starts one connection's runtime. The remote
    /// services move into the runtime; the engine keeps only the runtime.
    pub async fn connect(
        &self,
        config: ConnectionConfig,
        services: ConnectionServices<R>,
        validated: &hfdrive_windows::filesystem::validate::ValidatedRoot,
        account: AccountStore,
    ) -> Result<Arc<ConnectionRuntime<R>>, EngineError> {
        let connection_id = config.connection_id;
        let workspace = config.workspace;
        let mut running = self.running.lock().await;
        if let Some(entry) = running.get(&connection_id) {
            return Ok(entry.runtime.clone());
        }
        let start_paused = config.start_paused || account
            .settings(format!("connection/{connection_id}/paused"))
            .await?
            .is_some_and(|row| row.value_json.as_bool() == Some(true));
        registry::register_connection(
            &account,
            connection_id,
            validated,
            &self.config.user_sid,
            &self.config.version,
            &self.config.version,
        )
        .await?;
        let connection_cancel = self.cancel.child_token();
        let (notifications_tx, notifications_rx) = tokio::sync::mpsc::channel(64);
        let mut watch_task = match services.remote.event_source() {
            Ok(event_source) => {
                let watch_cancel = connection_cancel.clone();
                let (watch, control) = crate::remote_watch::RemoteWatch::new(Default::default());
                let state_for_watch = account.clone();
                Some(tokio::spawn(async move {
                    let resume = state_for_watch.scan_state(connection_id).await.ok().flatten()
                        .and_then(|scan| scan.cursor)
                        .and_then(|cursor| hfdrive_hf::EventCursor::new(cursor).ok());
                    let (notices_tx, mut notices_rx) = tokio::sync::mpsc::channel(16);
                    let mut run = Box::pin(watch.run(
                        event_source,
                        resume,
                        notices_tx,
                        watch_cancel.clone(),
                    ));
                    loop {
                        tokio::select! {
                            _ = watch_cancel.cancelled() => break,
                            _ = &mut run => break,
                            notice = notices_rx.recv() => {
                                let Some(notice) = notice else { break; };
                                let (cursor, persisted) = match notice {
                                    crate::remote_watch::WatchNotice::HeadInvalidated { cursor, .. } => {
                                        let durable_cursor = cursor.as_ref().map(|value| value.as_str().to_owned());
                                        let persisted = state_for_watch
                                            .record_head_invalidation(connection_id, durable_cursor)
                                            .await;
                                        (cursor, persisted)
                                    }
                                    crate::remote_watch::WatchNotice::Reset => {
                                        (None, state_for_watch.record_head_invalidation(connection_id, None).await)
                                    }
                                    crate::remote_watch::WatchNotice::StreamUnavailable { .. } => {
                                        control.acknowledge(None);
                                        continue;
                                    }
                                };
                                if persisted.is_err() {
                                    watch_cancel.cancel();
                                    break;
                                }
                                control.acknowledge(cursor);
                                // A full queue already represents a pending drive. The durable
                                // invalidation and the runtime's periodic round remain intact.
                                let _ = notifications_tx.try_send(());
                            }
                        }
                    }
                    watch_cancel.cancel();
                    let _ = run.await;
                }))
            }
            Err(_) => None,
        };
        let runtime = ConnectionRuntime::start(
            config,
            account.clone(),
            services.remote,
            self.scheduler.clone(),
            connection_cancel.clone(),
            notifications_rx,
        );
        let connected = match registry::connect_root(validated, workspace) {
            Ok(connected) => connected,
            Err(error) => {
                connection_cancel.cancel();
                if let Some(task) = watch_task.take() {
                    let _ = task.await;
                }
                return Err(EngineError::Admission(error));
            }
        };
        runtime.attach(connected).await;
        // Recovery boundary: classify interrupted local actions first.
        let _ = runtime.recover_actions().await;
        if !start_paused {
            runtime.resume();
        }
        running.insert(
            connection_id,
            Registered {
                runtime: runtime.clone(),
                cancel: connection_cancel,
                watch_task,
            },
        );
        Ok(runtime)
    }

    /// Explicitly initializes a brand-new managed prefix. Never implicit.
    pub async fn initialize(&self, connection_id: ConnectionId) -> Result<(), EngineError> {
        let running = self.running.lock().await;
        let entry = running.get(&connection_id).ok_or(EngineError::UnknownConnection)?;
        if !entry.runtime.writable() {
            return Err(EngineError::ReadOnly);
        }
        let cancel = self.cancel.child_token();
        let ctx = entry.runtime.round_context(&cancel);
        initialize_workspace(&ctx).await?;
        Ok(())
    }

    /// Per-connection health projection.
    pub async fn health(&self, connection_id: ConnectionId) -> Result<ConnectionHealth, EngineError> {
        let running = self.running.lock().await;
        let entry = running.get(&connection_id).ok_or(EngineError::UnknownConnection)?;
        Ok(entry.runtime.health())
    }

    /// Pauses one connection's remote scheduling (observation continues).
    pub async fn pause(&self, connection_id: ConnectionId) -> Result<(), EngineError> {
        let running = self.running.lock().await;
        let entry = running.get(&connection_id).ok_or(EngineError::UnknownConnection)?;
        entry.runtime.pause();
        Ok(())
    }

    /// Resumes one connection; the next drive revalidates capabilities.
    pub async fn resume(&self, connection_id: ConnectionId) -> Result<(), EngineError> {
        let running = self.running.lock().await;
        let entry = running.get(&connection_id).ok_or(EngineError::UnknownConnection)?;
        entry.runtime.resume();
        Ok(())
    }

    /// Pins or unpins one item subtree (requested pin and full hydration are
    /// tracked separately).
    pub async fn set_pin(
        &self,
        connection_id: ConnectionId,
        item_id: ItemId,
        pin: bool,
    ) -> Result<(), EngineError> {
        let running = self.running.lock().await;
        let entry = running.get(&connection_id).ok_or(EngineError::UnknownConnection)?;
        Ok(entry.runtime.set_pin(item_id, pin).await?)
    }

    /// Frees local space for one item with complete durable evidence.
    pub async fn free_space(
        &self,
        connection_id: ConnectionId,
        item_id: ItemId,
    ) -> Result<(), EngineError> {
        let running = self.running.lock().await;
        let entry = running.get(&connection_id).ok_or(EngineError::UnknownConnection)?;
        Ok(entry.runtime.free_space(item_id).await?)
    }

    /// Selective-sync exclusion for one subtree (never publishes deletions).
    pub async fn set_excluded(
        &self,
        connection_id: ConnectionId,
        item_id: ItemId,
        excluded: bool,
    ) -> Result<(), EngineError> {
        let running = self.running.lock().await;
        let entry = running.get(&connection_id).ok_or(EngineError::UnknownConnection)?;
        Ok(entry.runtime.set_excluded(item_id, excluded).await?)
    }

    /// Clears parked retry timers for one connection.
    pub async fn retry(&self, connection_id: ConnectionId) -> Result<(), EngineError> {
        let running = self.running.lock().await;
        let entry = running.get(&connection_id).ok_or(EngineError::UnknownConnection)?;
        Ok(entry.runtime.retry_now().await?)
    }

    /// Restores one item version as a new durable local intent.
    ///
    /// History restore is always a new operation against the latest head; the
    /// historical immutable version record is read and validated first
    /// (workspace agreement + exact payload binding). The intent carries the
    /// provenance (`restored_version_id`), a **fresh** version id for the
    /// record this operation publishes, and the validated payload reference —
    /// the historical record itself is never rewritten and no payload is
    /// re-uploaded. An unverifiable historical binding is refused outright.
    pub async fn restore_item(
        &self,
        connection_id: ConnectionId,
        item_id: ItemId,
        version: hfdrive_core::ids::VersionId,
        operation: OperationId,
    ) -> Result<OperationId, EngineError> {
        let running = self.running.lock().await;
        let entry = running.get(&connection_id).ok_or(EngineError::UnknownConnection)?;
        if !entry.runtime.writable() {
            return Err(EngineError::ReadOnly);
        }
        let account = self.state.open_account(entry.runtime.account_key()).await?;

        // The item must be a known live file on this connection.
        let item = account
            .item(connection_id, item_id)
            .await?
            .ok_or(EngineError::UnknownConnection)?;
        if matches!(item.kind, hfdrive_state::ItemKind::Directory) {
            return Err(EngineError::Publish(PublishError::LocalApply(
                "history restore applies to file items",
            )));
        }

        // The historical binding is proven by the immutable version record
        // itself: workspace agreement, size, digest and Xet identity.
        let cancel = self.cancel.child_token();
        let record = crate::sync::remote::version_record(
            entry.runtime.remote(),
            entry.runtime.workspace_id(),
            version,
            &cancel,
        )
        .await
        .map_err(|_| EngineError::Publish(PublishError::UnsupportedFormat))?;
        let object = ObjectRef {
            key: record.object_key,
            sha256: record.sha256,
            size: record.size,
            xet_file_id: record
                .xet_file_id
                .ok_or(EngineError::Publish(PublishError::UnsupportedFormat))?,
        };

        let intent = crate::sync::outbox::SyncIntent::Restore {
            item_id: *item_id.as_uuid(),
            // Provenance: the committed historical record that was verified.
            restored_version_id: *version.as_uuid(),
            // The fresh record this operation publishes (payload reuse, no
            // re-upload, no rewrite of the historical record).
            version_id: *hfdrive_core::ids::VersionId::new().as_uuid(),
            object,
            modified_at: record.display.modified_at,
        };
        let observation = account.bump_observation(connection_id, item_id, None).await?;
        let entry = crate::sync::outbox::intent_entry(
            connection_id,
            operation,
            Some(item_id),
            None,
            None,
            observation.generation,
            &intent,
        )
        .map_err(|_| PublishError::UnsupportedFormat)?;
        account.record_outbox(entry).await?;
        Ok(operation)
    }

    /// Resolves a conflict through a fresh durable operation, or verifies the
    /// existing deterministic keep-both item before closing the record.
    pub async fn resolve_conflict(
        &self,
        connection_id: ConnectionId,
        conflict_id: hfdrive_core::ids::ConflictId,
        resolution: hfdrive_state::ConflictResolution,
        operation: OperationId,
    ) -> Result<hfdrive_state::ConflictRecord, EngineError> {
        let running = self.running.lock().await;
        let runtime = running.get(&connection_id).ok_or(EngineError::UnknownConnection)?;
        if !runtime.runtime.writable() {
            return Err(EngineError::ReadOnly);
        }
        let account = self.state.open_account(runtime.runtime.account_key()).await?;
        let conflict = account.conflict(connection_id, conflict_id).await?
            .ok_or(EngineError::UnknownConflict)?;
        if conflict.resolution_state != hfdrive_state::ConflictResolution::Unresolved {
            return Err(EngineError::InvalidResolution);
        }
        if resolution == hfdrive_state::ConflictResolution::KeepBoth {
            let preserved_id = conflict.revisions_json.get("preserved_item_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| value.parse::<ItemId>().ok())
                .ok_or(EngineError::UnknownConflict)?;
            let preserved = account.item(connection_id, preserved_id).await?
                .ok_or(EngineError::UnknownConflict)?;
            if preserved.deleted {
                return Err(EngineError::UnknownConflict);
            }
            let expected_version = conflict.revisions_json.get("preserved_version_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| value.parse::<hfdrive_core::ids::VersionId>().ok());
            if expected_version.is_some() && preserved.content_version_id != expected_version {
                return Err(EngineError::UnknownConflict);
            }
            return Ok(account.resolve_conflict(connection_id, conflict_id, resolution).await?);
        }
        if !matches!(resolution, hfdrive_state::ConflictResolution::KeepLocal | hfdrive_state::ConflictResolution::KeepRemote) {
            return Err(EngineError::InvalidResolution);
        }
        let sides = resolution_sides(&conflict.revisions_json).ok_or(EngineError::UnknownConflict)?;
        let mut selected = None;
        for side in sides {
            let local = account.outbox_entry(connection_id, side.operation_id).await?.is_some();
            let wanted = match resolution {
                hfdrive_state::ConflictResolution::KeepLocal => local,
                hfdrive_state::ConflictResolution::KeepRemote => !local,
                _ => false,
            };
            if wanted {
                if selected.is_some() {
                    return Err(EngineError::UnknownConflict);
                }
                selected = Some(side);
            }
        }
        let side = selected.ok_or(EngineError::UnknownConflict)?;
        let item = account.item(connection_id, conflict.item_id).await?
            .ok_or(EngineError::UnknownConflict)?;
        let intent = if let Some(version) = side.content_version_id {
            if !matches!(item.kind, hfdrive_state::ItemKind::File) {
                return Err(EngineError::InvalidResolution);
            }
            let parent_id = side.parent_id.ok_or(EngineError::InvalidResolution)?;
            hfdrive_core::names::validate_name(&side.name).map_err(|_| EngineError::InvalidResolution)?;
            let cancel = self.cancel.child_token();
            let record = crate::sync::remote::version_record(
                runtime.runtime.remote(),
                runtime.runtime.workspace_id(),
                version,
                &cancel,
            ).await.map_err(|_| EngineError::UnknownConflict)?;
            let object = ObjectRef {
                key: record.object_key,
                sha256: record.sha256,
                size: record.size,
                xet_file_id: record.xet_file_id.ok_or(EngineError::UnknownConflict)?,
            };
            crate::sync::outbox::SyncIntent::Resolve {
                item_id: *conflict.item_id.as_uuid(),
                parent_id: *parent_id.as_uuid(),
                name: side.name,
                restored_version_id: *version.as_uuid(),
                version_id: *hfdrive_core::ids::VersionId::new().as_uuid(),
                object,
                modified_at: record.display.modified_at,
            }
        } else {
            crate::sync::outbox::SyncIntent::Delete { item_id: *conflict.item_id.as_uuid() }
        };
        let observation = account.bump_observation(connection_id, conflict.item_id, None).await?;
        let entry = crate::sync::outbox::intent_entry(
            connection_id,
            operation,
            Some(conflict.item_id),
            None,
            None,
            observation.generation,
            &intent,
        ).map_err(|_| PublishError::UnsupportedFormat)?;
        account.record_outbox(entry).await?;
        Ok(account.resolve_conflict(connection_id, conflict_id, resolution).await?)
    }

    // -----------------------------------------------------------------------
    // Unlink and drain
    // -----------------------------------------------------------------------

    /// Prepares an unlink: counts what preservation requires and computes the
    /// export space. The safe default **hydrates or durably exports** every
    /// required item, so dirty and online-only content are counted and
    /// reserved for, not refused. `blockers` holds only known impossibilities
    /// visible before execution (e.g. the recovery area is unavailable);
    /// retention failures surface during `execute_unlink` with the affected
    /// file list. Never mutates.
    pub async fn prepare_unlink(&self, connection_id: ConnectionId) -> Result<UnlinkPlan, EngineError> {
        let running = self.running.lock().await;
        let entry = running.get(&connection_id).ok_or(EngineError::UnknownConnection)?;
        let account = self.state.open_account(entry.runtime.account_key()).await?;
        let mut plan = UnlinkPlan {
            connection_id,
            ..UnlinkPlan::default()
        };
        let counts = account.work_counts(connection_id).await?;
        plan.dirty_files = counts.dirty_files;
        plan.conflict_files = counts.conflict_files;
        for snapshot in account.list_snapshots(connection_id).await? {
            if matches!(snapshot.status, SnapshotStatus::Capturing | SnapshotStatus::Ready) {
                plan.required_export_bytes += snapshot.size.unwrap_or(0);
            }
        }
        // Local placeholder residency and dirty sizes are checked through the
        // runtime's root.
        let entries = account.list_all_items(connection_id, true).await?;
        for item in entries {
            if item.deleted {
                continue;
            }
            let Some(path) =
                crate::sync::controller::registry_path(&account, connection_id, item.item_id).await
            else {
                plan.blockers.push(format!("item {} has no resolvable local path", item.item_id));
                continue;
            };
            let Ok(state) =
                hfdrive_windows::filesystem::volume::query_file_state(&entry.runtime.root().join(&path))
            else {
                plan.blockers.push(format!("{} cannot be inspected", path.to_string_lossy()));
                continue;
            };
            if state.size > 0 && state.identity.may_not_be_materialized() {
                let placeholder = hfdrive_windows::filesystem::volume::placeholder_state(
                    state.identity.attributes,
                    state.identity.reparse_tag,
                );
                if placeholder.is_partially_on_disk() {
                    plan.partial_files += 1;
                } else {
                    plan.online_only_files += 1;
                }
                plan.required_export_bytes += state.size;
            } else if entry_dirty(&account, connection_id, item.item_id).await {
                // Dirty resident bytes are exported to the recovery area
                // before anything destructive happens.
                plan.required_export_bytes += state.size;
            }
        }
        plan.all_resident = plan.online_only_files == 0 && plan.partial_files == 0;
        // Known impossibility only: without a writable recovery area no dirty
        // content can be retained.
        if !entry.runtime.recovery_area_ready() {
            plan.blockers
                .push("the recovery area is unavailable; dirty content cannot be preserved".to_owned());
        }
        Ok(plan)
    }

    /// Executes an unlink. `keep_registration` selects the explicitly
    /// labelled disconnect-keep-registration path; otherwise every required
    /// item is hydrated or durably exported first and the registration is
    /// removed only after preservation is proven.
    pub async fn execute_unlink(
        &self,
        connection_id: ConnectionId,
        plan: &UnlinkPlan,
        keep_registration: bool,
    ) -> Result<UnlinkOutcome, EngineError> {
        if &self.prepare_unlink(connection_id).await? != plan {
            return Err(EngineError::UnlinkBlocked(crate::sync::controller::UnlinkBlocked {
                reason: "unlink inputs changed; prepare a fresh preservation plan",
                files: Vec::new(),
            }));
        }
        if !keep_registration && !plan.blockers.is_empty() {
            return Err(EngineError::UnlinkBlocked(crate::sync::controller::UnlinkBlocked {
                reason: "unlink is blocked until the listed content is preserved",
                files: plan.blockers.clone(),
            }));
        }
        let mut running = self.running.lock().await;
        if keep_registration {
            let entry = running.remove(&connection_id).ok_or(EngineError::UnknownConnection)?;
            drop(running);
            // Registration, state and references stay for explicit reconnect.
            // Online-only bytes cannot open while disconnected.
            match Self::stop_entry(entry).await {
                Ok(_) => return Ok(UnlinkOutcome::DisconnectedKeptRegistration),
                Err((error, entry)) => {
                    self.running.lock().await.insert(connection_id, entry);
                    return Err(error);
                }
            }
        }
        // Preserve and convert before removal; any failure keeps the runtime
        // available for inspection and a later safe retry.
        let entry = running.get(&connection_id).ok_or(EngineError::UnknownConnection)?;
        entry.runtime.preserve_all_for_unlink(plan).await?;
        entry.runtime.revert_placeholders_to_normal().await?;
        let entry = running.remove(&connection_id).ok_or(EngineError::UnknownConnection)?;
        drop(running);
        match Self::stop_entry(entry).await {
            Ok(entry) => {
                if let Err(error) = registry::unregister_connection(&self.config.user_sid, connection_id) {
                    self.running.lock().await.insert(connection_id, entry);
                    return Err(error.into());
                }
                Ok(UnlinkOutcome::Unlinked)
            }
            Err((error, entry)) => {
                self.running.lock().await.insert(connection_id, entry);
                Err(error)
            }
        }
    }

    async fn stop_entry(mut entry: Registered<R>) -> Result<Registered<R>, (EngineError, Registered<R>)> {
        entry.cancel.cancel();
        let disconnected = entry.runtime.disconnect().await;
        if let Some(task) = entry.watch_task.take() {
            let _ = task.await;
        }
        match disconnected {
            Ok(()) => Ok(entry),
            Err(error) => Err((error.into(), entry)),
        }
    }

    /// Disconnects all accounts without closing the engine, preserving every
    /// registration and durable work item for a later sign-in.
    pub async fn disconnect_all(&self) -> Result<(), EngineError> {
        let entries = self.running.lock().await.drain().map(|(_, entry)| entry).collect::<Vec<_>>();
        let mut first_error = None;
        let mut failed = Vec::new();
        for entry in entries {
            match Self::stop_entry(entry).await {
                Ok(_) => {}
                Err((error, entry)) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                    failed.push(entry);
                }
            }
        }
        {
            let mut running = self.running.lock().await;
            for entry in failed {
                running.insert(entry.runtime.connection_id(), entry);
            }
        }
        let checkpoint = self.state.checkpoint().await;
        if let Some(error) = first_error {
            return Err(error);
        }
        checkpoint?;
        Ok(())
    }

    /// Provider drain (exit/upgrade): stop scheduling, checkpoint state and
    /// disconnect runtime callbacks. Registration, work and data survive.
    pub async fn drain(&self) -> Result<(), EngineError> {
        self.cancel.cancel();
        self.disconnect_all().await
    }
}

/// Re-exported for the parent's construction of the engine.
pub use crate::sync::controller::ConnectionConfig as RuntimeConfig;
