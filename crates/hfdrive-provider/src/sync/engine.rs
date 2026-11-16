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

use crate::remote_watch::{RemoteEvents, RemoteWatch, WatchControl, WatchNotice};
use crate::scheduler::Scheduler;
use crate::sync::controller::{
    ConnectionConfig, ConnectionHealth, ConnectionRuntime, WatchFailure, WatchUpdate,
};
use crate::sync::publish::{PublishError, initialize_workspace};
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

/// Runs one connection's remote-watch worker.
///
/// Scope rule: this worker owns **only** its own child cancellation token.
/// Nothing here may cancel the connection scope (the token the CFAPI pump and
/// the drive loop share): an SSE/poll transport failure, a `StreamUnavailable`
/// notice, or a persistence failure of one invalidation must never disconnect
/// the sync root or stop synchronization. The failure is recorded through
/// [`WatchUpdate::WatchFailed`] (observable in connection health) and:
///
/// * a persistence failure leaves the cursor **unacknowledged** and the
///   notice outstanding (the watch coalesces later triggers into it and
///   replays from the last acknowledged position on reconnect); the watch
///   loop keeps running — there is no restart and the independent runtime
///   interval/poll keeps driving work;
/// * the run future is polled by exactly one owner; the cleanup join point
///   reuses that owner and never polls a completed future twice;
/// * parent-scope cancellation still ends this worker: it is observed as its
///   own token firing (a child of the cancelled scope).
async fn run_connection_watch<E: RemoteEvents>(
    watch: RemoteWatch,
    control: WatchControl,
    event_source: E,
    connection_id: ConnectionId,
    account: AccountStore,
    notifications: tokio::sync::mpsc::Sender<WatchUpdate>,
    cancel: CancellationToken,
) {
    let (notices_tx, mut notices_rx) = tokio::sync::mpsc::channel(16);
    let mut run = Box::pin(watch.run(
        event_source,
        resume_cursor(&account, connection_id).await,
        notices_tx,
        cancel.clone(),
    ));
    let mut run_done = false;
    let mut notice_channel_open = true;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            result = &mut run, if !run_done => {
                // The watch ended on its own. From here on the run future is
                // complete and is never polled again; the teardown below
                // skips the join for exactly this reason.
                run_done = true;
                let _ = result;
                break;
            }
            notice = notices_rx.recv(), if notice_channel_open => {
                let Some(notice) = notice else {
                    // The watch run has released its sender. Its completion is
                    // joined through the run branch (guarded by `run_done`):
                    // disabling this branch is what keeps a closed channel
                    // from spinning `select!`.
                    notice_channel_open = false;
                    continue;
                };
                let (cursor, source, failure) = match notice {
                    WatchNotice::HeadInvalidated { cursor, source } => {
                        // A poll carries no cursor: a cursor-less invalidation
                        // must never erase the durable resume position. Only
                        // the notice's own cursor advances it.
                        let durable_cursor = match &cursor {
                            Some(value) => Some(value.as_str().to_owned()),
                            None => resume_cursor(&account, connection_id)
                                .await
                                .map(|value| value.as_str().to_owned()),
                        };
                        let persisted = account.record_head_invalidation(connection_id, durable_cursor).await;
                        match persisted {
                            Ok(_) => (cursor, source, None),
                            Err(error) => {
                                tracing::warn!(
                                    %error,
                                    connection = %connection_id,
                                    "remote change could not be recorded durably; \
                                     the cursor is not acknowledged and the change is replayed on reconnect"
                                );
                                // The cursor is deliberately NOT acknowledged:
                                // a reconnect must replay this change.
                                (None, source, Some(WatchFailure::Persistence))
                            }
                        }
                    }
                    WatchNotice::Reset => (
                        None,
                        crate::remote_watch::NoticeSource::Resync,
                        match account.record_head_invalidation(connection_id, None).await {
                            Ok(_) => None,
                            Err(error) => {
                                tracing::warn!(
                                    %error,
                                    connection = %connection_id,
                                    "remote reset could not be recorded durably; \
                                     the cursor is not acknowledged and the reset replays on reconnect"
                                );
                                Some(WatchFailure::Persistence)
                            }
                        },
                    ),
                    WatchNotice::StreamUnavailable { issue, .. } => {
                        // The independent poll keeps running inside the watch
                        // loop; report the stream condition and release the
                        // coalesced notice slot without advancing any cursor.
                        control.acknowledge(None);
                        let _ = notifications.try_send(WatchUpdate::WatchFailed(
                            WatchFailure::Stream(issue),
                        ));
                        continue;
                    }
                };
                match failure {
                    Some(failure) => {
                        // The notice stays outstanding and unacknowledged:
                        // the watch keeps coalescing later triggers into it
                        // and its cursor resumes from the last acknowledged
                        // position. The watch is never restarted here (its run
                        // future has exactly one owner) and this failure never
                        // touches the parent connection scope: the CFAPI pump
                        // and the runtime's independent interval/poll keep
                        // driving work.
                        let _ = notifications.try_send(WatchUpdate::WatchFailed(failure));
                    }
                    None => {
                        control.acknowledge(cursor);
                        // A full queue already represents a pending drive: the
                        // durable invalidation and the runtime's periodic
                        // round remain intact.
                        let _ = notifications.try_send(WatchUpdate::HeadInvalidated { source });
                    }
                }
            }
        }
    }
    // Teardown: only this worker's own scope. A completed run future is not
    // polled again; the join happens exactly once and only for a run that has
    // not completed.
    cancel.cancel();
    if !run_done {
        let _ = (&mut run).await;
    }
}

/// The durable resume position: the persisted event cursor of this
/// connection, validated as an opaque cursor. An invalid persisted value is
/// never used to skip events; the watch starts from the beginning instead.
async fn resume_cursor(account: &AccountStore, connection_id: ConnectionId) -> Option<hfdrive_hf::EventCursor> {
    account
        .scan_state(connection_id)
        .await
        .ok()
        .flatten()
        .and_then(|scan| scan.cursor)
        .and_then(|cursor| hfdrive_hf::EventCursor::new(cursor).ok())
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
    /// The provider-wide live-work registry (one shared instance for every
    /// connection's CFAPI pump). No new config field: the engine creates it
    /// in [`SyncEngine::new`] and hands it to each runtime.
    activity: Arc<crate::sync::activity::ActivityRegistry>,
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
        Self {
            config,
            state,
            scheduler,
            activity: Arc::new(crate::sync::activity::ActivityRegistry::new()),
            running: Mutex::new(HashMap::new()),
            cancel,
        }
    }

    /// The shared scheduler (provider-wide, never per connection).
    pub fn scheduler(&self) -> &Arc<Scheduler> {
        &self.scheduler
    }

    /// The provider-wide live-work registry used by every connection's CFAPI
    /// pump. The activity projection reads in-flight spans through
    /// [`crate::sync::activity::ActivityRegistry::snapshot`].
    pub(crate) fn activity_registry(&self) -> &crate::sync::activity::ActivityRegistry {
        &self.activity
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
        let mut running = self.running.lock().await;
        if let Some(existing) = running.get(&connection_id).map(|entry| entry.runtime.clone()) {
            // Idempotent connect reuses a registry entry only while its CFAPI
            // runtime is actually driving the root. A stale entry (missing,
            // cancelled or finished runtime) is not a successful connect: it
            // is drained and the existing root is reconnected below —
            // registration identity, durable state and work are preserved
            // and no remote work is ever reinitialized on this path.
            if existing.runtime_state().await.is_active() {
                return Ok(existing);
            }
            let stale = running
                .remove(&connection_id)
                .expect("the entry exists under the map lock");
            if let Err((error, _drained)) = Self::stop_entry(stale).await {
                tracing::warn!(
                    %error,
                    connection = %connection_id,
                    "stale connection runtime did not drain cleanly; reconnecting the existing root"
                );
            }
        }
        self.connect_locked(&mut running, config, services, validated, account)
            .await
    }

    /// Replaces one connection's runtime and its remote services atomically:
    /// any existing entry, active or stale, is stopped and drained first, so
    /// an existing active runtime can never retain stale remote services
    /// (repaired publication credentials must reach the live transport).
    /// Registration identity, durable state and work are preserved and the
    /// same root is reconnected; nothing is ever reinitialized here.
    pub async fn reconnect(
        &self,
        config: ConnectionConfig,
        services: ConnectionServices<R>,
        validated: &hfdrive_windows::filesystem::validate::ValidatedRoot,
        account: AccountStore,
    ) -> Result<Arc<ConnectionRuntime<R>>, EngineError> {
        let mut running = self.running.lock().await;
        if let Some(entry) = running.remove(&config.connection_id) {
            if let Err((error, entry)) = Self::stop_entry(entry).await {
                // Keep the entry for the next connect's stale drain (the
                // runtime is no longer driving the root either way) and
                // surface the failure instead of silently continuing.
                running.insert(config.connection_id, entry);
                return Err(error);
            }
        }
        self.connect_locked(&mut running, config, services, validated, account)
            .await
    }

    /// Quiesces one connection's remote dispatch in memory and waits for its
    /// in-flight drive round to finish; observation and the durable pause
    /// intent continue untouched. A connection without a runtime has nothing
    /// dispatching and quiesces trivially.
    pub async fn quiesce(&self, connection_id: ConnectionId) -> Result<(), EngineError> {
        let runtime = {
            let running = self.running.lock().await;
            running.get(&connection_id).map(|entry| entry.runtime.clone())
        };
        if let Some(runtime) = runtime {
            runtime.quiesce().await;
        }
        Ok(())
    }

    /// Registers, connects and starts one connection's runtime under the
    /// connection registry lock. The remote services move into the runtime;
    /// the engine keeps only the runtime.
    async fn connect_locked(
        &self,
        running: &mut HashMap<ConnectionId, Registered<R>>,
        config: ConnectionConfig,
        services: ConnectionServices<R>,
        validated: &hfdrive_windows::filesystem::validate::ValidatedRoot,
        account: AccountStore,
    ) -> Result<Arc<ConnectionRuntime<R>>, EngineError> {
        let connection_id = config.connection_id;
        let workspace = config.workspace;
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
                // The watch runs in its own strictly narrower scope: its child
                // token stops only this observation worker. A watch or
                // persistence failure must never cancel the connection scope,
                // which owns the CFAPI pump and the drive loop.
                let watch_cancel = connection_cancel.child_token();
                let (watch, control) = crate::remote_watch::RemoteWatch::new(Default::default());
                Some(tokio::spawn(run_connection_watch(
                    watch,
                    control,
                    event_source,
                    connection_id,
                    account.clone(),
                    notifications_tx,
                    watch_cancel,
                )))
            }
            Err(_) => None,
        };
        let runtime = ConnectionRuntime::start(
            config,
            account.clone(),
            services.remote,
            self.scheduler.clone(),
            self.activity.clone(),
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

    /// Per-connection health projection. The runtime liveness is folded in by
    /// the async [`ConnectionRuntime::health`] (never a stale snapshot), and
    /// the registry lock is released before it runs so foreground status never
    /// waits behind connection restoration or drain work holding this map.
    pub async fn health(&self, connection_id: ConnectionId) -> Result<ConnectionHealth, EngineError> {
        let runtime = {
            let running = self.running.lock().await;
            running
                .get(&connection_id)
                .ok_or(EngineError::UnknownConnection)?
                .runtime
                .clone()
        };
        Ok(runtime.health().await)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::time::Duration;

    use hfdrive_core::ids::{AccountKey, WorkspaceId};
    use hfdrive_core::storage::{
        BucketBinding, BucketId, BucketName, DriveBinding, Namespace, OwnerId, OwnerKind,
        RemotePrefix,
    };
    use hfdrive_hf::{EventCursor, NativeError, NativeEvent};
    use hfdrive_state::{
        AccountRecord, AccountStatus, ConnectionMode, CredentialRef, SetupDraft, StatePaths,
    };

    // ---- deterministic fake event feed --------------------------

    #[derive(Default)]
    struct FakeFeedState {
        /// One script per `open_events` call. A missing script is a dead
        /// stream (transport failure), exactly like the watch-loop tests.
        feeds: std::sync::Mutex<VecDeque<Vec<Result<Option<NativeEvent>, NativeError>>>>,
    }

    struct FakeFeed {
        events: VecDeque<Result<Option<NativeEvent>, NativeError>>,
    }

    impl crate::remote_watch::EventFeed for FakeFeed {
        fn next_event<'a>(
            &'a mut self,
            _cancel: &'a CancellationToken,
        ) -> Pin<Box<dyn Future<Output = Result<Option<NativeEvent>, NativeError>> + Send + 'a>> {
            let next = self.events.pop_front();
            Box::pin(async move { next.unwrap_or(Ok(None)) })
        }

        fn idle_for(&self) -> Duration {
            Duration::ZERO
        }
    }

    struct FakeEvents {
        state: Arc<FakeFeedState>,
    }

    impl RemoteEvents for FakeEvents {
        fn open_events(
            &self,
            _resume: Option<EventCursor>,
            _cancel: CancellationToken,
        ) -> Pin<Box<dyn Future<Output = Result<Box<dyn crate::remote_watch::EventFeed>, NativeError>> + Send>>
        {
            let script = self
                .state
                .feeds
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .pop_front();
            Box::pin(async move {
                match script {
                    Some(events) => Ok(Box::new(FakeFeed { events: events.into() })
                        as Box<dyn crate::remote_watch::EventFeed>),
                    None => Err(NativeError::Transport),
                }
            })
        }
    }

    /// An open that never answers on its own: the watch sits inside its
    /// observation until the owning scope ends it.
    struct PendingEvents;

    impl RemoteEvents for PendingEvents {
        fn open_events(
            &self,
            _resume: Option<EventCursor>,
            _cancel: CancellationToken,
        ) -> Pin<Box<dyn Future<Output = Result<Box<dyn crate::remote_watch::EventFeed>, NativeError>> + Send>>
        {
            Box::pin(std::future::pending::<
                Result<Box<dyn crate::remote_watch::EventFeed>, NativeError>,
            >())
        }
    }

    fn change(raw: &str) -> NativeEvent {
        NativeEvent::Changes {
            cursor: Some(EventCursor::new(raw.to_owned()).unwrap()),
            changes: vec![hfdrive_hf::NativeChange {
                key: "HEAD".to_owned(),
                op: hfdrive_hf::ChangeOp::Update,
                size: None,
                xet_file_id: None,
                uploaded_at: None,
                mtime: None,
                mtime_nanos: None,
            }],
        }
    }

    fn watch_config(poll: Duration) -> crate::remote_watch::WatchConfig {
        crate::remote_watch::WatchConfig {
            poll_interval: (poll, poll),
            stream_idle_timeout: Duration::from_secs(3600),
            backoff_base: Duration::from_millis(1),
            backoff_ceiling: Duration::from_millis(20),
            jitter_seed: Some(7),
        }
    }

    // ---- real temp StateStore fixtures --------------------------

    async fn open_state() -> (tempfile::TempDir, Arc<StateStore>, AccountStore) {
        let directory = tempfile::tempdir().expect("test state directory");
        let state = Arc::new(
            StateStore::open(StatePaths::new(directory.path().to_path_buf()))
                .await
                .expect("test state store"),
        );
        let account_key = AccountKey::from_subject("https://huggingface.co", "engine-watch-test");
        state
            .record_account(AccountRecord {
                account_key,
                issuer: "https://huggingface.co".to_owned(),
                subject: "engine-watch-test".to_owned(),
                namespace: "fixture-person".to_owned(),
                credential_ref: CredentialRef("oauth.hfdcred".to_owned()),
                auth_epoch: 1,
                status: AccountStatus::Active,
            })
            .await
            .expect("test account");
        let account = state.open_account(account_key).await.expect("test account handle");
        (directory, state, account)
    }

    fn drive_binding(account_key: AccountKey) -> DriveBinding {
        DriveBinding {
            account_key,
            bucket: BucketBinding {
                bucket_id: BucketId::new("bucket-01".to_owned()).unwrap(),
                bucket_name: BucketName::new("engine-fixture".to_owned()).unwrap(),
                owner_id: OwnerId::new("owner-01".to_owned()).unwrap(),
                owner_kind: OwnerKind::Personal,
                owner_namespace: Namespace::new("fixture-person".to_owned()).unwrap(),
            },
            prefix: RemotePrefix::new(format!("hfdrive/{}", WorkspaceId::new())).unwrap(),
            workspace_id: WorkspaceId::new(),
        }
    }

    /// Registers one real connection through the setup journal, so its durable
    /// `event_cursors` row exists exactly as production registration creates it.
    async fn registered_connection(
        state: &StateStore,
        account_key: AccountKey,
        root: &Path,
    ) -> ConnectionId {
        let setup = state
            .reserve_setup(SetupDraft {
                operation_id: OperationId::new(),
                account_key,
                binding: drive_binding(account_key),
                initialize: false,
            })
            .await
            .expect("test setup");
        state
            .attach_setup_preview(
                setup.setup_id,
                serde_json::json!({"fixture": true}),
                root.to_path_buf(),
                ConnectionMode::ReadOnly,
            )
            .await
            .expect("test preview");
        state.finalize_setup(setup.setup_id).await.expect("test registration");
        setup.connection_id
    }

    /// A failed durable recording of one invalidation is reported truthfully
    /// and changes **nothing** else: the connection scope the CFAPI pump and
    /// the drive loop share stays alive, the watch keeps observing (there is
    /// no restart-and-die loop), and the notice's cursor is never
    /// acknowledged — it stays outstanding and coalesces later triggers
    /// instead of faking recovery.
    #[tokio::test]
    async fn persistence_failure_keeps_the_connection_scope_alive_and_the_cursor_unacknowledged() {
        let (_directory, _state, account) = open_state().await;
        // A connection whose durable `event_cursors` row is absent is the
        // exact production persistence failure (recording one invalidation
        // errors) this worker must survive without touching any parent scope.
        let connection = ConnectionId::new();
        let shared = Arc::new(FakeFeedState::default());
        shared.feeds.lock().unwrap().push_back(vec![
            Ok(Some(change("c1"))),
            Ok(Some(change("c2"))),
            Ok(None),
        ]);
        let (watch, control) =
            crate::remote_watch::RemoteWatch::new(watch_config(Duration::from_secs(3600)));
        let (updates_tx, mut updates_rx) = tokio::sync::mpsc::channel(64);
        let connection_cancel = CancellationToken::new();
        let watch_cancel = connection_cancel.child_token();
        let task = tokio::spawn(run_connection_watch(
            watch,
            control.clone(),
            FakeEvents { state: shared.clone() },
            connection,
            account.clone(),
            updates_tx,
            watch_cancel.clone(),
        ));
        let update = tokio::time::timeout(Duration::from_secs(5), updates_rx.recv())
            .await
            .expect("watch update")
            .expect("watch worker alive");
        assert!(
            matches!(update, WatchUpdate::WatchFailed(WatchFailure::Persistence)),
            "the durable recording failure is reported, not swallowed: {update:?}"
        );
        assert!(
            control.acknowledged_cursor().is_none(),
            "a failed persistence never acknowledges a cursor; a reconnect must replay the change"
        );
        // The notice stays outstanding: later triggers coalesce into it and no
        // further update is delivered until it is durably applied.
        assert!(
            tokio::time::timeout(Duration::from_millis(200), updates_rx.recv()).await.is_err(),
            "an unacknowledged notice keeps coalescing; no fake recovery is reported"
        );
        assert!(
            !connection_cancel.is_cancelled(),
            "a watch failure must never cancel the connection/CFAPI scope"
        );
        assert!(
            !watch_cancel.is_cancelled(),
            "the watch keeps observing; there is no failure-restart that kills its own scope"
        );
        assert!(!task.is_finished(), "the watch worker survives its persistence failure");
        connection_cancel.cancel();
        task.await.unwrap();
    }

    /// Parent (connection/CFAPI scope) cancellation ends the watch worker
    /// through its child token and joins it promptly.
    #[tokio::test]
    async fn parent_cancellation_terminates_the_watch_worker() {
        let (_directory, _state, account) = open_state().await;
        let connection = ConnectionId::new();
        let (watch, control) =
            crate::remote_watch::RemoteWatch::new(watch_config(Duration::from_secs(3600)));
        let (updates_tx, _updates_rx) = tokio::sync::mpsc::channel(8);
        let connection_cancel = CancellationToken::new();
        let watch_cancel = connection_cancel.child_token();
        let task = tokio::spawn(run_connection_watch(
            watch,
            control,
            PendingEvents,
            connection,
            account,
            updates_tx,
            watch_cancel.clone(),
        ));
        tokio::task::yield_now().await;
        assert!(!task.is_finished(), "the watch is live before cancellation");
        assert!(!watch_cancel.is_cancelled());
        connection_cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("parent cancellation terminates the watch")
            .unwrap();
    }

    /// Cursor semantics at the durable boundary: a cursor-less poll
    /// invalidation re-records the existing resume position and never erases
    /// it; a feed reset clears the replayed position (its cursor is expired —
    /// the authoritative HEAD must be re-read) and requests that re-read.
    #[tokio::test]
    async fn poll_notices_preserve_the_durable_cursor_and_reset_clears_it() {
        let (_directory, state, account) = open_state().await;
        let root = std::env::temp_dir().join("hfdrive-engine-watch-root");
        let connection =
            registered_connection(&state, account.account_key(), &root).await;
        // Seed the durable resume position and clear its pending flag so the
        // reset's effect is observable on its own.
        account
            .record_head_invalidation(connection, Some("c0".to_owned()))
            .await
            .expect("seed cursor");
        account.ack_head_refresh(connection).await.expect("clear pending flag");

        let shared = Arc::new(FakeFeedState::default());
        // One empty feed (immediate EOF) then dead opens: only the independent
        // poll fires notices until the reset script arrives.
        shared.feeds.lock().unwrap().push_back(Vec::new());
        let (watch, control) =
            crate::remote_watch::RemoteWatch::new(watch_config(Duration::from_millis(25)));
        let (updates_tx, mut updates_rx) = tokio::sync::mpsc::channel(64);
        let connection_cancel = CancellationToken::new();
        let task = tokio::spawn(run_connection_watch(
            watch,
            control,
            FakeEvents { state: shared.clone() },
            connection,
            account.clone(),
            updates_tx,
            connection_cancel.child_token(),
        ));

        // Phase 1: a poll-sourced invalidation (no cursor of its own).
        loop {
            let update = tokio::time::timeout(Duration::from_secs(5), updates_rx.recv())
                .await
                .expect("poll update")
                .expect("watch worker alive");
            if matches!(
                update,
                WatchUpdate::HeadInvalidated {
                    source: crate::remote_watch::NoticeSource::Poll
                }
            ) {
                break;
            }
        }
        let scan = account.scan_state(connection).await.expect("scan state").expect("cursor row");
        assert_eq!(
            scan.cursor.as_deref(),
            Some("c0"),
            "a cursor-less poll must never erase the durable resume position"
        );

        // Phase 2: the server resets the feed (replay expired).
        shared
            .feeds
            .lock()
            .unwrap()
            .push_back(vec![Ok(Some(NativeEvent::Reset {
                reason: "replay expired".to_owned(),
            }))]);
        loop {
            let update = tokio::time::timeout(Duration::from_secs(5), updates_rx.recv())
                .await
                .expect("reset update")
                .expect("watch worker alive");
            if matches!(
                update,
                WatchUpdate::HeadInvalidated {
                    source: crate::remote_watch::NoticeSource::Resync
                }
            ) {
                break;
            }
        }
        let scan = account.scan_state(connection).await.expect("scan state").expect("cursor row");
        assert!(
            scan.cursor.is_none(),
            "a feed reset clears the replayed resume position; the authoritative HEAD is re-read"
        );
        assert!(scan.pending_head_refresh, "the reset's authoritative re-read is durably pending");

        connection_cancel.cancel();
        task.await.unwrap();
    }
}
