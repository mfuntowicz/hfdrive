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
//!
//! Startup recovery boundary: every connect classifies interrupted journaled
//! local actions **before** the connection runs. A recovery error is never
//! ignored: it is propagated and the connection is left paused and not ready
//! (its just-started runtime is torn down; registration, durable state and
//! work are preserved) — nothing ever resumes into pending destructive local
//! actions whose crash state was never classified. The failed boundary also
//! records the durable pause intent, so the next successful recovery starts
//! paused until the user explicitly resumes.
//!
//! Known limitation (no unlink-phase journal): a crash inside an unlink's
//! destructive phase leaves the connection row in place, so ordinary startup
//! restoration reconnects it and the recovery boundary only classifies the
//! interrupted per-file actions; it does not know an unlink was in flight and
//! may resume synchronization on a partially converted root. Completing an
//! interrupted removal therefore takes a fresh reviewed unlink preview. A
//! durable unlink-phase marker is not invented here.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hfdrive_core::ids::{ConnectionId, ItemId, OperationId};
use hfdrive_core::storage::{DriveBinding, ObjectRef};
use hfdrive_state::{
    AccountStore, SnapshotStatus, StateStore,
};
use hfdrive_windows::filesystem::volume::query_file_state;
use sha2::{Digest, Sha256};
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

/// How an unlink removes one connection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnlinkMode {
    /// Hydrate or durably export every required byte, convert resident files
    /// to normal files, then unregister. Never discards unavailable bytes.
    #[default]
    SafeRemove,
    /// Disconnect the runtime and keep the registration, binding and remote
    /// references for explicit recovery. Never silently chosen.
    DisconnectKeepRegistration,
    /// Remove the connection even where committed bytes cannot be retained
    /// locally: clean zero-residency placeholders are deleted after explicit
    /// abandonment consent, resident files are converted and kept, partially
    /// hydrated files block the removal.
    RemoveUnavailable,
}

/// One exact local identity an unlink plan binds. Prepared from the live
/// placeholder identity (HFDR record) plus the NTFS identity, size and
/// modification time of the entry at preview time; the guarded removal
/// re-verifies all of them immediately before any deletion.
///
/// `version_id` is `None` exactly for directories; `partial` is true when
/// only part of a file is locally resident.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnlinkFile {
    /// Durable item identity of the entry.
    pub item_id: ItemId,
    /// Relative path inside the sync root at preparation time.
    pub path: PathBuf,
    /// Immutable content version the placeholder carried at preparation time.
    pub version_id: Option<hfdrive_core::ids::VersionId>,
    /// NTFS volume serial number of the entry.
    pub volume_serial_number: u64,
    /// NTFS 128-bit file identity of the entry.
    pub file_id: [u8; 16],
    /// Logical size in bytes.
    pub size: u64,
    /// Last write time in Windows 100ns units since 1601.
    pub last_write_time_100ns: i64,
    /// True when only part of the file is locally resident.
    pub partial: bool,
}

/// The parent-facing plan of a safe unlink.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnlinkPlan {
    pub connection_id: ConnectionId,
    /// The mode this plan was reviewed for.
    pub mode: UnlinkMode,
    pub online_only_files: u32,
    pub partial_files: u32,
    pub dirty_files: u32,
    pub conflict_files: u32,
    pub required_export_bytes: u64,
    /// Empty when safe removal may proceed; otherwise the blocking reasons.
    pub blockers: Vec<String>,
    /// True when every required item is already fully resident.
    pub all_resident: bool,
    /// Exact identities of every entry a removal may abandon: not-fully
    /// resident placeholder files (`partial` marks the partially hydrated
    /// ones) and managed placeholder directories whose subtree holds nothing
    /// resident. Populated in every mode so the fingerprint binds the same
    /// reviewed identities; only [`UnlinkMode::RemoveUnavailable`] ever
    /// deletes them. Sorted by path for determinism.
    pub abandon: Vec<UnlinkFile>,
}

impl UnlinkPlan {
    /// SHA-256 over the canonical serialization of the **full** plan
    /// (every field, including the exact abandon identities), lowercase hex.
    /// Identical plans fingerprint identically; any changed identity, count,
    /// mode or blocker produces a different fingerprint and forces a fresh
    /// review.
    pub fn preview_fingerprint(&self) -> String {
        let encoded = serde_json::to_vec(self).unwrap_or_default();
        hex::encode(Sha256::digest(&encoded))
    }

    /// Abandonment consent is required exactly when a [`UnlinkMode::RemoveUnavailable`]
    /// plan would actually abandon entries (`abandon` nonempty).
    pub fn requires_abandon_consent(&self) -> bool {
        self.mode == UnlinkMode::RemoveUnavailable && !self.abandon.is_empty()
    }
}

/// Pure abandonment rule: only clean zero-residency entries may be deleted
/// by a lossy removal. Partial files and dirty/conflicted content block and
/// are preserved or resolved instead. Enforced at execution time:
/// [`ConnectionRuntime::abandon_unavailable`](crate::sync::controller::ConnectionRuntime::abandon_unavailable)
/// re-applies this rule to each live entry immediately before deleting it,
/// and the plan-level partial/dirty/conflict counts block the lossy removal
/// up front (in the parent's protocol layer and again in `execute_unlink`).
pub(crate) fn abandonable(partial: bool, dirty: bool, conflicted: bool) -> bool {
    !partial && !dirty && !conflicted
}

/// Live facts the guarded deletion re-checks immediately before removing one
/// reviewed entry. Every field is read again at deletion time; the reviewed
/// plan's facts are never trusted in their place.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AbandonLiveFacts {
    pub volume_serial_number: u64,
    pub file_id: [u8; 16],
    pub size: u64,
    pub last_write_time_100ns: i64,
    /// Unique resident bytes proven from real on-disk ranges
    /// (`CfGetPlaceholderRangeInfo`), never recall attributes alone.
    pub resident_bytes: u64,
    pub partial: bool,
    pub dirty: bool,
    pub conflicted: bool,
}

/// Verdict of the guarded deletion for one reviewed abandonment entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AbandonVerdict {
    /// Every guard holds: the entry may be deleted right now.
    Proceed,
    /// The entry is already gone **and** the current prepare still matches
    /// the reviewed plan: deletion is idempotent and the entry already sits
    /// in its desired end state.
    AlreadyGone,
    /// The entry must be preserved untouched; the caller blocks the unlink
    /// naming it.
    Preserve(&'static str),
}

/// Pure guarded-deletion rule for one reviewed abandonment entry.
///
/// * `live: None` — the entry is missing. A missing entry is idempotent
///   **only** when the current prepare still matches the reviewed plan
///   (`plan_current`); otherwise a vanished entry proves the reviewed inputs
///   drifted and it blocks.
/// * `live: Some(_)` — the entry is present and must match the reviewed
///   identity (volume serial, 128-bit file id, size, modification time) and
///   hold **zero** resident bytes; partial, dirty, conflicted or
///   partly/fully resident entries never pass.
pub(crate) fn abandon_delete_verdict(
    live: Option<AbandonLiveFacts>,
    reviewed: &UnlinkFile,
    plan_current: bool,
) -> AbandonVerdict {
    let Some(live) = live else {
        return if plan_current {
            AbandonVerdict::AlreadyGone
        } else {
            AbandonVerdict::Preserve(
                "the entry vanished and the reviewed plan is no longer current; prepare a fresh preview",
            )
        };
    };
    if live.volume_serial_number != reviewed.volume_serial_number
        || live.file_id != reviewed.file_id
        || live.size != reviewed.size
        || live.last_write_time_100ns != reviewed.last_write_time_100ns
    {
        return AbandonVerdict::Preserve(
            "the entry changed since the reviewed preview; prepare a fresh preview",
        );
    }
    // Zero residency is part of the same rule: any resident byte, partial or
    // whole, blocks the deletion with the same preserve verdict.
    if !abandonable(live.partial, live.dirty, live.conflicted) || live.resident_bytes != 0 {
        return AbandonVerdict::Preserve(
            "the entry is no longer clean and zero-residency at execution time; it is preserved untouched",
        );
    }
    AbandonVerdict::Proceed
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
    #[error("preview inputs changed; review a fresh preview")]
    PreviewChanged,
    #[error("the operation requires sign-in")]
    NeedsSignIn,
    #[error("the connection is read-only for this operation")]
    ReadOnly,
}

// ---------------------------------------------------------------------------
// Startup recovery boundary
// ---------------------------------------------------------------------------

/// The startup recovery boundary: classify every interrupted journaled local
/// action before the connection may run. Returns how many interrupted actions
/// were requeued as fresh local work.
///
/// A recovery error is **never** ignored. The connection is left paused (and
/// durably paused when durable state is writable) and the error is the
/// connect's result: nothing may resume into pending destructive local
/// actions whose crash state was never classified.
async fn run_startup_recovery<R: RemoteOps>(
    runtime: &Arc<ConnectionRuntime<R>>,
    account: &AccountStore,
    connection_id: ConnectionId,
) -> Result<usize, EngineError> {
    let failure = match runtime.recover_actions().await {
        Ok(requeued) => {
            if requeued > 0 {
                tracing::info!(
                    requeued,
                    connection = %connection_id,
                    "interrupted local actions were requeued as fresh local work"
                );
            }
            return Ok(requeued);
        }
        Err(PublishError::State(state_error)) => EngineError::State(state_error),
        Err(error) => EngineError::Publish(error),
    };
    tracing::warn!(
        error = %failure,
        connection = %connection_id,
        "interrupted local actions could not be classified; \
         the connection stays paused and no work is resumed into them"
    );
    runtime.pause();
    // Fail closed across restarts too: the durable pause intent makes the
    // next successful recovery start paused, so the user resumes explicitly
    // after reviewing the error.
    if let Err(state_error) = account
        .set_settings(
            format!("connection/{connection_id}/paused"),
            serde_json::Value::Bool(true),
            None,
        )
        .await
    {
        tracing::warn!(
            %state_error,
            connection = %connection_id,
            "the durable pause intent could not be recorded after a failed recovery boundary"
        );
    }
    Err(failure)
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
        // Recovery boundary: classify interrupted local actions first. A
        // failed classification is propagated, never ignored: this just-started
        // runtime is torn down again (registration, durable state and work are
        // preserved) and the connect fails with the connection paused and not
        // ready — nothing ever resumes into pending destructive local actions
        // whose crash state was never classified. The durable pause intent is
        // recorded by the boundary, so the next successful recovery starts
        // paused as well and the user resumes explicitly.
        if let Err(error) = run_startup_recovery(&runtime, &account, connection_id).await {
            connection_cancel.cancel();
            if let Some(task) = watch_task.take() {
                let _ = task.await;
            }
            if let Err(disconnect) = runtime.disconnect().await {
                tracing::warn!(
                    %disconnect,
                    connection = %connection_id,
                    "the runtime did not disconnect cleanly after a failed recovery boundary; \
                     registration, state and work are preserved"
                );
            }
            return Err(error);
        }
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

    /// Prepares an unlink for one exact mode: counts what preservation
    /// requires, computes the export space and records the **exact identity**
    /// of every entry a removal may abandon. Never mutates.
    ///
    /// `blockers` holds only known impossibilities visible before execution
    /// (e.g. the recovery area is unavailable, an entry cannot be inspected,
    /// an unidentifiable placeholder holds unavailable bytes); retention
    /// failures surface during `execute_unlink` with the affected file list.
    ///
    /// `abandon` is populated identically in every mode so
    /// [`UnlinkPlan::preview_fingerprint`] binds the same reviewed identities
    /// for the same connection state; only [`UnlinkMode::RemoveUnavailable`]
    /// ever deletes them, and then only entries that are still clean,
    /// zero-residency and conflict-free at execution time.
    pub async fn prepare_unlink(
        &self,
        connection_id: ConnectionId,
        mode: UnlinkMode,
    ) -> Result<UnlinkPlan, EngineError> {
        let running = self.running.lock().await;
        let entry = running.get(&connection_id).ok_or(EngineError::UnknownConnection)?;
        let account = self.state.open_account(entry.runtime.account_key()).await?;
        let workspace = entry.runtime.workspace_id();
        let root = entry.runtime.root().to_path_buf();
        let mut plan = UnlinkPlan {
            connection_id,
            mode,
            ..UnlinkPlan::default()
        };
        let counts = account.work_counts(connection_id).await?;
        plan.dirty_files = counts.dirty_files;
        plan.conflict_files = counts.conflict_files;
        if plan.conflict_files > 0 {
            plan.blockers.push("unresolved conflicts must be resolved before removal".to_owned());
        }
        for snapshot in account.list_snapshots(connection_id).await? {
            if matches!(snapshot.status, SnapshotStatus::Capturing | SnapshotStatus::Ready) {
                plan.required_export_bytes += snapshot.size.unwrap_or(0);
            }
        }

        // Per-item local facts, collected first: the directory abandonment
        // rule needs every child classified before its parent.
        struct ItemFacts {
            path: PathBuf,
            /// HFDR placeholder identity verified against the registry item.
            version_id: Option<hfdrive_core::ids::VersionId>,
            /// HFDR ownership proven for this connection's workspace.
            owned: bool,
            directory: bool,
            partial: bool,
            size: u64,
            volume_serial_number: u64,
            file_id: [u8; 16],
            last_write_time_100ns: i64,
            /// A file a lossy removal may abandon: owned placeholder, not
            /// fully resident.
            file_candidate: bool,
        }
        let entries = account.list_all_items(connection_id, true).await?;
        let mut parents: HashMap<ItemId, Option<ItemId>> = HashMap::new();
        let mut facts: HashMap<ItemId, ItemFacts> = HashMap::new();
        for item in &entries {
            parents.insert(item.item_id, item.parent_id);
        }
        for item in &entries {
            if item.deleted || item.parent_id.is_none() {
                // The sync root itself is never an abandonment candidate.
                continue;
            }
            let Some(path) =
                crate::sync::controller::registry_path(&account, connection_id, item.item_id).await
            else {
                plan.blockers.push(format!("item {} has no resolvable local path", item.item_id));
                continue;
            };
            let absolute = root.join(&path);
            let live = match query_file_state(&absolute) {
                Ok(live) => live,
                Err(hfdrive_windows::filesystem::FsError::NotFound { .. }) => {
                    // The local entry is already absent: it holds no bytes to
                    // preserve or abandon and already sits in its unlink end
                    // state. A missing entry is idempotent — it never blocks,
                    // never counts and never enters the reviewed identity set.
                    continue;
                }
                Err(_) => {
                    plan.blockers.push(format!("{} cannot be inspected", path.to_string_lossy()));
                    continue;
                }
            };
            let placeholder = hfdrive_windows::filesystem::volume::placeholder_state(
                live.identity.attributes,
                live.identity.reparse_tag,
            );
            let directory = matches!(item.kind, hfdrive_state::ItemKind::Directory);
            // Residency comes from real on-disk ranges, never recall
            // attributes alone: `resident == size` is fully resident,
            // `0 < resident < size` is partial, `resident == 0` is
            // zero-residency. Directories carry no content bytes.
            let (not_resident, partial) = if directory || live.size == 0 {
                (false, false)
            } else if placeholder.is_placeholder() {
                match hfdrive_windows::cfapi::ops::resident_bytes(&absolute, live.size) {
                    Ok(resident) if resident >= live.size => (false, false),
                    Ok(resident) => (true, resident > 0),
                    Err(_) => {
                        plan.blockers
                            .push(format!("{} residency cannot be inspected", path.to_string_lossy()));
                        continue;
                    }
                }
            } else if live.identity.may_not_be_materialized() {
                // Non-placeholder content whose bytes may not be local (for
                // example another provider's cloud data): its residency cannot
                // be proven here. It is neither preserved nor abandoned; the
                // removal reports it instead of guessing.
                (true, false)
            } else {
                (false, false)
            };

            // HFDR ownership: only an identity that decodes for this
            // connection's workspace and agrees with the registry item and
            // content version is ever recorded as abandonable. Anything else
            // — a foreign placeholder, an unknown identity record or one that
            // disagrees with the registry — is preserved untouched and blocks
            // the removal: NTFS identity alone never authorizes changing it.
            let mut version_id = None;
            let mut owned = false;
            if placeholder.is_placeholder() {
                match hfdrive_windows::cfapi::read_placeholder_identity(&absolute, Some(workspace))
                {
                    Ok(Some(identity))
                        if identity.item == item.item_id
                            && identity.is_directory() == directory
                            && identity.version == item.content_version_id =>
                    {
                        version_id = identity.version;
                        owned = true;
                    }
                    Ok(Some(_)) => {
                        plan.blockers.push(format!(
                            "{} carries a placeholder identity that disagrees with the sync registry",
                            path.to_string_lossy()
                        ));
                    }
                    Ok(None) => {
                        plan.blockers.push(format!(
                            "{} is a placeholder without this drive's identity; it is preserved untouched",
                            path.to_string_lossy()
                        ));
                    }
                    Err(_) => {
                        plan.blockers.push(format!(
                            "{} cannot be verified as this connection's placeholder",
                            path.to_string_lossy()
                        ));
                    }
                }
            }
            if not_resident {
                if partial {
                    plan.partial_files += 1;
                } else {
                    plan.online_only_files += 1;
                }
                plan.required_export_bytes += live.size;
                if !owned && !placeholder.is_placeholder() {
                    plan.blockers.push(format!(
                        "{} holds unavailable bytes but is not an HF Drive placeholder; it can be neither preserved nor abandoned",
                        path.to_string_lossy()
                    ));
                }
            } else if entry_dirty(&account, connection_id, item.item_id).await {
                // Dirty resident bytes are exported to the recovery area
                // before anything destructive happens.
                plan.required_export_bytes += live.size;
            }
            facts.insert(
                item.item_id,
                ItemFacts {
                    path,
                    version_id,
                    owned,
                    directory,
                    partial,
                    size: live.size,
                    volume_serial_number: live.identity.volume_serial_number,
                    file_id: live.identity.file_id,
                    last_write_time_100ns: live.last_write_time_100ns,
                    file_candidate: owned && not_resident && !directory,
                },
            );
        }

        // Directory rule: a managed placeholder directory is an abandonment
        // candidate exactly when its whole subtree is — every transitive
        // descendant is itself a candidate. Any retained entry (resident,
        // plain, foreign) marks all of its ancestors as retained.
        let mut children: HashMap<ItemId, Vec<ItemId>> = HashMap::new();
        for (item_id, parent) in &parents {
            if let Some(parent) = parent {
                children.entry(*parent).or_default().push(*item_id);
            }
        }
        let depth = |item_id: ItemId| -> usize {
            let mut depth = 0;
            let mut current = parents.get(&item_id).copied().flatten();
            while let Some(id) = current {
                depth += 1;
                current = parents.get(&id).copied().flatten();
            }
            depth
        };
        let mut candidates: std::collections::BTreeSet<ItemId> = facts
            .iter()
            .filter(|(_, fact)| fact.file_candidate)
            .map(|(item_id, _)| *item_id)
            .collect();
        let mut ordered: Vec<ItemId> = facts
            .iter()
            .filter(|(_, fact)| fact.directory)
            .map(|(item_id, _)| *item_id)
            .collect();
        ordered.sort_by_key(|item_id| std::cmp::Reverse(depth(*item_id)));
        for item_id in ordered {
            let Some(fact) = facts.get(&item_id) else { continue; };
            if !fact.owned || fact.version_id.is_some() {
                // Only HFDR-owned directory placeholders (no content version)
                // can be abandoned; an inconsistent record was reported above.
                continue;
            }
            let all_candidates = children
                .get(&item_id)
                .map(|kids| kids.iter().all(|kid| candidates.contains(kid)))
                .unwrap_or(true);
            if all_candidates {
                candidates.insert(item_id);
            }
        }
        for item_id in candidates {
            let Some(fact) = facts.get(&item_id) else { continue; };
            plan.abandon.push(UnlinkFile {
                item_id,
                path: fact.path.clone(),
                version_id: fact.version_id,
                volume_serial_number: fact.volume_serial_number,
                file_id: fact.file_id,
                size: fact.size,
                last_write_time_100ns: fact.last_write_time_100ns,
                partial: fact.partial,
            });
        }
        plan.abandon.sort_by(|a, b| a.path.cmp(&b.path));

        plan.all_resident = plan.online_only_files == 0 && plan.partial_files == 0;
        // Known impossibility only: without a writable recovery area no dirty
        // content can be retained.
        if !entry.runtime.recovery_area_ready() {
            plan.blockers
                .push("the recovery area is unavailable; dirty content cannot be preserved".to_owned());
        }
        Ok(plan)
    }

    /// Executes an unlink in one exact mode. The mode drives the safety
    /// decision explicitly:
    ///
    /// * [`UnlinkMode::DisconnectKeepRegistration`] disconnects the runtime
    ///   and retains registration, binding, state and data for explicit
    ///   recovery;
    /// * [`UnlinkMode::SafeRemove`] preserves dirty bytes as verified
    ///   recovery copies, hydrates or exports every required placeholder,
    ///   converts resident files to normal files, and removes nothing;
    /// * [`UnlinkMode::RemoveUnavailable`] additionally **abandons** the
    ///   reviewed clean zero-residency placeholders — but only after zero
    ///   partial files are proven, dirty bytes are preserved, watchers are
    ///   stopped, and every deletion passes the HFDR-ownership,
    ///   identity/size/mtime and `resident_bytes == 0` guard.
    ///
    /// Both removal modes end with a complete live residue scan, then
    /// unregistration, a verified registration-absence check and
    /// `remove_connection`. The plan must still be current: any change to
    /// counts, blockers or exact identities is [`EngineError::PreviewChanged`]
    /// and nothing is touched.
    pub async fn execute_unlink(
        &self,
        connection_id: ConnectionId,
        plan: &UnlinkPlan,
        mode: UnlinkMode,
    ) -> Result<UnlinkOutcome, EngineError> {
        if mode != plan.mode || &self.prepare_unlink(connection_id, mode).await? != plan {
            return Err(EngineError::PreviewChanged);
        }
        let mut running = self.running.lock().await;
        if mode == UnlinkMode::DisconnectKeepRegistration {
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
        if !plan.blockers.is_empty() {
            return Err(EngineError::UnlinkBlocked(crate::sync::controller::UnlinkBlocked {
                reason: "unlink is blocked until the listed content is preserved",
                files: plan.blockers.clone(),
            }));
        }
        if mode == UnlinkMode::RemoveUnavailable {
            // The lossy removal abandons bytes; it requires zero partial
            // files and never proceeds past unsynchronized or conflicted
            // content.
            let mut reasons = Vec::new();
            if plan.partial_files > 0 {
                reasons.push(format!(
                    "{} partially resident files cannot be abandoned and must be hydrated, exported or resolved first",
                    plan.partial_files
                ));
            }
            if plan.dirty_files > 0 {
                reasons.push(format!(
                    "{} files retain unsynchronized local changes and must be preserved before removal",
                    plan.dirty_files
                ));
            }
            if plan.conflict_files > 0 {
                reasons.push(format!(
                    "{} files have unresolved conflicts and must be resolved before removal",
                    plan.conflict_files
                ));
            }
            if !reasons.is_empty() {
                return Err(EngineError::UnlinkBlocked(crate::sync::controller::UnlinkBlocked {
                    reason: "the lossy removal is blocked until unsynchronized content is preserved or resolved",
                    files: reasons,
                }));
            }
        }
        let runtime = running
            .get(&connection_id)
            .ok_or(EngineError::UnknownConnection)?
            .runtime
            .clone();
        // Remote dispatch stops first; nothing publishes during teardown.
        runtime.quiesce().await;
        // Preservation work runs with observers still live only in the safe
        // mode (its conversions are provider-applied and echo-suppressed).
        // Both removal modes stop every watcher before any deletion so the
        // provider's own removals can never become remote delete intents.
        match mode {
            UnlinkMode::SafeRemove => {
                // Preserve dirty bytes as verified recovery copies, hydrate
                // or export every required placeholder, convert resident
                // files to normal files. Nothing is deleted.
                runtime.preserve_all_for_unlink(plan).await?;
                runtime.stop_observation().await;
                runtime.revert_placeholders_to_normal(&std::collections::BTreeSet::new()).await?;
                runtime.live_residue(&[])?;
            }
            UnlinkMode::RemoveUnavailable => {
                // Preserve dirty content first (unique, metadata-checked,
                // hash-verified recovery copies); it blocks the lossy path
                // but is never left unpreserved before destructive work.
                let preserved = runtime.preserve_dirty_before_removal().await?;
                if !preserved.is_empty() {
                    return Err(EngineError::UnlinkBlocked(crate::sync::controller::UnlinkBlocked {
                        reason: "unsynchronized local changes were preserved to the recovery area and block abandonment; resolve them first",
                        files: preserved,
                    }));
                }
                runtime.stop_observation().await;
                // Convert resident files (and every managed entry outside the
                // reviewed abandonment set) to normal files.
                let skip: std::collections::BTreeSet<ItemId> =
                    plan.abandon.iter().map(|file| file.item_id).collect();
                runtime.revert_placeholders_to_normal(&skip).await?;
                runtime.abandon_unavailable(plan, true).await?;
                runtime.live_residue(&plan.abandon)?;
            }
            UnlinkMode::DisconnectKeepRegistration => unreachable!("handled above"),
        }
        let entry = running.remove(&connection_id).ok_or(EngineError::UnknownConnection)?;
        drop(running);
        match Self::stop_entry(entry).await {
            Ok(entry) => {
                if let Err(error) = registry::unregister_connection(&self.config.user_sid, connection_id) {
                    self.running.lock().await.insert(connection_id, entry);
                    return Err(error.into());
                }
                // Registration absence is proven before durable state drops.
                let expected =
                    hfdrive_windows::cfapi::registration::sync_root_id(&self.config.user_sid, connection_id)
                        .map_err(|_| registry::AdmissionError::Registration)?;
                let still_registered = registry::registered_roots()?
                    .iter()
                    .any(|root| root.id == expected);
                if still_registered {
                    self.running.lock().await.insert(connection_id, entry);
                    return Err(EngineError::UnlinkBlocked(crate::sync::controller::UnlinkBlocked::new(
                        "the Windows registration is still present after unregistration; durable state is retained for recovery",
                    )));
                }
                let account = self.state.open_account(entry.runtime.account_key()).await?;
                account.remove_connection(connection_id).await?;
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

    use hfdrive_core::ids::{AccountKey, ActionId, DeviceId, WorkspaceId};
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

    // ---- pure unlink safety regressions ----------------------

    /// The pure abandonment rule: exactly the clean, zero-residency,
    /// conflict-free entry may be deleted by a lossy removal.
    #[test]
    fn abandonable_accepts_only_clean_zero_residency_entries() {
        assert!(abandonable(false, false, false));
        for (partial, dirty, conflicted) in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (true, true, false),
            (true, false, true),
            (false, true, true),
            (true, true, true),
        ] {
            assert!(
                !abandonable(partial, dirty, conflicted),
                "partial={partial} dirty={dirty} conflicted={conflicted} must never be abandonable"
            );
        }
    }

    /// The fingerprint binds the **full** reviewed plan: identical plans
    /// fingerprint identically, and any change to an exact identity, count,
    /// mode or blocker produces a different fingerprint and rotates consent.
    #[test]
    fn the_preview_fingerprint_binds_the_full_plan_and_any_change_rotates_it() {
        let file = |item_id: ItemId, path: &str, version: bool| UnlinkFile {
            item_id,
            path: PathBuf::from(path),
            version_id: version.then(hfdrive_core::ids::VersionId::new),
            volume_serial_number: 7,
            file_id: [1; 16],
            size: 2048,
            last_write_time_100ns: 133_738_424_000_000_000,
            partial: false,
        };
        let base = UnlinkPlan {
            connection_id: ConnectionId::new(),
            mode: UnlinkMode::RemoveUnavailable,
            online_only_files: 2,
            partial_files: 0,
            dirty_files: 1,
            conflict_files: 0,
            required_export_bytes: 4096,
            blockers: Vec::new(),
            all_resident: false,
            abandon: vec![file(ItemId::new(), "docs\\a.bin", true), file(ItemId::new(), "docs\\empty", false)],
        };
        let fingerprint = base.preview_fingerprint();
        assert_eq!(fingerprint.len(), 64, "lowercase hex SHA-256");
        assert!(
            fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "the fingerprint is lowercase hex: {fingerprint}"
        );
        assert_eq!(
            fingerprint,
            base.clone().preview_fingerprint(),
            "identical reviewed plans fingerprint identically"
        );

        let mut changed_identity = base.clone();
        changed_identity.abandon[0].file_id = [2; 16];
        assert_ne!(fingerprint, changed_identity.preview_fingerprint(), "the exact NTFS file identity is bound");

        let mut changed_version = base.clone();
        changed_version.abandon[0].version_id = Some(hfdrive_core::ids::VersionId::new());
        assert_ne!(fingerprint, changed_version.preview_fingerprint(), "the immutable content version is bound");

        let mut changed_path = base.clone();
        changed_path.abandon[0].path = PathBuf::from("docs\\b.bin");
        assert_ne!(fingerprint, changed_path.preview_fingerprint(), "the reviewed path is bound");

        let mut changed_count = base.clone();
        changed_count.online_only_files += 1;
        assert_ne!(fingerprint, changed_count.preview_fingerprint(), "the counts are bound");

        let mut changed_mode = base.clone();
        changed_mode.mode = UnlinkMode::SafeRemove;
        assert_ne!(fingerprint, changed_mode.preview_fingerprint(), "the reviewed mode is bound");

        let mut changed_blocker = base.clone();
        changed_blocker.blockers.push("a new blocker".to_owned());
        assert_ne!(fingerprint, changed_blocker.preview_fingerprint(), "the blockers are bound");

        let mut reordered = base.clone();
        reordered.abandon.reverse();
        assert_ne!(fingerprint, reordered.preview_fingerprint(), "the reviewed identity order is bound");
    }

    /// Abandonment consent is required exactly when a `RemoveUnavailable`
    /// plan would actually abandon entries; safe removal hydrates/exports and
    /// disconnect-keep-registration discards nothing, so neither asks for it.
    #[test]
    fn abandon_consent_is_required_exactly_for_nonempty_abandonment() {
        let mut plan = UnlinkPlan {
            connection_id: ConnectionId::new(),
            mode: UnlinkMode::RemoveUnavailable,
            ..UnlinkPlan::default()
        };
        assert!(
            !plan.requires_abandon_consent(),
            "an empty abandonment destroys no managed-only bytes and needs no consent"
        );
        plan.abandon.push(UnlinkFile {
            item_id: ItemId::new(),
            path: PathBuf::from("online-only.bin"),
            version_id: Some(hfdrive_core::ids::VersionId::new()),
            volume_serial_number: 7,
            file_id: [1; 16],
            size: 4096,
            last_write_time_100ns: 133_738_424_000_000_000,
            partial: false,
        });
        assert!(
            plan.requires_abandon_consent(),
            "the lossy removal destroys bytes that exist only in managed storage"
        );
        plan.mode = UnlinkMode::SafeRemove;
        assert!(!plan.requires_abandon_consent(), "safe removal never discards unavailable bytes");
        plan.mode = UnlinkMode::DisconnectKeepRegistration;
        assert!(!plan.requires_abandon_consent(), "disconnect keeps every entry and reference");
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
        let seeded = account
            .record_head_invalidation(connection, Some("c0".to_owned()))
            .await
            .expect("seed cursor");
        account.ack_head_refresh(connection, seeded.head_refresh_generation).await.expect("clear pending flag");

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

    // ---- startup recovery boundary ------------------------------

    /// One interrupted `UpdatePlaceholder` journaled against a real local
    /// file: its expected file identity never matches the live file, so
    /// classification requeues it as fresh local work.
    fn interrupted_update(connection: ConnectionId, path: &str) -> hfdrive_state::LocalAction {
        hfdrive_state::LocalAction {
            connection_id: connection,
            action_id: ActionId::new(),
            item_id: Some(ItemId::new()),
            kind: hfdrive_state::LocalActionKind::UpdatePlaceholder,
            expected_file_id: Some("00000000000000000000000000000000".to_owned()),
            expected_generation: Some(1),
            expected_usn: None,
            old_version: None,
            new_version: None,
            source_path: Some(PathBuf::from(path)),
            target_path: None,
            recovery_path: None,
            state: hfdrive_state::LocalActionState::Pending,
        }
    }

    /// The recovery boundary success path: interrupted local actions are
    /// classified (requeued as fresh local work) and the boundary releases
    /// **no** remote scheduling of its own — no remote work runs until the
    /// caller explicitly resumes (the probe is sensitive: an explicit resume
    /// does schedule the round).
    #[tokio::test]
    async fn a_successful_recovery_boundary_requeues_interrupted_actions_without_resuming() {
        use crate::sync::test_support::{HeadOnlyRemote, connection_fixture};
        let fixture = connection_fixture().await;
        std::fs::write(fixture.root.join("doc.txt"), b"changed locally").unwrap();
        let action = interrupted_update(fixture.connection, "doc.txt");
        let action_id = action.action_id;
        fixture.account.record_local_action(action).await.unwrap();

        let remote = HeadOnlyRemote { head: None, ..Default::default() };
        let reads = remote.head_reads.clone();
        let cancel = CancellationToken::new();
        let (_notifications, receiver) = tokio::sync::mpsc::channel(1);
        let runtime = ConnectionRuntime::start(
            ConnectionConfig {
                connection_id: fixture.connection, workspace: fixture.workspace,
                root_item_id: fixture.root_item, device_id: DeviceId::new(),
                root: fixture.root.clone(), staging_dir: fixture.directory.path().join("snapshots"),
                recovery_dir: fixture.directory.path().join("recovery"),
                mode: hfdrive_state::ConnectionMode::Writable, start_paused: true,
            },
            fixture.account.clone(), remote,
            Arc::new(Scheduler::new(Default::default())),
            Arc::new(crate::sync::activity::ActivityRegistry::new()),
            cancel.clone(), receiver,
        );
        let requeued = run_startup_recovery(&runtime, &fixture.account, fixture.connection)
            .await
            .expect("a classified boundary succeeds");
        assert_eq!(requeued, 1, "the interrupted action is requeued as fresh local work");
        let recorded = fixture.account.local_action(fixture.connection, action_id).await.unwrap().unwrap();
        assert_eq!(
            recorded.state,
            hfdrive_state::LocalActionState::Requeued,
            "the classification is durable before the boundary reports success"
        );
        let pause_intent = fixture.account
            .settings(format!("connection/{}/paused", fixture.connection))
            .await
            .unwrap();
        assert!(
            pause_intent.is_none(),
            "a successful boundary records no new durable pause intent"
        );
        // The boundary itself never resumes remote scheduling.
        runtime.drive().await;
        assert_eq!(reads.load(std::sync::atomic::Ordering::Relaxed), 0, "no remote work ran unreleased");
        // The probe is sensitive: an explicit resume does release scheduling.
        runtime.resume();
        runtime.drive().await;
        runtime.drive().await;
        assert!(reads.load(std::sync::atomic::Ordering::Relaxed) > 0, "an explicit resume releases scheduling");
        cancel.cancel();
        runtime.disconnect().await.unwrap();
        fixture.state.close().await.unwrap();
    }

    /// The recovery failure path (F01): the error is propagated — never
    /// ignored — the interrupted action stays journaled and unclassified
    /// (nothing resumed into it), and the durable pause intent is recorded
    /// fail-closed so the next successful recovery also starts paused. The
    /// in-memory pause is asserted indirectly: the boundary forced the pause
    /// from a resumed state and nothing re-released it (covered by the
    /// success-path scheduling probe above).
    #[tokio::test]
    async fn a_failed_recovery_boundary_propagates_and_leaves_the_connection_paused() {
        use crate::sync::test_support::{HeadOnlyRemote, connection_fixture};
        let fixture = connection_fixture().await;
        std::fs::write(fixture.root.join("doc.txt"), b"changed locally").unwrap();
        let action = interrupted_update(fixture.connection, "doc.txt");
        let action_id = action.action_id;
        fixture.account.record_local_action(action).await.unwrap();
        let account_key = fixture.account.account_key();

        // The runtime keeps the fixture's own state handle, whose worker is
        // stopped below: `recover_actions` then fails exactly as durable state
        // failing at a real recovery boundary does.
        let runtime_account = fixture.account.clone();
        let state_dir = fixture.directory.path().join("state");
        fixture.state.close().await.unwrap();
        // A fresh handle over the same databases: the boundary's own durable
        // state must remain writable so its fail-closed pause intent lands in
        // the connection's real account database (as it does when recovery
        // fails while the state worker is healthy).
        let recovery_state = hfdrive_state::StateStore::open(StatePaths::new(state_dir)).await.unwrap();
        let recovery_account = recovery_state.open_account(account_key).await.unwrap();

        let cancel = CancellationToken::new();
        let (_notifications, receiver) = tokio::sync::mpsc::channel(1);
        let runtime = ConnectionRuntime::start(
            ConnectionConfig {
                connection_id: fixture.connection, workspace: fixture.workspace,
                root_item_id: fixture.root_item, device_id: DeviceId::new(),
                root: fixture.root.clone(), staging_dir: fixture.directory.path().join("snapshots"),
                recovery_dir: fixture.directory.path().join("recovery"),
                mode: hfdrive_state::ConnectionMode::Writable, start_paused: true,
            },
            runtime_account, HeadOnlyRemote { head: None, ..Default::default() },
            Arc::new(Scheduler::new(Default::default())),
            Arc::new(crate::sync::activity::ActivityRegistry::new()),
            cancel.clone(), receiver,
        );
        // Prove the failure forces the pause even from a resumed state: the
        // engine resumes only after a successful boundary, so the failure
        // itself must take the release back.
        runtime.resume();
        let error = run_startup_recovery(&runtime, &recovery_account, fixture.connection)
            .await
            .expect_err("a failed recovery boundary is never ignored");
        assert!(
            matches!(error, EngineError::State(_)),
            "the recovery failure is propagated to the connect caller: {error}"
        );
        let pause_intent = recovery_account
            .settings(format!("connection/{}/paused", fixture.connection))
            .await
            .unwrap()
            .expect("the durable pause intent is recorded so the next recovery starts paused");
        assert_eq!(
            pause_intent.value_json,
            serde_json::Value::Bool(true),
            "the durable pause intent is fail-closed"
        );
        let recorded = recovery_account.local_action(fixture.connection, action_id).await.unwrap()
            .expect("the interrupted action is still journaled");
        assert_eq!(
            recorded.state,
            hfdrive_state::LocalActionState::Pending,
            "no recovery decision was applied; the action stays unclassified, never resumed into"
        );
        cancel.cancel();
        runtime.disconnect().await.unwrap();
        recovery_state.close().await.unwrap();
    }

    // ---- pure unlink planning and guarded deletion rules ----------------

    fn unlink_file(
        item_id: ItemId,
        path: &str,
        size: u64,
        mtime: i64,
    ) -> UnlinkFile {
        UnlinkFile {
            item_id,
            path: PathBuf::from(path),
            version_id: Some(hfdrive_core::ids::VersionId::new()),
            volume_serial_number: 7,
            file_id: [3u8; 16],
            size,
            last_write_time_100ns: mtime,
            partial: false,
        }
    }

    /// The preview fingerprint binds the **full** reviewed set, not a bounded
    /// sample: an identical plan fingerprints identically and any changed
    /// identity (even outside the mapped wire window) rotates the fingerprint.
    #[test]
    fn preview_fingerprint_binds_the_full_reviewed_identity_set() {
        let item = ItemId::new();
        let mut plan = UnlinkPlan {
            connection_id: ConnectionId::new(),
            mode: UnlinkMode::RemoveUnavailable,
            abandon: vec![
                unlink_file(item, "a\\one.bin", 10, 1),
                unlink_file(ItemId::new(), "b\\two.bin", 20, 2),
                unlink_file(ItemId::new(), "c\\three.bin", 30, 3),
            ],
            ..UnlinkPlan::default()
        };
        let fingerprint = plan.preview_fingerprint();
        assert_eq!(fingerprint.len(), 64, "a lowercase SHA-256 hex digest");
        // Rebuilding the identical plan reproduces the same fingerprint.
        let again = UnlinkPlan {
            connection_id: plan.connection_id,
            mode: plan.mode,
            abandon: plan.abandon.clone(),
            ..UnlinkPlan::default()
        };
        assert_eq!(again.preview_fingerprint(), fingerprint, "identical plans fingerprint identically");
        // Any changed reviewed identity rotates the fingerprint.
        let changed_size = UnlinkPlan {
            connection_id: plan.connection_id,
            mode: plan.mode,
            abandon: vec![
                unlink_file(item, "a\\one.bin", 11, 1),
                plan.abandon[1].clone(),
                plan.abandon[2].clone(),
            ],
            ..UnlinkPlan::default()
        };
        assert_ne!(changed_size.preview_fingerprint(), fingerprint, "a changed size rotates consent");
        // The set is order-insensitive only because the producer sorts it;
        // the fingerprint covers every entry, so one added entry changes it.
        let extra = UnlinkPlan {
            connection_id: plan.connection_id,
            mode: plan.mode,
            abandon: vec![
                plan.abandon[0].clone(),
                plan.abandon[1].clone(),
                plan.abandon[2].clone(),
                unlink_file(ItemId::new(), "d\\four.bin", 40, 4),
            ],
            ..UnlinkPlan::default()
        };
        assert_ne!(extra.preview_fingerprint(), fingerprint, "an extra reviewed entry rotates consent");
        // The mode is part of the reviewed plan: the same files under another
        // mode are a different review.
        plan.mode = UnlinkMode::SafeRemove;
        assert_ne!(plan.preview_fingerprint(), fingerprint, "a changed mode rotates consent");
    }

    /// The guarded-deletion rule: only clean zero-residency entries with the
    /// exact reviewed identity may be deleted, and a missing entry is
    /// idempotent only while the current prepare still matches.
    #[test]
    fn abandonment_guards_identity_residency_and_missing_entries() {
        use super::AbandonLiveFacts;
        let reviewed = unlink_file(ItemId::new(), "docs\\gone.bin", 42, 9);
        let matching = AbandonLiveFacts {
            volume_serial_number: reviewed.volume_serial_number,
            file_id: reviewed.file_id,
            size: reviewed.size,
            last_write_time_100ns: reviewed.last_write_time_100ns,
            resident_bytes: 0,
            partial: false,
            dirty: false,
            conflicted: false,
        };
        // The reviewed identity, zero residency and clean state: deletable.
        assert_eq!(
            abandon_delete_verdict(Some(matching), &reviewed, true),
            AbandonVerdict::Proceed
        );
        // Any drifted identity (size, mtime, file id, volume) blocks.
        let mut drifted = matching;
        drifted.size += 1;
        assert_eq!(
            abandon_delete_verdict(Some(drifted), &reviewed, true),
            AbandonVerdict::Preserve("the entry changed since the reviewed preview; prepare a fresh preview")
        );
        let mut drifted = matching;
        drifted.last_write_time_100ns += 1;
        assert_eq!(
            abandon_delete_verdict(Some(drifted), &reviewed, true),
            AbandonVerdict::Preserve("the entry changed since the reviewed preview; prepare a fresh preview")
        );
        let mut drifted = matching;
        drifted.file_id[0] ^= 1;
        assert_eq!(
            abandon_delete_verdict(Some(drifted), &reviewed, true),
            AbandonVerdict::Preserve("the entry changed since the reviewed preview; prepare a fresh preview")
        );
        let mut drifted = matching;
        drifted.volume_serial_number += 1;
        assert_eq!(
            abandon_delete_verdict(Some(drifted), &reviewed, true),
            AbandonVerdict::Preserve("the entry changed since the reviewed preview; prepare a fresh preview")
        );
        // Resident bytes, partial state, dirty state or an unresolved
        // conflict all block: nothing locally valuable is ever discarded.
        for facts in [
            AbandonLiveFacts { resident_bytes: 1, ..matching },
            AbandonLiveFacts { partial: true, ..matching },
            AbandonLiveFacts { dirty: true, ..matching },
            AbandonLiveFacts { conflicted: true, ..matching },
        ] {
            assert_eq!(
                abandon_delete_verdict(Some(facts), &reviewed, true),
                AbandonVerdict::Preserve("the entry is no longer clean and zero-residency at execution time; it is preserved untouched"),
                "unavailable, partial, dirty or conflicted content is never deleted"
            );
        }
        // Zero residency is proven by range evidence: a partially resident
        // file whose resident bytes are reported separately must not pass
        // just because the guard only compares the identity.
        let mut partial_evidence = matching;
        partial_evidence.partial = true;
        partial_evidence.resident_bytes = 1;
        assert_ne!(
            abandon_delete_verdict(Some(partial_evidence), &reviewed, true),
            AbandonVerdict::Proceed,
            "partial residency always blocks abandonment"
        );
        // A missing entry is idempotent exactly while the current prepare
        // still matches the reviewed plan.
        assert_eq!(abandon_delete_verdict(None, &reviewed, true), AbandonVerdict::AlreadyGone);
        assert_eq!(
            abandon_delete_verdict(None, &reviewed, false),
            AbandonVerdict::Preserve(
                "the entry vanished and the reviewed plan is no longer current; prepare a fresh preview"
            )
        );
    }
}
