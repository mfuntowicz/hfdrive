//! The per-connection runtime: observation -> intent -> capture/upload ->
//! publication -> guarded local apply, plus the parent-facing control plane
//! (pause/resume, pin, free space, selective sync, retry, recovery).
//!
//! Durability rules enforced by the loop:
//!
//! * every local observation persists its generation and its outbox intent
//!   **before** any capture or network effect; provider-applied changes are
//!   absorbed by the echo filter and never become intents;
//! * superseded uploads never clear newer edits: completion is generation
//!   guarded and a `CompletedWithNewerGeneration` result schedules the next
//!   intent;
//! * pause stops new remote scheduling but keeps observation and durable
//!   intent; resume revalidates capabilities before dispatch; read-only
//!   connections never upload or mutate remotely and keep local edits
//!   recoverable;
//! * remote `HEAD` invalidations (SSE/polling owned by `remote_watch`) and
//!   local invalidations (watcher overflow, USN reset) only wake the loop —
//!   every decision re-reads durable state.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use hfdrive_core::ids::{ConnectionId, DeviceId, ItemId, OperationId, UploadId, VersionId, WorkspaceId};
use hfdrive_core::reconcile::ReconcileMode;
use hfdrive_state::{
    AccountStore, LocalActionState, ObservationFlags, OutboxEntry, OutboxState,
};
use hfdrive_windows::filesystem::volume::{FileState, query_file_state};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::scheduler::Scheduler;
use crate::sync::observe::{
    Classification, EchoTable, LocalObserver, ObserverConfig, PendingRemovals,
    classify_observation, resolve_item,
};
use crate::sync::outbox::{
    IntentKind, PendingContent, PhaseStep, SyncIntent, display_timestamp, intent_entry,
    next_step, parse_intent,
};
use crate::sync::publish::{PublishError, RoundContext, RoundOutcome, run_round, upload_entry};
use crate::sync::remote::RemoteOps;

/// Per-connection runtime configuration.
pub struct ConnectionConfig {
    pub connection_id: ConnectionId,
    pub workspace: WorkspaceId,
    pub root_item_id: ItemId,
    pub device_id: DeviceId,
    pub root: PathBuf,
    pub staging_dir: PathBuf,
    pub recovery_dir: PathBuf,
    pub mode: hfdrive_state::ConnectionMode,
    /// Keep remote scheduling paused until the caller explicitly resumes.
    pub start_paused: bool,
}

/// Liveness of one connection's CFAPI runtime.
///
/// The status and reconnect paths must be able to tell a healthy active
/// runtime from a missing, cancelled or finished one: none of the latter are
/// synchronized, and none of them may be reported as if they were. Local data
/// is preserved in every state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RuntimeState {
    /// No CFAPI pump is attached: the root is not being driven.
    #[default]
    Missing,
    /// The connection's cancellation fired: the runtime is stopping or has
    /// stopped.
    Cancelled,
    /// The CFAPI pump ran to its end (or is draining): the sync root is no
    /// longer driven by this runtime.
    Finished,
    /// Callbacks are attached and the pump is running.
    Active,
}

impl RuntimeState {
    /// True only for a CFAPI runtime that is actually driving the root.
    pub fn is_active(self) -> bool {
        matches!(self, RuntimeState::Active)
    }

    /// Non-secret explanation for the status layer. None of these claim that
    /// local data was lost: state, registration and files are preserved.
    pub fn describe(self) -> &'static str {
        match self {
            RuntimeState::Active => "the local sync runtime is connected and running",
            RuntimeState::Missing => {
                "the local sync runtime is not connected; local files are preserved and reconnect resumes synchronization"
            }
            RuntimeState::Cancelled => {
                "the local sync runtime was stopped; local files are preserved and reconnect resumes synchronization"
            }
            RuntimeState::Finished => {
                "the local sync runtime ended; local files are preserved and reconnect resumes synchronization"
            }
        }
    }
}

/// Durable capability + health state surfaced to the parent's status layer.
#[derive(Debug, Clone, Default)]
pub struct ConnectionHealth {
    pub paused: bool,
    pub writable: bool,
    pub pending_files: u32,
    pub dirty_files: u32,
    pub conflict_files: u32,
    pub last_error: Option<String>,
    /// The remote observation worker (SSE/poll) recorded a failure. The
    /// connection's own drive loop and CFAPI runtime are unaffected; remote
    /// reconciliation continues and the failure stays visible until a live
    /// watch proves itself again.
    pub watch_error: Option<WatchFailure>,
    /// Live CFAPI runtime liveness, folded in by
    /// [`ConnectionRuntime::health`]. A stale snapshot is never presented as
    /// an active runtime.
    pub runtime: RuntimeState,
}

/// A recorded remote-watch failure. Non-secret; kept in health so the status
/// layer can project it truthfully instead of claiming "up to date".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchFailure {
    /// A remote change was observed but could not be recorded durably. Its
    /// cursor was not acknowledged, so a reconnect replays it.
    Persistence,
    /// The change feed is unavailable (throttled, needs sign-in, denied,
    /// offline or transport failure). Independent polling keeps running.
    Stream(crate::remote_watch::WatchIssue),
}

impl WatchFailure {
    /// Non-secret explanation for the status layer. Never claims local data
    /// was lost: state, registration and files are preserved.
    pub fn describe(self) -> &'static str {
        match self {
            WatchFailure::Persistence => {
                "a remote change could not be recorded durably; it is replayed on reconnect and local files are preserved"
            }
            WatchFailure::Stream(crate::remote_watch::WatchIssue::RateLimited) => {
                "the remote service throttled change observation; independent polling continues"
            }
            WatchFailure::Stream(crate::remote_watch::WatchIssue::AuthRequired) => {
                "change observation requires sign-in; local files are preserved"
            }
            WatchFailure::Stream(crate::remote_watch::WatchIssue::PermissionDenied) => {
                "change observation was denied; local files are preserved"
            }
            WatchFailure::Stream(crate::remote_watch::WatchIssue::RemoteUnavailable) => {
                "the remote service is unavailable; independent polling continues and local files are preserved"
            }
            WatchFailure::Stream(crate::remote_watch::WatchIssue::Transport) => {
                "change observation transport failed; independent polling continues and local files are preserved"
            }
        }
    }
}

/// Engine → connection-runtime notifications for one connection's remote
/// watch worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchUpdate {
    /// A remote `HEAD` invalidation was durably recorded and acknowledged.
    /// A poll-sourced invalidation proves durable persistence again but says
    /// nothing about the event stream; an event/reset-sourced one proves the
    /// whole observation path.
    HeadInvalidated {
        source: crate::remote_watch::NoticeSource,
    },
    /// The remote watch worker recorded a failure. The connection's drive
    /// loop and CFAPI runtime are deliberately unaffected by a watch failure.
    WatchFailed(WatchFailure),
}

/// One running connection.
pub struct ConnectionRuntime<R: RemoteOps> {
    config: ConnectionConfig,
    state: AccountStore,
    remote: R,
    scheduler: Arc<Scheduler>,
    /// The provider-wide live-work registry this connection's CFAPI pump
    /// opens its in-flight spans in.
    activity: Arc<crate::sync::activity::ActivityRegistry>,
    cancel: CancellationToken,
    paused: watch::Sender<bool>,
    health: watch::Sender<ConnectionHealth>,
    echo: tokio::sync::Mutex<EchoTable>,
    pending_removals: tokio::sync::Mutex<PendingRemovals>,
    /// Held across each drive round so quiescence can await exactly the
    /// in-flight dispatch instead of guessing at pause timing.
    dispatch: tokio::sync::Mutex<()>,
    pump: tokio::sync::Mutex<Option<PumpHandle>>,
    disconnect_failure: tokio::sync::Mutex<Option<DisconnectError>>,
    observer: tokio::sync::Mutex<Option<LocalObserver>>,
    observation_tx: tokio::sync::Mutex<Option<mpsc::Sender<crate::sync::observe::ObservationBatch>>>,
    local_ready: AtomicBool,
    scan_requested: AtomicBool,
    persistence_failed: AtomicBool,
    reconcile_requested: AtomicBool,
}

/// The live CFAPI pump of one connected root. Stopping it cancels its work
/// (every request's worker observes the pump's child token), drains every
/// in-flight request worker to completion, and disconnects the sync root
/// while the callback context is still valid. The task's result is the
/// pump's [`crate::sync::cfapi_pump::PumpOutcome`]: a disconnect failure is
/// carried there and surfaced by [`ConnectionRuntime::disconnect`], never
/// reported as a successful disconnect.
pub struct PumpHandle {
    pub(crate) token: CancellationToken,
    pub(crate) task: tokio::task::JoinHandle<crate::sync::cfapi_pump::PumpOutcome>,
}

/// Why a pump did not disconnect its sync root cleanly. Surfaced by
/// [`ConnectionRuntime::disconnect`]; the connection is no longer driving
/// the root either way.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DisconnectError {
    /// `CfDisconnectSyncRoot` failed; `code` is the Windows error code
    /// (`u32::MAX` when the failure carries no code).
    #[error("CfDisconnectSyncRoot failed (code={code})")]
    Disconnect { code: u32 },
    /// A request worker terminated abnormally during the pump's lifetime;
    /// each affected request was completed truthfully by its guard.
    #[error("a fetch worker terminated abnormally")]
    WorkerPanicked,
    /// The pump task itself did not run to a result.
    #[error("the pump task did not complete")]
    PumpTaskFailed,
}

/// Why an unlink cannot proceed safely. `files` lists the affected paths so
/// the caller can name exactly what must be preserved or hydrated first.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{reason}")]
pub struct UnlinkBlocked {
    pub reason: &'static str,
    pub files: Vec<String>,
}

impl UnlinkBlocked {
    pub fn new(reason: &'static str) -> Self {
        Self { reason, files: Vec::new() }
    }
}

/// Exports one dirty local file to the durable recovery area outside every
/// sync root. The source is untouched; the copy is the preservation proof.
fn export_dirty_file(source: &std::path::Path, recovery_dir: &std::path::Path) -> Result<(), &'static str> {
    match std::fs::metadata(source) {
        Ok(metadata) if metadata.is_file() && metadata.len() > 0 => {
            std::fs::create_dir_all(recovery_dir).map_err(|_| "recovery area unavailable")?;
            let name = source
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "unnamed".to_owned());
            let target = recovery_dir.join(format!("unlink-{name}"));
            std::fs::copy(source, &target)
                .map(|_| ())
                .map_err(|_| "exporting dirty bytes failed")
        }
        // Nothing resident to lose (directory, empty file or gone).
        _ => Ok(()),
    }
}

/// Pure runtime-liveness classification for one connection's CFAPI pump.
///
/// Cancellation of the connection scope wins first (the runtime is stopping),
/// then a missing pump handle (never attached or already detached), then the
/// handle's own evidence: a cancelled token or a task that ran to completion
/// is not an active runtime. Local data is preserved in every state.
fn pump_liveness(
    connection_cancel: &CancellationToken,
    pump: Option<&PumpHandle>,
) -> RuntimeState {
    if connection_cancel.is_cancelled() {
        return RuntimeState::Cancelled;
    }
    let Some(handle) = pump else {
        return RuntimeState::Missing;
    };
    if handle.token.is_cancelled() || handle.task.is_finished() {
        RuntimeState::Finished
    } else {
        RuntimeState::Active
    }
}

impl<R: RemoteOps> ConnectionRuntime<R> {
    /// The connection's managed workspace identity.
    pub fn workspace_id(&self) -> WorkspaceId {
        self.config.workspace
    }

    /// The provider-wide scheduler (read permits + clean range cache).
    pub fn scheduler(&self) -> &Scheduler {
        &self.scheduler
    }

    /// The connection's remote boundary (native + optional publication).
    pub fn remote(&self) -> &R {
        &self.remote
    }
}

/// The live pump drives this runtime: hydration reads come from the remote
/// boundary, observations and preservation return to the durable pipeline.
impl<R: RemoteOps> crate::sync::cfapi_pump::PumpHost<R> for ConnectionRuntime<R> {
    fn remote(&self) -> &R {
        &self.remote
    }

    fn scheduler(&self) -> &Scheduler {
        &self.scheduler
    }

    fn activity(&self) -> &crate::sync::activity::ActivityRegistry {
        &self.activity
    }

    fn connection_id(&self) -> ConnectionId {
        self.config.connection_id
    }

    fn workspace(&self) -> WorkspaceId {
        self.config.workspace
    }

    fn observe(&self, observations: Vec<crate::sync::observe::RawObservation>) -> impl Future<Output = ()> + Send {
        // The single classification funnel: watcher batches and CFAPI
        // notifications both run through `ingest_observations`, which shares
        // the runtime's echo table and persists generations and intents
        // before any effect.
        self.ingest_observations(crate::sync::observe::ObservationBatch {
            observations,
            rescan_required: false,
        })
    }

    fn preserve_dirty(
        &self,
        relative_path: &std::path::Path,
    ) -> impl Future<Output = Result<(), &'static str>> + Send {
        let source = self.config.root.join(relative_path);
        let recovery = self.config.recovery_dir.clone();
        async move {
            match std::fs::metadata(&source) {
                Ok(metadata) if metadata.is_file() && metadata.len() > 0 => {
                    std::fs::create_dir_all(&recovery)
                        .map_err(|_| "recovery area unavailable")?;
                    let target = recovery.join(format!(
                        "delete-{}.recovered",
                        relative_path.to_string_lossy().replace(['\\', '/'], "_")
                    ));
                    std::fs::copy(&source, &target)
                        .map(|_| ())
                        .map_err(|_| "preserving dirty bytes failed")
                }
                // Nothing resident to lose (directory, empty file or gone):
                // preservation is trivially satisfied.
                _ => Ok(()),
            }
        }
    }

    fn resolve(&self, components: &[String]) -> impl Future<Output = Option<ItemId>> + Send {
        let state = self.state.clone();
        let connection = self.config.connection_id;
        let root_item_id = self.config.root_item_id;
        let components = components.to_vec();
        async move {
            resolve_item(&state, connection, root_item_id, &components).await
        }
    }

    fn children(
        &self,
        parent: Option<ItemId>,
    ) -> impl Future<Output = Option<Vec<crate::sync::cfapi_pump::PumpChild>>> + Send {
        let state = self.state.clone();
        let connection = self.config.connection_id;
        async move {
            let rows = state.list_children(connection, parent, false).await.ok()?;
            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                let (sha256, size) = crate::sync::plan::registry_digest(&row);
                let _ = sha256;
                out.push(crate::sync::cfapi_pump::PumpChild {
                    item_id: row.item_id,
                    name: row.name.clone(),
                    is_directory: matches!(row.kind, hfdrive_state::ItemKind::Directory),
                    version: row.content_version_id,
                    size: size.unwrap_or(0),
                    modified_at_100ns: registry_mtime_100ns(&row),
                });
            }
            Some(out)
        }
    }

    fn is_dirty(&self, item_id: ItemId) -> impl Future<Output = bool> + Send {
        let state = self.state.clone();
        let connection = self.config.connection_id;
        async move {
            state
                .observation(connection, item_id)
                .await
                .ok()
                .flatten()
                .map(|observation| observation.dirty)
                .unwrap_or(false)
        }
    }

    fn void_delete_intents_for_present_items(&self) -> impl Future<Output = ()> + Send {
        let state = self.state.clone();
        let connection = self.config.connection_id;
        let root = self.config.root.clone();
        async move {
            let Ok(entries) = state.list_outbox(connection, None, u32::MAX).await else {
                return;
            };
            for entry in entries {
                if !matches!(entry.state, OutboxState::Observed) {
                    continue;
                }
                let Some(intent) = parse_intent(&entry).ok() else { continue; };
                if !matches!(intent, SyncIntent::Delete { .. }) {
                    continue;
                }
                let Some(path) = registry_path(&state, connection, intent.item_id()).await else {
                    continue;
                };
                if root.join(&path).symlink_metadata().is_ok() {
                    // The delete was abandoned: close the intent as converged
                    // instead of publishing a tombstone for a live file.
                    let _ = state
                        .transition_outbox(
                            connection,
                            entry.operation_id,
                            hfdrive_state::OutboxTransition::Published,
                        )
                        .await;
                    let _ = state
                        .transition_outbox(
                            connection,
                            entry.operation_id,
                            hfdrive_state::OutboxTransition::LocalApplyPending,
                        )
                        .await;
                    let _ = crate::sync::apply::complete_publication(
                        &state, connection, entry.operation_id,
                    )
                    .await;
                }
            }
        }
    }
}

/// Display-only modification time of a registry row (RFC 3339 in
/// `metadata_json.modified_at`), converted back to Windows 100ns units.
fn registry_mtime_100ns(item: &hfdrive_state::ItemRecord) -> i64 {
    let stamp = item
        .metadata_json
        .get("modified_at")
        .and_then(|value| value.as_str())
        .unwrap_or("1970-01-01T00:00:00Z");
    let _ = stamp;
    // Display metadata is provenance only; placeholder timestamps use the
    // canonical epoch reference when the RFC 3339 string is absent or
    // unparsable. Parsed values are re-derived below.
    parse_rfc3339_whole_seconds(stamp).unwrap_or(116_444_736_000_000_000)
}

/// Parses a canonical whole-second RFC 3339 UTC timestamp to Windows 100ns
/// units since 1601. Bounded and allocation-free.
fn parse_rfc3339_whole_seconds(value: &str) -> Option<i64> {
    if value.len() != 20 || !hfdrive_core::format::is_canonical_timestamp(value) {
        return None;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<i64> {
        value.get(range)?.parse::<i64>().ok()
    };
    let year = digits(0..4)?;
    let month = digits(5..7)?;
    let day = digits(8..10)?;
    let hour = digits(11..13)?;
    let minute = digits(14..16)?;
    let second = digits(17..19)?;
    // Days from 1970-01-01, civil calendar (Howard Hinnant's algorithm).
    let (y, m) = if month <= 2 { (year - 1, month + 12) } else { (year, month) };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m - 3) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let unix_seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;
    unix_seconds
        .checked_mul(10_000_000)
        .and_then(|value| value.checked_add(116_444_736_000_000_000))
}

impl<R: RemoteOps> ConnectionRuntime<R> {
    /// Builds the runtime and starts its worker loop. `notifications` carries
    /// the connection's remote-watch updates (durably recorded `HEAD`
    /// invalidations and watch failures) and wakes the loop. The runtime owns
    /// its directory watcher for its whole lifetime.
    pub fn start(
        config: ConnectionConfig,
        state: AccountStore,
        remote: R,
        scheduler: Arc<Scheduler>,
        activity: Arc<crate::sync::activity::ActivityRegistry>,
        cancel: CancellationToken,
        mut notifications: mpsc::Receiver<WatchUpdate>,
    ) -> Arc<Self> {
        // Engine connect explicitly resumes after durable pause state is
        // loaded, so a restored connection cannot dispatch during startup.
        let (paused_tx, _) = watch::channel(true);
        let (health_tx, _) = watch::channel(ConnectionHealth {
            last_error: Some("Local filesystem discovery is starting".to_owned()),
            ..ConnectionHealth::default()
        });
        let (observation_tx, mut observation_rx) =
            mpsc::channel::<crate::sync::observe::ObservationBatch>(64);
        let runtime = Arc::new(Self {
            config,
            state,
            remote,
            scheduler,
            activity,
            cancel: cancel.clone(),
            paused: paused_tx,
            health: health_tx,
            echo: tokio::sync::Mutex::new(EchoTable::default()),
            pending_removals: tokio::sync::Mutex::new(PendingRemovals::default()),
            dispatch: tokio::sync::Mutex::new(()),
            pump: tokio::sync::Mutex::new(None),
            disconnect_failure: tokio::sync::Mutex::new(None),
            observer: tokio::sync::Mutex::new(None),
            observation_tx: tokio::sync::Mutex::new(Some(observation_tx)),
            local_ready: AtomicBool::new(false),
            scan_requested: AtomicBool::new(true),
            persistence_failed: AtomicBool::new(false),
            reconcile_requested: AtomicBool::new(true),
        });


        // Worker loop.
        let worker = runtime.clone();
        let worker_cancel = cancel.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut notifications_open = true;
            let mut observations_open = true;
            let mut next_scan = tokio::time::Instant::now();
            loop {
                let mut wake = false;
                tokio::select! {
                    _ = worker_cancel.cancelled() => break,
                    notification = notifications.recv(), if notifications_open => {
                        match notification {
                            None => notifications_open = false,
                            Some(update) => {
                                worker.note_watch_update(update);
                                wake = true;
                            }
                        }
                    }
                    batch = observation_rx.recv(), if observations_open => {
                        match batch {
                            Some(batch) => worker.ingest_observations(batch).await,
                            None => {
                                observations_open = false;
                                if !worker_cancel.is_cancelled() {
                                    worker.local_failure("Local file observation stopped; reconnect the drive");
                                }
                            }
                        }
                        wake = true;
                    }
                    _ = interval.tick() => { wake = true; }
                }
                if !wake {
                    continue;
                }
                let observing = worker.observer.lock().await.as_ref().is_some_and(LocalObserver::is_running);
                if observing && (worker.scan_requested.swap(false, Ordering::AcqRel)
                    || tokio::time::Instant::now() >= next_scan)
                {
                    worker.scan_local().await;
                    next_scan = tokio::time::Instant::now() + crate::sync::observe::SCAN_INTERVAL;
                }
                if !worker.local_ready.load(Ordering::Acquire) { continue; }
                if *worker.paused.borrow() {
                    continue;
                }
                worker.drive().await;
            }
        });
        runtime
    }

    /// The connection identity.
    pub fn connection_id(&self) -> ConnectionId {
        self.config.connection_id
    }

    /// The connection's durable account handle key.
    pub fn account_key(&self) -> hfdrive_core::ids::AccountKey {
        self.state.account_key()
    }

    /// The connection's local sync root.
    pub fn root(&self) -> &Path {
        &self.config.root
    }

    /// Attaches the connected CFAPI callback pipeline and starts the live
    /// hydration pump: `FETCH_DATA` is served from each placeholder's exact
    /// immutable version, `FETCH_PLACEHOLDERS` from the durable registry, and
    /// rename/delete notifications are persisted before acknowledgement.
    pub async fn attach(self: &Arc<Self>, connected: crate::sync::registry::ConnectedRoot) {
        let crate::sync::registry::ConnectedRoot { connection, streams } = connected;
        let token = self.cancel.child_token();
        let host = self.clone();
        let pump_cancel = token.clone();
        let task = tokio::spawn(async move {
            crate::sync::cfapi_pump::run_pump(host, connection, streams, pump_cancel).await
        });
        *self.pump.lock().await = Some(PumpHandle { token, task });
        self.start_observer().await;
    }

    async fn start_observer(&self) {
        let Some(sender) = self.observation_tx.lock().await.take() else { return; };
        match LocalObserver::start(
            ObserverConfig { root: self.config.root.clone(), coalesce: crate::sync::observe::COALESCE_WINDOW },
            self.cancel.child_token(),
            sender,
        ).await {
            Ok(observer) => { *self.observer.lock().await = Some(observer); }
            Err(_) => self.local_failure("Local file observation could not start; local files are preserved"),
        }
    }

    /// Stops the live pump: cancellation marks its workers, every in-flight
    /// request is drained to completion (each accepted request reaches its
    /// terminal outcome), and the sync root is disconnected exactly once
    /// while the callback context is still valid. Registration, state and
    /// data are retained. Idempotent: a second call has no pump left and
    /// succeeds.
    ///
    /// Returns [`DisconnectError`] when the disconnect failed or a worker
    /// terminated abnormally; callers (engine drain/unlink) decide whether to
    /// continue their remaining cleanup, but must not report a successful
    /// disconnect when this returns an error.
    pub async fn disconnect(&self) -> Result<(), DisconnectError> {
        if let Some(error) = self.disconnect_failure.lock().await.clone() {
            return Err(error);
        }
        if let Some(observer) = self.observer.lock().await.take() {
            observer.shutdown().await;
        }
        // Take the handle and release the pump lock before awaiting the
        // drain: nothing else may hold this mutex across a worker join.
        let taken = self.pump.lock().await.take();
        let Some(handle) = taken else {
            return Ok(());
        };
        handle.token.cancel();
        let result = match handle.task.await {
            Ok(outcome) => match (outcome.disconnect, outcome.worker_panicked) {
                (Err(code), _) => Err(DisconnectError::Disconnect { code }),
                (Ok(()), true) => Err(DisconnectError::WorkerPanicked),
                (Ok(()), false) => Ok(()),
            },
            Err(error) => {
                tracing::error!(%error, "pump task did not complete");
                Err(DisconnectError::PumpTaskFailed)
            }
        };
        if let Err(error) = &result {
            *self.disconnect_failure.lock().await = Some(error.clone());
            let mut health = self.health.borrow().clone();
            health.last_error = Some(error.to_string());
            self.health.send_replace(health);
        }
        result
    }

    /// Exports one dirty local file to the durable recovery area before a
    /// destructive local action. The source is left untouched.
    fn export_dirty_bytes(&self, relative_path: &std::path::Path) -> Result<(), &'static str> {
        export_dirty_file(&self.config.root.join(relative_path), &self.config.recovery_dir)
    }

    /// True when the recovery area exists or can be created: without it no
    /// dirty content can be preserved before a destructive action.
    pub fn recovery_area_ready(&self) -> bool {
        std::fs::create_dir_all(&self.config.recovery_dir).is_ok()
    }

    /// Preserves every required item before unlink, then converts fully
    /// resident placeholders to normal files.
    ///
    /// Contract (matches `cfapi::revert_to_normal`):
    ///
    /// * dirty local content is durably exported to the recovery area first —
    ///   preservation failure blocks unlink naming the file;
    /// * online-only content is hydrated and residency verified; content that
    ///   cannot be made resident blocks unlink naming the file
    ///   (`cfapi` reports `Precondition` for such entries);
    /// * conversion runs with the strict identity/size/mtime/exact-USN guard:
    ///   `Applied` is idempotent for already-normal files, `Mismatch` leaves
    ///   the file preserved untouched and routed to the recovery path (never
    ///   forced), and only conversion that needs unavailable bytes blocks.
    ///
    /// Only when nothing partially hydrated remains may the caller disconnect
    /// and unregister.
    pub async fn preserve_all_for_unlink(
        &self,
        plan: &crate::sync::engine::UnlinkPlan,
    ) -> Result<(), UnlinkBlocked> {
        // 1. Dirty content is exported to the recovery area outside the root.
        //    Staged snapshots are already durable there.
        let mut blocked: Vec<String> = Vec::new();
        for item in self
            .state
            .list_all_items(self.config.connection_id, true)
            .await
            .map_err(|_| UnlinkBlocked::new("durable state is unavailable"))?
        {
            if item.deleted {
                continue;
            }
            let Some(path) = registry_path(&self.state, self.config.connection_id, item.item_id).await
            else {
                blocked.push(format!("item {} has no resolvable local path", item.item_id));
                continue;
            };
            let dirty = match self.state.observation(self.config.connection_id, item.item_id).await {
                Ok(Some(observation)) => observation.dirty,
                Ok(None) => false,
                Err(_) => {
                    blocked.push(path.to_string_lossy().into_owned());
                    continue;
                }
            };
            if dirty && self.export_dirty_bytes(&path).is_err() {
                blocked.push(path.to_string_lossy().into_owned());
            }
        }
        let actions = self
            .state
            .list_local_actions(self.config.connection_id, Some(LocalActionState::Pending))
            .await
            .map_err(|_| UnlinkBlocked::new("durable state is unavailable"))?;
        for action in actions {
            if let Some(source) = &action.source_path {
                if self.export_dirty_bytes(source).is_err() {
                    blocked.push(source.to_string_lossy().into_owned());
                }
            }
        }
        if !blocked.is_empty() {
            return Err(UnlinkBlocked {
                reason: "unsynchronized content could not be exported",
                files: blocked,
            });
        }

        // 2. Every online-only placeholder is hydrated and residency verified.
        let mut online_only: Vec<String> = Vec::new();
        for item in self
            .state
            .list_all_items(self.config.connection_id, true)
            .await
            .map_err(|_| UnlinkBlocked::new("durable state is unavailable"))?
        {
            if item.deleted {
                continue;
            }
            let Some(path) = registry_path(&self.state, self.config.connection_id, item.item_id).await
            else {
                online_only.push(format!("item {} has no resolvable local path", item.item_id));
                continue;
            };
            let absolute = self.config.root.join(&path);
            let Ok(live) = query_file_state(&absolute) else {
                online_only.push(path.to_string_lossy().into_owned());
                continue;
            };
            if live.identity.may_not_be_materialized() && live.size > 0 {
                let range = hfdrive_core::storage::ByteRange::new(0, live.size, live.size)
                    .map_err(|_| UnlinkBlocked::new("placeholder size exceeds the range bound"))?;
                let hydrated = hfdrive_windows::cfapi::ops::hydrate_range(&absolute, range)
                    .and_then(|_| query_file_state(&absolute).map_err(|_| {
                        hfdrive_windows::cfapi::CfError::Precondition("hydrated placeholder became unreadable")
                    }));
                let resident = match hydrated {
                    Ok(after) => !after.identity.may_not_be_materialized(),
                    Err(_) => false,
                };
                if !resident {
                    online_only.push(path.to_string_lossy().into_owned());
                }
            }
        }
        if !online_only.is_empty() {
            // Unlink requires fully resident content; unavailable bytes block
            // removal and are listed for the caller.
            return Err(UnlinkBlocked {
                reason: "unlink requires fully resident content; hydrate or export before conversion",
                files: online_only,
            });
        }
        if plan.conflict_files > 0 {
            return Err(UnlinkBlocked {
                reason: "unresolved conflicts must be resolved before removal",
                files: Vec::new(),
            });
        }
        Ok(())
    }

    /// Converts every fully resident placeholder to a normal file through the
    /// guarded `cfapi::revert_to_normal`.
    ///
    /// Contract: an already-normal file is idempotent `Applied` (no OS call);
    /// a strict identity/size/mtime/exact-USN guard runs first and `Mismatch`
    /// leaves the entry preserved untouched on the recovery path (never
    /// forced); content that is not fully resident or an OS refusal blocks
    /// unlink naming the affected files. Pin state is not a precondition —
    /// pinned resident content converts with its bytes kept.
    ///
    /// `Mismatch(UsnUnknown)` has two distinct causes with different
    /// treatments:
    ///
    /// * the volume has no usable USN journal (`file_usn_of` is `None` and
    ///   the live state carries no USN on every read): the strict guard can
    ///   **never** match on this volume. This is an actionable block ("volume
    ///   provides no USN evidence; conversion cannot be verified") — no bytes
    ///   are at risk, the file simply stays managed;
    /// * the journal exists but one read's evidence is missing (expected USN
    ///   known, live read failed): a retryable evidence gap — re-observe once
    ///   and retry; if it persists the entry is listed as unverifiable rather
    ///   than treated as dirty content.
    ///
    /// `Applied { usn: Some(_) }` records a conversion that landed just now;
    /// `Applied { usn: None }` is the already-normal fast path or a
    /// conversion on a volume without a journal after the fact.
    pub async fn revert_placeholders_to_normal(&self) -> Result<(), UnlinkBlocked> {
        let mut blocked: Vec<String> = Vec::new();
        let mut no_usn_evidence: Vec<String> = Vec::new();
        let mut unverified: Vec<String> = Vec::new();
        for item in self
            .state
            .list_all_items(self.config.connection_id, true)
            .await
            .map_err(|_| UnlinkBlocked::new("durable state is unavailable"))?
        {
            if item.deleted {
                continue;
            }
            let Some(path) = registry_path(&self.state, self.config.connection_id, item.item_id).await
            else {
                unverified.push(format!("item {} has no resolvable local path", item.item_id));
                continue;
            };
            let absolute = self.config.root.join(&path);
            let Ok(live) = query_file_state(&absolute) else {
                unverified.push(path.to_string_lossy().into_owned());
                continue;
            };
            let placeholder = hfdrive_windows::filesystem::volume::placeholder_state(
                live.identity.attributes,
                live.identity.reparse_tag,
            );
            if !placeholder.is_placeholder() {
                // Already a normal file: conversion is idempotent and needs
                // no OS call (`Applied { usn: None }` fast path).
                continue;
            }
            match hfdrive_windows::cfapi::revert_to_normal(&absolute, &live) {
                Ok(hfdrive_windows::cfapi::ops::GuardOutcome::Applied { .. }) => {
                    // `usn: Some(_)` converted just now; `usn: None` means no
                    // journal evidence after conversion. Both keep the bytes.
                }
                Ok(hfdrive_windows::cfapi::ops::GuardOutcome::Mismatch(
                    hfdrive_windows::cfapi::ops::GuardMismatch::UsnUnknown,
                )) => {
                    // Two causes, deliberately distinguished.
                    let journal_usn =
                        hfdrive_windows::filesystem::usn::file_usn_of(&absolute).ok().flatten();
                    if live.usn.is_none() && journal_usn.is_none() {
                        // (b) No USN journal on this volume: the strict
                        // guard can never match here. Actionable block, not
                        // the dirty-content recovery path: no bytes at risk.
                        no_usn_evidence.push(path.to_string_lossy().into_owned());
                        continue;
                    }
                    // (a) Retryable evidence gap: re-observe once and retry.
                    let retry = query_file_state(&absolute).ok().and_then(|fresh| {
                        match hfdrive_windows::cfapi::revert_to_normal(&absolute, &fresh) {
                            Ok(hfdrive_windows::cfapi::ops::GuardOutcome::Applied { .. }) => {
                                Some(())
                            }
                            Ok(hfdrive_windows::cfapi::ops::GuardOutcome::Mismatch(
                                hfdrive_windows::cfapi::ops::GuardMismatch::UsnUnknown,
                            )) => None,
                            // Any other guard mismatch leaves the placeholder
                            // untouched and therefore blocks unregistration.
                            Ok(_) => {
                                blocked.push(path.to_string_lossy().into_owned());
                                Some(())
                            },
                            Err(_) => {
                                blocked.push(path.to_string_lossy().into_owned());
                                Some(())
                            }
                        }
                    });
                    if retry.is_none() {
                        unverified.push(path.to_string_lossy().into_owned());
                    }
                }
                Ok(hfdrive_windows::cfapi::ops::GuardOutcome::Mismatch(_)) => {
                    // The guard preserved the placeholder, so removal is not
                    // complete and unregistration must not proceed.
                    blocked.push(path.to_string_lossy().into_owned());
                }
                Err(_) => {
                    // `Precondition` (or any OS refusal): the entry needs
                    // unavailable bytes; block and list it.
                    blocked.push(path.to_string_lossy().into_owned());
                }
            }
        }
        if !no_usn_evidence.is_empty() {
            return Err(UnlinkBlocked {
                reason: "volume provides no USN evidence; conversion cannot be verified",
                files: no_usn_evidence,
            });
        }
        if !unverified.is_empty() {
            return Err(UnlinkBlocked {
                reason: "local identity evidence is unavailable; conversion cannot be verified",
                files: unverified,
            });
        }
        if !blocked.is_empty() {
            return Err(UnlinkBlocked {
                reason: "placeholder conversion refused these entries",
                files: blocked,
            });
        }
        Ok(())
    }

    /// Pauses remote scheduling. Observation and durable intent continue.
    pub fn pause(&self) {
        self.paused.send_replace(true);
    }

    /// Quiesces dispatch in memory: pauses remote scheduling and waits for the
    /// in-flight drive round to finish. Observation and the durable pause
    /// intent continue untouched; after this returns, no publication dispatch
    /// is running or can start until `resume`.
    pub async fn quiesce(&self) {
        self.pause();
        let _round = self.dispatch.lock().await;
    }

    /// Resumes remote scheduling; the next drive revalidates capabilities.
    pub fn resume(&self) {
        self.reconcile_requested.store(true, Ordering::Release);
        self.paused.send_replace(false);
    }

    /// Records one remote-watch notification. A watch failure is observable
    /// in health and never stops this connection's drive loop or its CFAPI
    /// runtime: the independent poll and the durable intent remain intact.
    fn note_watch_update(&self, update: WatchUpdate) {
        let mut health = self.health.borrow().clone();
        match update {
            WatchUpdate::HeadInvalidated { source } => {
                // A durably recorded and acknowledged change proves durable
                // persistence again. Only an event/reset-sourced one proves
                // the event stream itself: a poll firing is not evidence that
                // SSE recovered.
                match source {
                    crate::remote_watch::NoticeSource::Poll => {
                        if matches!(health.watch_error, Some(WatchFailure::Persistence)) {
                            health.watch_error = None;
                        }
                    }
                    crate::remote_watch::NoticeSource::Event
                    | crate::remote_watch::NoticeSource::Resync => {
                        health.watch_error = None;
                    }
                }
            }
            WatchUpdate::WatchFailed(failure) => {
                health.watch_error = Some(failure);
            }
        }
        self.health.send_replace(health);
    }

    /// Current health projection for the parent's status layer.
    ///
    /// The runtime liveness is folded in here, never trusted from the stale
    /// snapshot: a missing, cancelled or finished CFAPI runtime is always
    /// reported as such and is never presented as if it were driving the
    /// root. Local data is preserved in every state.
    pub async fn health(&self) -> ConnectionHealth {
        let mut health = self.health.borrow().clone();
        health.runtime = self.runtime_state().await;
        if health.runtime.is_active()
            && self.observer.lock().await.as_ref().is_none_or(|observer| !observer.is_running())
        {
            health.last_error = Some("Local file observation is unavailable; reconnect the drive".to_owned());
        }
        health
    }

    /// Live liveness of this connection's CFAPI runtime, rechecked on every
    /// call: a pump handle being present is not proof that the task is still
    /// running.
    pub async fn runtime_state(&self) -> RuntimeState {
        let pump = self.pump.lock().await;
        pump_liveness(&self.cancel, pump.as_ref())
    }

    /// True when this connection may dispatch remote mutation.
    pub fn writable(&self) -> bool {
        matches!(self.config.mode, hfdrive_state::ConnectionMode::Writable)
    }

    /// The round context for engine-driven publication work (explicit
    /// initialization).
    pub fn round_context<'a>(&'a self, cancel: &'a CancellationToken) -> RoundContext<'a, R> {
        RoundContext {
            state: &self.state,
            remote: &self.remote,
            connection: self.config.connection_id,
            workspace: self.config.workspace,
            root_item_id: self.config.root_item_id,
            device_id: self.config.device_id,
            mode: match self.config.mode {
                hfdrive_state::ConnectionMode::ReadOnly => ReconcileMode::ReadOnly,
                hfdrive_state::ConnectionMode::Writable => ReconcileMode::Writable,
            },
            root: &self.config.root,
            staging_dir: &self.config.staging_dir,
            recovery_dir: &self.config.recovery_dir,
            scheduler: &self.scheduler,
            cancel,
        }
    }

    // -----------------------------------------------------------------------
    // Observation ingestion
    // -----------------------------------------------------------------------

    /// Classifies one observation batch and persists generations and intents
    /// before any effect. Watcher overflow voids deletion evidence.
    pub async fn ingest_observations(&self, batch: crate::sync::observe::ObservationBatch) {
        if batch.rescan_required {
            self.scan_requested.store(true, Ordering::Release);
            let _ = self.state.invalidate_scan(self.config.connection_id).await;
        }
        let echo = self.echo.lock().await;
        for observation in batch.observations {
            let classification = classify_observation(
                &self.state,
                self.config.connection_id,
                self.config.root_item_id,
                &self.config.root,
                &echo,
                &observation.relative_path,
                observation.action,
                now_ms(),
            )
            .await;
            match classification {
                Classification::Echo { .. }
                | Classification::Excluded
                | Classification::Ignored => {}
                Classification::RescanRequired => {
                    self.scan_requested.store(true, Ordering::Release);
                    let _ = self.state.invalidate_scan(self.config.connection_id).await;
                }
                Classification::Created {
                    item_id,
                    is_directory,
                    state,
                } => {
                    self.persist_change(item_id, &observation.relative_path, Some(is_directory), &state, true)
                        .await;
                }
                Classification::ContentChanged { item_id, state } => {
                    self.persist_change(item_id, &observation.relative_path, None, &state, false)
                        .await;
                }
                Classification::Moved { item_id, state } => {
                    self.persist_move(item_id, &observation.relative_path, &state).await;
                }
                Classification::Removed { item_id } => {
                    self.pending_removals.lock().await.park(item_id, observation.relative_path.clone(), now_ms());
                    self.scan_requested.store(true, Ordering::Release);
                    let _ = self.state.invalidate_scan(self.config.connection_id).await;
                }
                Classification::UntrackedRemoval => {
                    let _ = self.state.invalidate_scan(self.config.connection_id).await;
                }
            }
        }
    }

    /// Persists a create/content change with its resolved parent.
    async fn persist_change(
        &self,
        item_id: ItemId,
        relative_path: &std::path::Path,
        is_directory: Option<bool>,
        state: &FileState,
        is_create: bool,
    ) {
        let Some(parent) = self.resolve_parent(relative_path).await else { return; };
        let name = file_name(relative_path);
        let modified_at = display_timestamp(state.last_write_time_100ns);
        let content = (!is_directory.unwrap_or(false)).then(|| PendingContent {
            upload_id: UploadId::new().as_uuid().clone(),
            version_id: VersionId::new().as_uuid().clone(),
            modified_at: modified_at.clone(),
        });
        let intent = if is_create {
            SyncIntent::Create {
                item_id: *item_id.as_uuid(),
                parent_id: parent,
                name,
                kind: if is_directory.unwrap_or(false) {
                    IntentKind::Directory
                } else {
                    IntentKind::File
                },
                content,
            }
        } else {
            SyncIntent::Content {
                item_id: *item_id.as_uuid(),
                content: content.unwrap_or_else(|| PendingContent {
                    upload_id: UploadId::new().as_uuid().clone(),
                    version_id: VersionId::new().as_uuid().clone(),
                    modified_at,
                }),
            }
        };
        let item = if let SyncIntent::Create { name, .. } = &intent { Some(hfdrive_state::ItemRecord {
            connection_id: self.config.connection_id,
            item_id,
            parent_id: Some(ItemId::from_uuid(parent).expect("resolved parent is a non-nil item")),
            name: name.clone(),
            name_key: String::from_utf8(hfdrive_core::names::collision_key(name)).expect("collision keys are UTF-8"),
            kind: if is_directory == Some(true) { hfdrive_state::ItemKind::Directory } else { hfdrive_state::ItemKind::File },
            revision: OperationId::new(),
            content_version_id: None,
            deleted: false,
            metadata_json: serde_json::json!({ "size": state.size, "modified_at": display_timestamp(state.last_write_time_100ns) }),
        }) } else { None };
        self.persist_intent(intent, item, state.usn.and_then(|usn| u64::try_from(usn).ok())).await;
    }

    /// Persists a move/rename with its resolved parent.
    async fn persist_move(&self, item_id: ItemId, relative_path: &std::path::Path, _state: &FileState) {
        let Some(parent) = self.resolve_parent(relative_path).await else { return; };
        self.persist_intent(SyncIntent::Move {
            item_id: *item_id.as_uuid(),
            parent_id: parent,
            name: file_name(relative_path),
        }, None, _state.usn.and_then(|usn| u64::try_from(usn).ok()))
        .await;
    }

    /// Resolves the parent directory of a relative path to its item id
    /// (`nil` only for root-level items, where the root directory is the
    /// connection's `root_item_id`).
    async fn resolve_parent(&self, relative_path: &std::path::Path) -> Option<uuid::Uuid> {
        match relative_path.parent() {
            None => Some(*self.config.root_item_id.as_uuid()),
            Some(parent) if parent.as_os_str().is_empty() => {
                Some(*self.config.root_item_id.as_uuid())
            }
            Some(parent) => {
                let components: Vec<String> = parent
                    .components()
                    .map(|component| component.as_os_str().to_string_lossy().into_owned())
                    .collect();
                let parent_id = resolve_item(
                    &self.state,
                    self.config.connection_id,
                    self.config.root_item_id,
                    &components,
                )
                .await?;
                Some(*parent_id.as_uuid())
            }
        }
    }

    /// Item identity, generation, and intent commit together before capture.
    async fn persist_intent(
        &self,
        intent: SyncIntent,
        item: Option<hfdrive_state::ItemRecord>,
        usn: Option<u64>,
    ) {
        let result = async {
            let base = self.state.baseline(self.config.connection_id).await?.applied_commit;
            let entry = intent_entry(
                self.config.connection_id, OperationId::new(), Some(intent.item_id()),
                base, None, 0, &intent,
            ).map_err(|_| hfdrive_state::StateError::Io(std::io::Error::other("invalid local intent")))?;
            self.state.record_observed_work(item, entry, usn).await
        }.await;
        if result.is_err() {
            self.persistence_failed.store(true, Ordering::Release);
            self.local_failure("Local changes could not be recorded; local files are preserved");
        }
    }

    fn local_failure(&self, message: &str) {
        self.local_ready.store(false, Ordering::Release);
        let mut health = self.health.borrow().clone();
        health.last_error = Some(message.to_owned());
        self.health.send_replace(health);
    }

    async fn scan_local(&self) {
        let result: Result<(), &'static str> = async {
            let previous = self.state.scan_state(self.config.connection_id).await
                .map_err(|_| "Local scan state is unavailable")?
                .ok_or("Local scan state is missing")?;
            let known = self.state.list_all_items(self.config.connection_id, false).await
                .map_err(|_| "Local item registry is unavailable")?;
            self.state.begin_scan(self.config.connection_id, previous.volume_id, previous.journal_id).await
                .map_err(|_| "Local discovery could not be recorded")?;
            if let Some(observer) = self.observer.lock().await.as_ref() { observer.begin_scan(); }
            let root = self.config.root.clone();
            let cancelled = Arc::new(AtomicBool::new(false));
            let scan_cancel = cancelled.clone();
            let mut scan = tokio::task::spawn_blocking(move ||
                crate::sync::observe::enumerate_metadata(&root, &scan_cancel)
            );
            let (entries, report) = tokio::select! {
                result = &mut scan => result.map_err(|_| "Local discovery task failed")?
                    .map_err(|_| "Local discovery failed; local files are preserved")?,
                _ = self.cancel.cancelled() => {
                    cancelled.store(true, Ordering::Release);
                    let _ = scan.await;
                    return Err("Local discovery was cancelled");
                }
            };
            let observations = entries.iter().map(|entry| crate::sync::observe::RawObservation {
                relative_path: entry.relative_path.clone(),
                action: hfdrive_windows::filesystem::WatchAction::Modified,
            }).collect();
            self.ingest_observations(crate::sync::observe::ObservationBatch {
                observations, rescan_required: false,
            }).await;
            if !report.complete || report.overflow || self.persistence_failed.load(Ordering::Acquire) {
                return Err("Local discovery is incomplete; no deletions were inferred");
            }
            let lost = self.observer.lock().await.as_ref()
                .is_none_or(|observer| !observer.is_running() || observer.overflowed());
            if lost || self.cancel.is_cancelled() {
                return Err("Local observation changed during discovery; no deletions were inferred");
            }
            let completed = self.state.complete_scan(self.config.connection_id, None).await
                .map_err(|_| "Local discovery completion could not be recorded")?;
            if !completed.may_infer_deletion() {
                return Err("Local discovery was invalidated; no deletions were inferred");
            }
            let explicit: std::collections::HashSet<_> =
                self.pending_removals.lock().await.release(true).into_iter().collect();
            let seen: std::collections::HashSet<_> = entries.iter().map(|entry| entry.relative_path.as_path()).collect();
            let by_id: std::collections::HashMap<_, _> = known.iter().map(|item| (item.item_id, item)).collect();
            for item in &known {
                if item.item_id == self.config.root_item_id { continue; }
                if !explicit.contains(&item.item_id)
                    && self.state.observation(self.config.connection_id, item.item_id).await
                        .map_err(|_| "Local observation state is unavailable")?.is_none()
                { continue; }
                let mut names = Vec::new();
                let mut current = item;
                while let Some(parent) = current.parent_id {
                    names.push(current.name.as_str());
                    if names.len() > 512 { return Err("Local item ancestry is invalid"); }
                    current = by_id.get(&parent).copied().ok_or("Local item ancestry is incomplete")?;
                }
                let path: PathBuf = names.into_iter().rev().collect();
                if seen.contains(path.as_path()) { continue; }
                match std::fs::symlink_metadata(self.config.root.join(&path)) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        if self.observer.lock().await.as_ref().is_none_or(LocalObserver::overflowed) {
                            return Err("Local observation was lost; deletion inference stopped");
                        }
                        self.persist_intent(SyncIntent::Delete { item_id: *item.item_id.as_uuid() }, None, None).await;
                    }
                    Err(_) => return Err("A local item could not be inspected; no deletion was inferred"),
                    Ok(_) => {}
                }
            }
            if self.persistence_failed.load(Ordering::Acquire) { return Err("Local changes could not be recorded"); }
            Ok(())
        }.await;
        match result {
            Ok(()) => {
                self.local_ready.store(true, Ordering::Release);
                let mut health = self.health.borrow().clone();
                health.last_error = None;
                self.health.send_replace(health);
            }
            Err(message) => {
                let _ = self.state.invalidate_scan(self.config.connection_id).await;
                self.local_failure(message);
            }
        }
    }

    // -----------------------------------------------------------------------
    // The drive step
    // -----------------------------------------------------------------------

    /// One worker step: upload pass, publication round, apply pass.
    ///
    /// Holds the dispatch gate for the whole round so quiescence can await
    /// exactly the in-flight dispatch; paused is re-checked under the gate so
    /// a quiesce landing between the caller's check and this round can never
    /// start one.
    pub async fn drive(&self) {
        let _round = self.dispatch.lock().await;
        if *self.paused.borrow() {
            return;
        }
        let work = match self.state.reconciliation_work(self.config.connection_id, now_ms()).await {
            Ok(work) => work,
            Err(error) => {
                let mut health = self.health.borrow().clone();
                health.last_error = Some(error.to_string());
                self.health.send_replace(health);
                return;
            }
        };
        if !self.reconcile_requested.swap(false, Ordering::AcqRel) && !work.ready {
            return;
        }
        self.refresh_health().await;
        let cancel = self.cancel.child_token();
        let ctx = self.round_context(&cancel);
        if self.writable() {
            self.upload_pass(&ctx).await;
        }
        match run_round(&ctx, self.writable()).await {
            Ok(outcome) => match self.state.ack_head_refresh(
                self.config.connection_id, work.head_refresh_generation,
            ).await {
                Ok(_) => self.publish_health(&outcome),
                Err(error) => {
                    let mut health = self.health.borrow().clone();
                    health.last_error = Some(error.to_string());
                    self.health.send_replace(health);
                }
            },
            Err(error) => {
                let mut health = self.health.borrow().clone();
                health.last_error = Some(error.to_string());
                self.health.send_replace(health);
            }
        }
        self.apply_pass(&ctx).await;
        self.refresh_health().await;
    }

    async fn refresh_health(&self) {
        let mut health = self.health.borrow().clone();
        health.paused = *self.paused.borrow();
        health.writable = self.writable();
        if let Ok(counts) = self.state.work_counts(self.config.connection_id).await {
            health.pending_files = counts.pending_files;
            health.dirty_files = counts.dirty_files;
            health.conflict_files = counts.conflict_files;
        }
        self.health.send_replace(health);
    }

    fn publish_health(&self, _outcome: &RoundOutcome) {
        let mut health = self.health.borrow().clone();
        health.last_error = None;
        health.writable = self.writable();
        self.health.send_replace(health);
    }

    /// Drives every content-complete entry without a bound payload through
    /// capture and the staged Xet checkpoints.
    async fn upload_pass(&self, ctx: &RoundContext<'_, R>) {
        let Ok(entries) = self.state.list_outbox(self.config.connection_id, None, u32::MAX).await
        else {
            return;
        };
        for entry in entries {
            if !matches!(entry.state, OutboxState::Observed | OutboxState::SnapshotReady) {
                continue;
            }
            match next_step(&entry, now_ms()) {
                PhaseStep::Capture | PhaseStep::Upload => {
                    let _ = upload_entry(ctx, &entry).await;
                }
                _ => {}
            }
        }
    }

    /// Executes pending journaled local actions and closes finished entries
    /// with their generation guard.
    async fn apply_pass(&self, ctx: &RoundContext<'_, R>) {
        let _ = crate::sync::publish::execute_pending_actions(ctx).await;
        let Ok(entries) = self
            .state
            .list_outbox(self.config.connection_id, Some(OutboxState::LocalApplyPending), 256)
            .await
        else {
            return;
        };
        for entry in entries {
            let blocking = self
                .state
                .pending_local_actions(self.config.connection_id)
                .await
                .map(|actions| {
                    actions
                        .iter()
                        .any(|action| action.item_id.is_some() && action.item_id == entry.item_id)
                })
                .unwrap_or(true);
            if blocking {
                continue;
            }
            match crate::sync::apply::complete_publication(
                &self.state,
                self.config.connection_id,
                entry.operation_id,
            )
            .await
            {
                Ok(hfdrive_state::CompletionOutcome::CompletedWithNewerGeneration { .. }) => {
                    // The newer generation keeps dirty and gets its own
                    // intent; superseded uploads never clear it.
                    self.schedule_followup(&entry).await;
                }
                Ok(_) => {}
                Err(error) => {
                    // A real local-apply/close failure is recorded after the
                    // attempt (state advances above cleared stale errors), so
                    // the activity projection can name it.
                    crate::sync::work_errors::record_outbox_error(
                        &self.state,
                        self.config.connection_id,
                        entry.operation_id,
                        crate::sync::work_errors::codes::LOCAL_APPLY_FAILED,
                        &format!(
                            "closing the published work failed: {}",
                            crate::sync::work_errors::state_code(&error)
                        ),
                    )
                    .await;
                }
            }
        }
    }

    /// Schedules the follow-up intent for a generation that arrived while the
    /// entry's upload was in flight.
    async fn schedule_followup(&self, entry: &OutboxEntry) {
        let Some(item_id) = entry.item_id else { return; };
        let Ok(Some(item)) = self.state.item(self.config.connection_id, item_id).await else {
            return;
        };
        let path = registry_path(&self.state, self.config.connection_id, item_id)
            .await
            .unwrap_or_else(|| PathBuf::from(&item.name));
        let Ok(state) = query_file_state(&self.config.root.join(&path)) else { return; };
        self.persist_intent(SyncIntent::Content {
            item_id: *item_id.as_uuid(),
            content: PendingContent {
                upload_id: UploadId::new().as_uuid().clone(),
                version_id: VersionId::new().as_uuid().clone(),
                modified_at: display_timestamp(state.last_write_time_100ns),
            },
        }, None, state.usn.and_then(|usn| u64::try_from(usn).ok()))
        .await;
    }

    // -----------------------------------------------------------------------
    // Control plane
    // -----------------------------------------------------------------------

    /// Pins (or unpins) an item subtree. Requested pin and full hydration are
    /// tracked separately; a failed pin never claims availability.
    pub async fn set_pin(&self, item_id: ItemId, pin: bool) -> Result<(), PublishError> {
        let path = registry_path(&self.state, self.config.connection_id, item_id)
            .await
            .ok_or(PublishError::LocalApply("pinned item has no local path"))?;
        let request = if pin {
            hfdrive_windows::cfapi::ops::PinRequest::Pinned
        } else {
            hfdrive_windows::cfapi::ops::PinRequest::Unpinned
        };
        let outcome = crate::sync::apply::set_pin(&self.config.root.join(&path), request)
            .map_err(PublishError::LocalApply)?;
        self.state
            .set_observation_flags(
                self.config.connection_id,
                item_id,
                ObservationFlags {
                    pin_requested: Some(pin),
                    pin_complete: Some(outcome.fully_hydrated),
                    ..ObservationFlags::default()
                },
            )
            .await?;
        Ok(())
    }

    /// Frees local space for one item only with complete durable evidence:
    /// committed, clean, unpinned, conflict-free content with no staged
    /// snapshot dependency.
    pub async fn free_space(&self, item_id: ItemId) -> Result<(), PublishError> {
        let Ok(Some(item)) = self.state.item(self.config.connection_id, item_id).await else {
            return Err(PublishError::LocalApply("unknown item"));
        };
        let observation = self
            .state
            .observation(self.config.connection_id, item_id)
            .await?
            .map(|o| (o.pin_requested, o.dirty))
            .unwrap_or((false, false));
        let conflicts_open = self
            .state
            .list_conflicts(self.config.connection_id)
            .await?
            .iter()
            .any(|conflict| {
                conflict.item_id == item_id
                    && conflict.resolution_state == hfdrive_state::ConflictResolution::Unresolved
            });
        let evidence = crate::sync::apply::free_space_evidence(
            &self.state,
            self.config.connection_id,
            item_id,
            item.content_version_id,
            observation.0,
            conflicts_open,
        )
        .await;
        let path = registry_path(&self.state, self.config.connection_id, item_id)
            .await
            .ok_or(PublishError::LocalApply("item has no local path"))?;
        match crate::sync::apply::free_space(&self.config.root.join(&path), &evidence)
            .map_err(PublishError::LocalApply)?
        {
            hfdrive_windows::cfapi::ops::GuardOutcome::Applied { .. } => Ok(()),
            hfdrive_windows::cfapi::ops::GuardOutcome::Mismatch(_) => {
                Err(PublishError::LocalApply("free-space preconditions changed"))
            }
        }
    }

    /// Sets the selective-sync exclusion of one subtree. Excluding dirty or
    /// pinned content is refused (the caller surfaces the affected work for
    /// explicit user review); exclusions never publish deletions.
    pub async fn set_excluded(&self, item_id: ItemId, excluded: bool) -> Result<(), PublishError> {
        if excluded {
            let busy = self
                .state
                .observation(self.config.connection_id, item_id)
                .await?
                .map(|o| o.dirty || o.pin_requested)
                .unwrap_or(false);
            if busy {
                return Err(PublishError::LocalApply(
                    "dirty or pinned content must be resolved before exclusion",
                ));
            }
        }
        self.state
            .set_observation_flags(
                self.config.connection_id,
                item_id,
                ObservationFlags { excluded: Some(excluded), ..ObservationFlags::default() },
            )
            .await?;
        Ok(())
    }

    /// Clears every parked retry timer so the next drive re-attempts at once.
    pub async fn retry_now(&self) -> Result<(), PublishError> {
        let entries = self
            .state
            .list_outbox(self.config.connection_id, None, u32::MAX)
            .await?;
        for entry in entries {
            if entry.retry_class != hfdrive_state::RetryClass::None {
                let _ = self
                    .state
                    .transition_outbox(
                        self.config.connection_id,
                        entry.operation_id,
                        hfdrive_state::OutboxTransition::PublishUnknown {
                            retry_class: hfdrive_state::RetryClass::None,
                            next_attempt_at_ms: None,
                        },
                    )
                    .await;
            }
        }
        Ok(())
    }

    /// Classifies every interrupted journaled action against the real
    /// filesystem at startup (recovery boundary) and returns how many were
    /// requeued as fresh local work.
    pub async fn recover_actions(&self) -> Result<usize, PublishError> {
        let actions = self
            .state
            .pending_local_actions(self.config.connection_id)
            .await?;
        let mut requeued = 0;
        for action in actions {
            let live = action
                .source_path
                .as_ref()
                .or(action.target_path.as_ref())
                .and_then(|path| query_file_state(&self.config.root.join(path)).ok());
            let target_exists = action
                .target_path
                .as_ref()
                .is_some_and(|path| self.config.root.join(path).symlink_metadata().is_ok());
            let expected = match (
                action.expected_file_id.as_deref().and_then(parse_hex_file_id),
                action.expected_generation,
            ) {
                (Some(file_id), Some(generation)) => Some(crate::sync::apply::ExpectedLocal {
                    file_id,
                    volume_serial_number: live
                        .as_ref()
                        .map(|live| live.identity.volume_serial_number)
                        .unwrap_or(0),
                    generation,
                    usn: action.expected_usn.and_then(|value| i64::try_from(value).ok()),
                }),
                _ => None,
            };
            let decision = crate::sync::apply::classify_recovered(
                action.kind,
                expected.as_ref(),
                live.as_ref(),
                target_exists,
            );
            match decision {
                crate::sync::apply::RecoveryDecision::Done => {
                    self.state
                        .set_local_action_state(
                            self.config.connection_id,
                            action.action_id,
                            LocalActionState::Recovered,
                        )
                        .await?;
                }
                crate::sync::apply::RecoveryDecision::Retry => {}
                crate::sync::apply::RecoveryDecision::PreserveFirst => {
                    if let Some(source) = &action.source_path {
                        let _ = crate::sync::apply::preserve_dirty(
                            &self.config.root.join(source),
                            &self.config.recovery_dir,
                            action.action_id,
                        );
                    }
                }
                crate::sync::apply::RecoveryDecision::Requeue => {
                    self.state
                        .set_local_action_state(
                            self.config.connection_id,
                            action.action_id,
                            LocalActionState::Requeued,
                        )
                        .await?;
                    requeued += 1;
                }
            }
        }
        Ok(requeued)
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn file_name(relative_path: &std::path::Path) -> String {
    relative_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_owned()
}

/// Parses a journaled hex file identity.
fn parse_hex_file_id(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 {
        return None;
    }
    let mut file_id = [0u8; 16];
    for index in 0..16 {
        file_id[index] = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(file_id)
}

/// Resolves an item's relative path from the durable registry.
pub async fn registry_path(
    state: &AccountStore,
    connection: ConnectionId,
    item_id: ItemId,
) -> Option<PathBuf> {
    let mut components = Vec::new();
    let mut current = Some(item_id);
    let mut depth = 0;
    while let Some(id) = current {
        if depth > 512 {
            return None;
        }
        let item = state.item(connection, id).await.ok()??;
        if item.parent_id.is_none() {
            break;
        }
        components.push(item.name.clone());
        current = item.parent_id;
        depth += 1;
    }
    components.reverse();
    let mut path = PathBuf::new();
    for component in components {
        path.push(component);
    }
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::cfapi_pump::PumpOutcome;

    #[tokio::test]
    async fn startup_discovery_queues_an_existing_file_and_rolls_back_failed_work() {
        use crate::sync::test_support::{HeadOnlyRemote, connection_fixture};
        let fixture = connection_fixture().await;
        std::fs::write(fixture.root.join("already-here.txt"), b"recover these local bytes").unwrap();
        let cancel = CancellationToken::new();
        let (_notifications, receiver) = mpsc::channel(1);
        let runtime = ConnectionRuntime::start(
            ConnectionConfig {
                connection_id: fixture.connection, workspace: fixture.workspace,
                root_item_id: fixture.root_item, device_id: DeviceId::new(),
                root: fixture.root.clone(), staging_dir: fixture.directory.path().join("snapshots"),
                recovery_dir: fixture.directory.path().join("recovery"),
                mode: hfdrive_state::ConnectionMode::Writable, start_paused: true,
            },
            fixture.account.clone(), HeadOnlyRemote { head: None, ..Default::default() },
            Arc::new(Scheduler::new(Default::default())),
            Arc::new(crate::sync::activity::ActivityRegistry::new()),
            cancel.clone(), receiver,
        );
        runtime.start_observer().await;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !runtime.local_ready.load(Ordering::Acquire) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        let entries = fixture.account.list_outbox(fixture.connection, None, 100).await.unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert!(matches!(parse_intent(entry).unwrap(), SyncIntent::Create { name, .. } if name == "already-here.txt"));
        let item_id = entry.item_id.unwrap();
        let item = fixture.account.item(fixture.connection, item_id).await.unwrap().unwrap();
        assert_eq!(item.parent_id, Some(fixture.root_item));
        assert_eq!(item.name, "already-here.txt");
        let observation = fixture.account.observation(fixture.connection, item_id).await.unwrap().unwrap();
        assert!(observation.dirty);
        let mut replacement = item.clone();
        replacement.name = "must-not-survive.txt".to_owned();
        assert!(fixture.account.record_observed_work(Some(replacement), entry.clone(), None).await.is_err());
        assert_eq!(fixture.account.item(fixture.connection, item_id).await.unwrap(), Some(item));
        assert_eq!(fixture.account.observation(fixture.connection, item_id).await.unwrap(), Some(observation));
        assert_eq!(std::fs::read(fixture.root.join("already-here.txt")).unwrap(), b"recover these local bytes");
        cancel.cancel();
        runtime.disconnect().await.unwrap();
        fixture.state.close().await.unwrap();
    }

    #[tokio::test]
    async fn idle_reconciliation_waits_for_invalidations_and_preserves_directory_work() {
        use crate::sync::test_support::{HeadOnlyRemote, connection_fixture};
        let fixture = connection_fixture().await;
        let remote = HeadOnlyRemote::default();
        let reads = remote.head_reads.clone();
        let cancel = CancellationToken::new();
        let (_notifications, receiver) = mpsc::channel(1);
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
        runtime.resume();
        runtime.drive().await;
        runtime.drive().await;
        assert_eq!(reads.load(Ordering::Relaxed), 1, "an idle tick must not reread remote HEAD");

        fixture.account.record_head_invalidation(fixture.connection, Some("change".to_owned())).await.unwrap();
        runtime.drive().await;
        runtime.drive().await;
        assert_eq!(reads.load(Ordering::Relaxed), 2, "a persisted invalidation must wake an idle connection once");

        runtime.pause();
        fixture.account.record_head_invalidation(fixture.connection, Some("while-paused".to_owned())).await.unwrap();
        runtime.drive().await;
        assert_eq!(reads.load(Ordering::Relaxed), 2);
        assert!(fixture.account.scan_state(fixture.connection).await.unwrap().unwrap().pending_head_refresh);
        runtime.resume();
        runtime.drive().await;
        runtime.drive().await;
        assert_eq!(reads.load(Ordering::Relaxed), 3);

        let item_id = ItemId::new();
        let intent = SyncIntent::Create {
            item_id: *item_id.as_uuid(), parent_id: *fixture.root_item.as_uuid(),
            name: "folder".to_owned(), kind: IntentKind::Directory, content: None,
        };
        let entry = intent_entry(
            fixture.connection, OperationId::new(), Some(item_id), None, None, 0, &intent,
        ).unwrap();
        let operation = entry.operation_id;
        fixture.account.record_observed_work(Some(hfdrive_state::ItemRecord {
            connection_id: fixture.connection, item_id, parent_id: Some(fixture.root_item),
            name: "folder".to_owned(), name_key: "folder".to_owned(),
            kind: hfdrive_state::ItemKind::Directory, revision: operation,
            content_version_id: None, deleted: false, metadata_json: serde_json::json!({}),
        }), entry, None).await.unwrap();
        assert_eq!(fixture.account.work_counts(fixture.connection).await.unwrap().pending_files, 0);
        runtime.drive().await;
        assert_eq!(reads.load(Ordering::Relaxed), 4, "directory-only work cannot depend on pending file counts");
        assert_ne!(fixture.account.outbox_entry(fixture.connection, operation).await.unwrap().unwrap().state, OutboxState::Complete);
        cancel.cancel();
        runtime.disconnect().await.unwrap();
        fixture.state.close().await.unwrap();
    }

    fn pump_outcome() -> PumpOutcome {
        PumpOutcome { disconnect: Ok(()), worker_panicked: false }
    }

    /// Runtime liveness is classified from live evidence on every call, never
    /// from a stale snapshot: missing, cancelled, finished (own scope stopped
    /// or task ended) and active are all distinguishable, and local data is
    /// preserved in every state.
    #[tokio::test]
    async fn pump_liveness_reports_missing_cancelled_finished_and_active() {
        let connection = CancellationToken::new();

        // Missing: no CFAPI pump is attached.
        let missing = pump_liveness(&connection, None);
        assert_eq!(missing, RuntimeState::Missing);
        assert!(!missing.is_active());

        // Active: the pump's scope is live and its task has not ended.
        let (hold_tx, hold_rx) = tokio::sync::oneshot::channel::<()>();
        let pump_token = connection.child_token();
        let task = tokio::spawn(async move {
            let _ = hold_rx.await;
            pump_outcome()
        });
        let handle = PumpHandle { token: pump_token.clone(), task };
        assert_eq!(pump_liveness(&connection, Some(&handle)), RuntimeState::Active);

        // Finished: the pump's own scope stopped (its work is draining) even
        // though its task has not ended yet.
        pump_token.cancel();
        assert_eq!(pump_liveness(&connection, Some(&handle)), RuntimeState::Finished);
        drop(hold_tx);

        // Finished: the pump task ran to its end while its scope stayed live.
        let task = tokio::spawn(async { pump_outcome() });
        let handle = PumpHandle { token: connection.child_token(), task };
        while !handle.task.is_finished() {
            tokio::task::yield_now().await;
        }
        assert!(!handle.token.is_cancelled());
        assert_eq!(pump_liveness(&connection, Some(&handle)), RuntimeState::Finished);

        // Cancelled: the connection scope fired first, regardless of the pump.
        let task = tokio::spawn(async { pump_outcome() });
        let handle = PumpHandle { token: connection.child_token(), task };
        connection.cancel();
        assert_eq!(pump_liveness(&connection, Some(&handle)), RuntimeState::Cancelled);
        assert!(!pump_liveness(&connection, Some(&handle)).is_active());
    }
}
