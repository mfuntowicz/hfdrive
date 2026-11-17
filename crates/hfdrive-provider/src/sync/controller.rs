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

use futures_util::stream::{FuturesUnordered, StreamExt};

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
    /// The cancellation token of the round currently dispatching. Synchronous
    /// only for storing/taking the token; never held across an await. `pause`
    /// cancels it so a pause stops the upload or HEAD mutation already in
    /// flight, not merely the next round.
    active_round: std::sync::Mutex<Option<CancellationToken>>,
    pump: tokio::sync::Mutex<Option<PumpHandle>>,
    /// Synchronous only for storing/taking the join handle; never held across
    /// an await. Disconnect joins this worker after cancelling its token.
    worker: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
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
    /// The observation/scan/drive worker did not terminate normally.
    #[error("the connection drive worker did not complete")]
    DriveTaskFailed,
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

/// A durable clean flag alone is not deletion-safety evidence. The current
/// placeholder must still be in sync and its USN must match the USN captured
/// with the observation; missing current evidence fails closed.
fn dirty_or_stale(
    observation: &hfdrive_state::LocalObservation,
    current_in_sync: bool,
    current_usn: Option<i64>,
) -> bool {
    let current_usn = current_usn.and_then(|usn| u64::try_from(usn).ok());
    observation.dirty
        || !current_in_sync
        || !matches!(
            (observation.observed_usn, current_usn),
            (Some(observed), Some(current)) if observed == current
        )
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

    fn observe(&self, observations: Vec<crate::sync::observe::RawObservation>) -> impl Future<Output = Result<(), ()>> + Send {
        // The single classification funnel: watcher batches and CFAPI
        // notifications both run through `ingest_observations`, which shares
        // the runtime's echo table and persists generations and intents
        // before any effect.
        async move {
            let observed = self.ingest_observations(crate::sync::observe::ObservationBatch {
                observations,
                rescan_required: false,
            }).await;
            if observed.is_err() {
                self.persistence_failed.store(true, Ordering::Release);
            }
            observed
        }
    }

    fn preserve_dirty(
        &self,
        relative_path: &std::path::Path,
    ) -> impl Future<Output = Result<(), &'static str>> + Send {
        let source = self.config.root.join(relative_path);
        let recovery = self.config.recovery_dir.clone();
        let label = relative_path.to_string_lossy().replace(['\\', '/'], "_");
        let display = relative_path.to_string_lossy().into_owned();
        async move {
            // Unique, metadata-checked, hash-verified recovery copy: a
            // colliding name never overwrites earlier preserved bytes and a
            // copy that cannot be verified never counts as preserved.
            crate::sync::recovery::preserve_item_bytes(&source, &recovery, &label, &display)
                .map(|_| ())
                .map_err(|error| match error {
                    crate::sync::recovery::RecoveryError::AreaUnavailable => {
                        "recovery area unavailable"
                    }
                    crate::sync::recovery::RecoveryError::SourceGone => "the source file is gone",
                    crate::sync::recovery::RecoveryError::SourceChanged => {
                        "the source changed while being preserved"
                    }
                    crate::sync::recovery::RecoveryError::Unreadable => "preserving dirty bytes failed",
                    crate::sync::recovery::RecoveryError::WriteFailed => "preserving dirty bytes failed",
                    crate::sync::recovery::RecoveryError::DigestMismatch => {
                        "the recovery copy does not match the source bytes"
                    }
                })
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
        let root = self.config.root.clone();
        async move {
            let observation = match state.observation(connection, item_id).await {
                Ok(Some(observation)) => observation,
                // A missing observation or cleanliness query is never proof
                // that destructive deletion may proceed without preservation.
                Ok(None) | Err(_) => return true,
            };
            let Some(path) = registry_path(&state, connection, item_id).await else {
                return true;
            };
            let Ok(live) = query_file_state(&root.join(path)) else {
                return true;
            };
            let current_in_sync = hfdrive_windows::filesystem::volume::placeholder_state(
                live.identity.attributes,
                live.identity.reparse_tag,
            ).is_in_sync();
            dirty_or_stale(&observation, current_in_sync, live.usn)
        }
    }

    fn void_delete_intents_for_present_items(&self) -> impl Future<Output = ()> + Send {
        let state = self.state.clone();
        let connection = self.config.connection_id;
        let root = self.config.root.clone();
        let persistence_failed = &self.persistence_failed;
        async move {
            let fail = || persistence_failed.store(true, Ordering::Release);
            let entries = match state.list_outbox(connection, None, u32::MAX).await {
                Ok(entries) => entries,
                Err(_) => {
                    fail();
                    return;
                }
            };
            for entry in entries {
                if !matches!(
                    entry.state,
                    OutboxState::Observed | OutboxState::Published | OutboxState::LocalApplyPending
                ) {
                    continue;
                }
                let intent = match parse_intent(&entry) {
                    Ok(intent) => intent,
                    Err(_) => {
                        fail();
                        continue;
                    }
                };
                if !matches!(intent, SyncIntent::Delete { .. }) {
                    continue;
                }
                let Some(path) = registry_path(&state, connection, intent.item_id()).await else {
                    fail();
                    continue;
                };
                match root.join(&path).symlink_metadata() {
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(_) => {
                        fail();
                        continue;
                    }
                }
                // The delete was abandoned: a dedicated state operation
                // validates the delete intent and closes it with the normal
                // generation guard. No remote tombstone or fabricated CAS
                // evidence is produced, and every failure remains retryable.
                if state
                    .complete_abandoned_delete(connection, entry.operation_id)
                    .await
                    .is_err()
                {
                    fail();
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
            active_round: std::sync::Mutex::new(None),
            pump: tokio::sync::Mutex::new(None),
            worker: std::sync::Mutex::new(None),
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
        let worker_task = tokio::spawn(async move {
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
                            Some(batch) => {
                                let _ = worker.ingest_observations(batch).await;
                            }
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
        *runtime.worker.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(worker_task);
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
        let previous = self.disconnect_failure.lock().await.clone();
        // This also covers the no-pump recovery path: the drive worker must
        // not retain an Arc and continue scans or uploads after disconnect.
        self.cancel.cancel();
        if let Some(observer) = self.observer.lock().await.take() {
            observer.shutdown().await;
        }
        // Take handles and release their mutexes before awaiting either join.
        let pump_result = if let Some(handle) = self.pump.lock().await.take() {
            handle.token.cancel();
            match handle.task.await {
                Ok(outcome) => match (outcome.disconnect, outcome.worker_panicked) {
                    (Err(code), _) => Err(DisconnectError::Disconnect { code }),
                    (Ok(()), true) => Err(DisconnectError::WorkerPanicked),
                    (Ok(()), false) => Ok(()),
                },
                Err(error) => {
                    tracing::error!(%error, "pump task did not complete");
                    Err(DisconnectError::PumpTaskFailed)
                }
            }
        } else {
            Ok(())
        };
        let worker = self.worker.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take();
        let worker_result = if let Some(task) = worker {
            match task.await {
                Ok(()) => Ok(()),
                Err(error) => {
                    tracing::error!(%error, "connection drive worker did not complete");
                    Err(DisconnectError::DriveTaskFailed)
                }
            }
        } else {
            Ok(())
        };
        let result = match previous {
            Some(error) => Err(error),
            None => pump_result.and(worker_result),
        };
        if let Err(error) = &result {
            *self.disconnect_failure.lock().await = Some(error.clone());
            let mut health = self.health.borrow().clone();
            health.last_error = Some(error.to_string());
            self.health.send_replace(health);
        }
        result
    }

    /// Preserves one dirty local file to the durable recovery area before a
    /// destructive local action. The source is left untouched; the copy is
    /// unique, metadata-checked and hash-verified.
    fn export_dirty_bytes(&self, relative_path: &std::path::Path) -> Result<(), &'static str> {
        let source = self.config.root.join(relative_path);
        let label = relative_path.to_string_lossy().replace(['\\', '/'], "_");
        let display = relative_path.to_string_lossy().into_owned();
        crate::sync::recovery::preserve_item_bytes(&source, &self.config.recovery_dir, &label, &display)
            .map(|_| ())
            .map_err(|error| match error {
                crate::sync::recovery::RecoveryError::AreaUnavailable => "recovery area unavailable",
                crate::sync::recovery::RecoveryError::SourceGone => "the source file is gone",
                crate::sync::recovery::RecoveryError::SourceChanged => {
                    "the source changed while being preserved"
                }
                crate::sync::recovery::RecoveryError::Unreadable => {
                    "the source could not be read for preservation"
                }
                crate::sync::recovery::RecoveryError::WriteFailed => "exporting dirty bytes failed",
                crate::sync::recovery::RecoveryError::DigestMismatch => {
                    "the recovery copy does not match the source bytes"
                }
            })
    }

    /// True when the recovery area exists or can be created: without it no
    /// dirty content can be preserved before a destructive action.
    pub fn recovery_area_ready(&self) -> bool {
        std::fs::create_dir_all(&self.config.recovery_dir).is_ok()
    }

    /// Stops live filesystem observation (watcher, USN catch-up and scan
    /// scheduling) before any provider-driven deletion. Provider deletions
    /// after this point can never become remote delete intents: the watcher
    /// that would observe them is already shut down and joined.
    pub(crate) async fn stop_observation(&self) {
        if let Some(observer) = self.observer.lock().await.take() {
            observer.shutdown().await;
        }
    }

    /// Preserves dirty local bytes before a lossy removal as unique,
    /// metadata-checked, hash-verified recovery copies in the recovery area
    /// outside every sync root. Returns the paths of every file that held
    /// unsynchronized content (all of them now preserved); a preservation
    /// failure is a block naming the file, never a silent skip.
    pub(crate) async fn preserve_dirty_before_removal(&self) -> Result<Vec<String>, UnlinkBlocked> {
        let mut preserved = Vec::new();
        let items = self
            .state
            .list_all_items(self.config.connection_id, true)
            .await
            .map_err(|_| UnlinkBlocked::new("durable state is unavailable"))?;
        for item in items {
            if item.deleted {
                continue;
            }
            let Some(path) = registry_path(&self.state, self.config.connection_id, item.item_id).await
            else {
                return Err(UnlinkBlocked::new("durable state is unavailable"));
            };
            let dirty = match self.state.observation(self.config.connection_id, item.item_id).await {
                Ok(Some(observation)) => observation.dirty,
                Ok(None) => false,
                Err(_) => return Err(UnlinkBlocked::new("durable state is unavailable")),
            };
            if !dirty {
                continue;
            }
            if self.export_dirty_bytes(&path).is_err() {
                return Err(UnlinkBlocked {
                    reason: "unsynchronized content could not be exported",
                    files: vec![path.to_string_lossy().into_owned()],
                });
            }
            preserved.push(path.to_string_lossy().into_owned());
        }
        // Interrupted local actions may still carry unpreserved source bytes.
        let actions = self
            .state
            .list_local_actions(self.config.connection_id, Some(LocalActionState::Pending))
            .await
            .map_err(|_| UnlinkBlocked::new("durable state is unavailable"))?;
        for action in actions {
            if let Some(source) = &action.source_path {
                if self.export_dirty_bytes(source).is_err() {
                    return Err(UnlinkBlocked {
                        reason: "unsynchronized content could not be exported",
                        files: vec![source.to_string_lossy().into_owned()],
                    });
                }
                preserved.push(source.to_string_lossy().into_owned());
            }
        }
        Ok(preserved)
    }

    /// Abandons the reviewed clean zero-residency placeholders of a lossy
    /// removal. Every deletion is re-guarded immediately before it runs:
    ///
    /// 1. **live inspection**: the entry's current metadata must be readable;
    /// 2. **execution-time cleanliness**: the pure rule
    ///    [`crate::sync::engine::abandonable`] is re-applied to the live
    ///    entry's facts — partial residency, durable dirty state or an
    ///    unresolved conflict **now** means the entry is preserved untouched;
    /// 3. **HFDR ownership**: the entry must still be this connection's
    ///    placeholder — the inline identity must decode for this workspace
    ///    and agree with the registry item and content version;
    /// 4. **exact identity**: NTFS volume serial, 128-bit file id, size and
    ///    last-write time must match the reviewed plan entry exactly;
    /// 5. **zero residency**: `CfGetPlaceholderRangeInfo` must report
    ///    `resident_bytes == 0` — a partially hydrated entry is never deleted;
    /// 6. **shape**: files are removed with `remove_file`, directories with
    ///    `remove_dir` — deepest first, never `remove_dir_all`.
    ///
    /// Any refusal blocks the unlink naming the entry; the plan's
    /// `partial_files == 0` precondition is additionally re-checked here.
    pub(crate) async fn abandon_unavailable(
        &self,
        plan: &crate::sync::engine::UnlinkPlan,
        plan_current: bool,
    ) -> Result<(), UnlinkBlocked> {
        if plan.partial_files > 0 {
            return Err(UnlinkBlocked::new(
                "partially resident files cannot be abandoned; hydrate, export or resolve them first",
            ));
        }
        // Execution-time conflict evidence, collected once: an entry whose
        // conflict is still unresolved is never deleted.
        let mut conflicted: std::collections::BTreeSet<ItemId> = std::collections::BTreeSet::new();
        for conflict in self
            .state
            .list_conflicts(self.config.connection_id)
            .await
            .map_err(|_| UnlinkBlocked::new("durable state is unavailable"))?
        {
            if conflict.resolution_state == hfdrive_state::ConflictResolution::Unresolved {
                conflicted.insert(conflict.item_id);
            }
        }
        // Deepest entries first: children before their directories.
        let mut order: Vec<&crate::sync::engine::UnlinkFile> = plan.abandon.iter().collect();
        order.sort_by(|a, b| {
            b.path.components()
                .count()
                .cmp(&a.path.components().count())
                .then_with(|| a.path.cmp(&b.path))
        });
        for file in order {
            let absolute = self.config.root.join(&file.path);
            let display = file.path.to_string_lossy().into_owned();
            let blocked = |reason: &'static str| UnlinkBlocked {
                reason,
                files: vec![display.clone()],
            };
            // 1. Live inspection first; a missing entry is decided by the
            //    pure rule (idempotent only while the reviewed plan is
            //    current), never assumed to be success by a failed query.
            let live = match query_file_state(&absolute) {
                Ok(live) => live,
                Err(hfdrive_windows::filesystem::FsError::NotFound { .. }) => {
                    // Already in its end state: deleted or never present.
                    match crate::sync::engine::abandon_delete_verdict(None, file, plan_current) {
                        crate::sync::engine::AbandonVerdict::AlreadyGone => continue,
                        crate::sync::engine::AbandonVerdict::Proceed => {
                            return Err(blocked("the entry vanished before deletion; prepare a fresh preview"));
                        }
                        crate::sync::engine::AbandonVerdict::Preserve(reason) => {
                            return Err(blocked(reason));
                        }
                    }
                }
                Err(_) => return Err(blocked("the entry cannot be inspected")),
            };
            // 2. Execution-time state cleanliness, decided before any
            //    ownership question: dirty or conflicted content is never
            //    deleted whatever its shape, and partial residency blocks the
            //    same way. The pure rule decides; the preserve verdict names
            //    why the entry is kept.
            let placeholder = hfdrive_windows::filesystem::volume::placeholder_state(
                live.identity.attributes,
                live.identity.reparse_tag,
            );
            let partial_state = live.size > 0
                && live.identity.may_not_be_materialized()
                && placeholder.is_partially_on_disk();
            let dirty = match self.state.observation(self.config.connection_id, file.item_id).await {
                Ok(Some(observation)) => observation.dirty,
                Ok(None) => false,
                Err(_) => return Err(blocked("durable state is unavailable")),
            };
            if !crate::sync::engine::abandonable(partial_state, dirty, conflicted.contains(&file.item_id)) {
                return Err(blocked("the entry is no longer clean and zero-residency at execution time; it is preserved untouched"));
            }
            // 3. HFDR ownership and registry agreement — required before any
            //    reversion or abandonment; NTFS identity alone is not enough.
            match hfdrive_windows::cfapi::read_placeholder_identity(
                &absolute,
                Some(self.config.workspace),
            ) {
                Ok(Some(identity))
                    if identity.item == file.item_id && identity.version == file.version_id => {}
                Ok(Some(_)) | Ok(None) => {
                    return Err(blocked("the entry is no longer this connection's placeholder; it is preserved untouched"));
                }
                Err(_) => {
                    return Err(blocked("the entry cannot be verified as this connection's placeholder; it is preserved untouched"));
                }
            }
            // 4. Real range evidence, never recall attributes alone: zero
            //    residency is proven by `resident_bytes == 0` inside the rule,
            //    and partial residency is the same range fact.
            let resident = hfdrive_windows::cfapi::ops::resident_bytes(&absolute, live.size)
                .map_err(|_| blocked("the entry's residency cannot be inspected"))?;
            let partial = live.size > 0 && placeholder.is_placeholder() && resident > 0 && resident < live.size;
            // 5. The pure guarded-deletion rule: identity/size/mtime match,
            //    clean (not partial/dirty/conflicted) and `resident == 0`.
            let facts = crate::sync::engine::AbandonLiveFacts {
                volume_serial_number: live.identity.volume_serial_number,
                file_id: live.identity.file_id,
                size: live.size,
                last_write_time_100ns: live.last_write_time_100ns,
                resident_bytes: resident,
                partial,
                dirty,
                conflicted: conflicted.contains(&file.item_id),
            };
            match crate::sync::engine::abandon_delete_verdict(Some(facts), file, plan_current) {
                crate::sync::engine::AbandonVerdict::Proceed => {}
                crate::sync::engine::AbandonVerdict::AlreadyGone => continue,
                crate::sync::engine::AbandonVerdict::Preserve(reason) => return Err(blocked(reason)),
            }
            // 6. Verify and delete the exact same open object. The handle
            // denies write/delete sharing, and every identity/HFDR/residency
            // check above is repeated through it before deletion is marked.
            let identity = match file.version_id {
                Some(version) => hfdrive_windows::cfapi::identity::PlaceholderIdentity::file(
                    self.config.workspace,
                    file.item_id,
                    version,
                ),
                None => hfdrive_windows::cfapi::identity::PlaceholderIdentity::directory(
                    self.config.workspace,
                    file.item_id,
                ),
            };
            match hfdrive_windows::cfapi::ops::delete_owned_placeholder(&absolute, &live, &identity) {
                Ok(hfdrive_windows::cfapi::ops::GuardOutcome::Applied { .. }) => {}
                Ok(hfdrive_windows::cfapi::ops::GuardOutcome::Mismatch(_)) => {
                    return Err(blocked("the entry changed before deletion; it is preserved for inspection"));
                }
                Err(_) if matches!(
                    absolute.symlink_metadata(),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound
                ) => {
                    // The entry vanished before its handle could be opened:
                    // idempotent only while the reviewed plan is current.
                    if !plan_current {
                        return Err(blocked("the entry vanished and the reviewed plan is no longer current; prepare a fresh preview"));
                    }
                }
                Err(_) => {
                    return Err(blocked("the entry could not be removed; it is preserved for inspection"));
                }
            }
        }
        Ok(())
    }

    /// Complete live residue scan run before unregistration: after
    /// conversion/deletion the on-disk root must contain no provider-managed
    /// placeholder residue. The scan is a full metadata walk (never content
    /// reads) and must complete: a denied directory or overflowed budget
    /// blocks unregistration instead of hiding residue. Every reviewed
    /// abandoned entry must also be verifiably gone.
    pub(crate) fn live_residue(
        &self,
        abandoned: &[crate::sync::engine::UnlinkFile],
    ) -> Result<(), UnlinkBlocked> {
        for file in abandoned {
            if self.config.root.join(&file.path).symlink_metadata().is_ok() {
                return Err(UnlinkBlocked {
                    reason: "an abandoned entry is still present after removal",
                    files: vec![file.path.to_string_lossy().into_owned()],
                });
            }
        }
        use hfdrive_windows::filesystem::{MetadataEntry, ScanBudget, VisitFlow, scan_metadata};
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut residue: Vec<String> = Vec::new();
        let mut visit = |entry: &MetadataEntry| {
            if entry.placeholder.is_placeholder() || entry.placeholder.is_sync_root() {
                if residue.len() < 32 {
                    residue.push(entry.relative_path.to_string_lossy().into_owned());
                }
            }
            VisitFlow::Continue
        };
        let report = scan_metadata(&self.config.root, &ScanBudget::default(), &cancel, &mut visit)
            .map_err(|_| UnlinkBlocked::new("the live residue scan could not walk the root"))?;
        if !report.complete {
            return Err(UnlinkBlocked {
                reason: "the live residue scan could not prove the root is clean; unregistration is withheld",
                files: report.denied.iter().map(|path| path.to_string_lossy().into_owned()).collect(),
            });
        }
        if !residue.is_empty() {
            return Err(UnlinkBlocked {
                reason: "managed placeholder residue remains in the root; unregistration is withheld",
                files: residue,
            });
        }
        Ok(())
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
            let live = match query_file_state(&absolute) {
                Ok(live) => live,
                // Already absent: nothing to hydrate; the entry is in its
                // desired end state. Idempotent, never a block.
                Err(hfdrive_windows::filesystem::FsError::NotFound { .. }) => continue,
                Err(_) => {
                    online_only.push(path.to_string_lossy().into_owned());
                    continue;
                }
            };
            if live.identity.may_not_be_materialized() && live.size > 0 {
                let range = hfdrive_core::storage::ByteRange::new(0, live.size, live.size)
                    .map_err(|_| UnlinkBlocked::new("placeholder size exceeds the range bound"))?;
                let hydrated = hfdrive_windows::cfapi::ops::hydrate_range(&absolute, range)
                    .and_then(|_| hfdrive_windows::cfapi::ops::resident_bytes(&absolute, live.size));
                // Residency is proven from real on-disk ranges, never recall
                // attributes: every byte must be resident for the entry to
                // count as hydrated.
                let resident = matches!(hydrated, Ok(size) if size >= live.size);
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
    ///
    /// `skip` names the items a lossy removal will abandon: those stay
    /// placeholders until the guarded abandonment converts nothing and
    /// deletes them. Every other managed entry is converted here.
    pub async fn revert_placeholders_to_normal(
        &self,
        skip: &std::collections::BTreeSet<ItemId>,
    ) -> Result<(), UnlinkBlocked> {
        let mut blocked: Vec<String> = Vec::new();
        let mut no_usn_evidence: Vec<String> = Vec::new();
        let mut unverified: Vec<String> = Vec::new();
        for item in self
            .state
            .list_all_items(self.config.connection_id, true)
            .await
            .map_err(|_| UnlinkBlocked::new("durable state is unavailable"))?
        {
            if item.deleted || skip.contains(&item.item_id) {
                continue;
            }
            let Some(path) = registry_path(&self.state, self.config.connection_id, item.item_id).await
            else {
                unverified.push(format!("item {} has no resolvable local path", item.item_id));
                continue;
            };
            let absolute = self.config.root.join(&path);
            let live = match query_file_state(&absolute) {
                Ok(live) => live,
                // Already absent: nothing to convert; the entry is in its
                // desired end state. Idempotent, never a block.
                Err(hfdrive_windows::filesystem::FsError::NotFound { .. }) => continue,
                Err(_) => {
                    unverified.push(path.to_string_lossy().into_owned());
                    continue;
                }
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
            // HFDR ownership is proven before any reversion: only a
            // placeholder whose inline identity decodes for this connection's
            // workspace and agrees with the registry item and content version
            // is ever converted. A foreign, unknown or unreadable placeholder
            // is preserved untouched and blocks unregistration — NTFS
            // identity alone never authorizes a change to it.
            match hfdrive_windows::cfapi::read_placeholder_identity(
                &absolute,
                Some(self.config.workspace),
            ) {
                Ok(Some(identity))
                    if identity.item == item.item_id
                        && identity.version == item.content_version_id => {}
                Ok(Some(_)) | Ok(None) => {
                    blocked.push(path.to_string_lossy().into_owned());
                    continue;
                }
                Err(_) => {
                    unverified.push(path.to_string_lossy().into_owned());
                    continue;
                }
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
    ///
    /// The pause is authoritative for the round already dispatching: its token
    /// is cancelled here, so an in-flight upload or conditional `HEAD` write
    /// stops instead of running to completion. `drive` also re-checks the flag
    /// under the dispatch gate, so no queued upload or `HEAD` mutation starts
    /// after this call returns.
    pub fn pause(&self) {
        self.paused.send_replace(true);
        let active = self
            .active_round
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
        if let Some(token) = active {
            token.cancel();
        }
    }

    /// Retires the round's published token. `drive` holds the dispatch gate for
    /// the whole round, so at most one round is ever installed here; a `pause`
    /// that already took and cancelled it simply finds the slot empty.
    fn clear_active_round(&self, _cancel: &CancellationToken) {
        let mut slot = self.active_round.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *slot = None;
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
    pub async fn ingest_observations(&self, batch: crate::sync::observe::ObservationBatch) -> Result<(), ()> {
        let result: Result<(), ()> = async {
            if batch.rescan_required {
                self.scan_requested.store(true, Ordering::Release);
                self.state.invalidate_scan(self.config.connection_id).await.map_err(|_| ())?;
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
                        self.state.invalidate_scan(self.config.connection_id).await.map_err(|_| ())?;
                    }
                    Classification::Created {
                        item_id,
                        is_directory,
                        state,
                    } => {
                        self.persist_change(item_id, &observation.relative_path, Some(is_directory), &state, true)
                            .await?;
                    }
                    Classification::ContentChanged { item_id, state } => {
                        self.persist_change(item_id, &observation.relative_path, None, &state, false)
                            .await?;
                    }
                    Classification::Moved { item_id, state } => {
                        self.persist_move(item_id, &observation.relative_path, &state).await?;
                    }
                    Classification::Removed { item_id } => {
                        self.pending_removals.lock().await.park(item_id, observation.relative_path.clone(), now_ms());
                        self.scan_requested.store(true, Ordering::Release);
                        self.state.invalidate_scan(self.config.connection_id).await.map_err(|_| ())?;
                    }
                    Classification::UntrackedRemoval => {
                        self.state.invalidate_scan(self.config.connection_id).await.map_err(|_| ())?;
                    }
                }
            }
            Ok(())
        }.await;
        if result.is_err() {
            self.persistence_failed.store(true, Ordering::Release);
            self.local_failure("Local changes could not be recorded; local files are preserved");
        }
        result
    }

    /// Persists a create/content change with its resolved parent.
    async fn persist_change(
        &self,
        item_id: ItemId,
        relative_path: &std::path::Path,
        is_directory: Option<bool>,
        state: &FileState,
        is_create: bool,
    ) -> Result<(), ()> {
        let Some(parent) = self.resolve_parent(relative_path).await else { return Err(()); };
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
        self.persist_intent(intent, item, state.usn.and_then(|usn| u64::try_from(usn).ok())).await
    }

    /// Persists a move/rename with its resolved parent.
    async fn persist_move(&self, item_id: ItemId, relative_path: &std::path::Path, _state: &FileState) -> Result<(), ()> {
        let Some(parent) = self.resolve_parent(relative_path).await else { return Err(()); };
        self.persist_intent(SyncIntent::Move {
            item_id: *item_id.as_uuid(),
            parent_id: parent,
            name: file_name(relative_path),
        }, None, _state.usn.and_then(|usn| u64::try_from(usn).ok()))
        .await
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
    ) -> Result<(), ()> {
        let result = async {
            let base = self.state.baseline(self.config.connection_id).await?.applied_commit;
            let entry = intent_entry(
                self.config.connection_id, OperationId::new(), Some(intent.item_id()),
                base, None, 0, &intent,
            ).map_err(|_| hfdrive_state::StateError::Io(std::io::Error::other("invalid local intent")))?;
            self.state.record_observed_work(item, entry, usn).await
        }.await.map(|_| ()).map_err(|_| ());
        if result.is_err() {
            self.persistence_failed.store(true, Ordering::Release);
            self.local_failure("Local changes could not be recorded; local files are preserved");
        }
        result
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
            }).await.map_err(|()| "Local changes could not be recorded")?;
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
                        self.persist_intent(SyncIntent::Delete { item_id: *item.item_id.as_uuid() }, None, None)
                            .await.map_err(|()| "Local changes could not be recorded")?;
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
        // The round's token is published before any dispatch so `pause` can
        // cancel the work already running, not just the next round.
        *self.active_round.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(cancel.clone());
        let ctx = self.round_context(&cancel);
        if self.writable() {
            self.upload_pass(&ctx).await;
        }
        // A pause that landed while the upload pass ran must not let this
        // round's conditional `HEAD` write start.
        if *self.paused.borrow() {
            self.clear_active_round(&cancel);
            return;
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
        self.clear_active_round(&cancel);
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
    ///
    /// At most two entries run concurrently: overlapping capture/upload work
    /// is bounded while independent entries no longer serialize on each
    /// other. Each entry's failure is best-effort exactly as before — the
    /// error is recorded by [`upload_entry`] and the pass moves on to the
    /// next entry — and the staging-admission critical section inside capture
    /// remains the one capture at a time. Entries are dispatched in the
    /// durable oldest-first order only while the pass is unpaused: pause is
    /// authoritative per dispatch, so a pause landing during the pass stops
    /// the next queued upload from starting (work already dispatched drains).
    async fn upload_pass(&self, ctx: &RoundContext<'_, R>) {
        let Ok(entries) = self
            .state
            .list_active_outbox(self.config.connection_id, u32::MAX)
            .await
        else {
            return;
        };
        let eligible = entries
            .into_iter()
            .filter(|entry| {
                matches!(entry.state, OutboxState::Observed | OutboxState::SnapshotReady)
                    && matches!(next_step(entry, now_ms()), PhaseStep::Capture | PhaseStep::Upload)
            })
            .collect::<Vec<_>>();
        let mut in_flight = FuturesUnordered::new();
        let mut pending = eligible.into_iter();
        loop {
            // Fill the bounded window while unpaused: the check is what makes
            // a pause land between two dispatches and stop the next upload.
            while in_flight.len() < 2 && !*self.paused.borrow() {
                let Some(entry) = pending.next() else { break };
                // The upload owns its entry row for the whole flight.
                in_flight.push(async move { upload_entry(ctx, &entry).await });
            }
            if in_flight.is_empty() {
                return;
            }
            // Per-entry errors stay best-effort: upload_entry records them on
            // its work rows and the pass continues with the next entry.
            let _ = in_flight.next().await;
        }
    }

    /// Executes pending journaled local actions and closes finished entries
    /// with their generation guard.
    ///
    /// The blocking-action query runs **once per pass**, before the loop, and
    /// its result is reused for every entry: an entry whose item still has a
    /// pending/in-progress journaled action is skipped. A query failure fails
    /// closed — the pass closes nothing rather than assuming an empty action
    /// set, which would let a completion race an unfinished local apply.
    async fn apply_pass(&self, ctx: &RoundContext<'_, R>) {
        let _ = crate::sync::publish::execute_pending_actions(ctx).await;
        let blocking_items = match self
            .state
            .pending_local_actions(self.config.connection_id)
            .await
        {
            Ok(actions) => actions
                .iter()
                .filter_map(|action| action.item_id)
                .collect::<std::collections::BTreeSet<_>>(),
            Err(_) => return,
        };
        let Ok(entries) = self
            .state
            .list_outbox(self.config.connection_id, Some(OutboxState::LocalApplyPending), 256)
            .await
        else {
            return;
        };
        for entry in entries {
            let blocking = match entry.item_id {
                Some(item_id) => blocking_items.contains(&item_id),
                None => false,
            };
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
        let _ = self.persist_intent(SyncIntent::Content {
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
            let live = match action
                .source_path
                .as_ref()
                .or(action.target_path.as_ref())
            {
                Some(path) => recovery_live_state(query_file_state(&self.config.root.join(path)))?,
                None => crate::sync::apply::Probe::Missing,
            };
            let expected = match (
                action.expected_file_id.as_deref().and_then(parse_hex_file_id),
                action.expected_generation,
            ) {
                (Some(file_id), Some(generation)) => Some(crate::sync::apply::ExpectedLocal {
                    file_id,
                    volume_serial_number: match &live {
                        crate::sync::apply::Probe::Present(live) => {
                            live.identity.volume_serial_number
                        }
                        crate::sync::apply::Probe::Missing
                        | crate::sync::apply::Probe::Unreadable => 0,
                    },
                    generation,
                    usn: action.expected_usn.and_then(|value| i64::try_from(value).ok()),
                }),
                _ => None,
            };
            let generation = match action.item_id {
                Some(item_id) => self.state.observation(self.config.connection_id, item_id).await?
                    .map(|observation| observation.generation),
                None => None,
            }.or(action.expected_generation).unwrap_or(0);
            let identity = action.item_id.map(|item_id| crate::sync::apply::journaled_identity(
                self.config.workspace,
                item_id,
                action.new_version.or(action.old_version),
            ));
            let target = match (&action.target_path, action.kind) {
                (Some(path), hfdrive_state::LocalActionKind::CreatePlaceholder
                    | hfdrive_state::LocalActionKind::Rename) => {
                    crate::sync::apply::target_proof(
                        &self.config.root.join(path),
                        expected.as_ref(),
                        generation,
                        identity.as_ref().map(|_| self.config.workspace),
                        identity.as_ref(),
                        action.kind == hfdrive_state::LocalActionKind::CreatePlaceholder,
                    )
                }
                _ => crate::sync::apply::TargetProof::Missing,
            };
            let decision = crate::sync::apply::classify_recovered(
                action.kind,
                expected.as_ref(),
                &live,
                generation,
                target,
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
                    let source = action.source_path.as_ref().ok_or(
                        PublishError::LocalApply("recovery action has no source path to preserve"),
                    )?;
                    crate::sync::apply::preserve_dirty(
                        &self.config.root.join(source),
                        &self.config.recovery_dir,
                        action.action_id,
                    )
                    .map_err(PublishError::LocalApply)?;
                }
                crate::sync::apply::RecoveryDecision::Requeue => {
                    self.state
                        .set_local_action_state(
                            self.config.connection_id,
                            action.action_id,
                            LocalActionState::Requeued,
                        )
                        .await?;
                    // Requeued is terminal for the interrupted action. Fresh
                    // local work is derived by a complete scan, not by blind
                    // replay and not by leaving the old row pending forever.
                    self.scan_requested.store(true, Ordering::Release);
                    self.reconcile_requested.store(true, Ordering::Release);
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

/// Only a verified absence is an absent recovery source/target. Metadata
/// failures stay errors so recovery cannot misclassify a live file as gone.
fn recovery_live_state(
    queried: Result<FileState, hfdrive_windows::filesystem::FsError>,
) -> Result<crate::sync::apply::Probe, PublishError> {
    match queried {
        Ok(live) => Ok(crate::sync::apply::Probe::Present(live)),
        Err(hfdrive_windows::filesystem::FsError::NotFound { .. }) => {
            Ok(crate::sync::apply::Probe::Missing)
        }
        Err(_) => Err(PublishError::LocalApply(
            "recovery action metadata could not be read",
        )),
    }
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
    let ancestry = state.item_ancestry(connection, item_id).await.ok()?;
    // A valid path starts at a root and remains within the format's depth
    // bound. Cycles/overflows return no path instead of a partial prefix.
    if ancestry.is_empty() || ancestry.len() > 513 || ancestry[0].parent_id.is_some() {
        return None;
    }
    let mut path = PathBuf::new();
    for item in ancestry.iter().skip(1) {
        path.push(&item.name);
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

    // ---- unlink safety regressions ---------------------------

    /// Builds one runtime over the real fixture, paused so no remote work runs.
    fn unlink_runtime(
        fixture: &crate::sync::test_support::TestConnection,
    ) -> (Arc<ConnectionRuntime<crate::sync::test_support::HeadOnlyRemote>>, CancellationToken) {
        let cancel = CancellationToken::new();
        let (_notifications, receiver) = mpsc::channel(1);
        let runtime = ConnectionRuntime::start(
            ConnectionConfig {
                connection_id: fixture.connection,
                workspace: fixture.workspace,
                root_item_id: fixture.root_item,
                device_id: DeviceId::new(),
                root: fixture.root.clone(),
                staging_dir: fixture.directory.path().join("snapshots"),
                recovery_dir: fixture.directory.path().join("recovery"),
                mode: hfdrive_state::ConnectionMode::Writable,
                start_paused: true,
            },
            fixture.account.clone(),
            crate::sync::test_support::HeadOnlyRemote::default(),
            Arc::new(Scheduler::new(Default::default())),
            Arc::new(crate::sync::activity::ActivityRegistry::new()),
            cancel.clone(),
            receiver,
        );
        (runtime, cancel)
    }

    /// Registers one registry item with a real local file at `path`.
    async fn local_item(fixture: &crate::sync::test_support::TestConnection, path: &str) -> ItemId {
        let item_id = ItemId::new();
        fixture
            .account
            .upsert_item(hfdrive_state::ItemRecord {
                connection_id: fixture.connection,
                item_id,
                parent_id: Some(fixture.root_item),
                name: path.to_owned(),
                name_key: path.to_owned(),
                kind: hfdrive_state::ItemKind::File,
                revision: OperationId::new(),
                content_version_id: None,
                deleted: false,
                metadata_json: serde_json::json!({}),
            })
            .await
            .unwrap();
        item_id
    }

    /// The reviewed plan identity of one live file: exact NTFS identity, size
    /// and modification time as `prepare_unlink` would record them.
    fn unlink_entry(root: &Path, item_id: ItemId, path: &str) -> crate::sync::engine::UnlinkFile {
        let live = query_file_state(&root.join(path)).unwrap();
        crate::sync::engine::UnlinkFile {
            item_id,
            path: PathBuf::from(path),
            version_id: Some(VersionId::new()),
            volume_serial_number: live.identity.volume_serial_number,
            file_id: live.identity.file_id,
            size: live.size,
            last_write_time_100ns: live.last_write_time_100ns,
            partial: false,
        }
    }

    fn abandon_plan(
        connection: ConnectionId,
        entry: crate::sync::engine::UnlinkFile,
    ) -> crate::sync::engine::UnlinkPlan {
        crate::sync::engine::UnlinkPlan {
            connection_id: connection,
            mode: crate::sync::engine::UnlinkMode::RemoveUnavailable,
            abandon: vec![entry],
            ..Default::default()
        }
    }

    /// The guarded abandonment re-checks cleanliness **at execution time**:
    /// an entry that is dirty or carries an unresolved conflict is preserved
    /// untouched and blocks the removal, and a plan with any partial file is
    /// refused before a single deletion.
    #[tokio::test]
    async fn abandon_unavailable_never_deletes_dirty_or_conflicted_entries() {
        use crate::sync::test_support::connection_fixture;
        let fixture = connection_fixture().await;
        std::fs::write(fixture.root.join("dirty.txt"), b"unsynchronized local bytes").unwrap();
        std::fs::write(fixture.root.join("conflicted.txt"), b"competing local bytes").unwrap();
        let dirty_item = local_item(&fixture, "dirty.txt").await;
        let conflicted_item = local_item(&fixture, "conflicted.txt").await;
        let (runtime, cancel) = unlink_runtime(&fixture);

        // Dirty evidence: the entry can never be abandoned.
        fixture
            .account
            .bump_observation(fixture.connection, dirty_item, None)
            .await
            .unwrap();
        let error = runtime
            .abandon_unavailable(
                &abandon_plan(fixture.connection, unlink_entry(&fixture.root, dirty_item, "dirty.txt")),
                true,
            )
            .await
            .unwrap_err();
        assert!(
            error.reason.contains("no longer clean and zero-residency"),
            "a dirty entry is refused at the deletion boundary: {error:?}"
        );
        assert_eq!(error.files, vec!["dirty.txt".to_owned()]);
        assert_eq!(
            std::fs::read(fixture.root.join("dirty.txt")).unwrap(),
            b"unsynchronized local bytes",
            "the dirty entry is preserved untouched"
        );

        // Unresolved conflict evidence: the entry can never be abandoned.
        fixture
            .account
            .record_conflict(hfdrive_state::ConflictRecord {
                connection_id: fixture.connection,
                conflict_id: hfdrive_core::ids::ConflictId::new(),
                item_id: conflicted_item,
                competing_ops: vec![OperationId::new(), OperationId::new()],
                revisions_json: serde_json::json!({}),
                original_names: vec!["conflicted.txt".to_owned()],
                resolution_state: hfdrive_state::ConflictResolution::Unresolved,
                detected_at_ms: None,
            })
            .await
            .unwrap();
        let error = runtime
            .abandon_unavailable(
                &abandon_plan(
                    fixture.connection,
                    unlink_entry(&fixture.root, conflicted_item, "conflicted.txt"),
                ),
                true,
            )
            .await
            .unwrap_err();
        assert!(
            error.reason.contains("no longer clean and zero-residency"),
            "a conflicted entry is refused at the deletion boundary: {error:?}"
        );
        assert_eq!(
            std::fs::read(fixture.root.join("conflicted.txt")).unwrap(),
            b"competing local bytes",
            "the conflicted entry is preserved untouched"
        );

        // The plan-level partial-files precondition refuses everything.
        let mut plan = abandon_plan(fixture.connection, unlink_entry(&fixture.root, dirty_item, "dirty.txt"));
        plan.partial_files = 1;
        let error = runtime.abandon_unavailable(&plan, true).await.unwrap_err();
        assert!(
            error.reason.contains("partially resident files cannot be abandoned"),
            "a partially resident file always blocks the lossy removal: {error:?}"
        );

        cancel.cancel();
        runtime.disconnect().await.unwrap();
        fixture.state.close().await.unwrap();
    }

    /// The HFDR-ownership guard: an entry that is not this connection's
    /// placeholder is never deleted, even when it is clean and its NTFS
    /// identity still matches the reviewed plan entry.
    #[tokio::test]
    async fn abandon_unavailable_refuses_entries_that_are_no_longer_owned_placeholders() {
        use crate::sync::test_support::connection_fixture;
        let fixture = connection_fixture().await;
        std::fs::write(fixture.root.join("foreign.txt"), b"not this connection's placeholder").unwrap();
        let item = local_item(&fixture, "foreign.txt").await;
        let (runtime, cancel) = unlink_runtime(&fixture);

        let entry = unlink_entry(&fixture.root, item, "foreign.txt");
        let error = runtime
            .abandon_unavailable(&abandon_plan(fixture.connection, entry), true)
            .await
            .unwrap_err();
        assert_eq!(
            error.reason,
            "the entry is no longer this connection's placeholder; it is preserved untouched"
        );
        assert_eq!(error.files, vec!["foreign.txt".to_owned()]);
        assert_eq!(
            std::fs::read(fixture.root.join("foreign.txt")).unwrap(),
            b"not this connection's placeholder",
            "the foreign entry is preserved untouched"
        );

        cancel.cancel();
        runtime.disconnect().await.unwrap();
        fixture.state.close().await.unwrap();
    }

    /// The residue scan gate: unregistration is withheld while a reviewed
    /// abandoned entry is still present; ordinary files are not residue, and
    /// once the abandoned entry is gone the complete scan may pass.
    #[tokio::test]
    async fn live_residue_blocks_until_every_reviewed_entry_is_gone() {
        use crate::sync::test_support::connection_fixture;
        let fixture = connection_fixture().await;
        std::fs::write(fixture.root.join("notes.txt"), b"ordinary local content").unwrap();
        let item = local_item(&fixture, "notes.txt").await;
        let (runtime, cancel) = unlink_runtime(&fixture);

        // Ordinary files are not managed placeholder residue.
        runtime.live_residue(&[]).expect("a root holding only ordinary files is clean");

        // A reviewed abandoned entry that is still on disk blocks unregistration.
        let entry = unlink_entry(&fixture.root, item, "notes.txt");
        let error = runtime
            .live_residue(std::slice::from_ref(&entry))
            .expect_err("a live abandoned entry must block unregistration");
        assert_eq!(error.reason, "an abandoned entry is still present after removal");
        assert_eq!(error.files, vec!["notes.txt".to_owned()]);

        // Once it is verifiably gone the scan completes and the gate passes.
        std::fs::remove_file(fixture.root.join("notes.txt")).unwrap();
        runtime
            .live_residue(&[entry])
            .expect("the abandoned entry is gone and the residue scan completes");

        cancel.cancel();
        runtime.disconnect().await.unwrap();
        fixture.state.close().await.unwrap();
    }

    /// Before any lossy work, dirty bytes are preserved as unique,
    /// metadata-checked, hash-verified recovery copies outside the root, and
    /// the source file is left untouched. Clean content is not exported.
    #[tokio::test]
    async fn dirty_bytes_are_preserved_as_verified_recovery_copies_before_lossy_work() {
        use crate::sync::test_support::connection_fixture;
        let fixture = connection_fixture().await;
        std::fs::write(fixture.root.join("dirty.txt"), b"unsynchronized local bytes").unwrap();
        std::fs::write(fixture.root.join("clean.txt"), b"already synchronized").unwrap();
        let dirty_item = local_item(&fixture, "dirty.txt").await;
        local_item(&fixture, "clean.txt").await;
        fixture
            .account
            .bump_observation(fixture.connection, dirty_item, None)
            .await
            .unwrap();
        let (runtime, cancel) = unlink_runtime(&fixture);

        let preserved = runtime.preserve_dirty_before_removal().await.unwrap();
        assert_eq!(preserved, vec!["dirty.txt".to_owned()], "only unsynchronized content is exported");
        assert_eq!(
            std::fs::read(fixture.root.join("dirty.txt")).unwrap(),
            b"unsynchronized local bytes",
            "the source is left untouched"
        );

        // Exactly one recovery copy with its sidecar; the sidecar digest must
        // hash-verify against the copy's bytes on disk.
        let recovery_dir = fixture.directory.path().join("recovery");
        let mut copies = Vec::new();
        let mut sidecars = Vec::new();
        for entry in std::fs::read_dir(&recovery_dir).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".json") {
                sidecars.push(entry.path());
            } else {
                copies.push(entry.path());
            }
        }
        assert_eq!(copies.len(), 1, "exactly one recovery copy: {copies:?}");
        assert_eq!(sidecars.len(), 1, "exactly one sidecar: {sidecars:?}");
        let record: crate::sync::recovery::RecoverySource =
            serde_json::from_slice(&std::fs::read(&sidecars[0]).unwrap()).unwrap();
        let copied = std::fs::read(&copies[0]).unwrap();
        assert_eq!(copied, b"unsynchronized local bytes");
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(&copied);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&digest);
        assert_eq!(record.sha256, expected, "the recovery copy is hash-verified against the preserved bytes");
        assert_eq!(record.size, copied.len() as u64);
        assert_eq!(record.label, "dirty.txt");

        cancel.cancel();
        runtime.disconnect().await.unwrap();
        fixture.state.close().await.unwrap();
    }

    #[tokio::test]
    async fn observation_query_failure_is_conservatively_dirty() {
        use crate::sync::test_support::{HeadOnlyRemote, connection_fixture};
        let fixture = connection_fixture().await;
        let (runtime, _cancel) = unlink_runtime(&fixture);
        fixture.state.close().await.unwrap();
        assert!(
            <ConnectionRuntime<HeadOnlyRemote> as crate::sync::cfapi_pump::PumpHost<HeadOnlyRemote>>::is_dirty(
                &*runtime,
                ItemId::new(),
            )
            .await,
            "a cleanliness query error must preserve the file"
        );
        runtime.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn failed_observation_is_returned_and_marks_persistence_failed() {
        use crate::sync::test_support::{HeadOnlyRemote, connection_fixture};
        let fixture = connection_fixture().await;
        let (runtime, _cancel) = unlink_runtime(&fixture);
        fixture.state.close().await.unwrap();
        let observed = <ConnectionRuntime<HeadOnlyRemote> as crate::sync::cfapi_pump::PumpHost<HeadOnlyRemote>>::observe(
            &*runtime,
            vec![crate::sync::observe::RawObservation {
                relative_path: PathBuf::from("missing.txt"),
                action: hfdrive_windows::filesystem::WatchAction::Removed,
            }],
        ).await;
        assert_eq!(observed, Err(()), "a failed durable observation must reach the ACK path");
        assert!(runtime.persistence_failed.load(Ordering::Acquire));
        runtime.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn missing_observation_is_conservatively_dirty() {
        use crate::sync::test_support::{HeadOnlyRemote, connection_fixture};
        let fixture = connection_fixture().await;
        let (runtime, _cancel) = unlink_runtime(&fixture);
        let item = local_item(&fixture, "unobserved.txt").await;
        assert!(
            <ConnectionRuntime<HeadOnlyRemote> as crate::sync::cfapi_pump::PumpHost<HeadOnlyRemote>>::is_dirty(
                &*runtime,
                item,
            )
            .await,
            "missing cleanliness evidence requires preservation before deletion"
        );
        runtime.disconnect().await.unwrap();
        fixture.state.close().await.unwrap();
    }

    #[test]
    fn dirty_freshness_requires_in_sync_state_and_a_matching_usn() {
        let observation = hfdrive_state::LocalObservation {
            connection_id: ConnectionId::new(),
            item_id: ItemId::new(),
            generation: 1,
            observed_usn: Some(41),
            dirty: false,
            pin_requested: false,
            pin_complete: false,
            excluded: false,
            scan_epoch: 0,
        };
        assert!(!dirty_or_stale(&observation, true, Some(41)));
        assert!(dirty_or_stale(&observation, false, Some(41)), "out-of-sync content is dirty");
        assert!(dirty_or_stale(&observation, true, Some(42)), "a stale observed USN is dirty");
        assert!(dirty_or_stale(&observation, true, None), "missing current USN evidence is dirty");
        assert!(dirty_or_stale(
            &hfdrive_state::LocalObservation { observed_usn: None, ..observation.clone() },
            true,
            None,
        ), "missing durable USN evidence is dirty");
        assert!(dirty_or_stale(
            &hfdrive_state::LocalObservation { dirty: true, ..observation },
            true,
            Some(41),
        ), "the durable dirty flag remains authoritative");
    }

    #[test]
    fn recovery_metadata_errors_are_not_treated_as_missing_files() {
        let error = recovery_live_state(Err(hfdrive_windows::filesystem::FsError::Win32 {
            operation: "test metadata query",
            code: 5,
        })).unwrap_err();
        assert!(matches!(error, PublishError::LocalApply("recovery action metadata could not be read")));
        assert!(matches!(
            recovery_live_state(Err(hfdrive_windows::filesystem::FsError::NotFound {
                path: PathBuf::from("already-gone.txt"),
            })).unwrap(),
            crate::sync::apply::Probe::Missing
        ));
    }

    #[tokio::test]
    async fn delete_suppression_failure_is_visible_and_retryable() {
        use crate::sync::test_support::connection_fixture;
        let fixture = connection_fixture().await;
        let (runtime, _cancel) = unlink_runtime(&fixture);
        fixture.state.close().await.unwrap();
        crate::sync::cfapi_pump::PumpHost::void_delete_intents_for_present_items(&*runtime).await;
        assert!(runtime.persistence_failed.load(Ordering::Acquire));
        runtime.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn abandoned_delete_resumes_from_its_durable_completion_stage() {
        use crate::sync::test_support::connection_fixture;
        let fixture = connection_fixture().await;
        std::fs::write(fixture.root.join("present.txt"), b"local bytes remain").unwrap();
        let item_id = local_item(&fixture, "present.txt").await;
        let entry = intent_entry(
            fixture.connection,
            OperationId::new(),
            Some(item_id),
            None,
            None,
            0,
            &SyncIntent::Delete { item_id: *item_id.as_uuid() },
        )
        .unwrap();
        let operation = entry.operation_id;
        fixture.account.record_observed_work(None, entry, None).await.unwrap();
        for transition in [
            hfdrive_state::OutboxTransition::MetadataReady {
                candidate_commit: hfdrive_core::ids::CommitId::new(),
                candidate_head_json: serde_json::json!({}),
                expected_etag: "\"fixture\"".to_owned(),
            },
            hfdrive_state::OutboxTransition::Published,
            hfdrive_state::OutboxTransition::LocalApplyPending,
        ] {
            fixture.account.transition_outbox(fixture.connection, operation, transition).await.unwrap();
        }
        let (runtime, _cancel) = unlink_runtime(&fixture);
        crate::sync::cfapi_pump::PumpHost::void_delete_intents_for_present_items(&*runtime).await;
        assert_eq!(
            fixture.account.outbox_entry(fixture.connection, operation).await.unwrap().unwrap().state,
            OutboxState::Complete
        );
        assert!(!runtime.persistence_failed.load(Ordering::Acquire));
        assert_eq!(std::fs::read(fixture.root.join("present.txt")).unwrap(), b"local bytes remain");
        runtime.disconnect().await.unwrap();
        fixture.state.close().await.unwrap();
    }

    #[tokio::test]
    async fn disconnect_without_a_pump_cancels_and_joins_the_drive_worker() {
        use crate::sync::test_support::connection_fixture;
        let fixture = connection_fixture().await;
        let (runtime, cancel) = unlink_runtime(&fixture);
        assert!(runtime.worker.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).is_some());
        runtime.disconnect().await.unwrap();
        assert!(cancel.is_cancelled());
        assert!(runtime.worker.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).is_none());
        fixture.state.close().await.unwrap();
    }

    #[tokio::test]
    async fn requeued_actions_schedule_a_fresh_scan_without_blocking_completion() {
        use crate::sync::test_support::connection_fixture;
        let fixture = connection_fixture().await;
        std::fs::write(fixture.root.join("changed.txt"), b"new local bytes").unwrap();
        let action_id = hfdrive_core::ids::ActionId::new();
        fixture
            .account
            .record_local_action(hfdrive_state::LocalAction {
                connection_id: fixture.connection,
                action_id,
                item_id: Some(ItemId::new()),
                kind: hfdrive_state::LocalActionKind::UpdatePlaceholder,
                expected_file_id: Some("00000000000000000000000000000000".to_owned()),
                expected_generation: Some(1),
                expected_usn: None,
                old_version: None,
                new_version: None,
                source_path: Some(PathBuf::from("changed.txt")),
                target_path: None,
                recovery_path: None,
                state: LocalActionState::Pending,
            })
            .await
            .unwrap();
        let (runtime, _cancel) = unlink_runtime(&fixture);
        assert_eq!(runtime.recover_actions().await.unwrap(), 1);
        assert!(runtime.scan_requested.load(Ordering::Acquire));
        assert!(runtime.reconcile_requested.load(Ordering::Acquire));
        assert!(fixture.account.pending_local_actions(fixture.connection).await.unwrap().is_empty());
        let actions = fixture.account.list_local_actions(fixture.connection, None).await.unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].state, LocalActionState::Requeued);
        runtime.disconnect().await.unwrap();
        fixture.state.close().await.unwrap();
    }

    #[tokio::test]
    async fn registry_path_uses_the_complete_root_to_item_ancestry() {
        use crate::sync::test_support::connection_fixture;
        let fixture = connection_fixture().await;
        let directory = ItemId::new();
        let file = ItemId::new();
        for (item_id, parent_id, name) in [
            (directory, Some(fixture.root_item), "folder"),
            (file, Some(directory), "report.txt"),
        ] {
            fixture
                .account
                .upsert_item(hfdrive_state::ItemRecord {
                    connection_id: fixture.connection,
                    item_id,
                    parent_id,
                    name: name.to_owned(),
                    name_key: name.to_owned(),
                    kind: hfdrive_state::ItemKind::File,
                    revision: OperationId::new(),
                    content_version_id: None,
                    deleted: false,
                    metadata_json: serde_json::json!({}),
                })
                .await
                .unwrap();
        }
        assert_eq!(
            registry_path(&fixture.account, fixture.connection, file).await,
            Some(PathBuf::from("folder").join("report.txt"))
        );
        fixture.state.close().await.unwrap();
    }

    // ---- F3: one pending-action query per apply pass ------------

    /// A remote-to-local entry whose item still carries a pending journaled
    /// action is never closed. The pass asks **once** for the blocking set and
    /// reuses it for every entry, so N entries cost one query, not N.
    #[tokio::test]
    async fn apply_pass_queries_pending_actions_once_and_skips_blocked_items() {
        use crate::sync::test_support::connection_fixture;
        let fixture = connection_fixture().await;
        let (runtime, cancel) = unlink_runtime(&fixture);

        // Two entries in `LocalApplyPending`: one blocked by a pending action,
        // one free to close.
        let blocked_item = local_item(&fixture, "blocked.txt").await;
        let free_item = local_item(&fixture, "free.txt").await;
        let mut operations = Vec::new();
        for item_id in [blocked_item, free_item] {
            let entry = intent_entry(
                fixture.connection,
                OperationId::new(),
                Some(item_id),
                None,
                None,
                0,
                &SyncIntent::Delete { item_id: *item_id.as_uuid() },
            )
            .unwrap();
            let operation = entry.operation_id;
            fixture.account.record_observed_work(None, entry, None).await.unwrap();
            for transition in [
                hfdrive_state::OutboxTransition::MetadataReady {
                    candidate_commit: hfdrive_core::ids::CommitId::new(),
                candidate_head_json: serde_json::json!({}),
                    expected_etag: "\"fixture\"".to_owned(),
                },
                hfdrive_state::OutboxTransition::Published,
                hfdrive_state::OutboxTransition::LocalApplyPending,
            ] {
                fixture.account.transition_outbox(fixture.connection, operation, transition).await.unwrap();
            }
            operations.push(operation);
        }
        // The blocking action is journaled for the first item only.
        fixture
            .account
            .record_local_action(hfdrive_state::LocalAction {
                connection_id: fixture.connection,
                action_id: hfdrive_core::ids::ActionId::new(),
                item_id: Some(blocked_item),
                kind: hfdrive_state::LocalActionKind::UpdatePlaceholder,
                expected_file_id: Some("00000000000000000000000000000000".to_owned()),
                expected_generation: Some(1),
                expected_usn: None,
                old_version: None,
                new_version: None,
                source_path: None,
                target_path: Some(PathBuf::from("blocked.txt")),
                recovery_path: None,
                state: LocalActionState::Pending,
            })
            .await
            .unwrap();

        let ctx_cancel = CancellationToken::new();
        let ctx = runtime.round_context(&ctx_cancel);
        runtime.apply_pass(&ctx).await;

        let state = |operation| fixture.account.outbox_entry(fixture.connection, operation);
        assert_eq!(
            state(operations[0]).await.unwrap().unwrap().state,
            OutboxState::LocalApplyPending,
            "an item with a pending journaled action is never closed"
        );
        assert_eq!(
            state(operations[1]).await.unwrap().unwrap().state,
            OutboxState::Complete,
            "an unblocked entry closes normally"
        );
        cancel.cancel();
        runtime.disconnect().await.unwrap();
        fixture.state.close().await.unwrap();
    }

    /// A failed pending-action query fails closed: the pass closes nothing
    /// rather than assuming an empty action set, which would let a completion
    /// race an unfinished local apply.
    #[tokio::test]
    async fn apply_pass_fails_closed_when_pending_actions_cannot_be_read() {
        use crate::sync::test_support::connection_fixture;
        let fixture = connection_fixture().await;
        let (runtime, cancel) = unlink_runtime(&fixture);
        let item_id = local_item(&fixture, "unreadable.txt").await;
        let entry = intent_entry(
            fixture.connection,
            OperationId::new(),
            Some(item_id),
            None,
            None,
            0,
            &SyncIntent::Delete { item_id: *item_id.as_uuid() },
        )
        .unwrap();
        let operation = entry.operation_id;
        fixture.account.record_observed_work(None, entry, None).await.unwrap();
        for transition in [
            hfdrive_state::OutboxTransition::MetadataReady {
                candidate_commit: hfdrive_core::ids::CommitId::new(),
                candidate_head_json: serde_json::json!({}),
                expected_etag: "\"fixture\"".to_owned(),
            },
            hfdrive_state::OutboxTransition::Published,
            hfdrive_state::OutboxTransition::LocalApplyPending,
        ] {
            fixture.account.transition_outbox(fixture.connection, operation, transition).await.unwrap();
        }

        // Closing the state worker makes the query fail; the entry must stay
        // exactly where it is instead of being treated as unblocked.
        fixture.state.close().await.unwrap();
        let ctx_cancel = CancellationToken::new();
        let ctx = runtime.round_context(&ctx_cancel);
        runtime.apply_pass(&ctx).await;
        cancel.cancel();
        runtime.disconnect().await.unwrap();
    }

    // ---- G10: pause stops the next upload and HEAD write -----

    /// A recording remote: counts every payload-stage and `HEAD` effect so a
    /// test can prove exactly which external boundaries were reached. Unlike
    /// `HeadOnlyRemote` it never panics on a payload stage. An attached
    /// [`UploadWindow`] observes how many payload uploads run at once.
    struct RecordingRemote {
        head: Option<crate::sync::remote::RemoteHead>,
        head_reads: Arc<std::sync::atomic::AtomicUsize>,
        ingestions: Arc<std::sync::atomic::AtomicUsize>,
        cas_commits: Arc<std::sync::atomic::AtomicUsize>,
        bindings: Arc<std::sync::atomic::AtomicUsize>,
        publishes: Arc<std::sync::atomic::AtomicUsize>,
        upload_window: Option<Arc<UploadWindow>>,
    }

    /// Test window observing how many payload uploads overlap. Every span is
    /// taken inside exactly one `upload_entry` operation (ingestion entry to
    /// payload binding), so `live` can never exceed the number of
    /// `upload_entry` operations running concurrently. Spans are keyed by
    /// upload id, so occupancy survives the separate remote checkpoints.
    ///
    /// Uploads are held at the payload-binding boundary until the window
    /// releases them — that is what makes overlap observable deterministically
    /// instead of by timing. The test releases exactly the uploads it has
    /// observed.
    struct UploadWindow {
        live: std::sync::Mutex<std::collections::BTreeSet<String>>,
        peak: std::sync::atomic::AtomicUsize,
        /// Set when an upload entered while the window was already full.
        overflow: std::sync::atomic::AtomicBool,
        /// Payload upload identities that reached the upload stage.
        started: std::sync::Mutex<Vec<String>>,
        release: Arc<tokio::sync::Semaphore>,
        /// Held release permits: consumed permits never return to the pool,
        /// so a release is exactly one upload allowed to finish.
        held: std::sync::Mutex<Vec<tokio::sync::OwnedSemaphorePermit>>,
    }

    impl UploadWindow {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                live: Default::default(),
                peak: std::sync::atomic::AtomicUsize::new(0),
                overflow: std::sync::atomic::AtomicBool::new(false),
                started: Default::default(),
                release: Arc::new(tokio::sync::Semaphore::new(0)),
                held: Default::default(),
            })
        }

        fn enter(&self, upload: &UploadId) {
            let key = upload.to_string();
            let live = {
                let mut live = self.live.lock().unwrap();
                live.insert(key.clone());
                live.len()
            };
            self.peak.fetch_max(live, Ordering::SeqCst);
            if live > 2 {
                self.overflow.store(true, Ordering::SeqCst);
            }
            self.started.lock().unwrap().push(key);
        }

        fn exit(&self, upload: &UploadId) {
            self.live.lock().unwrap().remove(&upload.to_string());
        }

        /// Holds this upload's stage until the window releases it.
        async fn hold(&self) {
            let permit = match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                self.release.clone().acquire_owned(),
            )
            .await
            {
                Ok(Ok(permit)) => permit,
                // Safety valve: a miscounted window must not deadlock the
                // test; the window assertions are what the test trusts.
                _ => return,
            };
            self.held.lock().unwrap().push(permit);
        }

        /// Allows exactly `uploads` held uploads to finish.
        fn release_uploads(&self, uploads: usize) {
            self.release.add_permits(uploads);
        }

        fn started(&self) -> Vec<String> {
            self.started.lock().unwrap().clone()
        }

        fn live_now(&self) -> usize {
            self.live.lock().unwrap().len()
        }

        fn peak(&self) -> usize {
            self.peak.load(Ordering::SeqCst)
        }

        fn overflowed(&self) -> bool {
            self.overflow.load(Ordering::SeqCst)
        }
    }

    /// Waits until the window has observed `count` uploads at the payload
    /// stage. Bounded: a pass that never reaches the count fails the test.
    async fn wait_for_uploads(window: &UploadWindow, count: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while window.started().len() < count {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("only {} of {count} uploads reached the payload stage", window.started().len()));
    }

    impl crate::sync::remote::RemoteOps for RecordingRemote {
        type Reader = crate::sync::test_support::UnusedReader;
        type Events = crate::sync::test_support::UnusedEvents;

        fn event_source(&self) -> Result<Self::Events, crate::sync::remote::RemoteError> {
            Err(crate::sync::remote::RemoteError::Transport)
        }

        async fn read_head(
            &self,
            _: &CancellationToken,
        ) -> Result<Option<crate::sync::remote::RemoteHead>, crate::sync::remote::RemoteError> {
            self.head_reads.fetch_add(1, Ordering::Relaxed);
            Ok(self.head.clone())
        }

        async fn initialize(
            &self,
            _: hfdrive_publication::coordinator::PublicationCandidate,
            _: &CancellationToken,
        ) -> Result<hfdrive_publication::coordinator::InitOutcome, crate::sync::remote::RemoteError> {
            self.publishes.fetch_add(1, Ordering::Relaxed);
            Err(crate::sync::remote::RemoteError::Transport)
        }

        async fn publish(
            &self,
            _: &crate::sync::remote::RemoteHead,
            _: hfdrive_publication::coordinator::PublicationCandidate,
            _: &CancellationToken,
        ) -> Result<hfdrive_publication::coordinator::PublishResult, crate::sync::remote::RemoteError> {
            self.publishes.fetch_add(1, Ordering::Relaxed);
            Err(crate::sync::remote::RemoteError::Transport)
        }

        async fn resolve_uncertain(
            &self,
            _: &hfdrive_publication::coordinator::PublicationCandidate,
            _: Option<hfdrive_publication::ancestry::AncestryCursor>,
            _: &CancellationToken,
        ) -> Result<hfdrive_publication::coordinator::UncertainResolution, crate::sync::remote::RemoteError> {
            Err(crate::sync::remote::RemoteError::Transport)
        }

        async fn find_committed_operation(
            &self,
            _: hfdrive_core::ids::CommitId,
            _: hfdrive_core::ids::OperationId,
            _: &CancellationToken,
        ) -> Result<Option<hfdrive_core::ids::CommitId>, crate::sync::remote::RemoteError> {
            Ok(None)
        }

        async fn read_metadata(
            &self,
            _: hfdrive_publication::MetadataRecord,
            _: &CancellationToken,
        ) -> Result<bytes::Bytes, crate::sync::remote::RemoteError> {
            Err(crate::sync::remote::RemoteError::RemoteContentUnavailable)
        }

        async fn ingest_payload(
            &self,
            snapshot: &hfdrive_core::storage::StableSnapshot,
            _: &CancellationToken,
        ) -> Result<hfdrive_hf::IngestionCheckpoint, crate::sync::remote::RemoteError> {
            self.ingestions.fetch_add(1, Ordering::Relaxed);
            if let Some(window) = &self.upload_window {
                // The span opens at the upload stage's first external
                // boundary and closes at the binding stage below.
                window.enter(&snapshot.upload_id);
            }
            Ok(hfdrive_hf::IngestionCheckpoint {
                target_key: snapshot.path.to_string_lossy().into_owned(),
                xet_file_id: hfdrive_core::storage::XetFileId::new(format!("{:064x}", 7u64)).unwrap(),
                size: snapshot.size,
                sha256: snapshot.sha256.clone(),
                sdk_task_id: 1,
            })
        }

        async fn commit_payload_cas(
            &self,
            _: &hfdrive_core::storage::StableSnapshot,
            ingested: &hfdrive_hf::IngestionCheckpoint,
            _: &CancellationToken,
        ) -> Result<hfdrive_hf::CasCommitCheckpoint, crate::sync::remote::RemoteError> {
            self.cas_commits.fetch_add(1, Ordering::Relaxed);
            Ok(hfdrive_hf::CasCommitCheckpoint {
                target_key: ingested.target_key.clone(),
                xet_file_id: ingested.xet_file_id.clone(),
                size: ingested.size,
                sha256: ingested.sha256.clone(),
                sdk_task_id: ingested.sdk_task_id,
            })
        }

        async fn bind_payload(
            &self,
            snapshot: &hfdrive_core::storage::StableSnapshot,
            committed: &hfdrive_hf::CasCommitCheckpoint,
                _: &CancellationToken,
        ) -> Result<hfdrive_core::storage::ObjectRef, crate::sync::remote::RemoteError> {
            self.bindings.fetch_add(1, Ordering::Relaxed);
            if let Some(window) = &self.upload_window {
                // The span closes at the upload stage's last boundary. Held
                // until the test releases it: while an upload is held here
                // its `upload_entry` operation cannot finish, so the pass can
                // never dispatch past its bound.
                window.hold().await;
                window.exit(&snapshot.upload_id);
            }
            Ok(hfdrive_core::storage::ObjectRef {
                key: hfdrive_core::storage::PayloadKey::new(snapshot.upload_id),
                sha256: committed.sha256.clone(),
                size: committed.size,
                xet_file_id: committed.xet_file_id.clone(),
            })
        }

        async fn open_range(
            &self,
            _: &hfdrive_core::storage::ObjectRef,
            _: hfdrive_core::storage::ByteRange,
            _: &hfdrive_hf::RangeCache,
            _: &CancellationToken,
        ) -> Result<Self::Reader, crate::sync::remote::RemoteError> {
            Err(crate::sync::remote::RemoteError::Transport)
        }

        async fn probe_read(&self, _: &CancellationToken) -> Result<(), crate::sync::remote::RemoteError> {
            Ok(())
        }

        async fn probe_write(&self, _: &CancellationToken) -> Result<(), crate::sync::remote::RemoteError> {
            Ok(())
        }
    }

    /// Pause cancels the active round's token and is re-checked before every
    /// dispatch, so a pause landing while the bound window of uploads is in
    /// flight stops the queued uploads behind them from ever starting — and
    /// stops the round's `HEAD` write too. In-flight uploads drain.
    #[tokio::test]
    async fn pause_during_the_inflight_uploads_stops_the_queued_uploads_and_head_write() {
        use crate::sync::test_support::connection_fixture;
        let fixture = connection_fixture().await;
        let ingestions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cas_commits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let bindings = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let publishes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let head_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let window = UploadWindow::new();
        let remote = RecordingRemote {
            head: None,
            head_reads: head_reads.clone(),
            ingestions: ingestions.clone(),
            cas_commits: cas_commits.clone(),
            bindings: bindings.clone(),
            publishes: publishes.clone(),
            upload_window: Some(window.clone()),
        };
        let cancel = CancellationToken::new();
        let (_notifications, receiver) = mpsc::channel(1);
        let runtime = ConnectionRuntime::start(
            ConnectionConfig {
                connection_id: fixture.connection,
                workspace: fixture.workspace,
                root_item_id: fixture.root_item,
                device_id: DeviceId::new(),
                root: fixture.root.clone(),
                staging_dir: fixture.directory.path().join("snapshots"),
                recovery_dir: fixture.directory.path().join("recovery"),
                mode: hfdrive_state::ConnectionMode::Writable,
                start_paused: true,
            },
            fixture.account.clone(), remote,
            Arc::new(Scheduler::new(Default::default())),
            Arc::new(crate::sync::activity::ActivityRegistry::new()),
            cancel.clone(), receiver,
        );
        runtime.resume();

        // Three queued content uploads: two fill the bound window and stay in
        // flight at the payload stage, the third stays queued behind them.
        for name in ["first.txt", "second.txt", "third.txt"] {
            std::fs::write(fixture.root.join(name), b"local bytes").unwrap();
            let item_id = local_item(&fixture, name).await;
            let entry = intent_entry(
                fixture.connection,
                OperationId::new(),
                Some(item_id),
                None,
                None,
                0,
                &SyncIntent::Create {
                    item_id: *item_id.as_uuid(),
                    parent_id: *fixture.root_item.as_uuid(),
                    name: name.to_owned(),
                    kind: IntentKind::File,
                    content: Some(PendingContent {
                        upload_id: *UploadId::new().as_uuid(),
                        version_id: *VersionId::new().as_uuid(),
                        modified_at: "2026-11-17T00:00:00Z".to_owned(),
                    }),
                },
            )
            .unwrap();
            fixture.account.record_observed_work(None, entry, None).await.unwrap();
        }

        // The round runs on its own task: the test controls the interleaving
        // through the held upload window, never through timing.
        // Durable dispatch order (the pass lists in exactly this order): the
        // first two rows are the windowed pair, the last row is queued behind.
        let dispatch_order = fixture
            .account
            .list_active_outbox(fixture.connection, u32::MAX)
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.operation_id)
            .collect::<Vec<_>>();
        assert_eq!(dispatch_order.len(), 3);
        let drive = tokio::spawn({
            let runtime = runtime.clone();
            async move { runtime.drive().await }
        });

        // The two windowed uploads are in flight at the payload stage when
        // the pause lands; the third upload is still queued behind them.
        wait_for_uploads(&window, 2).await;
        assert_eq!(window.live_now(), 2, "the two uploads overlap in flight");
        assert_eq!(window.peak(), 2, "the bounded window runs at most two uploads at once");
        runtime.pause();
        window.release_uploads(2);
        drive.await.unwrap();

        // The in-flight uploads drain their durable payload boundary ...
        for operation in &dispatch_order[..2] {
            let entry = fixture.account.outbox_entry(fixture.connection, *operation).await.unwrap().unwrap();
            assert_eq!(entry.state, OutboxState::PayloadReady, "in-flight work drains: {entry:?}");
        }
        // ... while the queued third upload never starts, and the paused
        // round never reaches the `HEAD` write.
        let third = fixture.account.outbox_entry(fixture.connection, dispatch_order[2]).await.unwrap().unwrap();
        assert_eq!(third.state, OutboxState::Observed, "the queued third upload never started: {third:?}");
        assert!(third.object_ref.is_none(), "no payload was bound for the paused entry");
        assert!(third.candidate_commit.is_none(), "no HEAD mutation was staged for the paused entry");
        assert_eq!(window.started().len(), 2, "only the two windowed uploads ever ran");
        assert_eq!(publishes.load(Ordering::Relaxed), 0, "a paused round never reaches the HEAD write");
        cancel.cancel();
        runtime.disconnect().await.unwrap();
        fixture.state.close().await.unwrap();
    }

    /// The upload pass runs every eligible entry, overlaps at most two
    /// `upload_entry` operations at once, and never touches completed history.
    #[tokio::test]
    async fn upload_pass_bounds_concurrent_uploads_and_excludes_completed_history() {
        use crate::sync::test_support::connection_fixture;
        let fixture = connection_fixture().await;
        let window = UploadWindow::new();
        let remote = RecordingRemote {
            head: None,
            head_reads: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            ingestions: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            cas_commits: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            bindings: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            publishes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            upload_window: Some(window.clone()),
        };
        let cancel = CancellationToken::new();
        let (_notifications, receiver) = mpsc::channel(1);
        let runtime = ConnectionRuntime::start(
            ConnectionConfig {
                connection_id: fixture.connection,
                workspace: fixture.workspace,
                root_item_id: fixture.root_item,
                device_id: DeviceId::new(),
                root: fixture.root.clone(),
                staging_dir: fixture.directory.path().join("snapshots"),
                recovery_dir: fixture.directory.path().join("recovery"),
                mode: hfdrive_state::ConnectionMode::Writable,
                start_paused: true,
            },
            fixture.account.clone(), remote,
            Arc::new(Scheduler::new(Default::default())),
            Arc::new(crate::sync::activity::ActivityRegistry::new()),
            cancel.clone(), receiver,
        );
        runtime.resume();

        // Three eligible content entries in durable creation order.
        let mut operations = Vec::new();
        let mut eligible_uploads = Vec::new();
        for name in ["one.txt", "two.txt", "three.txt"] {
            std::fs::write(fixture.root.join(name), b"local bytes").unwrap();
            let item_id = local_item(&fixture, name).await;
            let pending = PendingContent {
                upload_id: *UploadId::new().as_uuid(),
                version_id: *VersionId::new().as_uuid(),
                modified_at: "2026-11-17T00:00:00Z".to_owned(),
            };
            eligible_uploads.push(pending.upload_id.to_string());
            let entry = intent_entry(
                fixture.connection,
                OperationId::new(),
                Some(item_id),
                None,
                None,
                0,
                &SyncIntent::Create {
                    item_id: *item_id.as_uuid(),
                    parent_id: *fixture.root_item.as_uuid(),
                    name: name.to_owned(),
                    kind: IntentKind::File,
                    content: Some(pending),
                },
            )
            .unwrap();
            let operation = entry.operation_id;
            fixture.account.record_observed_work(None, entry, None).await.unwrap();
            operations.push(operation);
        }

        // One completed history entry with the same eligible shape: a pass
        // that scanned history would try to upload it too.
        let history_item = local_item(&fixture, "history.txt").await;
        let history_entry = intent_entry(
            fixture.connection,
            OperationId::new(),
            Some(history_item),
            None,
            None,
            0,
            &SyncIntent::Create {
                item_id: *history_item.as_uuid(),
                parent_id: *fixture.root_item.as_uuid(),
                name: "history.txt".to_owned(),
                kind: IntentKind::File,
                content: Some(PendingContent {
                    upload_id: *UploadId::new().as_uuid(),
                    version_id: *VersionId::new().as_uuid(),
                    modified_at: "2026-11-17T00:00:00Z".to_owned(),
                }),
            },
        )
        .unwrap();
        let history_operation = history_entry.operation_id;
        fixture.account.record_observed_work(None, history_entry, None).await.unwrap();
        for transition in [
            hfdrive_state::OutboxTransition::MetadataReady {
                candidate_commit: hfdrive_core::ids::CommitId::new(),
                candidate_head_json: serde_json::json!({}),
                expected_etag: "\"fixture\"".to_owned(),
            },
            hfdrive_state::OutboxTransition::Published,
            hfdrive_state::OutboxTransition::LocalApplyPending,
        ] {
            fixture.account.transition_outbox(fixture.connection, history_operation, transition).await.unwrap();
        }
        fixture.account.complete_outbox(fixture.connection, history_operation).await.unwrap();

        // The pass's own listing sees only the three eligible rows; the
        // completed row stays durable history.
        let active = fixture.account.list_active_outbox(fixture.connection, u32::MAX).await.unwrap();
        assert_eq!(active.len(), 3, "completed history is excluded from the active listing");
        assert_eq!(
            fixture.account.list_outbox(fixture.connection, None, u32::MAX).await.unwrap().len(),
            4,
            "completed history is retained durably"
        );

        let pass = tokio::spawn({
            let runtime = runtime.clone();
            async move {
                let ctx_cancel = CancellationToken::new();
                let ctx = runtime.round_context(&ctx_cancel);
                runtime.upload_pass(&ctx).await;
            }
        });

        // Two uploads overlap at the payload stage; the pass must not start a
        // third while its window is full.
        wait_for_uploads(&window, 2).await;
        assert_eq!(window.live_now(), 2, "the first two eligible entries overlap");
        assert_eq!(window.peak(), 2, "the bounded window runs at most two uploads at once");
        assert!(!window.overflowed(), "no third upload ever overlapped the window");
        assert_eq!(
            window.started().len(),
            2,
            "a third upload must not start while two upload_entry operations are in flight"
        );
        window.release_uploads(2);

        // The pair drains and the last eligible entry runs on its own.
        wait_for_uploads(&window, 3).await;
        assert_eq!(window.peak(), 2, "the third upload starts only after a slot frees");
        window.release_uploads(1);
        pass.await.unwrap();

        // All eligible entries ran exactly once; history ran never.
        let mut ran = window.started();
        ran.sort();
        let mut expected = eligible_uploads;
        expected.sort();
        assert_eq!(ran, expected, "every eligible entry ran exactly once and history ran never");
        for operation in &operations {
            let entry = fixture.account.outbox_entry(fixture.connection, *operation).await.unwrap().unwrap();
            assert_eq!(
                entry.state,
                OutboxState::PayloadReady,
                "every eligible entry reached its durable payload boundary: {entry:?}"
            );
        }
        let history = fixture.account.outbox_entry(fixture.connection, history_operation).await.unwrap().unwrap();
        assert_eq!(history.state, OutboxState::Complete, "completed history stays completed");
        assert!(history.object_ref.is_none(), "completed history is never uploaded");

        cancel.cancel();
        runtime.disconnect().await.unwrap();
        fixture.state.close().await.unwrap();
    }
}
