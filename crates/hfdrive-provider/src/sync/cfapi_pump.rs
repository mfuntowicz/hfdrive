//! The live CFAPI callback pump: real Explorer hydration, directory
//! population and local-change notifications.
//!
//! Attached per connection, one pump consumes the typed callback streams and
//! serves the OS from the connection's **immutable** remote bindings:
//!
//! * `FETCH_DATA` resolves the placeholder identity's exact version record
//!   (`objects/<upload-uuid>` binding, size + Xet id) and streams the planned
//!   aligned chunks through `open_range` on the provider-wide clean range
//!   cache. The binding is captured per request: a fetch is always served
//!   from the one immutable version its identity names — never from a newer
//!   `HEAD`. Buffers stay bounded at the 1 MiB transfer-chunk size (EOF
//!   excepted); the required range is streamed sequentially, never
//!   accumulated whole-file.
//! * `CANCEL_FETCH_DATA` sets the request's shared cancellation flag (the
//!   hub owns it); the fetch loop notices between chunks and completes the
//!   request truthfully with `Cancelled`, keeping other overlapping requests
//!   alive. `cancel_matching` maintains the interest bookkeeping. Pump
//!   shutdown is a distinct signal: it cancels every request's child token
//!   (tied to the pump's cancellation token), which each remote read, range
//!   stream and scheduler wait observes, while the per-request CFAPI flag
//!   keeps its own meaning (`Cancelled` versus `ProviderStopping`).
//! * Every accepted `FETCH_DATA` request reaches **exactly one** terminal
//!   outcome through its fetch guard: success (its final planned chunk), an
//!   ordinary failure, cancellation, a worker panic, or an early return.
//!   The guard's synchronous `Drop` fails the request and cleans its
//!   interest bookkeeping unless a real terminal completion already disarmed
//!   it, so a normal failure never produces a second `CfExecute`.
//! * `FETCH_PLACEHOLDERS` populates one directory from the durable item
//!   registry in bounded batches, checking every per-entry outcome.
//! * `NOTIFY_RENAME` / `NOTIFY_DELETE` persist their observation **before**
//!   acknowledging. A delete of locally dirty content preserves the bytes to
//!   the recovery area first (and vetoes the delete when preservation is not
//!   possible), so no uncommitted local work can disappear. Provider-applied
//!   changes are absorbed by the echo filter and never become intents.
//! * `*_COMPLETION` events are post-facto bookkeeping; an abandoned delete
//!   voids its queued intent instead of publishing a tombstone for a file
//!   that still exists.
//!
//! Requests run as bounded child tasks under the shared scheduler's read
//! permits (`BlockingHydration`), so all hydration across the provider stays
//! inside the global concurrency limit.
//!
//! Shutdown is a graceful drain, never an abort: the loop stops scheduling,
//! cancels every request's child token and joins each worker to completion
//! (`join_next` until empty), so every accepted request finishes its
//! terminal outcome before the sync root is disconnected. The final
//! connection owner is unique by construction: the loop's `Arc` is the last
//! one after the drain, and only that owner calls `CfConnection::shutdown`,
//! whose disconnect failure is propagated to the caller instead of being
//! swallowed.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use hfdrive_core::ids::{ConnectionId, ItemId, VersionId, WorkspaceId};
use hfdrive_core::storage::{ByteRange, ObjectRef};
use hfdrive_windows::cfapi::events::{
    CancelTarget, CompletionEvent, DeleteNotification, FetchFailure, FetchRequest,
    PlaceholdersRequest, RenameNotification, TransferStatus,
};
use hfdrive_windows::cfapi::identity::PlaceholderIdentity;
use hfdrive_windows::cfapi::ops::{MetadataSpec, PlaceholderCreate, PlaceholderRequestOutcome};
use hfdrive_windows::cfapi::transfers::{TransferChunk, TransferCompletion, plan_chunks};
use hfdrive_windows::cfapi::CfConnection;
use hfdrive_windows::filesystem::WatchAction;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::scheduler::{Scheduler, WorkClass};
use crate::sync::observe::RawObservation;
use crate::sync::remote::{RangeSource, RemoteError, RemoteOps, version_object};

/// One registry child ready to become a placeholder.
#[derive(Debug, Clone)]
pub struct PumpChild {
    pub item_id: ItemId,
    pub name: String,
    pub is_directory: bool,
    pub version: Option<VersionId>,
    pub size: u64,
    pub modified_at_100ns: i64,
}

/// The host surface the pump drives. Implemented by
/// [`crate::sync::controller::ConnectionRuntime`]; the pump owns no durable
/// policy — every observation and preservation goes back through the host.
pub trait PumpHost<R: RemoteOps>: Send + Sync + 'static {
    /// The connection's remote boundary.
    fn remote(&self) -> &R;
    /// The provider-wide scheduler (read permits + clean range cache).
    fn scheduler(&self) -> &Scheduler;
    /// The connection identity (scheduler fairness key).
    fn connection_id(&self) -> ConnectionId;
    /// The connection's workspace (placeholder identity validation).
    fn workspace(&self) -> WorkspaceId;
    /// Durably ingest local observations (classification + intent
    /// persistence). Returns only after the durable records exist.
    fn observe(&self, observations: Vec<RawObservation>) -> impl Future<Output = ()> + Send;
    /// Preserve dirty bytes before a destructive local removal. `Ok(())`
    /// means the bytes are durable outside the sync root.
    fn preserve_dirty(
        &self,
        relative_path: &std::path::Path,
    ) -> impl Future<Output = Result<(), &'static str>> + Send;
    /// Resolve a relative path inside the root to a known item id.
    fn resolve(&self, components: &[String]) -> impl Future<Output = Option<ItemId>> + Send;
    /// The durable children of one directory item (`None` = the sync root).
    fn children(
        &self,
        parent: Option<ItemId>,
    ) -> impl Future<Output = Option<Vec<PumpChild>>> + Send;
    /// The current dirty state of one item (delete preservation gate).
    fn is_dirty(&self, item_id: ItemId) -> impl Future<Output = bool> + Send;
    /// Close every queued delete intent whose item still exists locally. An
    /// abandoned OS delete leaves the file in place; publishing a tombstone
    /// for it would destroy remote data that was never deleted.
    fn void_delete_intents_for_present_items(&self) -> impl Future<Output = ()> + Send;
}

/// Outcome of one pump run: the shutdown's connection result plus any
/// abnormal worker termination. Both are reported; a disconnect failure is
/// never hidden behind a clean `Ok`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PumpOutcome {
    /// `Ok(())` when the final owner's [`CfConnection::shutdown`] disconnected
    /// the sync root. `Err(code)` when `CfDisconnectSyncRoot` failed
    /// (`u32::MAX` when the failure carries no Windows code, e.g.
    /// `NotConnected`, or when a stale connection owner leaked).
    pub disconnect: Result<(), u32>,
    /// True when a request worker terminated abnormally. Its guard still
    /// completed that request truthfully on the way out.
    pub worker_panicked: bool,
}

impl PumpOutcome {
    /// True when the pump shut down cleanly: every worker finished normally
    /// and the sync root disconnected successfully.
    pub fn is_clean(&self) -> bool {
        self.disconnect.is_ok() && !self.worker_panicked
    }
}

/// Runs the pump until `cancel` fires or the streams end. Shutdown is a
/// graceful drain: scheduling stops, every request's child token is
/// cancelled, each worker is joined to completion (`join_next` until the set
/// is empty — never `JoinSet::shutdown`/abort), and only then does the final
/// connection owner disconnect the sync root while the callback context is
/// still valid. The disconnect result is returned, never swallowed.
pub async fn run_pump<R: RemoteOps, H: PumpHost<R>>(
    host: Arc<H>,
    connection: CfConnection,
    streams: hfdrive_windows::cfapi::ProviderStreams,
    cancel: CancellationToken,
) -> PumpOutcome {
    let connection = Arc::new(connection);
    let hfdrive_windows::cfapi::ProviderStreams {
        mut fetch,
        mut fetch_placeholders,
        mut cancels,
        mut renames,
        mut deletes,
        mut completions,
    } = streams;
    let mut inflight: JoinSet<()> = JoinSet::new();
    let mut worker_panicked = false;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            result = inflight.join_next(), if !inflight.is_empty() => {
                // A fetch worker that panicked already failed its request
                // truthfully from its own guard on the way out; record the
                // failure so shutdown is not reported as clean.
                if result.is_some_and(|result| result.is_err()) {
                    worker_panicked = true;
                    tracing::warn!("fetch worker terminated unexpectedly");
                }
            }
            request = fetch.recv() => {
                let Some(request) = request else { break; };
                let host = host.clone();
                let connection = connection.clone();
                // Every worker inherits pump shutdown through this child
                // token; its own `cancelled` flag stays the per-request
                // CFAPI cancellation signal.
                let worker_cancel = cancel.child_token();
                inflight.spawn(async move {
                    serve_fetch(&*host, &connection, request, worker_cancel).await;
                });
            }
            request = fetch_placeholders.recv() => {
                let Some(request) = request else { break; };
                serve_placeholders(&*host, &connection, request).await;
            }
            cancel_event = cancels.recv() => {
                let Some(cancel_event) = cancel_event else { break; };
                // Interest bookkeeping: only the matching request's ranges;
                // shared overlapping requests stay alive. The data loop of a
                // cancelled request notices its shared flag.
                connection.cancel_matching(
                    cancel_event.ack.request_key,
                    cancel_event.ranges.as_deref(),
                );
                if cancel_event.target == CancelTarget::FetchPlaceholders {
                    let _ = connection.fail_placeholders(cancel_event.ack, FetchFailure::Cancelled);
                }
            }
            rename = renames.recv() => {
                let Some(rename) = rename else { break; };
                handle_rename(&*host, &connection, rename).await;
            }
            delete = deletes.recv() => {
                let Some(delete) = delete else { break; };
                handle_delete(&*host, &connection, delete).await;
            }
            completion = completions.recv() => {
                let Some(completion) = completion else { break; };
                handle_completion(&*host, completion).await;
            }
        }
    }
    // Mark every request worker cancelled (idempotent when the pump token is
    // what ended the loop) and close the queues: any callback delivered from
    // now on is completed by the hub itself (its queue send fails), so the
    // hub, not a dropped receiver, owns that terminal outcome.
    cancel.cancel();
    fetch.close();
    fetch_placeholders.close();
    cancels.close();
    renames.close();
    deletes.close();
    completions.close();
    // Everything already accepted but never started reaches a terminal
    // outcome right here; notification observations are still durably
    // ingested (never silently lost), and post-facto completions still void
    // abandoned delete intents.
    while let Ok(cancel_event) = cancels.try_recv() {
        connection.cancel_matching(cancel_event.ack.request_key, cancel_event.ranges.as_deref());
        if cancel_event.target == CancelTarget::FetchPlaceholders {
            let _ = connection.fail_placeholders(cancel_event.ack, FetchFailure::Cancelled);
        }
    }
    while let Ok(request) = fetch.try_recv() {
        // Never started: fail truthfully, keeping the request's own CFAPI
        // cancellation meaning distinct from pump shutdown.
        let failure = if request.cancelled.load(Ordering::SeqCst) {
            FetchFailure::Cancelled
        } else {
            FetchFailure::ProviderStopping
        };
        let _ = connection.fail_fetch(request.ack, request.required, failure);
    }
    while let Ok(request) = fetch_placeholders.try_recv() {
        let _ = connection.fail_placeholders(request.ack, FetchFailure::ProviderStopping);
    }
    while let Ok(rename) = renames.try_recv() {
        handle_rename(&*host, &connection, rename).await;
    }
    while let Ok(delete) = deletes.try_recv() {
        handle_delete(&*host, &connection, delete).await;
    }
    while let Ok(completion) = completions.try_recv() {
        handle_completion(&*host, completion).await;
    }
    // Stop scheduling (already cancelled) and drain every request worker to
    // completion: cancellation is cooperative and each worker holds its
    // terminal-outcome guard, so no accepted request is abandoned mid-flight.
    while let Some(result) = inflight.join_next().await {
        if result.is_err() {
            worker_panicked = true;
            tracing::warn!("fetch worker terminated unexpectedly during drain");
        }
    }
    // The drain joined every worker and the pump loop's `connection` clone is
    // the last owner now (each worker held a clone only while running):
    // `try_unwrap` proves it before the single disconnect. If a stale owner
    // were ever present, never fall back to the best-effort `Drop` disconnect
    // that would hide `CfDisconnectSyncRoot` failures — surface the anomaly.
    let connection = match Arc::try_unwrap(connection) {
        Ok(connection) => connection,
        Err(connection) => {
            tracing::error!(
                "pump connection owner leaked; refusing best-effort disconnect"
            );
            drop(connection);
            return PumpOutcome {
                disconnect: Err(u32::MAX),
                worker_panicked,
            };
        }
    };
    // Exactly one disconnect, whatever the workers did; its result is the
    // outcome, never swallowed.
    let disconnect = match connection.shutdown() {
        Ok(()) => Ok(()),
        Err(error) => {
            tracing::warn!(%error, "sync root disconnect failed");
            match error {
                hfdrive_windows::cfapi::CfError::Win32 { code, .. } => Err(code),
                _ => Err(u32::MAX),
            }
        }
    };
    PumpOutcome {
        disconnect,
        worker_panicked,
    }
}

// ---------------------------------------------------------------------------
// FETCH_DATA: immutable-version range hydration
// ---------------------------------------------------------------------------

/// Guarantees exactly one terminal outcome for one accepted `FETCH_DATA`
/// request.
///
/// Armed with the request's real ack as soon as the request leaves the queue.
/// On every exit path — success (the final planned chunk), an ordinary error,
/// per-request cancellation, pump shutdown, panic unwind or an early return —
/// the request reaches exactly one terminal completion: the final chunk's
/// `CfExecute` (`complete_chunk(..., terminal: true)`) or `fail_fetch`, both
/// of which disarm the guard. If neither ran (panic, early return), the
/// synchronous `Drop` fails the request truthfully and cleans its interest
/// bookkeeping. Because every disarming path completes the request itself, a
/// normal failure can never produce a second `CfExecute` completion.
struct FetchGuard {
    connection: Arc<CfConnection>,
    ack: hfdrive_windows::cfapi::events::AckToken,
    required: ByteRange,
    armed: bool,
}

impl FetchGuard {
    /// Armed from the start: the request is accepted and must reach a
    /// terminal outcome no matter how the worker leaves.
    fn new(
        connection: Arc<CfConnection>,
        ack: hfdrive_windows::cfapi::events::AckToken,
        required: ByteRange,
    ) -> Self {
        Self {
            connection,
            ack,
            required,
            armed: true,
        }
    }

    /// Deliver one planned chunk. The final chunk of the final run is the
    /// request's terminal success completion and disarms the guard; a
    /// completion error keeps the guard armed so the failure path completes
    /// the request (the failing `CfExecute` did not complete it).
    fn complete_chunk(
        &mut self,
        chunk: TransferChunk,
        file_size: u64,
        bytes: &[u8],
        terminal: bool,
    ) -> Result<(), FetchFailure> {
        let completion = TransferCompletion {
            ack: self.ack,
            chunk,
            file_size,
        };
        match self.connection.complete_transfer(completion, bytes) {
            Ok(()) => {
                if terminal {
                    // Success terminal: drop the request's interest
                    // bookkeeping (failures go through `fail_fetch`, which
                    // already does this).
                    self.armed = false;
                    self.connection.finish_fetch(self.ack.request_key);
                }
                Ok(())
            }
            Err(error) => {
                tracing::warn!(%error, "fetch chunk completion failed");
                Err(FetchFailure::Internal)
            }
        }
    }

    /// Report genuine transfer progress to the OS.
    fn report_progress(&self, total: u64, completed: u64) {
        if let Err(error) = self.connection.report_progress(self.ack.transfer_key, total, completed)
        {
            tracing::warn!(%error, "fetch progress report failed");
        }
    }

    /// Complete the request with a terminal failure status and clean its
    /// interest bookkeeping. Disarms the guard (Drop does nothing afterwards).
    fn fail_now(&mut self, failure: FetchFailure) {
        self.armed = false;
        if let Err(error) = self.connection.fail_fetch(self.ack, self.required, failure) {
            tracing::warn!(%error, "fetch failure completion failed");
        }
    }
}

impl Drop for FetchGuard {
    fn drop(&mut self) {
        if self.armed {
            // The request never reached a real terminal (panic unwind, early
            // return, worker cancellation): complete it truthfully exactly
            // once here.
            if let Err(error) = self.connection.fail_fetch(self.ack, self.required, FetchFailure::Internal) {
                tracing::warn!(%error, "fetch guard terminal completion failed");
            }
        }
    }
}

async fn serve_fetch<R: RemoteOps, H: PumpHost<R>>(
    host: &H,
    connection: &Arc<CfConnection>,
    request: FetchRequest,
    pump_cancel: CancellationToken,
) {
    let FetchRequest {
        ack,
        identity,
        file_size,
        required,
        optional,
        cancelled,
        ..
    } = request;

    let mut guard = FetchGuard::new(connection.clone(), ack, required);
    // One child token per request: pump shutdown cancels it (canceling every
    // remote read, range stream and scheduler wait), while the request's own
    // `cancelled` flag remains the CFAPI cancellation signal.
    let cancel = pump_cancel.child_token();
    let failure = fetch_flow(
        host,
        &cancel,
        &cancelled,
        identity,
        file_size,
        required,
        optional,
        &mut guard,
    )
    .await;
    if guard.armed {
        // No real terminal completion happened (flow-reported failure, or an
        // impossible empty plan): complete the request exactly once here. A
        // cancellation that is not this request's own CFAPI cancellation is
        // the pump's shutdown and is reported as such.
        let failure = failure.unwrap_or(FetchFailure::Internal);
        let failure = match failure {
            FetchFailure::Cancelled if !cancelled.load(Ordering::SeqCst) => {
                FetchFailure::ProviderStopping
            }
            other => other,
        };
        guard.fail_now(failure);
    }
}

/// The fetch body: returns the terminal failure to report, or `None` when
/// the final planned chunk already completed the request (guard disarmed).
#[allow(clippy::too_many_arguments)]
async fn fetch_flow<R: RemoteOps, H: PumpHost<R>>(
    host: &H,
    cancel: &CancellationToken,
    cancelled: &Arc<std::sync::atomic::AtomicBool>,
    identity: PlaceholderIdentity,
    file_size: u64,
    required: ByteRange,
    optional: Option<ByteRange>,
    guard: &mut FetchGuard,
) -> Option<FetchFailure> {
    // Immutable binding: the identity names the exact version to serve.
    let Some(version) = identity.version else {
        // Directory identities never carry content.
        return Some(FetchFailure::InvalidRequest);
    };
    if cancelled.load(Ordering::SeqCst) {
        return Some(FetchFailure::Cancelled);
    }
    let object = match version_object(host.remote(), host.workspace(), version, cancel).await {
        Ok(object) => object,
        Err(error) => return Some(flow_failure(&error, cancelled)),
    };
    if object.size != file_size {
        // Placeholder metadata and the immutable binding disagree: fail
        // truthfully instead of serving a wrong-length object.
        return Some(FetchFailure::InvalidRequest);
    }

    let chunks = match plan_chunks(required, optional, file_size) {
        Ok(chunks) => chunks,
        Err(_) => return Some(FetchFailure::InvalidRequest),
    };
    let total: u64 = chunks.iter().map(|chunk| chunk.len).sum();
    let mut completed: u64 = 0;
    let runs = chunk_runs(&chunks, file_size);

    // Contiguous runs are streamed sequentially through one range reader
    // each; planned chunks are delivered exactly as planned and the run's
    // stream is consumed exactly (no hidden bytes, no holes).
    for (index, (run, range)) in runs.iter().enumerate() {
        if cancelled.load(Ordering::SeqCst) {
            return Some(FetchFailure::Cancelled);
        }
        if cancel.is_cancelled() {
            // Pump shutdown, not this request's own cancellation.
            return Some(FetchFailure::ProviderStopping);
        }
        // Blocking hydration may use every read permit; the scheduler keeps
        // the provider-wide bound.
        let _permit = match host
            .scheduler()
            .acquire_read(
                WorkClass::BlockingHydration,
                *host.connection_id().as_uuid(),
                cancel,
            )
            .await
        {
            Ok(permit) => permit,
            Err(error) => return Some(schedule_failure(&error, cancelled)),
        };
        let mut reader = match host
            .remote()
            .open_range(&object, *range, host.scheduler().range_cache(), cancel)
            .await
        {
            Ok(reader) => reader,
            Err(error) => return Some(flow_failure(&error, cancelled)),
        };
        let terminal_run = index + 1 == runs.len();
        match stream_run::<R>(
            cancel,
            run,
            file_size,
            &mut reader,
            &mut completed,
            total,
            cancelled,
            guard,
            terminal_run,
        )
        .await
        {
            Ok(()) => {}
            Err(failure) => {
                reader.cancel();
                return Some(failure);
            }
        }
    }
    // `plan_chunks` always yields at least one chunk and every run delivers
    // its chunks, so the final run's last chunk already disarmed the guard
    // (success terminal). A `None` with the guard still armed is impossible
    // here and completed defensively by `serve_fetch`.
    None
}

/// Streams one contiguous run: pieces from the range reader are sliced into
/// the exact planned chunks with a bounded buffer. The run's stream must be
/// consumed exactly — a short or overlong stream fails truthfully instead of
/// padding or discarding bytes. The last chunk of the last run is the
/// request's terminal completion (the guard is disarmed there and only
/// there).
#[allow(clippy::too_many_arguments)]
async fn stream_run<R: RemoteOps>(
    cancel: &CancellationToken,
    run: &[TransferChunk],
    file_size: u64,
    reader: &mut R::Reader,
    completed: &mut u64,
    total: u64,
    cancelled: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    guard: &mut FetchGuard,
    terminal_run: bool,
) -> Result<(), FetchFailure> {
    let mut pending: Option<bytes::Bytes> = None;
    let mut pending_offset = 0usize;
    for (index, chunk) in run.iter().enumerate() {
        let mut buffer: Vec<u8> = Vec::with_capacity(chunk.len as usize);
        while (buffer.len() as u64) < chunk.len {
            if cancelled.load(Ordering::SeqCst) {
                return Err(FetchFailure::Cancelled);
            }
            if cancel.is_cancelled() {
                return Err(FetchFailure::ProviderStopping);
            }
            if pending.is_none() || pending_offset >= pending.as_ref().map(|p| p.len()).unwrap_or(0) {
                pending = match reader.next_chunk(cancel).await {
                    Ok(Some(piece)) => Some(piece),
                    Ok(None) => {
                        // The immutable object ended before the planned
                        // range: never serve holes as zeroes.
                        return Err(FetchFailure::Internal);
                    }
                    Err(RemoteError::Cancelled) => return Err(FetchFailure::Cancelled),
                    Err(error) => return Err(flow_failure(&error, cancelled)),
                };
                pending_offset = 0;
            }
            let piece = pending.as_ref().expect("piece just loaded");
            let available = &piece[pending_offset..];
            let need = (chunk.len as usize).saturating_sub(buffer.len());
            let take = need.min(available.len());
            buffer.extend_from_slice(&available[..take]);
            pending_offset += take;
        }
        let terminal = terminal_run && index + 1 == run.len();
        guard.complete_chunk(*chunk, file_size, &buffer, terminal)?;
        *completed += chunk.len;
        guard.report_progress(total, *completed);
    }
    // Exact-consumption check: any unread tail means the stream disagreed
    // with the planned span; fail truthfully rather than hide bytes.
    if pending.as_ref().is_some_and(|piece| pending_offset < piece.len()) {
        return Err(FetchFailure::Internal);
    }
    Ok(())
}

/// Groups the planned chunks into contiguous runs and returns each run with
/// its full span. One range request per run keeps the stream sequential.
fn chunk_runs(chunks: &[TransferChunk], file_size: u64) -> Vec<(Vec<TransferChunk>, ByteRange)> {
    let mut runs: Vec<Vec<TransferChunk>> = Vec::new();
    for chunk in chunks {
        match runs.last_mut() {
            Some(run) => {
                let last = run.last().expect("nonempty run");
                if last.offset + last.len == chunk.offset {
                    run.push(*chunk);
                } else {
                    runs.push(vec![*chunk]);
                }
            }
            None => runs.push(vec![*chunk]),
        }
    }
    runs.into_iter()
        .filter_map(|run| {
            let first = *run.first()?;
            let last = *run.last()?;
            let range = ByteRange::new(first.offset, last.offset + last.len, file_size).ok()?;
            Some((run, range))
        })
        .collect()
}

/// A remote/read error's terminal failure. A cancellation that is not the
/// request's own CFAPI cancellation is pump shutdown and is reported as
/// `ProviderStopping`, never as the request's `Cancelled`.
fn flow_failure(error: &RemoteError, cancelled: &Arc<std::sync::atomic::AtomicBool>) -> FetchFailure {
    match fetch_failure(error) {
        FetchFailure::Cancelled if !cancelled.load(Ordering::SeqCst) => FetchFailure::ProviderStopping,
        other => other,
    }
}

/// A scheduler admission failure: cancellation is pump shutdown (see
/// [`flow_failure`]); queue exhaustion and policy denials stay distinct.
fn schedule_failure(
    error: &crate::scheduler::ScheduleError,
    cancelled: &Arc<std::sync::atomic::AtomicBool>,
) -> FetchFailure {
    use crate::scheduler::ScheduleError;
    match error {
        ScheduleError::Cancelled if !cancelled.load(Ordering::SeqCst) => FetchFailure::ProviderStopping,
        ScheduleError::Cancelled => FetchFailure::Cancelled,
        ScheduleError::Busy => FetchFailure::ResourceExhausted,
        // Unreachable for `BlockingHydration` (user-blocking work is admitted
        // while paused/metered); reported as temporarily unavailable rather
        // than as provider shutdown if policy ever refuses it.
        ScheduleError::Paused | ScheduleError::Metered => FetchFailure::Offline,
        ScheduleError::Offline => FetchFailure::Offline,
        ScheduleError::DiskFull | ScheduleError::ReservationTooLarge => {
            FetchFailure::ResourceExhausted
        }
    }
}

fn fetch_failure(error: &RemoteError) -> FetchFailure {
    match error {
        RemoteError::NeedsSignIn => FetchFailure::NeedsSignIn,
        RemoteError::Transport
        | RemoteError::RateLimited { .. }
        | RemoteError::SearchIncomplete => FetchFailure::Offline,
        RemoteError::RemoteContentUnavailable => FetchFailure::Missing,
        RemoteError::PermissionDenied
        | RemoteError::ReadOnly
        | RemoteError::StorageSetupRequired => FetchFailure::PermissionDenied,
        RemoteError::Cancelled => FetchFailure::Cancelled,
        RemoteError::UnsupportedFormat
        | RemoteError::Rejected { .. }
        | RemoteError::InvalidResponse
        | RemoteError::SourceChanged => FetchFailure::InvalidRequest,
    }
}

// ---------------------------------------------------------------------------
// FETCH_PLACEHOLDERS: registry-driven population
// ---------------------------------------------------------------------------

async fn serve_placeholders<R: RemoteOps, H: PumpHost<R>>(
    host: &H,
    connection: &Arc<CfConnection>,
    request: PlaceholdersRequest,
) {
    let PlaceholdersRequest { ack, normalized_path, pattern } = request;
    let components: Vec<String> = std::path::Path::new(&normalized_path)
        .components()
        .filter(|component| !component.as_os_str().is_empty())
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    let parent = if components.is_empty() {
        None // the sync root directory itself
    } else {
        match host.resolve(&components).await {
            Some(item) => Some(item),
            None => {
                let _ = connection.fail_placeholders(ack, FetchFailure::InvalidRequest);
                return;
            }
        }
    };
    let Some(children) = host.children(parent).await else {
        let _ = connection.fail_placeholders(ack, FetchFailure::Internal);
        return;
    };
    let mut entries: Vec<PlaceholderCreate> = Vec::new();
    for child in children {
        if let Some(pattern) = &pattern {
            if !pattern_matches(pattern, &child.name) {
                continue;
            }
        }
        let identity = if child.is_directory {
            PlaceholderIdentity::directory(host.workspace(), child.item_id)
        } else {
            let Some(version) = child.version else {
                // A file without a content version cannot become a
                // placeholder; skip it rather than fabricate content.
                continue;
            };
            PlaceholderIdentity::file(host.workspace(), child.item_id, version)
        };
        entries.push(PlaceholderCreate {
            name: child.name,
            metadata: MetadataSpec {
                size: child.size,
                creation_time_100ns: child.modified_at_100ns,
                last_write_time_100ns: child.modified_at_100ns,
                attributes: if child.is_directory { 0x10 } else { 0x20 },
            },
            identity,
            mark_in_sync: true,
        });
        if entries.len() >= 1000 {
            break;
        }
    }
    let total = entries.len();
    match connection.complete_placeholders(ack, total, &entries) {
        Ok(outcomes) => {
            // Per-entry results are reconciled, never assumed: an existing
            // path is left for the ordinary reconciliation path.
            for outcome in outcomes {
                match outcome.outcome {
                    PlaceholderRequestOutcome::Created { .. }
                    | PlaceholderRequestOutcome::AlreadyExists { .. } => {}
                    PlaceholderRequestOutcome::Failed { .. } => {
                        tracing::warn!("placeholder creation failed for one entry");
                    }
                }
            }
        }
        Err(_) => {
            let _ = connection.fail_placeholders(ack, FetchFailure::Internal);
        }
    }
}

/// Minimal `*` / `?` matching for the OS-provided search pattern.
fn pattern_matches(pattern: &str, name: &str) -> bool {
    fn matches(pattern: &[char], name: &[char]) -> bool {
        match (pattern.split_first(), name.split_first()) {
            (None, None) => true,
            (Some(('*', rest)), _) => (0..=name.len()).any(|skip| matches(rest, &name[skip..])),
            (Some(('?', rest)), Some((_, name_rest))) => matches(rest, name_rest),
            (Some((p, pattern_rest)), Some((n, name_rest))) if p == n => {
                matches(pattern_rest, name_rest)
            }
            _ => false,
        }
    }
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    matches(&pattern, &name)
}

// ---------------------------------------------------------------------------
// Local-change notifications (persist before acknowledging)
// ---------------------------------------------------------------------------

async fn handle_rename<R: RemoteOps, H: PumpHost<R>>(
    host: &H,
    connection: &Arc<CfConnection>,
    rename: RenameNotification,
) {
    let RenameNotification {
        ack,
        normalized_path,
        target_path,
        source_in_scope,
        target_in_scope,
        ..
    } = rename;

    // Provider-applied renames echo through this channel too; the durable
    // echo filter absorbs them inside `observe`, so persisting the raw
    // observation is always correct here.
    if source_in_scope && target_in_scope {
        host.observe(vec![RawObservation {
            relative_path: std::path::PathBuf::from(&target_path),
            action: WatchAction::RenamedTo,
        }])
        .await;
    } else if source_in_scope && !target_in_scope {
        // Moved out of the namespace: the item left this drive.
        host.observe(vec![RawObservation {
            relative_path: std::path::PathBuf::from(&normalized_path),
            action: WatchAction::Removed,
        }])
        .await;
    } else if !source_in_scope && target_in_scope {
        // Moved in: the watcher observes the new path as a create.
        host.observe(vec![RawObservation {
            relative_path: std::path::PathBuf::from(&target_path),
            action: WatchAction::Added,
        }])
        .await;
    }
    // Acknowledge only after the durable queue/persistence above returned.
    let _ = connection.ack_rename(ack, TransferStatus::Success);
}

async fn handle_delete<R: RemoteOps, H: PumpHost<R>>(
    host: &H,
    connection: &Arc<CfConnection>,
    delete: DeleteNotification,
) {
    let DeleteNotification { ack, normalized_path, is_undelete, .. } = delete;
    if is_undelete {
        // The user restored the entry; the ordinary observation path handles
        // the reappearance.
        host.observe(vec![RawObservation {
            relative_path: std::path::PathBuf::from(&normalized_path),
            action: WatchAction::Added,
        }])
        .await;
        let _ = connection.ack_delete(ack, TransferStatus::Success);
        return;
    }

    // A delete of locally dirty content must not lose uncommitted work: the
    // notification precedes the OS operation, so the bytes are preserved
    // first. When preservation is impossible the delete is vetoed truthfully
    // and the file keeps its data.
    let components: Vec<String> = std::path::Path::new(&normalized_path)
        .components()
        .filter(|component| !component.as_os_str().is_empty())
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    if let Some(item_id) = host.resolve(&components).await {
        if host.is_dirty(item_id).await
            && host.preserve_dirty(std::path::Path::new(&normalized_path)).await.is_err()
        {
            let _ = connection
                .ack_delete(ack, TransferStatus::Failed(FetchFailure::ResourceExhausted));
            return;
        }
    }
    host.observe(vec![RawObservation {
        relative_path: std::path::PathBuf::from(&normalized_path),
        action: WatchAction::Removed,
    }])
    .await;
    let _ = connection.ack_delete(ack, TransferStatus::Success);
}

async fn handle_completion<R: RemoteOps, H: PumpHost<R>>(host: &H, completion: CompletionEvent) {
    match completion {
        // Rename completions are post-facto; the notification already queued
        // the durable observation.
        CompletionEvent::Rename(_) => {}
        CompletionEvent::Delete(delete) => {
            if !delete.deleted {
                // The delete was abandoned: every queued delete intent whose
                // item still exists locally is voided instead of publishing a
                // tombstone for a file that was never removed.
                host.void_delete_intents_for_present_items().await;
            }
        }
    }
}
