//! Provider-wide bounded scheduling for transfer work.
//!
//! One global scheduler per provider process bounds concurrency (4 range reads
//! with 1 slot reserved for foreground hydration, 2 uploads, 8 metadata
//! requests), orders admission by work-class priority with round-robin fairness
//! across drives, and exposes RAII admission for reads, uploads, metadata,
//! transfer-buffer memory and capture staging. Resource limits are global:
//! they are never multiplied by the number of connections.
//!
//! Two distinct layers, never conflated:
//! - **Permits** ([`ReadPermit`], [`UploadPermit`], [`MetadataPermit`]) bound
//!   concurrent operations. Acquire one around each hydration read, upload or
//!   metadata call; dropping it releases the slot.
//! - **Bytes** are paced and counted by the shared
//!   [`hfdrive_hf::wire_budget::WireBudget`] at the actual transport
//!   boundaries (native HF bodies and Xet CAS/dedup/range wire bytes are
//!   gated inside `hfdrive-hf`; the S3 adapter attaches explicitly through
//!   `WireBudget::gate_write`/`gate_read`/`gate_stream`). Byte reservations
//!   ([`ByteReservation`]) bound buffered memory and staging, and survive live
//!   budget resizes.
//!
//! Pause/metered/offline policy is explicit and never loses work: admission
//! fails with a distinct [`ScheduleError`] and the caller keeps its durable
//! intent queued for retry. User-blocking reads (blocking hydration, directory
//! metadata) keep working while paused or on metered networks (the metered
//! choice is the caller's `background_allowed` flag); background reads/pins
//! and all mutation scheduling stop. Staging admission is local work and is
//! bounded by the staging budget — the capture's own bytes plus the durable
//! occupancy its retained snapshots already hold — and the staging volume's
//! free space; it never reclaims a pending snapshot to make room. Admission
//! is **one serialized critical section per capture**
//! ([`Scheduler::staging_admission`]): the retained-occupancy sample, the
//! staging reservation and the capture's completion all run while that
//! section is held, so a second capture can never sample occupancy before the
//! first snapshot is `Ready` (nor admit against a pre-capture zero).
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use hfdrive_hf::RangeCache;
use hfdrive_hf::wire_budget::{ByteBudget, ByteReservation, WireBudget};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Work classes in strict priority order (0 = highest). The order is the
/// scheduling contract: blocking hydration first, then directory metadata,
/// local edits/publication, explicit offline pins, and background scans last.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum WorkClass {
    /// User-blocking content hydration (opening/reading a placeholder).
    BlockingHydration = 0,
    /// Directory placeholder population and metadata fetch.
    DirectoryMetadata = 1,
    /// Local edits and their publication work.
    LocalEdit = 2,
    /// Explicit "keep offline" pin downloads.
    OfflinePin = 3,
    /// Background scans and reconciliation.
    BackgroundScan = 4,
}

impl WorkClass {
    /// Priority value; lower schedules first.
    pub fn priority(self) -> u8 {
        self as u8
    }

    fn is_foreground_hydration(self) -> bool {
        matches!(self, Self::BlockingHydration)
    }

    /// Classes that serve user-blocking browsing and survive pause/metered
    /// restrictions.
    fn is_user_blocking(self) -> bool {
        matches!(self, Self::BlockingHydration | Self::DirectoryMetadata)
    }
}

/// Network posture as observed/selected by the provider. `Metered` carries the
/// explicit metered-use choice: `background_allowed` is `true` only after the
/// user consented to metered background transfers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkState {
    Online,
    Metered { background_allowed: bool },
    Offline,
}

impl Default for NetworkState {
    fn default() -> Self {
        Self::Online
    }
}

/// Explicit admission failures. None of these drop work: the caller retains
/// its durable intent and retries after the named condition clears.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ScheduleError {
    /// The bounded admission queue is full.
    #[error("scheduler admission queue is full")]
    Busy,
    /// The wait was cancelled before a slot was granted.
    #[error("scheduler admission was cancelled")]
    Cancelled,
    /// Mutations and background work are paused.
    #[error("this work class is paused")]
    Paused,
    /// The network is offline.
    #[error("the network is offline")]
    Offline,
    /// The network is metered and metered background use was not consented.
    #[error("metered background use is not allowed")]
    Metered,
    /// Free space would drop below the configured floor.
    #[error("admitting this work would violate the free-space floor")]
    DiskFull,
    /// The requested byte reservation exceeds the whole budget.
    #[error("reservation exceeds the configured budget")]
    ReservationTooLarge,
}

/// Scheduler configuration. The defaults are the Step 7 contract values.
#[derive(Clone, Debug)]
pub struct SchedulerConfig {
    /// Global concurrent range reads.
    pub read_concurrency: usize,
    /// Read slots reserved for [`WorkClass::BlockingHydration`] (background
    /// reads can hold at most `read_concurrency - foreground_read_reservation`).
    pub foreground_read_reservation: usize,
    /// Global concurrent uploads.
    pub upload_concurrency: usize,
    /// Global concurrent metadata requests.
    pub metadata_concurrency: usize,
    /// Bounded admission queue depth per work class.
    pub queue_depth_per_class: usize,
    /// Transfer-buffer byte budget (RAII reservations).
    pub transfer_memory_bytes: u64,
    /// Persistent range-cache byte budget.
    pub range_cache_bytes: u64,
    /// Capture-staging byte budget.
    pub staging_admission_bytes: u64,
    /// Free-space floor retained on the staging volume.
    pub minimum_free_bytes: u64,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            read_concurrency: 4,
            foreground_read_reservation: 1,
            upload_concurrency: 2,
            metadata_concurrency: 8,
            queue_depth_per_class: 128,
            transfer_memory_bytes: 256 * 1024 * 1024,
            range_cache_bytes: 512 * 1024 * 1024,
            staging_admission_bytes: 10 * 1024 * 1024 * 1024,
            minimum_free_bytes: 1024 * 1024 * 1024,
        }
    }
}

/// Free-space observation for staging admission. Supplied by the parent from
/// the Windows volume APIs for the **staging** path being admitted — never the
/// sync root; `None` means the system cannot report free space (budget-only
/// admission then applies and the provider reports the unknown honestly).
pub trait FreeSpaceProbe: Send + Sync {
    fn available_bytes(&self, staging_path: &Path) -> Option<u64>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResourceKind {
    Read,
    Upload,
    Metadata,
}

#[derive(Debug, Default)]
struct PolicyState {
    paused: bool,
    network: NetworkState,
}

impl PolicyState {
    fn admit(&self, resource: ResourceKind, class: WorkClass) -> Result<(), ScheduleError> {
        match resource {
            ResourceKind::Upload => {
                // All mutation scheduling stops while paused; uploads are
                // background work on metered networks without consent.
                if self.paused {
                    return Err(ScheduleError::Paused);
                }
                match self.network {
                    NetworkState::Online => Ok(()),
                    NetworkState::Offline => Err(ScheduleError::Offline),
                    NetworkState::Metered { background_allowed: true } => Ok(()),
                    NetworkState::Metered { background_allowed: false } => Err(ScheduleError::Metered),
                }
            }
            ResourceKind::Read | ResourceKind::Metadata => {
                if self.paused && !class.is_user_blocking() {
                    return Err(ScheduleError::Paused);
                }
                match self.network {
                    NetworkState::Online => Ok(()),
                    NetworkState::Offline => Err(ScheduleError::Offline),
                    NetworkState::Metered { background_allowed: true } => Ok(()),
                    NetworkState::Metered { background_allowed: false } if class.is_user_blocking() => Ok(()),
                    NetworkState::Metered { background_allowed: false } => Err(ScheduleError::Metered),
                }
            }
        }
    }
}

/// One admission wait. `outcome` and `dropped` share one lock so a grant and a
/// drop of the same wait can never both take effect (the classic leak race).
#[derive(Debug)]
struct EntryState {
    outcome: Option<Result<(), ScheduleError>>,
    dropped: bool,
}

#[derive(Debug)]
struct QueueEntry {
    seq: u64,
    class: WorkClass,
    drive: Uuid,
    waker: Mutex<Option<Waker>>,
    state: Mutex<EntryState>,
}

impl QueueEntry {
    /// Complete a grant or refusal. Returns `false` when the waiter is already
    /// gone; the granter must then roll the granted slot back.
    fn finish(&self, outcome: Result<(), ScheduleError>) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.outcome.is_some() {
            return true;
        }
        if state.dropped {
            return false;
        }
        state.outcome = Some(outcome);
        drop(state);
        if let Some(waker) = self.waker.lock().unwrap_or_else(|e| e.into_inner()).take() {
            waker.wake();
        }
        true
    }

    /// Mark the wait abandoned. Returns `true` when a grant already landed and
    /// must be rolled back by the caller.
    fn abandon(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.dropped = true;
        let granted = matches!(state.outcome, Some(Ok(())));
        state.outcome = Some(Err(ScheduleError::Cancelled));
        granted
    }
}

#[derive(Debug)]
struct GateState {
    active: usize,
    active_background: usize,
    queued: [usize; 5],
    queue: VecDeque<Arc<QueueEntry>>,
    /// Round-robin fairness: last grant stamp per drive.
    drive_stamps: Vec<(Uuid, u64)>,
    stamp: u64,
    next_seq: u64,
}

#[derive(Debug)]
struct GateInner {
    capacity: usize,
    background_limit: usize,
    queue_depth_per_class: usize,
    resource: ResourceKind,
    policy: Arc<Mutex<PolicyState>>,
    state: Mutex<GateState>,
}

#[derive(Debug)]
struct Permit {
    gate: Arc<GateInner>,
    class: WorkClass,
    drive: Uuid,
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.gate.release(self.class);
    }
}

/// RAII range-read slot. Released on drop.
#[derive(Debug)]
pub struct ReadPermit(Permit);
/// RAII upload slot. Released on drop.
#[derive(Debug)]
pub struct UploadPermit(Permit);
/// RAII metadata slot. Released on drop.
#[derive(Debug)]
pub struct MetadataPermit(Permit);

macro_rules! permit_accessors {
    ($name:ident) => {
        impl $name {
            /// The work class this permit was admitted for.
            pub fn class(&self) -> WorkClass {
                self.0.class
            }
            /// The drive (connection id) this permit was admitted for.
            pub fn drive(&self) -> Uuid {
                self.0.drive
            }
        }
    };
}
permit_accessors!(ReadPermit);
permit_accessors!(UploadPermit);
permit_accessors!(MetadataPermit);

impl GateInner {
    fn new(
        capacity: usize,
        foreground_reservation: usize,
        queue_depth_per_class: usize,
        resource: ResourceKind,
        policy: Arc<Mutex<PolicyState>>,
    ) -> Arc<Self> {
        let capacity = capacity.max(1);
        let reservation = foreground_reservation.min(capacity);
        Arc::new(Self {
            capacity,
            background_limit: capacity - reservation,
            queue_depth_per_class: queue_depth_per_class.max(1),
            resource,
            policy,
            state: Mutex::new(GateState {
                active: 0,
                active_background: 0,
                queued: [0; 5],
                queue: VecDeque::new(),
                drive_stamps: Vec::new(),
                stamp: 0,
                next_seq: 0,
            }),
        })
    }

    fn try_grant(&self, state: &mut GateState, class: WorkClass, drive: Uuid) -> bool {
        if state.active >= self.capacity {
            return false;
        }
        if !class.is_foreground_hydration() && state.active_background >= self.background_limit {
            return false;
        }
        state.active += 1;
        if !class.is_foreground_hydration() {
            state.active_background += 1;
        }
        state.stamp += 1;
        let stamp = state.stamp;
        match state.drive_stamps.iter_mut().find(|(known, _)| *known == drive) {
            Some(entry) => entry.1 = stamp,
            None => state.drive_stamps.push((drive, stamp)),
        }
        true
    }

    /// Return one held slot and schedule the next grants.
    fn release(&self, class: WorkClass) {
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.active -= 1;
            if !class.is_foreground_hydration() {
                state.active_background -= 1;
            }
        }
        pump(self);
    }

    fn drive_stamp(state: &GateState, drive: &Uuid) -> u64 {
        state.drive_stamps.iter().find(|(known, _)| known == drive).map(|(_, stamp)| *stamp).unwrap_or(0)
    }
}

/// Grant queued entries: lowest priority class first, ties broken by the
/// least-recently-served drive (round-robin fairness), then by arrival order.
/// Abandoned and completed entries are pruned here. Policy is re-checked at
/// grant time so a pause/metered/offline change is never overridden by a stale
/// wait; a refusal wakes the waiter with the explicit error.
fn pump(gate: &GateInner) {
    loop {
        let mut state = gate.state.lock().unwrap_or_else(|e| e.into_inner());
        // Prune abandoned/completed waits without holding the borrow across
        // counter updates.
        let mut pruned = Vec::new();
        state.queue.retain(|entry| {
            let entry_state = entry.state.lock().unwrap_or_else(|e| e.into_inner());
            let live = entry_state.outcome.is_none() && !entry_state.dropped;
            if !live {
                pruned.push(entry.class);
            }
            live
        });
        for class in pruned {
            state.queued[class as usize] = state.queued[class as usize].saturating_sub(1);
        }

        if state.active >= gate.capacity {
            return;
        }
        let mut best: Option<usize> = None;
        let mut best_key: Option<(u8, u64, u64)> = None;
        for (index, entry) in state.queue.iter().enumerate() {
            if !entry.class.is_foreground_hydration() && state.active_background >= gate.background_limit {
                continue;
            }
            let key = (entry.class.priority(), GateInner::drive_stamp(&state, &entry.drive), entry.seq);
            if best_key.is_none_or(|current| key < current) {
                best = Some(index);
                best_key = Some(key);
            }
        }
        let Some(index) = best else { return };
        let entry = state.queue.remove(index).expect("index was selected from the queue");
        state.queued[entry.class as usize] = state.queued[entry.class as usize].saturating_sub(1);
        let policy = gate.policy.lock().unwrap_or_else(|e| e.into_inner()).admit(gate.resource, entry.class);
        match policy {
            Ok(()) => {
                gate.try_grant(&mut state, entry.class, entry.drive);
                if !entry.finish(Ok(())) {
                    // The waiter left between dequeue and grant: give the slot
                    // straight back (without recursing into pump).
                    state.active -= 1;
                    if !entry.class.is_foreground_hydration() {
                        state.active_background -= 1;
                    }
                }
            }
            Err(error) => {
                entry.finish(Err(error));
            }
        }
    }
}

/// Future returned by the gate's `acquire`; safe to drop (the queue entry is
/// pruned and any landed grant is rolled back).
struct AcquireFuture {
    gate: Arc<GateInner>,
    entry: Option<Arc<QueueEntry>>,
}

impl Future for AcquireFuture {
    type Output = Result<Permit, ScheduleError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let gate = this.gate.clone();
        let entry = match this.entry.as_ref() {
            Some(entry) => entry.clone(),
            None => return Poll::Ready(Err(ScheduleError::Cancelled)),
        };
        let outcome = entry.state.lock().unwrap_or_else(|e| e.into_inner()).outcome;
        match outcome {
            Some(Ok(())) => {
                this.entry = None;
                Poll::Ready(Ok(Permit { gate, class: entry.class, drive: entry.drive }))
            }
            Some(Err(error)) => {
                this.entry = None;
                Poll::Ready(Err(error))
            }
            None => {
                *entry.waker.lock().unwrap_or_else(|e| e.into_inner()) = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl Drop for AcquireFuture {
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take() {
            // A grant that landed while the future was being dropped is rolled
            // back here; without this the slot would leak.
            if entry.abandon() {
                self.gate.release(entry.class);
            } else {
                pump(&self.gate);
            }
        }
    }
}

fn acquire(gate: &Arc<GateInner>, class: WorkClass, drive: Uuid) -> Result<AcquireFuture, ScheduleError> {
    // Policy is checked before queuing so disallowed work fails immediately.
    gate.policy.lock().unwrap_or_else(|e| e.into_inner()).admit(gate.resource, class)?;
    let mut state = gate.state.lock().unwrap_or_else(|e| e.into_inner());
    if gate.try_grant(&mut state, class, drive) {
        drop(state);
        let entry = Arc::new(QueueEntry {
            seq: 0,
            class,
            drive,
            waker: Mutex::new(None),
            state: Mutex::new(EntryState { outcome: Some(Ok(())), dropped: false }),
        });
        return Ok(AcquireFuture { gate: gate.clone(), entry: Some(entry) });
    }
    if state.queued[class as usize] >= gate.queue_depth_per_class {
        return Err(ScheduleError::Busy);
    }
    state.stamp += 1;
    state.next_seq += 1;
    let entry = Arc::new(QueueEntry {
        seq: state.next_seq,
        class,
        drive,
        waker: Mutex::new(None),
        state: Mutex::new(EntryState { outcome: None, dropped: false }),
    });
    state.queued[class as usize] += 1;
    state.queue.push_back(entry.clone());
    drop(state);
    Ok(AcquireFuture { gate: gate.clone(), entry: Some(entry) })
}

struct LimitsState {
    minimum_free_bytes: u64,
    free_space_probe: Option<Arc<dyn FreeSpaceProbe>>,
}

/// Snapshot of scheduler occupancy for status/diagnostics. All numbers are
/// global (never per-connection multiplication).
#[derive(Clone, Debug, Default)]
pub struct SchedulerStats {
    pub read_active: usize,
    pub upload_active: usize,
    pub metadata_active: usize,
    /// Queued admission waits per [`WorkClass`] (index = `priority()`).
    pub queued_by_class: [usize; 5],
    pub transfer_memory_used_bytes: u64,
    pub range_cache_used_bytes: u64,
    pub staging_used_bytes: u64,
    pub paused: bool,
    pub network: NetworkState,
}

/// Staging-admission failure: the caller's retained-occupancy sample failed
/// (nothing was admitted) or admission refused the capture. Pending snapshots
/// are never reclaimed to change either outcome.
#[derive(Debug, thiserror::Error)]
pub enum StagingAdmissionError {
    /// Durable state could not report the retained occupancy; the section is
    /// released and nothing is admitted.
    #[error("durable state could not report retained staging occupancy: {0}")]
    RetainedOccupancy(#[source] hfdrive_state::StateError),
    /// Staging admission refused the capture.
    #[error(transparent)]
    Refused(#[from] ScheduleError),
}

/// The exclusive occupancy sample + staging reservation of one capture, held
/// across that capture's completion. A [`StagingAdmission`] guard **is** the
/// serialized critical section: while any guard lives, no other capture can
/// take the section, sample retained occupancy or admit. Dropping the guard
/// ends the section and releases the reservation together. The reservation is
/// charged the capture's own bytes **plus** the retained occupancy the sample
/// stood behind, so the section's occupancy never shrinks between the sample
/// and the capture's `Ready` boundary.
pub struct StagingAdmission {
    // Field order is load-bearing: dropping the guard returns the byte
    // reservation **before** releasing the section, so the next capture can
    // never see the previous capture's still-held quota inside its own
    // sampling window.
    reservation: ByteReservation,
    _section: OwnedMutexGuard<()>,
}

impl StagingAdmission {
    /// Reserved bytes: the capture's own bytes plus the retained occupancy
    /// the sample stood behind (the whole occupancy charged by admission).
    pub fn bytes(&self) -> u64 {
        self.reservation.bytes()
    }
}

impl std::fmt::Debug for StagingAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagingAdmission").field("bytes", &self.bytes()).finish()
    }
}

/// The provider-wide scheduler. Cheap to clone; all state is shared.
#[derive(Clone)]
pub struct Scheduler {
    inner: Arc<SchedulerInner>,
}

struct SchedulerInner {
    reads: Arc<GateInner>,
    uploads: Arc<GateInner>,
    metadata: Arc<GateInner>,
    transfer_memory: ByteBudget,
    staging: ByteBudget,
    /// The serialized staging-admission section: one capture at a time samples
    /// retained occupancy and reserves staging, and holds the section until
    /// its capture completes (see [`Scheduler::staging_admission`]).
    staging_admission_section: Arc<AsyncMutex<()>>,
    range_cache: RangeCache,
    budget: WireBudget,
    policy: Arc<Mutex<PolicyState>>,
    limits: Mutex<LimitsState>,
}

impl Scheduler {
    /// A scheduler sharing the process-wide [`WireBudget::global`].
    pub fn new(config: SchedulerConfig) -> Self {
        Self::new_with_budget(config, WireBudget::global())
    }

    /// A scheduler with the provider's shared transfer budget. The budget
    /// installs itself as [`WireBudget::global`] when none is installed yet;
    /// the same instance must also reach `NativeApi`, the Xet session and the
    /// publication adapter (one shared per-direction token bucket).
    pub fn new_with_budget(config: SchedulerConfig, budget: WireBudget) -> Self {
        budget.install_global();
        let policy = Arc::new(Mutex::new(PolicyState::default()));
        let reads = GateInner::new(
            config.read_concurrency,
            config.foreground_read_reservation,
            config.queue_depth_per_class,
            ResourceKind::Read,
            policy.clone(),
        );
        let uploads = GateInner::new(
            config.upload_concurrency,
            0,
            config.queue_depth_per_class,
            ResourceKind::Upload,
            policy.clone(),
        );
        let metadata = GateInner::new(
            config.metadata_concurrency,
            0,
            config.queue_depth_per_class,
            ResourceKind::Metadata,
            policy.clone(),
        );
        Self {
            inner: Arc::new(SchedulerInner {
                reads,
                uploads,
                metadata,
                transfer_memory: ByteBudget::new(config.transfer_memory_bytes),
                staging: ByteBudget::new(config.staging_admission_bytes),
                staging_admission_section: Arc::new(AsyncMutex::new(())),
                range_cache: RangeCache::new(config.range_cache_bytes),
                budget,
                policy,
                limits: Mutex::new(LimitsState {
                    minimum_free_bytes: config.minimum_free_bytes,
                    free_space_probe: None,
                }),
            }),
        }
    }

    /// The shared wire budget (per-direction token buckets + wire/logical
    /// counters). S3 bodies attach explicitly via `gate_write`/`gate_read`/
    /// `gate_stream`; native and Xet wire bytes are gated inside `hfdrive-hf`.
    pub fn wire_budget(&self) -> &WireBudget {
        &self.inner.budget
    }

    /// The shared bounded range cache; serve hydration reads through
    /// `NativeBucketStore::open_range_cached(.., scheduler.range_cache(), ..)`.
    pub fn range_cache(&self) -> &RangeCache {
        &self.inner.range_cache
    }

    /// Live transfer-rate change (`0` = unlimited). Applies to every metered
    /// transport boundary immediately, including current waiters.
    pub fn set_transfer_rates(&self, upload_bytes_per_second: u64, download_bytes_per_second: u64) {
        self.inner.budget.set_rates(upload_bytes_per_second, download_bytes_per_second);
    }

    /// Live memory-limit change. Byte budgets resize in place; held
    /// reservations are never cancelled (shrink blocks new admission until
    /// usage drops), and the range cache evicts only clean cached segments.
    pub fn set_memory_limits(
        &self,
        transfer_memory_bytes: u64,
        range_cache_bytes: u64,
        staging_admission_bytes: u64,
        minimum_free_bytes: u64,
    ) {
        self.inner.transfer_memory.set_capacity(transfer_memory_bytes);
        self.inner.range_cache.set_max_bytes(range_cache_bytes);
        self.inner.staging.set_capacity(staging_admission_bytes);
        self.inner.limits.lock().unwrap_or_else(|e| e.into_inner()).minimum_free_bytes = minimum_free_bytes;
    }

    /// Pause/resume mutation and background scheduling. Pausing never drops
    /// queued intent: affected admissions fail with [`ScheduleError::Paused`]
    /// and the caller retries after [`Scheduler::set_paused`]. Resume is
    /// admission-time only — the caller must revalidate account/resource
    /// capabilities before dispatching resumed work.
    pub fn set_paused(&self, paused: bool) {
        self.inner.policy.lock().unwrap_or_else(|e| e.into_inner()).paused = paused;
        pump(&self.inner.reads);
        pump(&self.inner.uploads);
        pump(&self.inner.metadata);
    }

    /// Live network posture (online / metered with explicit consent flag /
    /// offline). See [`NetworkState`].
    pub fn set_network_state(&self, network: NetworkState) {
        self.inner.policy.lock().unwrap_or_else(|e| e.into_inner()).network = network;
        pump(&self.inner.reads);
        pump(&self.inner.uploads);
        pump(&self.inner.metadata);
    }

    /// Free-space observation used by staging admission
    /// ([`Scheduler::staging_admission`]).
    pub fn set_free_space_probe(&self, probe: Option<Arc<dyn FreeSpaceProbe>>) {
        self.inner.limits.lock().unwrap_or_else(|e| e.into_inner()).free_space_probe = probe;
    }

    /// Acquire one global range-read slot (cancellation-aware, bounded queue).
    pub async fn acquire_read(
        &self,
        class: WorkClass,
        drive: Uuid,
        cancel: &CancellationToken,
    ) -> Result<ReadPermit, ScheduleError> {
        let acquire = acquire(&self.inner.reads, class, drive)?;
        tokio::select! {
            _ = cancel.cancelled() => Err(ScheduleError::Cancelled),
            result = acquire => result.map(ReadPermit),
        }
    }

    /// Acquire one global upload slot (cancellation-aware, bounded queue).
    pub async fn acquire_upload(
        &self,
        class: WorkClass,
        drive: Uuid,
        cancel: &CancellationToken,
    ) -> Result<UploadPermit, ScheduleError> {
        let acquire = acquire(&self.inner.uploads, class, drive)?;
        tokio::select! {
            _ = cancel.cancelled() => Err(ScheduleError::Cancelled),
            result = acquire => result.map(UploadPermit),
        }
    }

    /// Acquire one global metadata slot (cancellation-aware, bounded queue).
    pub async fn acquire_metadata(
        &self,
        class: WorkClass,
        drive: Uuid,
        cancel: &CancellationToken,
    ) -> Result<MetadataPermit, ScheduleError> {
        let acquire = acquire(&self.inner.metadata, class, drive)?;
        tokio::select! {
            _ = cancel.cancelled() => Err(ScheduleError::Cancelled),
            result = acquire => result.map(MetadataPermit),
        }
    }

    /// Reserve transfer-buffer bytes (RAII; returned on drop). Unbounded wait
    /// is never taken silently: waits are cancellation-aware and the budget is
    /// live-resizable.
    pub async fn reserve_transfer_memory(
        &self,
        class: WorkClass,
        bytes: u64,
        cancel: &CancellationToken,
    ) -> Result<ByteReservation, ScheduleError> {
        let _ = class;
        self.inner.transfer_memory.reserve(bytes, cancel).await.map_err(map_budget_error)
    }

    /// Inner step of [`Scheduler::staging_admission`]: reserves the capture's
    /// own `bytes` **plus** `retained_bytes`, the occupancy the `Capturing`/
    /// `Ready` snapshots the account still retains already hold. The caller
    /// samples `retained_bytes` from durable state inside the admission
    /// section on every capture, so the occupancy survives a restart where no
    /// transient reservation does. Pending snapshots are never reclaimed to
    /// satisfy admission: an occupancy that cannot fit is refused outright
    /// ([`ScheduleError::ReservationTooLarge`]) and the caller keeps its
    /// durable intent queued.
    ///
    /// The free-space floor (`available >= bytes + minimum_free_bytes`) is
    /// checked against the **staging** volume — never the sync root; unknown
    /// free space admits on budget alone and is reported as unknown by the
    /// provider. Staging is local work: pause/metered/offline never block it
    /// (captures become queued durable intent).
    async fn reserve_staging(
        &self,
        class: WorkClass,
        drive: Uuid,
        staging_path: &Path,
        bytes: u64,
        retained_bytes: u64,
        cancel: &CancellationToken,
    ) -> Result<ByteReservation, ScheduleError> {
        let _ = (class, drive);
        let (minimum_free, available) = {
            let limits = self.inner.limits.lock().unwrap_or_else(|e| e.into_inner());
            let available = limits.free_space_probe.as_ref().and_then(|probe| probe.available_bytes(staging_path));
            (limits.minimum_free_bytes, available)
        };
        if let Some(available) = available
            && available < bytes.saturating_add(minimum_free)
        {
            return Err(ScheduleError::DiskFull);
        }
        // The whole occupancy is charged while the capture stands, so a
        // concurrent capture cannot admit past the retained snapshots either.
        let occupancy = bytes.saturating_add(retained_bytes);
        if occupancy > self.inner.staging.capacity_bytes() {
            return Err(ScheduleError::ReservationTooLarge);
        }
        self.inner.staging.reserve(occupancy, cancel).await.map_err(map_budget_error)
    }

    /// The serialized staging-admission critical section for one capture:
    /// enter the section, **sample** the durable retained occupancy inside it
    /// (`retained` is a lazy future and is first polled here, never before),
    /// reserve the capture's own bytes plus that occupancy, and return a
    /// [`StagingAdmission`] guard the caller holds across its capture
    /// completion. The section is released only when the guard drops — after
    /// the caller's completion side effects — so a second capture can never
    /// sample occupancy before the first snapshot is `Ready` (nor admit
    /// against a stale pre-capture zero).
    ///
    /// Pending snapshots are never reclaimed here: admission is decided
    /// against the sampled occupancy exactly as durable state reports it, and
    /// a refused capture keeps its queued intent. A failed sample releases the
    /// section and admits nothing.
    pub async fn staging_admission<R>(
        &self,
        class: WorkClass,
        drive: Uuid,
        staging_path: &Path,
        bytes: u64,
        retained: R,
        cancel: &CancellationToken,
    ) -> Result<StagingAdmission, StagingAdmissionError>
    where
        R: Future<Output = Result<u64, hfdrive_state::StateError>> + Send,
    {
        // `lock_owned` yields a 'static guard: it outlives this call by
        // design (the caller holds it until its capture completes).
        let section = self.inner.staging_admission_section.clone().lock_owned().await;
        let retained_bytes = retained.await.map_err(StagingAdmissionError::RetainedOccupancy)?;
        let reservation = self
            .reserve_staging(class, drive, staging_path, bytes, retained_bytes, cancel)
            .await?;
        Ok(StagingAdmission { reservation, _section: section })
    }

    /// Occupancy snapshot for status/diagnostics.
    pub fn stats(&self) -> SchedulerStats {
        let (read_active, upload_active, metadata_active, queued_by_class) = {
            let reads = self.inner.reads.state.lock().unwrap_or_else(|e| e.into_inner());
            let uploads = self.inner.uploads.state.lock().unwrap_or_else(|e| e.into_inner());
            let metadata = self.inner.metadata.state.lock().unwrap_or_else(|e| e.into_inner());
            let queued = std::array::from_fn(|index| {
                reads.queued[index] + uploads.queued[index] + metadata.queued[index]
            });
            (reads.active, uploads.active, metadata.active, queued)
        };
        let policy = self.inner.policy.lock().unwrap_or_else(|e| e.into_inner());
        SchedulerStats {
            read_active,
            upload_active,
            metadata_active,
            queued_by_class,
            transfer_memory_used_bytes: self.inner.transfer_memory.used_bytes(),
            range_cache_used_bytes: self.inner.range_cache.used_bytes(),
            staging_used_bytes: self.inner.staging.used_bytes(),
            paused: policy.paused,
            network: policy.network,
        }
    }
}

fn map_budget_error(error: hfdrive_hf::wire_budget::BudgetError) -> ScheduleError {
    match error {
        hfdrive_hf::wire_budget::BudgetError::Cancelled => ScheduleError::Cancelled,
        hfdrive_hf::wire_budget::BudgetError::TooLarge => ScheduleError::ReservationTooLarge,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn scheduler(reads: usize, reservation: usize) -> Scheduler {
        Scheduler::new(SchedulerConfig {
            read_concurrency: reads,
            foreground_read_reservation: reservation,
            ..SchedulerConfig::default()
        })
    }

    fn drive(index: u8) -> Uuid {
        Uuid::from_u128(index as u128)
    }

    fn poll_pending<F: Future>(future: std::pin::Pin<&mut F>) {
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        assert!(future.poll(&mut context).is_pending());
    }

    #[tokio::test]
    async fn stats_aggregate_queued_work_across_all_resource_gates() {
        let scheduler = Scheduler::new(SchedulerConfig {
            read_concurrency: 1, foreground_read_reservation: 0,
            upload_concurrency: 1, metadata_concurrency: 1,
            ..SchedulerConfig::default()
        });
        let cancel = CancellationToken::new();
        let read = scheduler.acquire_read(WorkClass::LocalEdit, drive(1), &cancel).await.unwrap();
        let upload = scheduler.acquire_upload(WorkClass::LocalEdit, drive(1), &cancel).await.unwrap();
        let metadata = scheduler.acquire_metadata(WorkClass::DirectoryMetadata, drive(1), &cancel).await.unwrap();
        let queued_read = scheduler.acquire_read(WorkClass::LocalEdit, drive(2), &cancel);
        let queued_upload = scheduler.acquire_upload(WorkClass::LocalEdit, drive(2), &cancel);
        let queued_metadata = scheduler.acquire_metadata(WorkClass::DirectoryMetadata, drive(2), &cancel);
        tokio::pin!(queued_read, queued_upload, queued_metadata);
        poll_pending(queued_read.as_mut());
        poll_pending(queued_upload.as_mut());
        poll_pending(queued_metadata.as_mut());
        let stats = scheduler.stats();
        assert_eq!((stats.read_active, stats.upload_active, stats.metadata_active), (1, 1, 1));
        let mut expected = [0; 5];
        expected[WorkClass::LocalEdit as usize] = 2;
        expected[WorkClass::DirectoryMetadata as usize] = 1;
        assert_eq!(stats.queued_by_class, expected);
        cancel.cancel();
        assert_eq!(queued_read.await.unwrap_err(), ScheduleError::Cancelled);
        assert_eq!(queued_upload.await.unwrap_err(), ScheduleError::Cancelled);
        assert_eq!(queued_metadata.await.unwrap_err(), ScheduleError::Cancelled);
        assert_eq!(scheduler.stats().queued_by_class, [0; 5]);
        drop((read, upload, metadata));
        let stats = scheduler.stats();
        assert_eq!((stats.read_active, stats.upload_active, stats.metadata_active), (0, 0, 0));
    }

    #[tokio::test]
    async fn permits_are_raii_and_capacity_is_global() {
        let scheduler = scheduler(2, 1);
        let first = scheduler.acquire_read(WorkClass::BlockingHydration, drive(1), &CancellationToken::new()).await.unwrap();
        let second = scheduler.acquire_read(WorkClass::BlockingHydration, drive(1), &CancellationToken::new()).await.unwrap();
        let cancel = CancellationToken::new();
        let queued = scheduler.acquire_read(WorkClass::BlockingHydration, drive(1), &cancel);
        tokio::pin!(queued);
        assert!(tokio::time::timeout(Duration::from_millis(30), &mut queued).await.is_err(), "capacity 2 admits no third read");
        drop(first);
        assert!(queued.await.is_ok());
        drop(second);
    }

    #[tokio::test]
    async fn one_read_slot_is_reserved_for_foreground_hydration() {
        let scheduler = scheduler(4, 1);
        let token = CancellationToken::new();
        // Three background reads may run; the 4th slot stays reserved.
        let mut held = Vec::new();
        for index in 0..3 {
            held.push(scheduler.acquire_read(WorkClass::OfflinePin, drive(index), &token).await.unwrap());
        }
        let blocked = scheduler.acquire_read(WorkClass::BackgroundScan, drive(9), &token);
        tokio::pin!(blocked);
        assert!(tokio::time::timeout(Duration::from_millis(30), &mut blocked).await.is_err());
        // Foreground hydration takes the reserved slot immediately.
        let foreground = tokio::time::timeout(
            Duration::from_secs(5),
            scheduler.acquire_read(WorkClass::BlockingHydration, drive(8), &token),
        )
        .await
        .expect("reserved slot admits foreground hydration")
        .unwrap();
        drop(foreground);
        drop(held);
    }

    #[tokio::test]
    async fn grants_follow_class_priority() {
        let scheduler = Scheduler::new(SchedulerConfig {
            read_concurrency: 1,
            foreground_read_reservation: 0,
            queue_depth_per_class: 16,
            ..SchedulerConfig::default()
        });
        let token = CancellationToken::new();
        let held = scheduler.acquire_read(WorkClass::BackgroundScan, drive(1), &token).await.unwrap();
        let scan = scheduler.acquire_read(WorkClass::BackgroundScan, drive(1), &token);
        let pin = scheduler.acquire_read(WorkClass::OfflinePin, drive(1), &token);
        let hydration = scheduler.acquire_read(WorkClass::BlockingHydration, drive(1), &token);
        tokio::pin!(scan);
        tokio::pin!(pin);
        tokio::pin!(hydration);
        poll_pending(scan.as_mut());
        poll_pending(pin.as_mut());
        poll_pending(hydration.as_mut());
        drop(held);
        let hydration_permit = hydration.await.expect("highest priority class is granted first");
        // Nothing else was granted: capacity 1 is held by the hydration permit.
        assert!(tokio::time::timeout(Duration::from_millis(30), &mut pin).await.is_err());
        drop(hydration_permit);
    }

    #[tokio::test]
    async fn equal_class_grants_round_robin_across_drives() {
        let scheduler = scheduler(1, 0);
        let token = CancellationToken::new();
        let held = scheduler.acquire_read(WorkClass::LocalEdit, drive(1), &token).await.unwrap();
        let first = scheduler.acquire_read(WorkClass::LocalEdit, drive(1), &token);
        let second = scheduler.acquire_read(WorkClass::LocalEdit, drive(2), &token);
        tokio::pin!(first);
        tokio::pin!(second);
        drop(held);
        let winner = tokio::time::timeout(Duration::from_secs(5), &mut second).await.unwrap().unwrap();
        assert_eq!(winner.drive(), drive(2), "the less-recently-served drive wins the tie");
        drop(winner);
        assert!(first.await.is_ok());
    }

    #[tokio::test]
    async fn bounded_queues_reject_overflow_and_cancellation_leaks_nothing() {
        let scheduler = Scheduler::new(SchedulerConfig {
            read_concurrency: 1,
            foreground_read_reservation: 0,
            queue_depth_per_class: 1,
            ..SchedulerConfig::default()
        });
        let token = CancellationToken::new();
        let held = scheduler.acquire_read(WorkClass::LocalEdit, drive(1), &token).await.unwrap();
        let queued = scheduler.acquire_read(WorkClass::LocalEdit, drive(1), &token);
        tokio::pin!(queued);
        poll_pending(queued.as_mut());
        assert_eq!(
            scheduler.acquire_read(WorkClass::LocalEdit, drive(1), &token).await.unwrap_err(),
            ScheduleError::Busy,
            "per-class queue bound rejects overflow"
        );
        let cancelled = CancellationToken::new();
        let cancellation_scheduler = Scheduler::new(SchedulerConfig {
            read_concurrency: 1,
            foreground_read_reservation: 0,
            ..SchedulerConfig::default()
        });
        let held_metadata = cancellation_scheduler.acquire_read(WorkClass::DirectoryMetadata, drive(4), &token).await.unwrap();
        let doomed = cancellation_scheduler.acquire_read(WorkClass::DirectoryMetadata, drive(3), &cancelled);
        tokio::pin!(doomed);
        cancelled.cancel();
        assert_eq!(doomed.await.unwrap_err(), ScheduleError::Cancelled);
        drop(held_metadata);
        drop(held);
        assert!(queued.await.is_ok(), "cancelled and dropped waits never leak slots");
    }

    #[tokio::test]
    async fn dropped_waiters_never_leak_slots() {
        let scheduler = scheduler(1, 0);
        let token = CancellationToken::new();
        let held = scheduler.acquire_read(WorkClass::LocalEdit, drive(1), &token).await.unwrap();
        // Dropped while queued: capacity stays accounted.
        for _ in 0..8 {
            let doomed = scheduler.acquire_read(WorkClass::LocalEdit, drive(1), &token);
            tokio::pin!(doomed);
            drop(doomed);
        }
        drop(held);
        // The gate fully recovers: two sequential admissions succeed.
        let first = tokio::time::timeout(Duration::from_secs(5), scheduler.acquire_read(WorkClass::LocalEdit, drive(1), &token))
            .await
            .expect("slots recover after dropped waits")
            .unwrap();
        drop(first);
        let second = tokio::time::timeout(Duration::from_secs(5), scheduler.acquire_read(WorkClass::LocalEdit, drive(1), &token))
            .await
            .expect("the gate keeps granting")
            .unwrap();
        drop(second);
    }

    #[tokio::test]
    async fn pause_and_network_policy_are_explicit_and_live() {
        let scheduler = scheduler(4, 1);
        let token = CancellationToken::new();
        scheduler.set_paused(true);
        assert_eq!(
            scheduler.acquire_upload(WorkClass::LocalEdit, drive(1), &token).await.unwrap_err(),
            ScheduleError::Paused
        );
        assert_eq!(
            scheduler.acquire_read(WorkClass::OfflinePin, drive(1), &token).await.unwrap_err(),
            ScheduleError::Paused
        );
        // User-blocking browsing survives pause.
        let browsing = scheduler.acquire_read(WorkClass::BlockingHydration, drive(1), &token).await.unwrap();
        drop(browsing);
        let metadata = scheduler.acquire_metadata(WorkClass::DirectoryMetadata, drive(1), &token).await.unwrap();
        drop(metadata);

        scheduler.set_paused(false);
        scheduler.set_network_state(NetworkState::Metered { background_allowed: false });
        assert_eq!(
            scheduler.acquire_read(WorkClass::OfflinePin, drive(1), &token).await.unwrap_err(),
            ScheduleError::Metered
        );
        assert_eq!(
            scheduler.acquire_upload(WorkClass::LocalEdit, drive(1), &token).await.unwrap_err(),
            ScheduleError::Metered
        );
        // Explicit metered consent unlocks background work.
        scheduler.set_network_state(NetworkState::Metered { background_allowed: true });
        let pin = scheduler.acquire_read(WorkClass::OfflinePin, drive(1), &token).await.unwrap();
        drop(pin);
        scheduler.set_network_state(NetworkState::Offline);
        assert_eq!(
            scheduler.acquire_read(WorkClass::BlockingHydration, drive(1), &token).await.unwrap_err(),
            ScheduleError::Offline
        );
    }

    /// Admits one capture through the serialized staging-admission section,
    /// with the retained occupancy sampled by the given future. Tests use the
    /// public entry (the section, sample, reservation and guard) exactly as
    /// the capture path does.
    async fn admit(
        scheduler: &Scheduler,
        staging: &Path,
        bytes: u64,
        retained: u64,
        token: &CancellationToken,
    ) -> Result<StagingAdmission, StagingAdmissionError> {
        scheduler
            .staging_admission(
                WorkClass::LocalEdit,
                drive(1),
                staging,
                bytes,
                std::future::ready(Ok(retained)),
                token,
            )
            .await
    }

    #[tokio::test]
    async fn byte_budgets_and_free_space_gate_staging() {
        let scheduler = Scheduler::new(SchedulerConfig {
            staging_admission_bytes: 100,
            minimum_free_bytes: 50,
            ..SchedulerConfig::default()
        });
        let token = CancellationToken::new();
        struct Probe {
            available: Option<u64>,
            asked: Mutex<Vec<std::path::PathBuf>>,
        }
        impl FreeSpaceProbe for Probe {
            fn available_bytes(&self, staging_path: &Path) -> Option<u64> {
                self.asked.lock().unwrap().push(staging_path.to_path_buf());
                self.available
            }
        }
        let staging = Path::new("C:\\staging");
        let probe = Arc::new(Probe { available: Some(120), asked: Mutex::new(Vec::new()) });
        scheduler.set_free_space_probe(Some(probe.clone()));
        let error = admit(&scheduler, staging, 80, 0, &token).await.unwrap_err();
        assert!(
            matches!(error, StagingAdmissionError::Refused(ScheduleError::DiskFull)),
            "free-space floor is enforced before the budget, got {error:?}"
        );
        // Free space is asked of the staging path — never a sync root.
        assert_eq!(*probe.asked.lock().unwrap(), vec![staging.to_path_buf()]);
        let reservation = admit(&scheduler, staging, 60, 0, &token).await.unwrap();
        assert_eq!(scheduler.stats().staging_used_bytes, 60);
        drop(reservation);
        // Durable occupancy is charged together with the capture's own bytes:
        // 6 new bytes behind 60 retained bytes hold 66 of the 100-byte budget.
        let retained = admit(&scheduler, staging, 6, 60, &token).await.unwrap();
        assert_eq!(retained.bytes(), 66);
        assert_eq!(scheduler.stats().staging_used_bytes, 66);
        drop(retained);
        // A retained occupancy that cannot fit is refused outright: pending
        // snapshots are never reclaimed to make room for a new capture.
        let error = admit(&scheduler, staging, 6, 95, &token).await.unwrap_err();
        assert!(
            matches!(error, StagingAdmissionError::Refused(ScheduleError::ReservationTooLarge)),
            "got {error:?}"
        );
        // Unknown free space admits on budget alone.
        scheduler.set_free_space_probe(Some(Arc::new(Probe { available: None, asked: Mutex::new(Vec::new()) })));
        assert!(admit(&scheduler, staging, 60, 0, &token).await.is_ok());
        // Live shrink blocks new admission beyond the new budget.
        scheduler.set_memory_limits(64 * 1024 * 1024, 64 * 1024 * 1024, 10, 50);
        let error = admit(&scheduler, staging, 60, 0, &token).await.unwrap_err();
        assert!(
            matches!(error, StagingAdmissionError::Refused(ScheduleError::ReservationTooLarge)),
            "got {error:?}"
        );
    }

    /// Staging admission is **one serialized critical section**: the retained
    /// occupancy sample runs only after the previous capture's guard (its
    /// capture completion) is released. A second capture can therefore never
    /// sample occupancy before the first snapshot is `Ready` — nor admit
    /// against a stale pre-capture zero.
    #[tokio::test]
    async fn staging_admission_serializes_the_sample_until_the_guard_drops() {
        let scheduler = Scheduler::new(SchedulerConfig {
            staging_admission_bytes: 10,
            minimum_free_bytes: 0,
            ..SchedulerConfig::default()
        });
        let token = CancellationToken::new();
        let staging = Path::new("C:\\staging");

        // The first capture admits 6 bytes and holds the section across its
        // completion (the guard *is* the section).
        let first = admit(&scheduler, staging, 6, 0, &token).await.unwrap();
        assert_eq!(first.bytes(), 6);
        assert_eq!(scheduler.stats().staging_used_bytes, 6);

        // A second capture queues at the section entrance. Its occupancy
        // sample must not run at all while the first capture's guard is alive.
        let samples = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let record = samples.clone();
        let second = scheduler.staging_admission(
            WorkClass::LocalEdit,
            drive(2),
            staging,
            6,
            async move {
                record.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // The first capture's snapshot is `Ready`: 6 retained bytes.
                Ok(6)
            },
            &token,
        );
        tokio::pin!(second);
        poll_pending(second.as_mut());
        assert_eq!(
            samples.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no occupancy sample before the section is released"
        );

        // Dropping the guard completes the first capture's section and
        // returns its reservation with it. The second sample now runs and
        // reports the retained bytes: 6 + 6 = 12 > the 10-byte budget, so the
        // capture is refused without reclaiming anything.
        drop(first);
        assert_eq!(scheduler.stats().staging_used_bytes, 0, "the guard returned its reservation with it");
        let error = second.await.unwrap_err();
        assert!(
            matches!(error, StagingAdmissionError::Refused(ScheduleError::ReservationTooLarge)),
            "got {error:?}"
        );
        assert_eq!(
            samples.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the sample runs exactly once, after the section opens"
        );
    }

    #[tokio::test]
    async fn transfer_rates_update_the_shared_wire_budget_live() {
        let scheduler = scheduler(4, 1);
        scheduler.set_transfer_rates(2048, 4096);
        assert_eq!(scheduler.wire_budget().burst_bytes(), 1024 * 1024, "burst stays the 1 MiB contract value");
        scheduler.set_transfer_rates(0, 0);
        scheduler.wire_budget().gate(hfdrive_hf::wire_budget::Direction::Upload, 8).await;
        assert_eq!(scheduler.wire_budget().counters().wire_write_bytes, 8);
    }
}
