//! Provider-independent transfer-budget primitives shared by every HF Drive
//! transport boundary: the native HF API calls (`http`), the Xet CAS/dedup/range
//! paths (through the vendored `xet-client` transport hook), and the parent's
//! S3 publication adapter (through [`WireBudget::gate_write`] /
//! [`WireBudget::gate_read`] / [`WireBudget::gate_stream`]).
//!
//! Accounting contract:
//! - **Wire counters** count *encoded* body bytes as they are admitted at a
//!   transport boundary — the bytes that cross the wire for one request or
//!   response body. They are never reconstructed content and never include
//!   headers or framing.
//! - **Logical counters** count reconstructed content handed to or taken from
//!   consumers (range-reader deliveries, upload captures). They are recorded
//!   separately ([`WireBudget::note_logical_read`] /
//!   [`WireBudget::note_logical_write`]) and never merged with wire counters.
//! - A gated chunk is counted once, when the gate is created (the boundary has
//!   admitted it); pacing may still delay its delivery by at most one burst
//!   window. An aborted transfer can therefore leave at most its in-flight
//!   chunks counted without final delivery.
//!
//! Pacing contract:
//! - One shared token bucket per direction ([`Direction::Upload`] /
//!   [`Direction::Download`]); a process installs exactly one shared
//!   [`WireBudget`] ([`WireBudget::install_global`]).
//! - The bucket burst is bounded (1 MiB by default) so a transfer may wait at
//!   most `burst / rate` per grant; a chunk larger than the burst is granted in
//!   burst-sized pieces rather than blocking forever.
//! - A rate of `0` means **unlimited** (no pacing). Rates and the burst are
//!   live-adjustable ([`WireBudget::set_config`]); a rate increase wakes
//!   existing waiters immediately.
//! - Dropping a gate future never corrupts the bucket; its bytes stay counted
//!   (see above) and no token is re-added mid-flight.
//!
//! This module is dependency-light on purpose: `hfdrive-publication` can use it
//! without taking a dependency on the provider.
#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// Default burst for each direction: 1 MiB, matching the provider's transfer
/// pacing contract.
pub const DEFAULT_BURST_BYTES: u64 = 1024 * 1024;

/// Direction of encoded body bytes at a transport boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Direction {
    /// Request bodies leaving the process (native uploads, Xet CAS/shard
    /// writes, S3 PUT bodies).
    Upload,
    /// Response bodies entering the process (native reads, Xet CAS/xorb/dedup
    /// reads, S3 GET bodies).
    Download,
}

/// Snapshot of the byte counters. Wire and logical byte counts are distinct by
/// contract and are never summed together here.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WireCounters {
    /// Encoded body bytes admitted at metered upload boundaries.
    pub wire_write_bytes: u64,
    /// Encoded body bytes admitted at metered download boundaries.
    pub wire_read_bytes: u64,
    /// Reconstructed content bytes produced for consumers.
    pub logical_read_bytes: u64,
    /// Captured content bytes accepted from consumers.
    pub logical_write_bytes: u64,
}

/// Token-bucket configuration. `0` for a rate means unlimited.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetConfig {
    /// Upload bytes per second; `0` disables upload pacing.
    pub upload_bytes_per_second: u64,
    /// Download bytes per second; `0` disables download pacing.
    pub download_bytes_per_second: u64,
    /// Burst size in bytes for both directions; never `0`.
    pub burst_bytes: u64,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            upload_bytes_per_second: 0,
            download_bytes_per_second: 0,
            burst_bytes: DEFAULT_BURST_BYTES,
        }
    }
}

/// Failure modes for byte-budget admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BudgetError {
    /// The wait was cancelled before capacity was granted.
    #[error("budget admission was cancelled")]
    Cancelled,
    /// The requested reservation exceeds the budget capacity even when empty;
    /// waiting can never satisfy it.
    #[error("reservation exceeds the budget capacity")]
    TooLarge,
}

/// Internal per-direction bucket state. Pure arithmetic is factored out so it
/// can be tested with synthetic instants.
struct BucketState {
    /// Bytes per second; `0` means unlimited.
    rate_per_second: u64,
    /// Maximum retained tokens (burst) in bytes.
    burst_bytes: u64,
    /// Currently available tokens in bytes (never negative, never above burst
    /// after refill).
    tokens: f64,
    /// Last refill timestamp.
    updated: Instant,
}

impl BucketState {
    fn new(rate_per_second: u64, burst_bytes: u64) -> Self {
        let burst = burst_bytes.max(1) as f64;
        Self { rate_per_second, burst_bytes: burst_bytes.max(1), tokens: burst, updated: Instant::now() }
    }

    /// Refill tokens up to `now`. Only passage of time adds tokens.
    fn refill(&mut self, now: Instant) {
        if self.rate_per_second == 0 {
            self.tokens = self.burst_bytes as f64;
            self.updated = now;
            return;
        }
        let elapsed = now.saturating_duration_since(self.updated);
        self.updated = now;
        let gained = elapsed.as_secs_f64() * self.rate_per_second as f64;
        self.tokens = (self.tokens + gained).min(self.burst_bytes as f64);
    }

    /// Try to take up to `want` bytes at `now`; returns the granted amount
    /// (bounded by the burst so a large chunk cannot block forever).
    fn take(&mut self, now: Instant, want: u64) -> u64 {
        self.refill(now);
        if self.rate_per_second == 0 {
            return want;
        }
        let cap = want.min(self.burst_bytes);
        let grant = cap.min(self.tokens.floor() as u64);
        self.tokens -= grant as f64;
        grant
    }

    /// Duration until at least one byte can be granted at `now`.
    fn wait_hint(&self, now: Instant) -> Duration {
        if self.rate_per_second == 0 {
            return Duration::ZERO;
        }
        let elapsed = now.saturating_duration_since(self.updated);
        let tokens_now =
            (self.tokens + elapsed.as_secs_f64() * self.rate_per_second as f64).min(self.burst_bytes as f64);
        let missing = 1.0f64 - tokens_now;
        if missing <= 0.0 {
            Duration::ZERO
        } else {
            let seconds = missing / self.rate_per_second as f64;
            Duration::from_secs_f64(seconds.max(0.0))
        }
    }
}

struct DirectionBudget {
    state: Mutex<BucketState>,
    /// Bumped on every configuration change; waiters wake and recompute.
    changed: watch::Sender<u64>,
}

struct BudgetInner {
    upload: DirectionBudget,
    download: DirectionBudget,
    wire_write: AtomicU64,
    wire_read: AtomicU64,
    logical_read: AtomicU64,
    logical_write: AtomicU64,
}

impl DirectionBudget {
    fn new(rate_per_second: u64, burst_bytes: u64) -> Self {
        Self {
            state: Mutex::new(BucketState::new(rate_per_second, burst_bytes)),
            changed: watch::channel(0).0,
        }
    }

    fn reconfigure(&self, rate_per_second: u64, burst_bytes: u64) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.rate_per_second = rate_per_second;
        guard.burst_bytes = burst_bytes.max(1);
        if guard.tokens > guard.burst_bytes as f64 {
            guard.tokens = guard.burst_bytes as f64;
        }
        drop(guard);
        let _ = self.changed.send_modify(|generation| *generation = generation.wrapping_add(1));
    }

    fn bucket(&self, direction: Direction) -> &DirectionBudget {
        let _ = direction;
        self
    }
}

/// Shared transfer budget: one token bucket per direction plus the wire and
/// logical byte counters. Cloning shares the same state; a process installs one
/// instance as the global budget before any transfer starts.
#[derive(Clone)]
pub struct WireBudget {
    inner: Arc<BudgetInner>,
}

static GLOBAL: OnceLock<WireBudget> = OnceLock::new();

impl WireBudget {
    /// Create a budget from explicit configuration.
    pub fn new(config: BudgetConfig) -> Self {
        Self {
            inner: Arc::new(BudgetInner {
                upload: DirectionBudget::new(config.upload_bytes_per_second, config.burst_bytes),
                download: DirectionBudget::new(config.download_bytes_per_second, config.burst_bytes),
                wire_write: AtomicU64::new(0),
                wire_read: AtomicU64::new(0),
                logical_read: AtomicU64::new(0),
                logical_write: AtomicU64::new(0),
            }),
        }
    }

    /// The process-shared budget created with [`BudgetConfig::default`].
    pub fn global() -> Self {
        GLOBAL.get_or_init(|| Self::new(BudgetConfig::default())).clone()
    }

    /// Install this budget as the process-shared budget. Call exactly once per
    /// process during provider initialization, before any transfer starts.
    /// Returns `false` when another budget is already installed (the caller
    /// must then keep using [`WireBudget::global`]); it never silently swaps a
    /// budget that transfers are already using.
    pub fn install_global(&self) -> bool {
        let existing = GLOBAL.get_or_init(|| self.clone());
        Arc::ptr_eq(&existing.inner, &self.inner)
    }

    /// Live budget change: rates (`0` = unlimited) and the shared burst size.
    /// Rate increases wake current waiters immediately; held tokens above a
    /// reduced burst are clamped.
    pub fn set_config(&self, config: BudgetConfig) {
        self.inner.upload.reconfigure(config.upload_bytes_per_second, config.burst_bytes);
        self.inner.download.reconfigure(config.download_bytes_per_second, config.burst_bytes);
    }

    /// Convenience live update of the two rates; the burst is kept.
    pub fn set_rates(&self, upload_bytes_per_second: u64, download_bytes_per_second: u64) {
        let burst = self.burst_bytes();
        self.set_config(BudgetConfig {
            upload_bytes_per_second,
            download_bytes_per_second,
            burst_bytes: burst,
        });
    }

    /// The configured burst size in bytes.
    pub fn burst_bytes(&self) -> u64 {
        let guard = self.inner.upload.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.burst_bytes
    }

    /// Snapshot of the byte counters; wire and logical counts stay distinct.
    pub fn counters(&self) -> WireCounters {
        WireCounters {
            wire_write_bytes: self.inner.wire_write.load(Ordering::Relaxed),
            wire_read_bytes: self.inner.wire_read.load(Ordering::Relaxed),
            logical_read_bytes: self.inner.logical_read.load(Ordering::Relaxed),
            logical_write_bytes: self.inner.logical_write.load(Ordering::Relaxed),
        }
    }

    /// Count reconstructed content delivered to a consumer (never wire bytes).
    pub fn note_logical_read(&self, bytes: u64) {
        self.inner.logical_read.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Count captured content accepted from a consumer (never wire bytes).
    pub fn note_logical_write(&self, bytes: u64) {
        self.inner.logical_write.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Count encoded body bytes without pacing (for boundaries that must not
    /// wait). Used sparingly; every paced boundary uses [`WireBudget::gate`].
    pub fn note_wire(&self, direction: Direction, bytes: u64) {
        match direction {
            Direction::Upload => self.inner.wire_write.fetch_add(bytes, Ordering::Relaxed),
            Direction::Download => self.inner.wire_read.fetch_add(bytes, Ordering::Relaxed),
        };
    }

    /// Account `bytes` of encoded body traffic in `direction` and complete only
    /// when the shared bucket permits them. This is the single admission point
    /// every metered transport boundary funnels through; an unwired boundary is
    /// a bug, not an acceptable state.
    pub fn gate(&self, direction: Direction, bytes: u64) -> BudgetGate {
        self.note_wire(direction, bytes);
        let budget = self.clone();
        let wait = async move { budget.wait_for(direction, bytes).await };
        BudgetGate { inner: Box::pin(wait) }
    }

    /// Count and pace one encoded body write (S3 adapter hook).
    pub async fn gate_write(&self, bytes: u64) {
        self.gate(Direction::Upload, bytes).await;
    }

    /// Count and pace one encoded body read (S3 adapter hook).
    pub async fn gate_read(&self, bytes: u64) {
        self.gate(Direction::Download, bytes).await;
    }

    /// Wrap a byte stream so every chunk it yields is counted and paced at the
    /// encoded-body boundary (S3 adapter hook for streamed request/response
    /// bodies). Chunks are yielded unchanged; no bytes are copied.
    pub fn gate_stream<S, B, E>(&self, direction: Direction, stream: S) -> GatedBudgetStream<S, B>
    where
        S: futures_util::Stream<Item = Result<B, E>> + Unpin,
        B: AsRef<[u8]>,
    {
        GatedBudgetStream {
            inner: stream,
            budget: self.clone(),
            direction,
            pending: None,
        }
    }

    async fn wait_for(&self, direction: Direction, mut bytes: u64) {
        if bytes == 0 {
            return;
        }
        let budget = match direction {
            Direction::Upload => &self.inner.upload,
            Direction::Download => &self.inner.download,
        };
        let mut changed = budget.changed.subscribe();
        loop {
            let now = Instant::now();
            let (granted, hint) = {
                let mut guard = budget.state.lock().unwrap_or_else(|e| e.into_inner());
                let granted = guard.take(now, bytes);
                let hint = if granted == 0 { guard.wait_hint(now) } else { Duration::ZERO };
                (granted, hint)
            };
            bytes -= granted;
            if bytes == 0 {
                return;
            }
            if granted > 0 {
                // Part of a burst-sized chunk was granted; immediately try the
                // next piece instead of sleeping first.
                continue;
            }
            let deadline = tokio::time::Instant::now() + hint.max(Duration::from_millis(1));
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {}
                _ = changed.changed() => {}
            }
        }
    }
}

/// Future returned by [`WireBudget::gate`]. Yields when the shared bucket has
/// admitted the gated bytes. Dropping it early is safe (see the module
/// accounting contract).
pub struct BudgetGate {
    inner: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl Future for BudgetGate {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.inner.as_mut().poll(cx)
    }
}

/// Stream adapter that counts and paces every chunk it yields (see
/// [`WireBudget::gate_stream`]). Chunks pass through unchanged; nothing is
/// copied.
pub struct GatedBudgetStream<S, B> {
    inner: S,
    budget: WireBudget,
    direction: Direction,
    pending: Option<(B, BudgetGate)>,
}

impl<S, B, E> futures_util::Stream for GatedBudgetStream<S, B>
where
    S: futures_util::Stream<Item = Result<B, E>> + Unpin,
    B: AsRef<[u8]> + Unpin,
{
    type Item = Result<B, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some((_, gate)) = self.pending.as_mut() {
            match Pin::new(gate).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => {}
            }
            let (chunk, _) = self.pending.take().expect("pending gated chunk exists");
            return Poll::Ready(Some(Ok(chunk)));
        }
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                let len = chunk.as_ref().len() as u64;
                let mut gate = self.budget.gate(self.direction, len);
                match Pin::new(&mut gate).poll(cx) {
                    Poll::Ready(()) => Poll::Ready(Some(Ok(chunk))),
                    Poll::Pending => {
                        self.pending = Some((chunk, gate));
                        Poll::Pending
                    }
                }
            }
            other => other,
        }
    }
}

/// RAII reservation against a byte quota ([`ByteBudget`]); the quota is
/// returned on drop. Reservations survive budget resizes: shrinking the budget
/// never cancels held reservations, it only blocks new admission until usage
/// drops below the new capacity.
#[derive(Debug)]
pub struct ByteReservation {
    budget: Arc<ByteBudgetInner>,
    bytes: u64,
}

impl ByteReservation {
    /// Reserved bytes.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl Drop for ByteReservation {
    fn drop(&mut self) {
        let mut guard = self.budget.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.used = guard.used.saturating_sub(self.bytes);
        drop(guard);
        self.budget.notify();
    }
}

#[derive(Debug)]
struct ByteBudgetState {
    capacity: u64,
    used: u64,
    waiters: Vec<std::task::Waker>,
}

#[derive(Debug)]
struct ByteBudgetInner {
    state: Mutex<ByteBudgetState>,
}

impl ByteBudgetInner {
    fn notify(&self) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let waiters = std::mem::take(&mut guard.waiters);
        drop(guard);
        for waker in waiters {
            waker.wake();
        }
    }
}

/// Byte quota with RAII reservations, live resizing, and cancellation-aware
/// waits. Used for the transfer-buffer, range-cache and staging admission
/// budgets.
#[derive(Clone)]
pub struct ByteBudget {
    inner: Arc<ByteBudgetInner>,
}

impl ByteBudget {
    /// A budget with the given capacity in bytes.
    pub fn new(capacity_bytes: u64) -> Self {
        Self {
            inner: Arc::new(ByteBudgetInner {
                state: Mutex::new(ByteBudgetState { capacity: capacity_bytes, used: 0, waiters: Vec::new() }),
            }),
        }
    }

    /// Live resize. Existing reservations are never cancelled; admission
    /// resumes when usage falls below the new capacity.
    pub fn set_capacity(&self, capacity_bytes: u64) {
        {
            let mut guard = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
            guard.capacity = capacity_bytes;
        }
        self.inner.notify();
    }

    /// Current capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        self.inner.state.lock().unwrap_or_else(|e| e.into_inner()).capacity
    }

    /// Currently reserved bytes.
    pub fn used_bytes(&self) -> u64 {
        self.inner.state.lock().unwrap_or_else(|e| e.into_inner()).used
    }

    /// Non-blocking admission; `None` when the quota cannot currently admit
    /// `bytes`.
    pub fn try_reserve(&self, bytes: u64) -> Result<ByteReservation, BudgetError> {
        let mut guard = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        if bytes > guard.capacity {
            return Err(BudgetError::TooLarge);
        }
        if guard.used.saturating_add(bytes) > guard.capacity {
            return Err(BudgetError::Cancelled);
        }
        guard.used += bytes;
        Ok(ByteReservation { budget: self.inner.clone(), bytes })
    }

    /// Cancellation-aware admission: waits for capacity, fails fast when the
    /// reservation can never fit ([`BudgetError::TooLarge`]) and returns
    /// [`BudgetError::Cancelled`] when `cancel` fires first. A cancelled wait
    /// never leaks quota.
    pub async fn reserve(&self, bytes: u64, cancel: &CancellationToken) -> Result<ByteReservation, BudgetError> {
        if bytes > self.capacity_bytes() {
            return Err(BudgetError::TooLarge);
        }
        let mut registered = false;
        let granted = std::future::poll_fn(|cx| {
            if cancel.is_cancelled() {
                return Poll::Ready(Err(BudgetError::Cancelled));
            }
            let mut guard = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
            if guard.used.saturating_add(bytes) <= guard.capacity {
                guard.used += bytes;
                return Poll::Ready(Ok(()));
            }
            if !registered {
                guard.waiters.push(cx.waker().clone());
                registered = true;
            }
            Poll::Pending
        })
        .await;
        granted?;
        Ok(ByteReservation { budget: self.inner.clone(), bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;

    /// Pure bucket arithmetic with synthetic instants: refill, burst ceiling,
    /// burst-bounded grants for oversized chunks, and the unlimited mode.
    #[test]
    fn bucket_math_is_deterministic_and_burst_bounded() {
        let base = Instant::now();
        let mut bucket = BucketState::new(1000, 1000);
        bucket.updated = base;
        assert_eq!(bucket.take(base, 400), 400, "burst is available immediately");
        assert_eq!(bucket.take(base, 400), 400);
        assert_eq!(bucket.take(base, 400), 200, "grants stop at the token floor");
        assert_eq!(bucket.take(base, 400), 0, "empty bucket grants nothing");
        let later = base + Duration::from_millis(200);
        assert_eq!(bucket.take(later, 400), 200, "200ms at 1000 B/s refills 200 B");
        assert_eq!(bucket.take(later, 400), 0);
        // Oversized chunk is granted in burst-sized pieces, never blocks forever.
        let mut big = BucketState::new(1000, 1000);
        big.updated = base;
        assert_eq!(big.take(base, 5000), 1000);
        // Unlimited rate grants everything and never paces.
        let mut open = BucketState::new(0, 1000);
        assert_eq!(open.take(base, 5000), 5000);
    }

    /// Refill never exceeds the burst even after a long idle period.
    #[test]
    fn refill_clamps_to_burst() {
        let base = Instant::now();
        let mut bucket = BucketState::new(1000, 1000);
        bucket.updated = base;
        bucket.refill(base + Duration::from_secs(3600));
        assert_eq!(bucket.take(base + Duration::from_secs(3600), 1000), 1000);
        assert_eq!(bucket.take(base + Duration::from_secs(3600), 1), 0);
    }

    #[tokio::test]
    async fn wire_and_logical_counters_stay_distinct() {
        let budget = WireBudget::new(BudgetConfig { upload_bytes_per_second: 0, download_bytes_per_second: 0, burst_bytes: 1024 });
        budget.gate(Direction::Upload, 10).await;
        budget.gate(Direction::Download, 20).await;
        budget.note_wire(Direction::Download, 5);
        budget.note_logical_read(30);
        budget.note_logical_write(40);
        let counters = budget.counters();
        assert_eq!(counters.wire_write_bytes, 10);
        assert_eq!(counters.wire_read_bytes, 25);
        assert_eq!(counters.logical_read_bytes, 30);
        assert_eq!(counters.logical_write_bytes, 40);
    }

    #[tokio::test]
    async fn gate_counts_at_creation_even_when_dropped_before_delivery() {
        let budget = WireBudget::new(BudgetConfig { upload_bytes_per_second: 1, download_bytes_per_second: 0, burst_bytes: 64 });
        let gate = budget.gate(Direction::Upload, 1024);
        drop(gate);
        assert_eq!(budget.counters().wire_write_bytes, 1024, "gated bytes are counted once at admission");
    }

    /// An exhausted bucket holds a gate open; it completes only when time
    /// refills tokens or a live rate change releases it (the release path is
    /// exercised end-to-end in `tests/wire_budget.rs`).
    #[tokio::test]
    async fn stalled_gate_does_not_complete_on_an_empty_bucket() {
        let budget = WireBudget::new(BudgetConfig { upload_bytes_per_second: 1, download_bytes_per_second: 0, burst_bytes: 8 });
        // Exhaust the burst.
        budget.gate(Direction::Upload, 8).await;
        let stalled = budget.gate(Direction::Upload, 8);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut { stalled }).await.is_err(),
            "an empty bucket at 1 B/s does not complete quickly"
        );
    }

    #[tokio::test]
    async fn unlimited_rate_never_paces() {
        let budget = WireBudget::new(BudgetConfig::default());
        let gate = budget.gate(Direction::Download, u64::MAX);
        tokio::time::timeout(Duration::from_millis(1), gate).await.expect("unlimited budget completes immediately");
    }

    #[tokio::test]
    async fn gated_stream_paces_and_counts_every_chunk() {
        let budget = WireBudget::new(BudgetConfig { upload_bytes_per_second: 0, download_bytes_per_second: 0, burst_bytes: 1024 });
        let source = futures_util::stream::iter([
            Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"abc")),
            Ok(bytes::Bytes::from_static(b"defg")),
        ]);
        let mut gated = budget.gate_stream(Direction::Download, source);
        assert_eq!(gated.next().await.unwrap().unwrap(), bytes::Bytes::from_static(b"abc"));
        assert_eq!(gated.next().await.unwrap().unwrap(), bytes::Bytes::from_static(b"defg"));
        assert!(gated.next().await.is_none());
        assert_eq!(budget.counters().wire_read_bytes, 7);
    }

    #[tokio::test]
    async fn byte_budget_admission_is_raii_and_live_resizable() {
        let budget = ByteBudget::new(100);
        let first = budget.try_reserve(60).unwrap();
        assert!(budget.try_reserve(60).is_err(), "over-capacity admission fails fast");
        let second = budget.try_reserve(40).unwrap();
        assert_eq!(budget.used_bytes(), 100);
        drop(first);
        assert_eq!(budget.used_bytes(), 40);
        drop(second);
        assert_eq!(budget.used_bytes(), 0);
        budget.set_capacity(10);
        assert_eq!(budget.try_reserve(11).unwrap_err(), BudgetError::TooLarge);
        assert_eq!(budget.capacity_bytes(), 10);
    }

    #[tokio::test]
    async fn byte_budget_waiters_wake_on_release_and_resize() {
        let budget = ByteBudget::new(10);
        let held = budget.try_reserve(10).unwrap();
        let token = CancellationToken::new();
        let waiting = budget.reserve(10, &token);
        tokio::pin!(waiting);
        assert!(tokio::time::timeout(Duration::from_millis(30), &mut waiting).await.is_err());
        drop(held);
        let reservation = tokio::time::timeout(Duration::from_secs(5), waiting).await.expect("released capacity wakes the waiter").unwrap();
        assert_eq!(reservation.bytes(), 10);
    }

    #[tokio::test]
    async fn byte_budget_reservation_honors_cancellation_without_leaking() {
        let budget = ByteBudget::new(10);
        let held = budget.try_reserve(10).unwrap();
        let cancel = CancellationToken::new();
        let cancelled = cancel.clone();
        let waiting = budget.reserve(10, &cancelled);
        tokio::pin!(waiting);
        cancelled.cancel();
        assert_eq!(waiting.await.unwrap_err(), BudgetError::Cancelled);
        drop(held);
        assert_eq!(budget.used_bytes(), 0, "a cancelled wait never leaks quota");
    }
}
