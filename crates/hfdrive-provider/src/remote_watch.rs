//! Coalesced remote observation: native change-feed events plus independent
//! jittered HEAD polling, with a stream-silence fallback.
//!
//! Contract:
//! - Events are **HEAD invalidations**, never deletions. The parent re-reads
//!   the authoritative HEAD/catalog on each notice; raw bucket listings are
//!   never diffed (eventual bucket indexing is not the namespace).
//! - Cursors are optional and opaque. A cursor advances the watch's resume
//!   position **only after [`WatchControl::acknowledge`] reports durable
//!   application**; until then reconnects replay from the last acknowledged
//!   cursor, so a lost acknowledgment can never skip a change.
//! - Invalidations deduplicate and coalesce: at most one notice is outstanding
//!   (awaiting acknowledgment); further triggers merge into it and one fresh
//!   notice follows the acknowledgment.
//! - The stream reconnects on EOF/error and on silence (no encoded body bytes,
//!   heartbeats included, for `stream_idle_timeout`). Failures back off with
//!   explicit `Retry-After` handling and exponential full-jitter (1s base,
//!   60s ceiling) — no busy loop, ever. Metered/offline conditions surface as
//!   explicit [`WatchNotice::StreamUnavailable`] notices while polling keeps
//!   running; no observation work is lost.
//! - A `reset`/replay expiry discards the resume cursor and requests an
//!   authoritative HEAD re-read; it is never interpreted as deletion churn.
#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hfdrive_auth::TokenSource;
use hfdrive_hf::{EventCursor, EventResume, NativeBucketStore, NativeError, NativeEvent, NativeEventStream, NativeLease};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

/// Where a HEAD invalidation came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoticeSource {
    /// A native change-feed event named changed keys.
    Event,
    /// The independent jittered HEAD poll fired.
    Poll,
    /// The feed was reset/replayed and the authoritative HEAD must be re-read.
    Resync,
}

/// Named stream conditions the parent can surface. Never carries SDK text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchIssue {
    RateLimited,
    AuthRequired,
    PermissionDenied,
    RemoteUnavailable,
    Transport,
}

/// One coalesced observation notice. Every notice must be acknowledged after
/// the parent's durable application before the next one is delivered.
#[derive(Clone, Debug)]
pub enum WatchNotice {
    /// The remote HEAD may have changed. Re-read the authoritative HEAD and
    /// catalog through the publication/native boundary. `cursor` (when the
    /// source supplied one) must be acknowledged via
    /// [`WatchControl::acknowledge`] only **after** the invalidation is
    /// durably applied.
    HeadInvalidated { source: NoticeSource, cursor: Option<EventCursor> },
    /// The server reset the feed (replay expired): the resume cursor has been
    /// discarded and the authoritative HEAD must be re-read. Never a deletion.
    Reset,
    /// The event stream is unavailable right now; `retry_in` is the backoff
    /// the watch will wait before retrying. Polling continues meanwhile.
    StreamUnavailable { issue: WatchIssue, retry_in: Duration },
}

/// Terminal reason [`RemoteWatch::run`] returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchExit {
    /// The watch was cancelled.
    Cancelled,
    /// The notices channel was closed by the consumer.
    NoticesClosed,
}

/// Watch-loop timing and jitter configuration. Defaults are the Step 7
/// contract: jittered 60–90s HEAD polling, 90s stream-silence reconnect, and
/// full-jitter reconnect backoff from 1s to a 60s ceiling.
#[derive(Clone, Debug)]
pub struct WatchConfig {
    /// Inclusive jitter range for the independent HEAD poll.
    pub poll_interval: (Duration, Duration),
    /// No encoded body bytes (heartbeats included) for this long triggers a
    /// reconnect.
    pub stream_idle_timeout: Duration,
    /// Full-jitter backoff bounds for reconnects after failures.
    pub backoff_base: Duration,
    pub backoff_ceiling: Duration,
    /// Deterministic jitter seed for tests; production seeds from the OS
    /// CSPRNG-derived value.
    pub jitter_seed: Option<u64>,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            poll_interval: (Duration::from_secs(60), Duration::from_secs(90)),
            stream_idle_timeout: Duration::from_secs(90),
            backoff_base: Duration::from_secs(1),
            backoff_ceiling: Duration::from_secs(60),
            jitter_seed: None,
        }
    }
}

/// One open event feed (the storage plane's raw SSE source).
pub trait EventFeed: Send {
    /// Next event; `Ok(None)` is end-of-stream (the caller reconnects).
    fn next_event<'a>(
        &'a mut self,
        cancel: &'a CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<Option<NativeEvent>, NativeError>> + Send + 'a>>;

    /// Time since the last encoded body byte (heartbeat comments included).
    fn idle_for(&self) -> Duration;
}

impl EventFeed for NativeEventStream {
    fn next_event<'a>(
        &'a mut self,
        cancel: &'a CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<Option<NativeEvent>, NativeError>> + Send + 'a>> {
        Box::pin(NativeEventStream::next_event(self, cancel))
    }

    fn idle_for(&self) -> Duration {
        NativeEventStream::idle_for(self)
    }
}

/// Event-source surface used by the watch loop; implemented for the storage
/// plane via [`StoreEvents`] and by fakes in tests.
pub trait RemoteEvents: Send + 'static {
    fn open_events(
        &self,
        resume: Option<EventCursor>,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn EventFeed>, NativeError>> + Send>>;
}

/// The storage-plane event source: one drive store plus the operation lease
/// captured for observation (thread it exactly like any other durable
/// operation's lease).
pub struct StoreEvents<T: TokenSource> {
    store: NativeBucketStore<T>,
    lease: NativeLease,
}

impl<T: TokenSource> StoreEvents<T> {
    pub fn new(store: NativeBucketStore<T>, lease: NativeLease) -> Self {
        Self { store, lease }
    }
}

impl<T: TokenSource + 'static> RemoteEvents for StoreEvents<T> {
    fn open_events(
        &self,
        resume: Option<EventCursor>,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn EventFeed>, NativeError>> + Send>> {
        let store = self.store.clone();
        let lease = self.lease.clone();
        Box::pin(async move {
            let stream = store.events(&lease, resume.map(EventResume::Cursor), &cancel).await?;
            Ok(Box::new(stream) as Box<dyn EventFeed>)
        })
    }
}

struct WatchShared {
    acknowledged: Mutex<Option<EventCursor>>,
    /// Bumped on every acknowledgment so the run loop can deliver the next
    /// coalesced notice.
    acks: watch::Sender<u64>,
}

/// Parent-side control for one running watch: acknowledge durable application
/// and inspect the acknowledged resume cursor.
#[derive(Clone)]
pub struct WatchControl {
    shared: Arc<WatchShared>,
}

impl WatchControl {
    /// Acknowledge durable application of the outstanding notice. Supply the
    /// notice's cursor (after it is transactionally persisted and applied) to
    /// advance the resume position; `None` unlocks the next notice without
    /// advancing. Until this call, reconnects replay from the previously
    /// acknowledged cursor only.
    pub fn acknowledge(&self, applied: Option<EventCursor>) {
        if let Some(cursor) = applied {
            *self.shared.acknowledged.lock().unwrap_or_else(|e| e.into_inner()) = Some(cursor);
        }
        let _ = self.shared.acks.send_modify(|value| *value = value.wrapping_add(1));
    }

    /// The resume position proven by durable application (`None` until the
    /// first cursor is acknowledged).
    pub fn acknowledged_cursor(&self) -> Option<EventCursor> {
        self.shared.acknowledged.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// Deterministic xorshift64* jitter; tests pin the seed.
struct Jitter(u64);

impl Jitter {
    fn new(seed: Option<u64>) -> Self {
        Self(seed.unwrap_or_else(|| uuid::Uuid::new_v4().as_u128() as u64) | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    /// Uniform value in `low..=high` (when `high > low`).
    fn range(&mut self, low: Duration, high: Duration) -> Duration {
        let span = high.saturating_sub(low).as_millis() as u64;
        if span == 0 {
            return low;
        }
        low + Duration::from_millis(self.next_u64() % (span + 1))
    }

    /// Exponential full-jitter backoff: uniform in `0..min(ceiling, base*2^attempt)`,
    /// never below the caller's floor.
    fn full_jitter(&mut self, attempt: u32, base: Duration, ceiling: Duration) -> Duration {
        let exponential = base.saturating_mul(1u32 << attempt.min(20));
        let bound = exponential.min(ceiling).as_millis() as u64;
        if bound == 0 {
            base
        } else {
            Duration::from_millis(self.next_u64() % (bound + 1))
        }
    }
}

fn issue_of(error: &NativeError) -> WatchIssue {
    match error {
        NativeError::RateLimited { .. } => WatchIssue::RateLimited,
        NativeError::NeedsSignIn => WatchIssue::AuthRequired,
        NativeError::PermissionDenied => WatchIssue::PermissionDenied,
        NativeError::RemoteContentUnavailable => WatchIssue::RemoteUnavailable,
        _ => WatchIssue::Transport,
    }
}

/// One coalesced remote observer for one drive. Run exactly one loop per
/// connected drive; the poll cadence and backoff are independent per instance.
pub struct RemoteWatch {
    config: WatchConfig,
    control: Arc<WatchShared>,
}

impl RemoteWatch {
    /// Create a watch. Use [`RemoteWatch::control`] from the parent to
    /// acknowledge durable application of notices.
    pub fn new(config: WatchConfig) -> (Self, WatchControl) {
        let shared = Arc::new(WatchShared {
            acknowledged: Mutex::new(None),
            acks: watch::channel(0).0,
        });
        (
            Self { config, control: shared.clone() },
            WatchControl { shared },
        )
    }

    /// Run the observation loop until cancellation or channel closure.
    ///
    /// `resume` is the persisted cursor from `event_cursors` (it must be a
    /// cursor whose invalidation was durably applied before it was persisted).
    /// Unacknowledged cursors never advance the resume position.
    pub async fn run<E: RemoteEvents>(
        self,
        source: E,
        resume: Option<EventCursor>,
        notices: mpsc::Sender<WatchNotice>,
        cancel: CancellationToken,
    ) -> WatchExit {
        let mut jitter = Jitter::new(self.config.jitter_seed);
        let mut acks = self.control.acks.subscribe();
        // Last invalidated cursor awaiting durable application; latest wins.
        let mut merged: Option<WatchNotice> = None;
        let mut outstanding = false;

        let mut poll_due = tokio::time::Instant::now()
            + jitter.range(self.config.poll_interval.0, self.config.poll_interval.1);

        let mut attempt: u32 = 0;
        let mut resume = resume;
        'outer: loop {
            // Open (or reopen) the feed from the acknowledged position only.
            let resume_position = self
                .control
                .acknowledged
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
                .or_else(|| resume.clone());
            let stream_cancel = cancel.child_token();
            let opening = source.open_events(resume_position, stream_cancel.clone());
            tokio::pin!(opening);
            let opened = loop {
                tokio::select! {
                    _ = cancel.cancelled() => return WatchExit::Cancelled,
                    changed = acks.changed() => {
                        if changed.is_err() {
                            return WatchExit::NoticesClosed;
                        }
                        outstanding = false;
                        if !deliver(&notices, &mut merged, &mut outstanding, &cancel).await {
                            return WatchExit::NoticesClosed;
                        }
                    }
                    _ = tokio::time::sleep_until(poll_due) => {
                        poll_due = tokio::time::Instant::now()
                            + jitter.range(self.config.poll_interval.0, self.config.poll_interval.1);
                        merge_notice(&mut merged, WatchNotice::HeadInvalidated { source: NoticeSource::Poll, cursor: None });
                        if !deliver(&notices, &mut merged, &mut outstanding, &cancel).await {
                            return WatchExit::NoticesClosed;
                        }
                    }
                    result = &mut opening => break result,
                }
            };
            let feed = match opened {
                Ok(feed) => {
                    attempt = 0;
                    feed
                }
                Err(error) => {
                    if cancel.is_cancelled() {
                        return WatchExit::Cancelled;
                    }
                    let retry_in = match &error {
                        NativeError::Cancelled => return WatchExit::Cancelled,
                        NativeError::RateLimited { retry_after_seconds } => retry_after_seconds
                            .map(|seconds| Duration::from_secs(seconds))
                            .filter(|duration| *duration > Duration::ZERO)
                            .unwrap_or_else(|| {
                                jitter.full_jitter(attempt, self.config.backoff_base, self.config.backoff_ceiling)
                            }),
                        _ => {
                            attempt = attempt.saturating_add(1);
                            jitter.full_jitter(attempt, self.config.backoff_base, self.config.backoff_ceiling)
                        }
                    };
                    merge_notice(&mut merged, WatchNotice::StreamUnavailable { issue: issue_of(&error), retry_in });
                    if !deliver(&notices, &mut merged, &mut outstanding, &cancel).await {
                        return WatchExit::NoticesClosed;
                    }
                    let retry_deadline = tokio::time::Instant::now() + retry_in;
                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => return WatchExit::Cancelled,
                            changed = acks.changed() => {
                                if changed.is_err() {
                                    return WatchExit::NoticesClosed;
                                }
                                outstanding = false;
                                if !deliver(&notices, &mut merged, &mut outstanding, &cancel).await {
                                    return WatchExit::NoticesClosed;
                                }
                            }
                            _ = tokio::time::sleep_until(poll_due) => {
                                poll_due = tokio::time::Instant::now()
                                    + jitter.range(self.config.poll_interval.0, self.config.poll_interval.1);
                                merge_notice(&mut merged, WatchNotice::HeadInvalidated { source: NoticeSource::Poll, cursor: None });
                                if !deliver(&notices, &mut merged, &mut outstanding, &cancel).await {
                                    return WatchExit::NoticesClosed;
                                }
                            }
                            _ = tokio::time::sleep_until(retry_deadline) => continue 'outer,
                        }
                    }
                }
            };
            let mut feed = feed;
            let mut idle_tick = tokio::time::interval(Duration::from_secs(5));
            idle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            // Stream lifetime: events, silence fallback, independent poll, acks.
            loop {
                let next = tokio::select! {
                    _ = cancel.cancelled() => return WatchExit::Cancelled,
                    changed = acks.changed() => {
                        if changed.is_err() {
                            return WatchExit::NoticesClosed;
                        }
                        outstanding = false;
                        None
                    }
                    _ = tokio::time::sleep_until(poll_due) => {
                        poll_due = tokio::time::Instant::now()
                            + jitter.range(self.config.poll_interval.0, self.config.poll_interval.1);
                        Some(Err(()))
                    }
                    _ = idle_tick.tick() => {
                        if feed.idle_for() >= self.config.stream_idle_timeout {
                            // Silence past the heartbeat budget: reconnect.
                            stream_cancel.cancel();
                            break;
                        }
                        None
                    }
                    event = feed.next_event(&stream_cancel) => {
                        match event {
                            Ok(None) => {
                                // End of stream: reconnect from the
                                // acknowledged position.
                                stream_cancel.cancel();
                                break;
                            }
                            Ok(Some(event)) => Some(Ok(event)),
                            Err(error) => {
                                if matches!(error, NativeError::Cancelled) {
                                    if cancel.is_cancelled() {
                                        return WatchExit::Cancelled;
                                    }
                                    break;
                                }
                                attempt = attempt.saturating_add(1);
                                let retry_in =
                                    jitter.full_jitter(attempt, self.config.backoff_base, self.config.backoff_ceiling);
                                merge_notice(&mut merged, WatchNotice::StreamUnavailable { issue: issue_of(&error), retry_in });
                                if !deliver(&notices, &mut merged, &mut outstanding, &cancel)
                                    .await
                                {
                                    return WatchExit::NoticesClosed;
                                }
                                break;
                            }
                        }
                    }
                };
                match next {
                    None => {}
                    Some(Err(())) => {
                        // Independent jittered HEAD poll: an invalidation like
                        // any other; polling survives a dead stream's next
                        // iteration only when the stream loop continues, so
                        // polls are also the "missing notification" fallback.
                        merge_notice(&mut merged, WatchNotice::HeadInvalidated { source: NoticeSource::Poll, cursor: None });
                    }
                    Some(Ok(NativeEvent::Ready { cursor: _ })) => {
                        // Established; the ready cursor is resume metadata, not
                        // an invalidation. No notice, no cursor advance.
                    }
                    Some(Ok(NativeEvent::Changes { cursor, changes })) => {
                        if !changes.is_empty() || cursor.is_some() {
                            merge_notice(&mut merged, WatchNotice::HeadInvalidated { source: NoticeSource::Event, cursor });
                        }
                    }
                    Some(Ok(NativeEvent::Reset { reason: _ })) => {
                        // Replay expired: discard the resume cursor (fresh
                        // authoritative reads only) and re-read the HEAD.
                        *self.control.acknowledged.lock().unwrap_or_else(|e| e.into_inner()) = None;
                        resume = None;
                        merge_notice(&mut merged, WatchNotice::Reset);
                        if !deliver(&notices, &mut merged, &mut outstanding, &cancel).await {
                            return WatchExit::NoticesClosed;
                        }
                        stream_cancel.cancel();
                        break;
                    }
                    Some(Ok(NativeEvent::Reconnect { cursor: _ })) => {
                        // The server asked for a reconnect; the resume position
                        // stays the acknowledged cursor.
                        break;
                    }
                }
                if !deliver(&notices, &mut merged, &mut outstanding, &cancel).await {
                    return WatchExit::NoticesClosed;
                }
            }
        }
    }
}

/// Preserve the strongest unsatisfied observation while coalescing. Stream
/// health must not erase a pending invalidation, and an ordinary notice must
/// not erase a reset whose authoritative rescan is still outstanding.
fn merge_notice(merged: &mut Option<WatchNotice>, notice: WatchNotice) {
    let replace = match (merged.as_ref(), &notice) {
        (None, _) => true,
        (Some(WatchNotice::Reset), WatchNotice::HeadInvalidated { .. } | WatchNotice::StreamUnavailable { .. }) => false,
        (Some(WatchNotice::HeadInvalidated { .. }), WatchNotice::StreamUnavailable { .. }) => false,
        _ => true,
    };
    if replace {
        *merged = Some(notice);
    }
}

/// Coalescing delivery: at most one notice is outstanding (awaiting
/// acknowledgment); further triggers merge into `merged`. Returns `false` when
/// the channel closed.
async fn deliver(
    notices: &mpsc::Sender<WatchNotice>,
    merged: &mut Option<WatchNotice>,
    outstanding: &mut bool,
    cancel: &CancellationToken,
) -> bool {
    if *outstanding {
        // The parent has not acknowledged; the merged notice stays queued.
        return true;
    }
    let Some(notice) = merged.take() else {
        return true;
    };
    tokio::select! {
        _ = cancel.cancelled() => return true,
        sent = notices.send(notice) => {
            if sent.is_err() {
                return false;
            }
        }
    }
    *outstanding = true;
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use tokio::sync::mpsc;

    #[derive(Default)]
    struct FakeShared {
        /// Scripted open results/feeds: each entry is one feed's event script.
        feeds: Mutex<VecDeque<Vec<Result<Option<NativeEvent>, NativeError>>>>,
        /// Resume positions requested at each open.
        resumes: Mutex<Vec<Option<String>>>,
    }

    struct FakeFeed {
        events: VecDeque<Result<Option<NativeEvent>, NativeError>>,
    }

    impl EventFeed for FakeFeed {
        fn next_event(
            &mut self,
            _cancel: &CancellationToken,
        ) -> Pin<Box<dyn Future<Output = Result<Option<NativeEvent>, NativeError>> + Send>> {
            let next = self.events.pop_front();
            Box::pin(async move { next.unwrap_or(Ok(None)) })
        }

        fn idle_for(&self) -> Duration {
            Duration::ZERO
        }
    }

    struct FakeSource {
        shared: Arc<FakeShared>,
    }

    impl RemoteEvents for FakeSource {
        fn open_events(
            &self,
            resume: Option<EventCursor>,
            _cancel: CancellationToken,
        ) -> Pin<Box<dyn Future<Output = Result<Box<dyn EventFeed>, NativeError>> + Send>> {
            self.shared
                .resumes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(resume.map(|cursor| cursor.as_str().to_owned()));
            let script = self.shared.feeds.lock().unwrap_or_else(|e| e.into_inner()).pop_front();
            Box::pin(async move {
                match script {
                    Some(events) => Ok(Box::new(FakeFeed { events: events.into() }) as Box<dyn EventFeed>),
                    None => Err(NativeError::Transport),
                }
            })
        }
    }

    fn cursor(raw: &str) -> Option<EventCursor> {
        Some(EventCursor::new(raw.to_owned()).unwrap())
    }

    fn change(raw: &str) -> NativeEvent {
        NativeEvent::Changes {
            cursor: cursor(raw),
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

    fn watch(seed: u64, poll: Duration) -> (RemoteWatch, WatchControl) {
        RemoteWatch::new(WatchConfig {
            poll_interval: (poll, poll),
            stream_idle_timeout: Duration::from_secs(3600),
            backoff_base: Duration::from_millis(1),
            backoff_ceiling: Duration::from_millis(20),
            jitter_seed: Some(seed),
        })
    }

    /// Coalescing: many triggers before acknowledgment yield one notice; the
    /// acknowledgment releases the merged follow-up carrying the latest cursor.
    #[tokio::test]
    async fn invalidations_coalesce_until_durable_application_is_acknowledged() {
        let (watch, control) = watch(7, Duration::from_secs(3600));
        let shared = Arc::new(FakeShared::default());
        shared.feeds.lock().unwrap().push_back(vec![
            Ok(Some(change("c1"))),
            Ok(Some(change("c2"))),
            Ok(Some(change("c3"))),
            Ok(None),
        ]);
        let (tx, mut rx) = mpsc::channel(8);
        let run = tokio::spawn(watch.run(FakeSource { shared: shared.clone() }, None, tx, CancellationToken::new()));
        let first = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        match first {
            WatchNotice::HeadInvalidated { source: NoticeSource::Event, cursor: Some(cursor) } => {
                assert_eq!(cursor.as_str(), "c1");
            }
            other => panic!("unexpected notice: {other:?}"),
        }
        // No further notice before acknowledgment.
        assert!(tokio::time::timeout(Duration::from_millis(50), rx.recv()).await.is_err());
        control.acknowledge(None);
        let merged = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        match merged {
            WatchNotice::HeadInvalidated { cursor: Some(cursor), .. } => assert_eq!(cursor.as_str(), "c3"),
            other => panic!("unexpected notice: {other:?}"),
        }
        control.acknowledge(Some(EventCursor::new("c3".to_owned()).unwrap()));
        assert_eq!(control.acknowledged_cursor().unwrap().as_str(), "c3");
        drop(rx);
        run.await.unwrap();
    }

    /// Reconnects resume strictly from the acknowledged cursor, never from an
    /// unacknowledged one.
    #[tokio::test]
    async fn resume_position_advances_only_on_acknowledgment() {
        let (watch, control) = watch(11, Duration::from_secs(3600));
        let shared = Arc::new(FakeShared::default());
        shared.feeds.lock().unwrap().push_back(vec![Ok(Some(change("c1"))), Ok(None)]);
        shared.feeds.lock().unwrap().push_back(vec![Ok(None)]);
        shared.feeds.lock().unwrap().push_back(vec![Ok(None)]);
        let (tx, mut rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let run_cancel = cancel.clone();
        let run = tokio::spawn(watch.run(FakeSource { shared: shared.clone() }, Some(EventCursor::new("c0".into()).unwrap()), tx, run_cancel));
        let _ = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        // Reconnect happens without acknowledgment -> replays from "c0".
        tokio::time::sleep(Duration::from_millis(50)).await;
        control.acknowledge(Some(EventCursor::new("c1".into()).unwrap()));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let resumes = shared.resumes.lock().unwrap().clone();
        assert_eq!(resumes[0].as_deref(), Some("c0"));
        assert_eq!(resumes[1].as_deref(), Some("c0"), "unacknowledged cursors never advance the resume position");
        assert_eq!(resumes.last().unwrap().as_deref(), Some("c1"), "acknowledged cursors do");
        cancel.cancel();
        drop(rx);
        run.await.unwrap();
    }

    /// Reset discards the resume cursor and requests an authoritative re-read;
    /// it is never treated as deletion churn.
    #[tokio::test]
    async fn reset_discards_cursor_and_requests_resync() {
        let (watch, control) = watch(13, Duration::from_secs(3600));
        let shared = Arc::new(FakeShared::default());
        shared.feeds.lock().unwrap().push_back(vec![
            Ok(Some(change("c1"))),
            Ok(Some(NativeEvent::Reset { reason: "replay expired".to_owned() })),
        ]);
        shared.feeds.lock().unwrap().push_back(vec![Ok(None)]);
        let (tx, mut rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let run_cancel = cancel.clone();
        let run = tokio::spawn(watch.run(FakeSource { shared: shared.clone() }, None, tx, run_cancel));
        let first = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        assert!(matches!(first, WatchNotice::HeadInvalidated { .. }));
        // Unlock only: a cursor acknowledgment must not resurrect the cursor
        // the reset discarded (a late pre-reset ack is self-healing: the server
        // resets the expired cursor again and the authoritative re-read runs).
        control.acknowledge(None);
        let second = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        assert!(matches!(second, WatchNotice::Reset));
        assert!(control.acknowledged_cursor().is_none(), "reset discards the resume cursor");
        cancel.cancel();
        drop(rx);
        run.await.unwrap();
    }

    /// The independent jittered poll keeps invalidating even when no events
    /// arrive; stream failures surface explicitly and never busy-loop.
    #[tokio::test]
    async fn poll_is_independent_and_failures_surface_explicitly() {
        let (watch, control) = watch(17, Duration::from_millis(30));
        let shared = Arc::new(FakeShared::default());
        // One empty feed then permanent open failures (Transport).
        shared.feeds.lock().unwrap().push_back(vec![]);
        let (tx, mut rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let run_cancel = cancel.clone();
        let run = tokio::spawn(watch.run(FakeSource { shared: shared.clone() }, None, tx, run_cancel));
        let mut polls = 0;
        let mut unavailable = 0;
        for _ in 0..12 {
            match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap() {
                WatchNotice::HeadInvalidated { source: NoticeSource::Poll, .. } => {
                    polls += 1;
                    control.acknowledge(None);
                }
                WatchNotice::StreamUnavailable { issue: WatchIssue::Transport, .. } => {
                    unavailable += 1;
                    control.acknowledge(None);
                }
                other => panic!("unexpected notice: {other:?}"),
            }
            if polls >= 2 && unavailable >= 1 {
                break;
            }
        }
        assert!(polls >= 2, "the poll keeps discovering HEAD changes");
        assert!(unavailable >= 1, "stream failures are explicit, not silent");
        cancel.cancel();
        drop(rx);
        run.await.unwrap();
    }

    #[tokio::test]
    async fn cancellation_exits_cleanly() {
        let (watch, _control) = watch(19, Duration::from_secs(3600));
        let shared = Arc::new(FakeShared::default());
        shared.feeds.lock().unwrap().push_back(vec![]);
        let (tx, _rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let run_cancel = cancel.clone();
        let run = tokio::spawn(watch.run(FakeSource { shared }, None, tx, run_cancel));
        cancel.cancel();
        assert_eq!(tokio::time::timeout(Duration::from_secs(5), run).await.unwrap().unwrap(), WatchExit::Cancelled);
    }

    #[test]
    fn jitter_is_deterministic_and_full_jitter_stays_bounded() {
        let mut first = Jitter::new(Some(42));
        let mut second = Jitter::new(Some(42));
        for _ in 0..16 {
            assert_eq!(first.next_u64(), second.next_u64());
        }
        let mut jitter = Jitter::new(Some(7));
        for attempt in 0..12 {
            let delay = jitter.full_jitter(attempt, Duration::from_millis(500), Duration::from_secs(2));
            assert!(delay <= Duration::from_secs(2));
        }
        let low = Duration::from_secs(60);
        let high = Duration::from_secs(90);
        for _ in 0..32 {
            let value = jitter.range(low, high);
            assert!((low..=high).contains(&value));
        }
    }
}
