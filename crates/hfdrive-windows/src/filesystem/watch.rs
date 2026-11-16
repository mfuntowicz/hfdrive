//! Prompt `ReadDirectoryChangesW` change watching.
//!
//! One watcher thread per sync root feeds a **bounded** tokio channel; a full
//! channel is surfaced as [`WatchAction::Overflow`] (and the
//! [`DirectoryWatcher::overflowed`] flag), never silently dropped. Overflow
//! invalidates the caller's deletion evidence exactly like a directory scan
//! failure: the provider must rescan before inferring disappearance.
//!
//! [`DirectoryWatcher::start`] reports arming truthfully: it returns `Ok` only
//! after the native watch is armed on the worker thread; an unarmed watch is a
//! start failure (`Err`), never a silently dead watcher. The only wait observed
//! as quiet is the OS wait timeout — a wait or I/O failure ends (or gaps) the
//! watch with an overflow signal, so observation loss is always surfaced.
//!
//! Loss-notice policy: whenever an event cannot be delivered (channel full) or
//! a batch is lost (buffer overflow, malformed chain, undecodable name, failed
//! request), the sticky flag is set and an [`WatchAction::Overflow`] notice is
//! latched until the consumer's channel accepts it. The notice is retried every
//! loop cycle, so a consumer that keeps draining always learns about the loss.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::sync::mpsc::Sender;

use crate::ffi::watchdir::{BatchOutcome, RawNotify, WatchSession};

use super::names::{validate_component, NameCheckError};
use super::{FsError, FsResult};

/// Change action for one relative name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchAction {
    Added,
    Removed,
    Modified,
    RenamedFrom,
    RenamedTo,
    /// No per-name information: the watch buffer overflowed and every
    /// deletion inference since the last rescan is void.
    Overflow,
}

/// One change observation.
#[derive(Clone, Debug)]
pub struct WatchEvent {
    pub action: WatchAction,
    /// Relative name (`dir\sub` chain). `None` for [`WatchAction::Overflow`].
    pub name: Option<String>,
}

/// An armed directory watcher. Dropping it stops the thread.
pub struct DirectoryWatcher {
    thread: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    overflowed: Arc<AtomicBool>,
}

impl DirectoryWatcher {
    /// Start watching `root` (whole subtree) and deliver events to `events`.
    ///
    /// Returns `Ok` only after the native watch is armed. Arming failures are
    /// returned instead of leaving a silently dead watcher. A full delivery
    /// channel records observation loss without blocking the native thread.
    pub fn start(root: &std::path::Path, events: Sender<WatchEvent>) -> FsResult<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let overflowed = Arc::new(AtomicBool::new(false));
        let (armed_tx, armed_rx) = std_mpsc::channel();
        let thread_stop = stop.clone();
        let thread_overflowed = overflowed.clone();
        let path = root.to_path_buf();
        let thread = std::thread::Builder::new()
            .name("hfdrive-watch".into())
            .spawn(move || {
                // The session is created and armed here, on the worker thread,
                // so its `OVERLAPPED`/buffer never move after arming; the
                // handshake reports the arming outcome before the first wait.
                let mut session = match WatchSession::start(&path) {
                    Ok(session) => session,
                    Err(code) => {
                        thread_overflowed.store(true, Ordering::SeqCst);
                        let _ = armed_tx.send(Err(code));
                        return;
                    }
                };
                let _ = armed_tx.send(Ok(()));
                run_loop(&mut session, events, thread_stop, thread_overflowed);
            })
            .map_err(|err| {
                overflowed.store(true, Ordering::SeqCst);
                FsError::Io(err)
            })?;
        // The worker sends its outcome before its first wait; `recv` also
        // returns `Disconnected` if it died first, so nothing is hidden.
        match armed_rx.recv() {
            Ok(Ok(())) => Ok(DirectoryWatcher {
                thread: Some(thread),
                stop,
                overflowed,
            }),
            Ok(Err(code)) => {
                overflowed.store(true, Ordering::SeqCst);
                let _ = thread.join();
                Err(FsError::Win32 {
                    operation: "ReadDirectoryChangesW(arm)",
                    code,
                })
            }
            Err(_) => {
                overflowed.store(true, Ordering::SeqCst);
                let _ = thread.join();
                Err(FsError::Io(std::io::Error::other(
                    "watch worker failed before arming the directory watch",
                )))
            }
        }
    }

    /// True when any batch was lost (channel full, directory overflow, wait or
    /// I/O failure, or an undecodable name). While true, the caller may not
    /// infer deletions.
    pub fn overflowed(&self) -> bool {
        self.overflowed.load(Ordering::SeqCst)
    }

    /// Start fresh loss accounting before an authoritative metadata scan.
    pub fn clear_overflowed(&self) {
        self.overflowed.store(false, Ordering::SeqCst);
    }

    /// Stop the watcher and join its thread. Idempotent; at most one join runs,
    /// and the running watch thread never joins itself.
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            if thread.thread().id() == std::thread::current().id() {
                // Never join the running thread from itself.
                return;
            }
            let _ = thread.join();
        }
    }
}

impl Drop for DirectoryWatcher {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The watch loop. The session is armed on entry and each batch is re-armed
/// before it is delivered, so no change window is uncovered. Observation loss
/// of any kind sets the overflow flag and latches an overflow notice; the loop
/// only ends after surfacing the reason (channel closed, watch failure).
fn run_loop(
    session: &mut WatchSession,
    events: Sender<WatchEvent>,
    stop: Arc<AtomicBool>,
    overflowed: Arc<AtomicBool>,
) {
    let mut notice_pending = false;
    while !stop.load(Ordering::SeqCst) {
        // Surface a latched loss notice before anything else; retry every
        // cycle until the consumer's channel accepts it.
        if notice_pending {
            match flush_notice(&events) {
                NoticeFlush::Queued => notice_pending = false,
                NoticeFlush::Full => {}
                NoticeFlush::Closed => break,
            }
        }
        match session.next_batch(200) {
            Ok(BatchOutcome::TimedOut) => continue,
            Ok(BatchOutcome::Overflow) => {
                // The directory changed faster than the buffer could report:
                // deletion evidence is void until a rescan.
                overflowed.store(true, Ordering::SeqCst);
                notice_pending = true;
            }
            Ok(BatchOutcome::Events(batch)) => {
                for raw in batch {
                    if !deliver_notify(&events, &overflowed, &mut notice_pending, raw) {
                        return;
                    }
                }
            }
            Err(code) => {
                // Wait failure or a dead handle: the watch itself failed.
                // Surface overflow semantics (deletion evidence void) with the
                // code for diagnostics, then stop.
                tracing::debug!(
                    target: "hfdrive_windows::watch",
                    code,
                    "watch wait failed; observation stops with overflow"
                );
                overflowed.store(true, Ordering::SeqCst);
                notice_pending = true;
                break;
            }
        }
    }
    if notice_pending {
        let _ = flush_notice(&events);
    }
    session.cancel();
}

/// Deliver one raw notification. An undecodable name is observation loss: the
/// overflow flag is set, a loss notice is latched, and the record is not
/// delivered — nothing is silently dropped or mis-decoded.
fn deliver_notify(
    events: &Sender<WatchEvent>,
    overflowed: &AtomicBool,
    notice_pending: &mut bool,
    raw: RawNotify,
) -> bool {
    let action = match raw.action {
        1 => WatchAction::Added,
        2 => WatchAction::Removed,
        3 => WatchAction::Modified,
        4 => WatchAction::RenamedFrom,
        5 => WatchAction::RenamedTo,
        // Unknown action codes are treated as a generic change so nothing is
        // silently lost.
        _ => WatchAction::Modified,
    };
    // Observation names are decoded component-by-component when possible;
    // unpaired-surrogate or invalid-component names are surfaced as loss
    // rather than mis-decoded strings.
    let name = match decode_relative_path(&raw.name) {
        Ok(name) => Some(name),
        Err(_) => {
            overflowed.store(true, Ordering::SeqCst);
            *notice_pending = true;
            return true;
        }
    };
    deliver(
        events,
        overflowed,
        notice_pending,
        WatchEvent { action, name },
    )
}

/// Deliver one event without blocking. A full channel marks the watcher
/// overflowed and latches a loss notice (the dropped event voids deletion
/// evidence until rescan); a closed channel stops the watcher.
fn deliver(
    events: &Sender<WatchEvent>,
    overflowed: &AtomicBool,
    notice_pending: &mut bool,
    event: WatchEvent,
) -> bool {
    match events.try_send(event) {
        Ok(()) => true,
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            overflowed.store(true, Ordering::SeqCst);
            *notice_pending = true;
            true
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
    }
}

/// Result of trying to queue the latched overflow notice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NoticeFlush {
    /// The notice is queued; the latch may clear.
    Queued,
    /// The channel is still full; keep the latch and retry.
    Full,
    /// The channel is closed; the watcher must stop.
    Closed,
}

/// Try to queue the overflow notice on the consumer's channel.
fn flush_notice(events: &Sender<WatchEvent>) -> NoticeFlush {
    let notice = WatchEvent {
        action: WatchAction::Overflow,
        name: None,
    };
    match events.try_send(notice) {
        Ok(()) => NoticeFlush::Queued,
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => NoticeFlush::Full,
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => NoticeFlush::Closed,
    }
}

/// Decode one root-relative wide name into a `\`-separated relative path,
/// validating every component exactly as the namespace requires. `\` is the
/// only separator `ReadDirectoryChangesW` produces and it is forbidden inside
/// a component name.
fn decode_relative_path(units: &[u16]) -> Result<String, NameCheckError> {
    if units.is_empty() {
        return Err(NameCheckError::Empty);
    }
    let path = String::from_utf16(units).map_err(|_| NameCheckError::ForbiddenCharacter)?;
    for component in path.split('\\') {
        validate_component(component)?;
    }
    Ok(path)
}

/// Small delay helper kept for deterministic tests of the loop policy.
#[allow(dead_code)]
fn poll_interval() -> Duration {
    Duration::from_millis(200)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unitize(name: &str) -> Vec<u16> {
        name.encode_utf16().collect()
    }

    fn added(name: &str) -> WatchEvent {
        WatchEvent {
            action: WatchAction::Added,
            name: Some(name.to_owned()),
        }
    }

    #[test]
    fn overflow_event_carries_no_name() {
        let event = WatchEvent {
            action: WatchAction::Overflow,
            name: None,
        };
        assert!(event.name.is_none());
        assert_eq!(event.action, WatchAction::Overflow);
    }

    #[test]
    fn relative_paths_decode_component_by_component() {
        assert_eq!(
            decode_relative_path(&unitize("created.txt")).unwrap(),
            "created.txt"
        );
        assert_eq!(
            decode_relative_path(&unitize("sub\\deep\\file.bin")).unwrap(),
            "sub\\deep\\file.bin"
        );
        // An empty or invalid component is observation loss, not a guess.
        assert!(decode_relative_path(&[]).is_err());
        assert!(decode_relative_path(&unitize("a\\\\b")).is_err());
        assert!(decode_relative_path(&unitize("bad.")).is_err());
    }

    #[tokio::test]
    async fn closed_channel_stops_delivery() {
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        drop(receiver);
        let overflowed = AtomicBool::new(false);
        let mut notice_pending = false;
        // A closed channel stops the watcher; it is not an observation loss
        // (the consumer intentionally went away), so no overflow is flagged.
        assert!(!deliver(&sender, &overflowed, &mut notice_pending, added("a")));
        assert!(!overflowed.load(Ordering::SeqCst));
        assert_eq!(flush_notice(&sender), NoticeFlush::Closed);
    }

    #[tokio::test]
    async fn dropped_events_surface_the_loss_and_retry_the_notice() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let overflowed = AtomicBool::new(false);
        let mut notice_pending = false;
        // The one slot fills, then a further event is dropped: the loss is
        // flagged and a notice latched, but the full channel cannot take it.
        assert!(deliver(&sender, &overflowed, &mut notice_pending, added("first")));
        assert!(deliver(&sender, &overflowed, &mut notice_pending, added("second")));
        assert!(overflowed.load(Ordering::SeqCst), "loss is surfaced");
        assert!(notice_pending);
        assert_eq!(flush_notice(&sender), NoticeFlush::Full);
        // Once the consumer drains, the latched notice lands — a consumer that
        // keeps reading always learns about the loss.
        let first = receiver.recv().await.expect("queued event");
        assert_eq!(first.name.as_deref(), Some("first"));
        assert_eq!(flush_notice(&sender), NoticeFlush::Queued);
        let notice = receiver.recv().await.expect("loss notice");
        assert_eq!(notice.action, WatchAction::Overflow);
        assert!(notice.name.is_none());
    }

    /// End-to-end observation on an ordinary disposable temp directory: a
    /// newly created file and a file in a new subdirectory must both surface
    /// with their exact root-relative names, and shutdown must join promptly.
    /// No cloud registration, network or user-root actions are involved.
    #[cfg(windows)]
    #[test]
    fn new_files_in_root_and_subtree_are_observed() {
        use std::fs;
        use std::time::Instant;

        let dir = tempfile::tempdir().expect("temp directory");
        let root = dir.path().to_path_buf();
        let (sender, mut receiver) = tokio::sync::mpsc::channel(64);
        let mut watcher =
            DirectoryWatcher::start(&root, sender).expect("watch arms on a plain directory");

        fs::write(root.join("created.txt"), b"x").expect("create in root");
        fs::create_dir(root.join("sub")).expect("create subdirectory");
        fs::write(root.join("sub").join("nested.txt"), b"y").expect("create in subtree");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        let events: Vec<WatchEvent> = runtime.block_on(async {
            let mut events = Vec::new();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            let mut saw_root_file = false;
            let mut saw_subtree_file = false;
            while !(saw_root_file && saw_subtree_file) {
                let remaining = deadline
                    .checked_duration_since(tokio::time::Instant::now())
                    .expect("observation within timeout");
                let event = tokio::time::timeout(remaining, receiver.recv())
                    .await
                    .expect("event within timeout")
                    .expect("channel stays open");
                if event.action == WatchAction::Added {
                    match event.name.as_deref() {
                        Some("created.txt") => saw_root_file = true,
                        Some("sub\\nested.txt") => saw_subtree_file = true,
                        _ => {}
                    }
                }
                events.push(event);
            }
            events
        });

        assert!(
            events
                .iter()
                .any(|event| event.action == WatchAction::Added
                    && event.name.as_deref() == Some("created.txt")),
            "root file observed: {events:?}"
        );
        assert!(
            events
                .iter()
                .any(|event| event.action == WatchAction::Added
                    && event.name.as_deref() == Some("sub\\nested.txt")),
            "subtree file observed under its root-relative name: {events:?}"
        );
        assert!(!watcher.overflowed(), "no loss in a quiet tree");

        let started = Instant::now();
        watcher.shutdown();
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "shutdown joins promptly"
        );
        // Idempotent.
        watcher.shutdown();
    }
}
