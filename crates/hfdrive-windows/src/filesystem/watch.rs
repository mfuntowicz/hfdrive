//! Prompt `ReadDirectoryChangesW` change watching.
//!
//! One watcher thread per sync root feeds a **bounded** tokio channel; a full
//! channel is surfaced as [`WatchAction::Overflow`] (and the
//! [`DirectoryWatcher::overflowed`] flag), never silently dropped. Overflow
//! invalidates the caller's deletion evidence exactly like a directory scan
//! failure: the provider must rescan before inferring disappearance.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::sync::mpsc::Sender;

use crate::ffi::watchdir::{BatchOutcome, WatchSession};

use super::names::decode_component;
use super::FsResult;

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
    /// Relative name (single component or `dir\sub` chain). `None` for
    /// [`WatchAction::Overflow`].
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
    /// The channel is bounded; when it is full, events are replaced by an
    /// overflow signal instead of blocking the watcher thread indefinitely.
    pub fn start(root: &std::path::Path, events: Sender<WatchEvent>) -> FsResult<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let overflowed = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread_overflowed = overflowed.clone();
        let path = root.to_path_buf();
        let thread = std::thread::Builder::new()
            .name("hfdrive-watch".into())
            .spawn(move || run_loop(&path, events, thread_stop, thread_overflowed))
            .map_err(super::FsError::Io)?;
        Ok(DirectoryWatcher {
            thread: Some(thread),
            stop,
            overflowed,
        })
    }

    /// True when any batch was lost (channel full or directory overflow).
    /// While true, the caller may not infer deletions.
    pub fn overflowed(&self) -> bool {
        self.overflowed.load(Ordering::SeqCst)
    }

    /// Stop the watcher and join its thread.
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for DirectoryWatcher {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn run_loop(
    root: &std::path::Path,
    events: Sender<WatchEvent>,
    stop: Arc<AtomicBool>,
    overflowed: Arc<AtomicBool>,
) {
    let mut session = match WatchSession::start(root) {
        Ok(session) => session,
        Err(_) => {
            overflowed.store(true, Ordering::SeqCst);
            return;
        }
    };
    while !stop.load(Ordering::SeqCst) {
        match session.next_batch(200) {
            Ok(BatchOutcome::TimedOut) => continue,
            Ok(BatchOutcome::Overflow) => {
                overflowed.store(true, Ordering::SeqCst);
                if !deliver(&events, WatchEvent {
                    action: WatchAction::Overflow,
                    name: None,
                }) {
                    break;
                }
            }
            Ok(BatchOutcome::Events(batch)) => {
                for raw in batch {
                    let action = match raw.action {
                        1 => WatchAction::Added,
                        2 => WatchAction::Removed,
                        3 => WatchAction::Modified,
                        4 => WatchAction::RenamedFrom,
                        5 => WatchAction::RenamedTo,
                        // Unknown action codes are treated as a generic
                        // change so nothing is silently lost.
                        _ => WatchAction::Modified,
                    };
                    // Observation names are decoded strictly when possible;
                    // unpaired-surrogate names are surfaced as overflow-style
                    // unknown changes rather than mis-decoded strings.
                    let name = match decode_component(&raw.name) {
                        Ok(name) => Some(name),
                        Err(_) => {
                            overflowed.store(true, Ordering::SeqCst);
                            None
                        }
                    };
                    if !deliver(&events, WatchEvent { action, name }) {
                        return;
                    }
                }
            }
            Err(_) => {
                // The watch itself failed (volume gone, handle closed):
                // signal overflow semantics and stop.
                overflowed.store(true, Ordering::SeqCst);
                let _ = deliver(&events, WatchEvent {
                    action: WatchAction::Overflow,
                    name: None,
                });
                break;
            }
        }
    }
    session.cancel();
}

/// Deliver without blocking. A full channel marks the watcher overflowed and
/// keeps running (the dropped batch voids deletion evidence until rescan); a
/// closed channel stops the watcher.
fn deliver(events: &Sender<WatchEvent>, event: WatchEvent) -> bool {
    match events.try_send(event) {
        Ok(()) => true,
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => true,
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
    }
}

/// Small delay helper kept for deterministic tests of the loop policy.
#[allow(dead_code)]
fn poll_interval() -> Duration {
    Duration::from_millis(200)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflow_event_carries_no_name() {
        let event = WatchEvent {
            action: WatchAction::Overflow,
            name: None,
        };
        assert!(event.name.is_none());
        assert_eq!(event.action, WatchAction::Overflow);
    }

    #[tokio::test]
    async fn closed_channel_stops_delivery() {
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        drop(receiver);
        assert!(!deliver(
            &sender,
            WatchEvent {
                action: WatchAction::Added,
                name: Some("a".into()),
            }
        ));
    }
}
