//! The provider-side callback hub: bounded per-kind queues, synchronous
//! cancellation matching and truthful queue-exhaustion completions.
//!
//! Every queue is bounded and panic-safe (the FFI trampolines contain
//! panics), and every event is an owned deep copy. When a queue is full the
//! affected request is completed right away with
//! `STATUS_CLOUD_FILE_INSUFFICIENT_RESOURCES` instead of blocking the OS
//! callback thread or silently losing the request; notification acks fail
//! truthfully for the same reason. Cancellation flags are set **synchronously
//! in the callback** so shared overlapping range interests of *other*
//! requests stay alive while the matching ones stop.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use hfdrive_core::storage::ByteRange;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::ffi::cfapi::EventSink;

use super::events::{
    CancelRanges, CompletionEvent, DeleteCompletion, DeleteNotification, FetchFailure, FetchRequest,
    PlaceholdersRequest, RenameCompletion, RenameNotification, TransferStatus,
};

/// Bounded capacities for the per-kind callback queues.
#[derive(Clone, Copy, Debug)]
pub struct QueueCapacity {
    pub fetch: usize,
    pub placeholders: usize,
    pub cancels: usize,
    pub renames: usize,
    pub deletes: usize,
    pub completions: usize,
}

impl Default for QueueCapacity {
    fn default() -> Self {
        QueueCapacity {
            fetch: 256,
            placeholders: 64,
            cancels: 256,
            renames: 128,
            deletes: 128,
            completions: 128,
        }
    }
}

/// The provider's typed receive ends of the callback queues.
pub struct ProviderStreams {
    pub fetch: Receiver<FetchRequest>,
    pub fetch_placeholders: Receiver<PlaceholdersRequest>,
    pub cancels: Receiver<CancelRanges>,
    pub renames: Receiver<RenameNotification>,
    pub deletes: Receiver<DeleteNotification>,
    pub completions: Receiver<CompletionEvent>,
}

struct Interest {
    request_key: i64,
    transfer_key: i64,
    ranges: Vec<ByteRange>,
    cancelled: Arc<AtomicBool>,
}

/// Owned by the connection and shared with the callback context.
pub(crate) struct CallbackHub {
    fetch: Sender<FetchRequest>,
    placeholders: Sender<PlaceholdersRequest>,
    cancels: Sender<CancelRanges>,
    renames: Sender<RenameNotification>,
    deletes: Sender<DeleteNotification>,
    completions: Sender<CompletionEvent>,
    interests: Mutex<HashMap<i64, Interest>>,
    dropped_completions: AtomicU64,
}

impl CallbackHub {
    pub(crate) fn new(capacity: QueueCapacity) -> (Arc<Self>, ProviderStreams) {
        let (fetch_tx, fetch_rx) = channel(capacity.fetch);
        let (placeholders_tx, placeholders_rx) = channel(capacity.placeholders);
        let (cancels_tx, cancels_rx) = channel(capacity.cancels);
        let (renames_tx, renames_rx) = channel(capacity.renames);
        let (deletes_tx, deletes_rx) = channel(capacity.deletes);
        let (completions_tx, completions_rx) = channel(capacity.completions);
        let hub = Arc::new(CallbackHub {
            fetch: fetch_tx,
            placeholders: placeholders_tx,
            cancels: cancels_tx,
            renames: renames_tx,
            deletes: deletes_tx,
            completions: completions_tx,
            interests: Mutex::new(HashMap::new()),
            dropped_completions: AtomicU64::new(0),
        });
        let streams = ProviderStreams {
            fetch: fetch_rx,
            fetch_placeholders: placeholders_rx,
            cancels: cancels_rx,
            renames: renames_rx,
            deletes: deletes_rx,
            completions: completions_rx,
        };
        (hub, streams)
    }

    /// Cancel the matching range interests (same request + overlapping
    /// range). Returns how many interests were cancelled; interests of other
    /// requests are never touched.
    pub(crate) fn cancel_matching(&self, request_key: i64, ranges: Option<&[ByteRange]>) -> usize {
        let mut cancelled = 0usize;
        if let Ok(mut interests) = self.interests.lock() {
            for interest in interests.values_mut() {
                if interest.request_key != request_key {
                    continue;
                }
                let matches = match ranges {
                    None => true,
                    Some(ranges) => ranges
                        .iter()
                        .any(|r| interest.ranges.iter().any(|i| ranges_overlap(i, r))),
                };
                if matches {
                    interest.cancelled.store(true, Ordering::SeqCst);
                    cancelled += 1;
                }
            }
        }
        cancelled
    }

    /// Drop a finished/failed request's interest bookkeeping.
    pub(crate) fn finish_request(&self, request_key: i64) {
        if let Ok(mut interests) = self.interests.lock() {
            interests.remove(&request_key);
        }
    }

    /// Completion notifications dropped because the queue was full. The
    /// provider treats a nonzero count as "observations lost: rescan".
    pub(crate) fn dropped_completions(&self) -> u64 {
        self.dropped_completions.load(Ordering::SeqCst)
    }

    fn register(&self, interest: Interest) {
        if let Ok(mut interests) = self.interests.lock() {
            interests.insert(interest.request_key, interest);
        }
    }
}

fn ranges_overlap(a: &ByteRange, b: &ByteRange) -> bool {
    a.start() < b.end_exclusive() && a.end_exclusive() > b.start()
}

impl EventSink for CallbackHub {
    fn on_fetch_data(&self, request: FetchRequest) {
        let ack = request.ack;
        let interest = Interest {
            request_key: ack.request_key,
            transfer_key: ack.transfer_key,
            ranges: std::iter::once(request.required)
                .chain(request.optional)
                .collect(),
            cancelled: request.cancelled.clone(),
        };
        self.register(interest);
        let terminal = request.terminal.clone();
        match self.fetch.try_send(request) {
            Ok(()) => terminal.disarm(),
            Err(tokio::sync::mpsc::error::TrySendError::Full(request)) => {
                self.finish_request(ack.request_key);
                request.terminal.complete(FetchFailure::ResourceExhausted);
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(request)) => {
                self.finish_request(ack.request_key);
                request.terminal.complete(FetchFailure::ProviderStopping);
            }
        }
    }

    fn on_cancel_fetch_data(&self, cancel: CancelRanges) {
        // Synchronous matching first: the flags are the authoritative stop
        // signal even if the event below cannot be delivered.
        self.cancel_matching(cancel.ack.request_key, cancel.ranges.as_deref());
        let _ = self.cancels.try_send(cancel);
    }

    fn on_fetch_placeholders(&self, request: PlaceholdersRequest) {
        if self.placeholders.try_send(request.clone()).is_err() {
            let _ = crate::ffi::cfapi::transfer_placeholders(
                request.ack,
                TransferStatus::Failed(FetchFailure::ResourceExhausted),
                0,
                &[],
            );
        }
    }

    fn on_cancel_fetch_placeholders(&self, cancel: CancelRanges) {
        let _ = self.cancels.try_send(cancel);
    }

    fn on_rename(&self, notification: RenameNotification) {
        if self.renames.try_send(notification.clone()).is_err() {
            let _ = crate::ffi::cfapi::ack_rename(
                notification.ack,
                TransferStatus::Failed(FetchFailure::ResourceExhausted),
            );
        }
    }

    fn on_delete(&self, notification: DeleteNotification) {
        if self.deletes.try_send(notification.clone()).is_err() {
            let _ = crate::ffi::cfapi::ack_delete(
                notification.ack,
                TransferStatus::Failed(FetchFailure::ResourceExhausted),
            );
        }
    }

    fn on_rename_completion(&self, completion: RenameCompletion) {
        if self
            .completions
            .try_send(CompletionEvent::Rename(completion))
            .is_err()
        {
            self.dropped_completions.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn on_delete_completion(&self, completion: DeleteCompletion) {
        if self
            .completions
            .try_send(CompletionEvent::Delete(completion))
            .is_err()
        {
            self.dropped_completions.fetch_add(1, Ordering::SeqCst);
        }
    }
}
