//! Owned, validated callback event types crossing from the CFAPI trampolines
//! to the provider. Every event deep-copies its paths and identity bytes; no
//! pointer into an OS buffer ever escapes the adapter layer.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use hfdrive_core::storage::ByteRange;

use crate::cfapi::identity::PlaceholderIdentity;

/// Keys identifying one outstanding CFAPI request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckToken {
    pub connection_key: i64,
    pub transfer_key: i64,
    pub request_key: i64,
}

/// Callback-entry terminal ownership. The guard is armed before parsing and
/// disarmed only after the callback hub accepts the request into its queue.
/// Every other exit, including panic unwinding, fails the exact required range.
#[derive(Debug)]
pub(crate) struct CallbackTerminal {
    ack: AckToken,
    offset: i64,
    length: i64,
    disarmed: AtomicBool,
    failure: Mutex<FetchFailure>,
}

impl CallbackTerminal {
    pub(crate) fn new(ack: AckToken, offset: i64, length: i64) -> Self {
        Self {
            ack,
            offset,
            length,
            disarmed: AtomicBool::new(false),
            failure: Mutex::new(FetchFailure::Internal),
        }
    }

    pub(crate) fn disarm(&self) {
        self.disarmed.store(true, Ordering::SeqCst);
    }

    pub(crate) fn fail_with(&self, failure: FetchFailure) {
        *self.failure.lock().unwrap_or_else(|error| error.into_inner()) = failure;
    }

    pub(crate) fn complete(&self, failure: FetchFailure) {
        self.fail_with(failure);
        self.complete_once();
    }

    fn complete_once(&self) {
        if self.disarmed.swap(true, Ordering::SeqCst) {
            return;
        }
        let failure = *self.failure.lock().unwrap_or_else(|error| error.into_inner());
        let _ = crate::ffi::cfapi::fail_transfer(self.ack, failure, self.offset, self.length);
    }
}

impl Drop for CallbackTerminal {
    fn drop(&mut self) {
        self.complete_once();
    }
}

/// A `FETCH_DATA` request: the immutable version to read, the required range
/// and the OS's optional read-ahead hint.
#[derive(Debug)]
pub struct FetchRequest {
    pub ack: AckToken,
    pub identity: PlaceholderIdentity,
    /// File size reported by the OS for the placeholder.
    pub file_size: u64,
    pub required: ByteRange,
    /// Optional range hint (read-ahead). Bounded to at most 4 MiB by the
    /// transfer planner regardless of what the OS asked for.
    pub optional: Option<ByteRange>,
    /// `CF_CALLBACK_FETCH_DATA_FLAG_EXPLICIT_HYDRATION` (pin/hydrate request).
    pub explicit_hydration: bool,
    /// `CF_CALLBACK_FETCH_DATA_FLAG_RECOVERY` (recovery of prior data).
    pub recovery: bool,
    /// Shared cancellation flag for this request's range interests. Set by
    /// matching `CANCEL_FETCH_DATA`; shared overlapping requests keep their
    /// own flags and stay alive.
    pub cancelled: Arc<AtomicBool>,
    pub(crate) terminal: Arc<CallbackTerminal>,
}

/// A `CANCEL_FETCH_DATA` / `CANCEL_FETCH_PLACEHOLDERS` notice.
#[derive(Clone, Debug)]
pub struct CancelRanges {
    pub ack: AckToken,
    /// Which request queue the cancellation targets.
    pub target: CancelTarget,
    /// Cancelled ranges (half-open). `None` cancels every range interest of
    /// the request.
    pub ranges: Option<Vec<ByteRange>>,
}

/// The kind of request a cancellation targets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelTarget {
    FetchData,
    FetchPlaceholders,
}

/// A `FETCH_PLACEHOLDERS` request (directory population).
#[derive(Clone, Debug)]
pub struct PlaceholdersRequest {
    pub ack: AckToken,
    /// Sync-root-relative path of the directory inside the sync root — the
    /// same spelling as [`RenameNotification::normalized_path`]. The sync
    /// root directory itself is the empty spelling.
    pub normalized_path: String,
    /// Optional search pattern supplied by the OS.
    pub pattern: Option<String>,
}

/// A `NOTIFY_RENAME` observation. Acknowledge only after the observation is
/// durably queued/persisted.
#[derive(Clone, Debug)]
pub struct RenameNotification {
    pub ack: AckToken,
    /// Current path of the item: sync-root-relative when it is inside the
    /// sync root (the root itself is the empty spelling), otherwise the
    /// OS's absolute spelling with `source_in_scope` false — an outside
    /// spelling is kept meaningful and never reinterpreted.
    pub normalized_path: String,
    /// Requested target: sync-root-relative when inside the sync root,
    /// otherwise the OS's absolute spelling (`target_in_scope` false).
    pub target_path: String,
    pub is_directory: bool,
    pub source_in_scope: bool,
    pub target_in_scope: bool,
}

/// A `NOTIFY_DELETE` observation (delete or undelete).
#[derive(Clone, Debug)]
pub struct DeleteNotification {
    pub ack: AckToken,
    /// Sync-root-relative path of the item inside the sync root (the root
    /// directory itself is the empty spelling).
    pub normalized_path: String,
    pub is_directory: bool,
    pub is_undelete: bool,
}

/// A `NOTIFY_RENAME_COMPLETION` outcome (already completed by the OS).
#[derive(Clone, Debug)]
pub struct RenameCompletion {
    /// The pre-rename source: sync-root-relative when it was inside the
    /// sync root, otherwise the OS's absolute spelling.
    pub source_path: String,
}

/// A `NOTIFY_DELETE_COMPLETION` outcome (already completed by the OS).
#[derive(Clone, Debug)]
pub struct DeleteCompletion {
    pub deleted: bool,
}

/// Completion notifications (post-facto; no acknowledgement is required).
#[derive(Clone, Debug)]
pub enum CompletionEvent {
    Rename(RenameCompletion),
    Delete(DeleteCompletion),
}

/// Terminal failure classification for a CFAPI request. Mapped to the
/// generated `STATUS_CLOUD_FILE_*` / NTSTATUS values at completion time; no
/// error text or secret crosses the boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FetchFailure {
    /// Authorization is gone: the user must sign in again.
    NeedsSignIn,
    /// The machine is offline or the network is unavailable.
    Offline,
    /// The remote content is unavailable (404/object gone).
    Missing,
    /// The request was cancelled.
    Cancelled,
    /// The remote side denied access.
    PermissionDenied,
    /// Local resource exhaustion (bounded queues, memory).
    ResourceExhausted,
    /// The request was malformed/out of bounds.
    InvalidRequest,
    /// The provider is stopping/disconnecting.
    ProviderStopping,
    /// Unclassified internal failure.
    Internal,
}

/// Completion status of a CFAPI request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferStatus {
    Success,
    Failed(FetchFailure),
}

impl TransferStatus {
    pub fn from_failure(failure: Option<FetchFailure>) -> Self {
        match failure {
            None => TransferStatus::Success,
            Some(f) => TransferStatus::Failed(f),
        }
    }
}

/// One callback batch from the OS to the provider.
#[derive(Debug)]
pub enum ProviderEvent {
    FetchData(FetchRequest),
    CancelFetchData(CancelRanges),
    FetchPlaceholders(PlaceholdersRequest),
    CancelFetchPlaceholders(CancelRanges),
    NotifyRename(RenameNotification),
    NotifyDelete(DeleteNotification),
    NotifyRenameCompletion(RenameCompletion),
    NotifyDeleteCompletion(DeleteCompletion),
}

impl ProviderEvent {
    /// The keys to use when completing (or failing) this event.
    pub fn ack(&self) -> AckToken {
        match self {
            ProviderEvent::FetchData(f) => f.ack,
            ProviderEvent::CancelFetchData(c) => c.ack,
            ProviderEvent::FetchPlaceholders(p) => p.ack,
            ProviderEvent::CancelFetchPlaceholders(c) => c.ack,
            ProviderEvent::NotifyRename(r) => r.ack,
            ProviderEvent::NotifyDelete(d) => d.ack,
            ProviderEvent::NotifyRenameCompletion(_) | ProviderEvent::NotifyDeleteCompletion(_) => {
                AckToken {
                    connection_key: 0,
                    transfer_key: 0,
                    request_key: 0,
                }
            }
        }
    }
}
