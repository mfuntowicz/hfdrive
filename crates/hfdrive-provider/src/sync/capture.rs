//! Stable whole-file capture: materialize, then read one coherent immutable
//! snapshot into the account/drive staging area.
//!
//! The capture boundary is what makes an upload honest:
//!
//! * a partially hydrated placeholder is **fully materialized from its bound
//!   immutable version first** — holes are never uploaded as zeroes;
//! * the source is opened denying concurrent write and delete, its stable
//!   identity/size/mtime/USN are recorded as [`CaptureEvidence`], and the
//!   staged file is flushed (`FlushFileBuffers`) before it is referenced by
//!   durable state;
//! * admission is bounded by the shared scheduler's staging budget and the
//!   volume's free space (`minimum_free_bytes`); exceeding it stops new
//!   captures but never deletes staged snapshots or dirty work;
//! * retryable failures (sharing, disk space, identity drift, partially
//!   materialized sources) retain the durable intent for retry; nothing is
//!   uploaded and nothing is marked clean.

use std::path::{Path, PathBuf};

use hfdrive_core::ids::{OperationId, SnapshotId};
use hfdrive_state::{AccountStore, RetryClass};
use hfdrive_windows::filesystem::volume::{FileState, query_file_state};
use hfdrive_windows::filesystem::{FsError, capture_snapshot};
use tokio_util::sync::CancellationToken;

use crate::scheduler::{Scheduler, WorkClass};
use crate::sync::outbox::{CaptureEvidence, StagedPayload};

/// What the caller observed before deciding to capture; the capture verifies
/// the file has not drifted away from it.
pub struct CaptureRequest {
    pub connection_id: hfdrive_core::ids::ConnectionId,
    pub source: PathBuf,
    pub staging_dir: PathBuf,
    pub item_id: hfdrive_core::ids::ItemId,
    pub operation_id: OperationId,
    pub snapshot_id: SnapshotId,
    /// The payload key identity persisted at intent time (`objects/<uuid>`).
    pub upload_id: hfdrive_core::ids::UploadId,
    /// The state observed when the intent was created, when known.
    pub expected: Option<FileState>,
    /// The connection's local root (for staging admission checks).
    pub root: PathBuf,
}

/// A fully staged, flushed, hash-verified payload with its binding evidence.
pub struct CapturedPayload {
    pub staged: StagedPayload,
    pub evidence: CaptureEvidence,
    pub warnings: Vec<hfdrive_windows::filesystem::SnapshotWarning>,
}

/// Capture failure classification. `Retry` keeps the intent and its
/// generation; `Blocked` needs a user-visible action; `Missing` means the
/// source disappeared mid-capture and must be re-observed (never uploaded,
/// never deleted).
#[derive(Debug, thiserror::Error)]
pub enum CaptureFailure {
    #[error("capture will be retried: {0}")]
    Retry(FsError),
    #[error("capture is blocked: {0}")]
    Blocked(&'static str),
    #[error("the source disappeared before capture")]
    Missing,
    #[error("capture was cancelled")]
    Cancelled,
    #[error("staging admission failed: {0}")]
    Admission(String),
}

impl CaptureFailure {
    pub fn retry_class(&self) -> RetryClass {
        match self {
            CaptureFailure::Retry(_) => RetryClass::Backoff,
            CaptureFailure::Blocked(_) => RetryClass::NeedsUser,
            CaptureFailure::Missing => RetryClass::None,
            CaptureFailure::Cancelled => RetryClass::None,
            CaptureFailure::Admission(_) => RetryClass::Backoff,
        }
    }
}

/// Materializes `path` fully when it is not resident on disk. Uses the
/// provider's own placeholder hydration path so the fetch pipeline and its
/// ranges/integrity checks run unchanged.
pub fn materialize_first(path: &Path, state: &FileState) -> Result<(), CaptureFailure> {
    if !state.identity.may_not_be_materialized() {
        return Ok(());
    }
    if state.size == 0 {
        return Ok(());
    }
    let range = hfdrive_core::storage::ByteRange::new(0, state.size, state.size)
        .map_err(|_| CaptureFailure::Blocked("source size exceeds the immutable range bound"))?;
    hfdrive_windows::cfapi::ops::hydrate_range(path, range)
        .map_err(|_| CaptureFailure::Retry(FsError::NotMaterialized))?;
    // Re-check: hydration is asynchronous at the OS level; the capture below
    // is the authoritative materialization gate and will refuse again (and
    // retry later) if bytes are still not resident.
    Ok(())
}

/// Runs one coherent capture and journals its evidence. Durable ordering:
/// `begin_snapshot` (Capturing) -> flushed staged file -> `complete_snapshot`
/// (Ready) -> transfer journal with capture evidence. Nothing external is
/// referenced before the staged file is flushed.
pub async fn capture_local_change(
    state: &AccountStore,
    scheduler: &Scheduler,
    drive: uuid::Uuid,
    request: &CaptureRequest,
    cancel: &CancellationToken,
) -> Result<CapturedPayload, CaptureFailure> {
    // 1. Observed state and materialization gate.
    let live = query_file_state(&request.source)
        .map_err(|error| classify_missing(error))?;
    if let Some(expected) = &request.expected {
        if expected.identity.file_id != live.identity.file_id
            || expected.identity.volume_serial_number != live.identity.volume_serial_number
        {
            // Atomic replacement or a different file: re-observe instead of
            // capturing against a stale identity.
            return Err(CaptureFailure::Retry(FsError::IdentityChanged));
        }
    }
    if live.identity.is_encrypted() {
        return Err(CaptureFailure::Blocked("EFS-encrypted content is not synchronized"));
    }
    if live.identity.has_multiple_links() {
        return Err(CaptureFailure::Blocked("multiply linked files are not uploaded"));
    }
    if live.identity.is_reparse_point() {
        return Err(CaptureFailure::Blocked("reparse points are not uploaded"));
    }
    materialize_first(&request.source, &live)?;
    if cancel.is_cancelled() {
        return Err(CaptureFailure::Cancelled);
    }

    // 2. Staging admission: bounded staging + always keep minimum free space.
    let admission = scheduler
        .reserve_staging(
            WorkClass::LocalEdit,
            drive,
            &request.root,
            live.size,
            cancel,
        )
        .await
        .map_err(|error| CaptureFailure::Admission(error.to_string()))?;

    // 3. Durable capture intent, then the coherent read.
    state
        .begin_snapshot(
            request.connection_id,
            request.snapshot_id,
            request.staging_dir.join(format!("{}.snap", request.snapshot_id)),
        )
        .await
        .map_err(|error| CaptureFailure::Blocked(leak_state_error(&error)))?;
    let staging_dir = request.staging_dir.clone();
    let source = request.source.clone();
    let snapshot_id = request.snapshot_id;
    let expected = request.expected.clone();
    let captured = tokio::task::spawn_blocking(move || {
        capture_snapshot(&source, &staging_dir, snapshot_id, expected.as_ref())
    })
    .await
    .map_err(|_| CaptureFailure::Cancelled)?;

    let captured = match captured {
        Ok(captured) => captured,
        Err(error) => {
            // A failed capture leaves the Capturing row for reconciliation
            // and the intent untouched; retryable classes are explicit.
            return Err(if error.retryable() {
                CaptureFailure::Retry(error)
            } else if matches!(error, FsError::Cancelled) {
                CaptureFailure::Cancelled
            } else if matches!(error, FsError::NotFound { .. }) {
                CaptureFailure::Missing
            } else {
                CaptureFailure::Blocked("capture refused the source file")
            });
        }
    };

    // 4. The staged file is flushed; only now is it safe to reference.
    let evidence = CaptureEvidence {
        volume_serial_number: captured.evidence.state_after.identity.volume_serial_number,
        file_id: captured.evidence.state_after.identity.file_id,
        size: captured.size,
        last_write_time_100ns: captured.evidence.state_after.last_write_time_100ns,
        usn: captured.evidence.usn,
    };
    state
        .complete_snapshot(
            request.connection_id,
            request.snapshot_id,
            captured.size,
            captured.sha256,
        )
        .await
        .map_err(|error| CaptureFailure::Blocked(leak_state_error(&error)))?;

    Ok(CapturedPayload {
        staged: StagedPayload {
            snapshot_id: request.snapshot_id,
            upload_id: request.upload_id,
            staged_path: captured.staged_path,
            size: captured.size,
            sha256: captured.sha256,
        },
        evidence,
        warnings: captured.evidence.warnings,
    })
}

fn classify_missing(error: FsError) -> CaptureFailure {
    match error {
        FsError::NotFound { .. } => CaptureFailure::Missing,
        error if error.retryable() => CaptureFailure::Retry(error),
        FsError::Cancelled => CaptureFailure::Cancelled,
        _ => CaptureFailure::Blocked("source file cannot be read"),
    }
}

fn leak_state_error(error: &hfdrive_state::StateError) -> &'static str {
    // State errors are structured and non-secret; the classification is all
    // the capture path needs.
    let _ = error;
    "durable state rejected the snapshot journal update"
}
