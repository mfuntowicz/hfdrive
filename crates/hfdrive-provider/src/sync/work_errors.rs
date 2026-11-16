//! Classified durable work-error recording for the activity projection.
//!
//! When a real capture, upload, publication, local-apply or transfer attempt
//! fails, the classified failure is persisted against its durable work row so
//! the read-only `list_activity` projection can show *why* work is stuck. The
//! rules enforced here:
//!
//! * **codes are a stable contract**: the UI may classify on `codes::*`; a
//!   code's meaning never changes once published;
//! * **details are safe by construction**: only the structured, non-secret
//!   error types of this crate reach a detail string. Tokens, signed URLs,
//!   authorization codes, request bodies and payload bytes never appear in
//!   them (the safe error types carry only static descriptions, error codes,
//!   item identifiers and local paths);
//! * **normal cancellation is not a failure**: shutdown, pause and per-request
//!   cancellation end work without recording a permanent fake failure;
//! * **the new failure wins**: callers record *after* any retry transition
//!   that clears stale errors for the same work, so a stored error always
//!   describes the most recent actual failure.

use hfdrive_core::ids::{ActionId, ConnectionId, OperationId, TransferId};
use hfdrive_state::{AccountStore, StateError, WorkErrorKind};

use crate::scheduler::ScheduleError;
use crate::sync::capture::CaptureFailure;
use crate::sync::publish::PublishError;
use crate::sync::remote::RemoteError;

/// Stable classified error codes. These strings are part of the activity
/// projection contract: consumers may switch on them, so new codes are added
/// and old meanings are never repurposed.
pub mod codes {
    /// A coherent capture could not be produced (see the detail).
    pub const CAPTURE_FAILED: &str = "capture_failed";
    /// The staged snapshot row or its durable evidence is unusable.
    pub const SNAPSHOT_UNAVAILABLE: &str = "snapshot_unavailable";
    /// The item's local source path is unknown or gone.
    pub const SOURCE_UNAVAILABLE: &str = "source_unavailable";
    /// The source disappeared before capture (re-observation needed).
    pub const SOURCE_MISSING: &str = "source_missing";
    /// The source changed/identity drifted during the attempt (retry).
    pub const SOURCE_CHANGED: &str = "source_changed";
    /// Another writer holds the source file.
    pub const SHARING_VIOLATION: &str = "sharing_violation";
    /// The staging volume ran out of space.
    pub const DISK_FULL: &str = "disk_full";
    /// The source is not fully materialized on disk.
    pub const NOT_MATERIALIZED: &str = "not_materialized";
    /// EFS-encrypted content is not synchronized.
    pub const ENCRYPTED_FILE: &str = "encrypted_file";
    /// Multiply linked files are not uploaded.
    pub const HARD_LINKED: &str = "hard_linked";
    /// Reparse points are not uploaded.
    pub const REPARSE_POINT: &str = "reparse_point";
    /// A capture precondition refused the source (see the detail).
    pub const CAPTURE_BLOCKED: &str = "capture_blocked";
    /// A Windows API failed during capture (see the detail for the code).
    pub const CAPTURE_OS_ERROR: &str = "capture_os_error";
    /// Capture evidence is missing for a staged payload.
    pub const CAPTURE_EVIDENCE_MISSING: &str = "capture_evidence_missing";
    /// The durable work state does not allow this step.
    pub const INVALID_STATE: &str = "invalid_state";
    /// The conditional publication lost its race; re-reconciling.
    pub const PUBLISH_PRECONDITION_FAILED: &str = "publish_precondition_failed";
    /// The conditional publication outcome is unknown; resolving by identity.
    pub const PUBLISH_AMBIGUOUS: &str = "publish_ambiguous";
    /// The pure reconciliation planner refused the round.
    pub const PLAN_FAILED: &str = "plan_failed";
    /// A guarded local apply refused or failed (see the detail).
    pub const LOCAL_APPLY_FAILED: &str = "local_apply_failed";
    /// The managed remote format is unsupported.
    pub const UNSUPPORTED_FORMAT: &str = "unsupported_format";
}

/// The stable class of a durable state failure.
pub fn state_code(error: &StateError) -> &'static str {
    match error {
        StateError::Io(_) | StateError::Database(_) | StateError::Corrupt { .. } => {
            "state_storage_failed"
        }
        StateError::WorkerStopped => "state_unavailable",
        StateError::NotAnHfDriveDatabase { .. }
        | StateError::SchemaTooNew { .. }
        | StateError::SchemaUnsupported { .. } => "state_schema_unsupported",
        StateError::NotFound { .. } => "state_record_missing",
        _ => "state_rejected",
    }
}

/// The stable class of a remote boundary failure.
pub fn remote_code(error: &RemoteError) -> &'static str {
    match error {
        RemoteError::NeedsSignIn => "needs_sign_in",
        RemoteError::PermissionDenied => "permission_denied",
        RemoteError::StorageSetupRequired => "storage_setup_required",
        RemoteError::ReadOnly => "read_only",
        RemoteError::UnsupportedFormat => "unsupported_format",
        RemoteError::RemoteContentUnavailable => "remote_content_unavailable",
        RemoteError::Transport => "transport_failed",
        RemoteError::SearchIncomplete => "search_incomplete",
        RemoteError::RateLimited { .. } => "rate_limited",
        RemoteError::SourceChanged => "source_changed",
        RemoteError::Rejected { .. } => "remote_rejected",
        RemoteError::InvalidResponse => "invalid_response",
        RemoteError::Cancelled => "cancelled",
    }
}

/// The stable class of a scheduler admission failure.
pub fn schedule_code(error: &ScheduleError) -> &'static str {
    match error {
        ScheduleError::Busy => "scheduler_busy",
        ScheduleError::Cancelled => "cancelled",
        ScheduleError::Paused => "paused",
        ScheduleError::Offline => "offline",
        ScheduleError::Metered => "metered",
        ScheduleError::DiskFull => "disk_full",
        ScheduleError::ReservationTooLarge => "reservation_too_large",
    }
}

/// The stable class of a capture failure. `Retry` classes carry their real
/// filesystem cause so a stuck capture can be acted on.
pub fn capture_code(error: &CaptureFailure) -> &'static str {
    match error {
        CaptureFailure::Retry(error) => fs_code(error),
        CaptureFailure::Blocked(_) => codes::CAPTURE_BLOCKED,
        CaptureFailure::Missing => codes::SOURCE_MISSING,
        CaptureFailure::Cancelled => "cancelled",
        CaptureFailure::Admission { code, .. } => code,
    }
}

fn fs_code(error: &hfdrive_windows::filesystem::FsError) -> &'static str {
    use hfdrive_windows::filesystem::FsError;
    match error {
        FsError::NotFound { .. } => codes::SOURCE_MISSING,
        FsError::SourceChanged | FsError::IdentityChanged => codes::SOURCE_CHANGED,
        FsError::SharingViolation => codes::SHARING_VIOLATION,
        FsError::DiskFull => codes::DISK_FULL,
        FsError::NotMaterialized => codes::NOT_MATERIALIZED,
        FsError::EncryptedFile => codes::ENCRYPTED_FILE,
        FsError::HardLinked => codes::HARD_LINKED,
        FsError::ReparsePoint { .. } => codes::REPARSE_POINT,
        FsError::Cancelled => "cancelled",
        FsError::Win32 { .. } => codes::CAPTURE_OS_ERROR,
        _ => codes::CAPTURE_FAILED,
    }
}

/// Classifies one publication-loop failure into a stable code and its safe
/// detail text.
///
/// Data minimization, not text filtering: `RemoteError::Rejected` carries an
/// arbitrary remote-supplied string (it may embed signed URLs, tokens or
/// echoed request fragments), so its `detail` is **discarded** and replaced
/// with this fixed classified message — arbitrary text can never propagate
/// by construction. Every other variant's detail is its own structured,
/// non-secret rendering (static descriptions, error codes, file identities,
/// local paths). Classified codes are preserved exactly.
pub fn publish_error_parts(error: &PublishError) -> (&'static str, String) {
    let code = match error {
        PublishError::Plan(_) => codes::PLAN_FAILED,
        PublishError::Remote(error) => remote_code(error),
        PublishError::State(error) => state_code(error),
        PublishError::Capture { code, .. } => code,
        PublishError::LocalApply(_) => codes::LOCAL_APPLY_FAILED,
        PublishError::UnsupportedFormat => codes::UNSUPPORTED_FORMAT,
        PublishError::Cancelled => "cancelled",
    };
    let detail = match error {
        PublishError::Remote(RemoteError::Rejected { .. }) => {
            "the remote request was rejected".to_owned()
        }
        _ => error.to_string(),
    };
    (code, detail)
}

/// True when the failure is ordinary cancellation (shutdown, pause or a
/// per-request cancel). Cancellation is not recorded as a permanent failure.
pub fn publish_is_cancellation(error: &PublishError) -> bool {
    matches!(
        error,
        PublishError::Cancelled | PublishError::Remote(RemoteError::Cancelled)
    )
}

/// Records one classified failure against one durable work row. `code` and
/// `detail` MUST come from the safe classifiers above (data minimization at
/// the classifier, not text filtering here). A failure to record is a
/// warning only: the work itself must continue its retry semantics.
pub async fn record_error(
    state: &AccountStore,
    connection_id: ConnectionId,
    kind: WorkErrorKind,
    work_id: uuid::Uuid,
    code: &str,
    detail: &str,
) {
    if let Err(error) = state
        .record_work_error(connection_id, kind, work_id, code.to_owned(), detail.to_owned())
        .await
    {
        tracing::warn!(code, "work error could not be recorded: {}", state_code(&error));
    }
}

/// Records one publication-loop failure against one durable work row.
/// Cancellation is skipped: it is not a permanent failure.
pub async fn record_publish_error(
    state: &AccountStore,
    connection_id: ConnectionId,
    kind: WorkErrorKind,
    work_id: uuid::Uuid,
    error: &PublishError,
) {
    if publish_is_cancellation(error) {
        return;
    }
    let (code, detail) = publish_error_parts(error);
    record_error(state, connection_id, kind, work_id, code, &detail).await;
}

/// Records one classified failure against an outbox operation.
pub async fn record_outbox_error(
    state: &AccountStore,
    connection_id: ConnectionId,
    operation: OperationId,
    code: &str,
    detail: &str,
) {
    record_error(state, connection_id, WorkErrorKind::Outbox, *operation.as_uuid(), code, detail)
        .await;
}

/// Records one publication-loop failure against an outbox operation.
pub async fn record_outbox_failure(
    state: &AccountStore,
    connection_id: ConnectionId,
    operation: OperationId,
    error: &PublishError,
) {
    record_publish_error(state, connection_id, WorkErrorKind::Outbox, *operation.as_uuid(), error)
        .await;
}

/// Records one publication-loop failure against a journaled local action.
pub async fn record_action_failure(
    state: &AccountStore,
    connection_id: ConnectionId,
    action: ActionId,
    error: &PublishError,
) {
    record_publish_error(state, connection_id, WorkErrorKind::Action, *action.as_uuid(), error).await;
}

/// Records one publication-loop failure against a transfer journal row.
pub async fn record_transfer_failure(
    state: &AccountStore,
    connection_id: ConnectionId,
    transfer: TransferId,
    error: &PublishError,
) {
    record_publish_error(
        state,
        connection_id,
        WorkErrorKind::Transfer,
        *transfer.as_uuid(),
        error,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_is_not_a_permanent_failure() {
        assert!(publish_is_cancellation(&PublishError::Cancelled));
        assert!(publish_is_cancellation(&PublishError::Remote(RemoteError::Cancelled)));
        assert!(!publish_is_cancellation(&PublishError::Remote(RemoteError::Transport)));
        assert!(!publish_is_cancellation(&PublishError::UnsupportedFormat));
        // Shutdown-like capture cancellation is classified as cancellation too.
        assert_eq!(
            capture_code(&CaptureFailure::Cancelled),
            "cancelled",
            "normal cancellation must not be reported as a failure class"
        );
    }

    #[test]
    fn failure_classes_are_stable_and_actual() {
        assert_eq!(
            publish_error_parts(&PublishError::Remote(RemoteError::Transport)).0,
            "transport_failed"
        );
        assert_eq!(
            publish_error_parts(&PublishError::State(StateError::WorkerStopped)).0,
            "state_unavailable"
        );
        assert_eq!(
            publish_error_parts(&PublishError::Capture {
                code: codes::SNAPSHOT_UNAVAILABLE,
                detail: "staged snapshot row is missing".to_owned(),
            })
            .0,
            codes::SNAPSHOT_UNAVAILABLE
        );
        assert_eq!(
            publish_error_parts(&PublishError::LocalApply("guarded apply refused")).0,
            codes::LOCAL_APPLY_FAILED
        );
        // Admission failures keep their real scheduler class.
        let admission = CaptureFailure::Admission {
            code: schedule_code(&ScheduleError::DiskFull),
            detail: "staging admission refused".to_owned(),
        };
        assert_eq!(capture_code(&admission), codes::DISK_FULL);
    }

    #[test]
    fn rejected_text_never_propagates_to_the_persisted_detail() {
        // Data minimization, not redaction: whatever arbitrary text the
        // remote embeds in `Rejected.detail` (signed URLs, tokens, echoed
        // request fragments, anything) must never reach the persisted
        // detail — the fixed classified message replaces it by construction.
        let sentinels = [
            "https://cas.hf.co/x?X-Amz-Signature=deadbeefcafe1234",
            "Bearer hf_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd",
            "hf_QQQQQQQQrrrrrrrrsssssssstttttttt00000000",
            "AKIAABCDEFGHIJKLMNOPQRSTUVWXYZ0123",
            "client_secret=supersecretvalue",
            "arbitrary fragment with \u{1F511} in it",
        ];
        for sentinel in sentinels {
            let (code, detail) =
                publish_error_parts(&PublishError::Remote(RemoteError::Rejected {
                    detail: sentinel.to_owned(),
                }));
            assert_eq!(code, "remote_rejected", "classified codes are preserved");
            assert_eq!(
                detail, "the remote request was rejected",
                "rejected text {sentinel:?} must never propagate"
            );
        }
        // The fixed message is itself useful and safe, whatever the input.
        let (_, empty_detail) = publish_error_parts(&PublishError::Remote(RemoteError::Rejected {
            detail: String::new(),
        }));
        assert_eq!(empty_detail, "the remote request was rejected");

        // Known-safe structured metadata of other variants is retained.
        let (code, detail) = publish_error_parts(&PublishError::Capture {
            code: codes::SOURCE_CHANGED,
            detail: "file identity does not match the expected state".to_owned(),
        });
        assert_eq!(code, codes::SOURCE_CHANGED);
        assert!(detail.contains("file identity"), "safe structured detail survives");
    }
}
