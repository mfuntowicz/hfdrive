//! Stable whole-file capture: materialize, then read one coherent immutable
//! snapshot into the account/drive staging area.
//!
//! The capture boundary is what makes an upload honest:
//!
//! * a partially hydrated placeholder is **fully materialized from its bound
//!   immutable version first** — holes are never uploaded as zeroes;
//! * a **verified owned HFDR placeholder** is recaptured in place from its
//!   edited local bytes and bound to its own item/workspace identity; a
//!   foreign reparse point (junction, symlink, another provider's
//!   placeholder) is rejected and never followed;
//! * the capture reads exactly the file its gate observed: the capture's
//!   expected observation is taken at this boundary after materialization and
//!   bound to the coherent handle, so a replacement — a substituted plain
//!   file or a link at the path — fails the identity binding before any
//!   payload byte is read or staged;
//! * the source is opened denying concurrent write and delete, its stable
//!   identity/size/mtime/USN are recorded as [`CaptureEvidence`], and the
//!   staged file is flushed (`FlushFileBuffers`) before it is referenced by
//!   durable state;
//! * the coherent read is bound to the state observed at capture entry: a
//!   path replacement in that window — even an ordinary file, even a
//!   same-size/same-timestamp one — is drift ([`FsError::IdentityChanged`],
//!   retried after re-observation), never accepted snapshot bytes;
//! * admission is bounded by the shared scheduler's staging budget and the
//!   volume's free space (`minimum_free_bytes`); exceeding it stops new
//!   captures but never deletes staged snapshots or dirty work;
//! * retryable failures (sharing, disk space, identity drift, partially
//!   materialized sources) retain the durable intent for retry; nothing is
//!   uploaded and nothing is marked clean.

use std::path::{Path, PathBuf};

use hfdrive_core::ids::{ItemId, OperationId, SnapshotId, WorkspaceId};
use hfdrive_state::{AccountStore, RetryClass};
use hfdrive_windows::cfapi::identity::PlaceholderIdentity;
use hfdrive_windows::filesystem::volume::{FileState, query_file_state};
use hfdrive_windows::filesystem::snapshot::{capture_snapshot_with, PlaceholderPolicy};
use hfdrive_windows::filesystem::FsError;
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
    /// The state observed when the intent was created, when known. It binds
    /// the intent to one file (identity only: materialization may legitimately
    /// advance the USN); the capture additionally takes its own real
    /// post-materialization observation and refuses any replacement — plain
    /// file or link — before payload use.
    pub expected: Option<FileState>,
    /// The connection's workspace: a recaptured placeholder must belong to
    /// it, or the capture is refused and re-observed — never re-bound.
    pub workspace: WorkspaceId,
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
    /// Staging admission refused the capture. `code` is the classified
    /// scheduler class (`work_errors::codes`), `detail` a safe description.
    #[error("staging admission failed: {detail}")]
    Admission { code: &'static str, detail: String },
}

impl CaptureFailure {
    pub fn retry_class(&self) -> RetryClass {
        match self {
            CaptureFailure::Retry(_) => RetryClass::Backoff,
            CaptureFailure::Blocked(_) => RetryClass::NeedsUser,
            CaptureFailure::Missing => RetryClass::None,
            CaptureFailure::Cancelled => RetryClass::None,
            CaptureFailure::Admission { .. } => RetryClass::Backoff,
        }
    }

    /// The classified stable error code of this failure, for the durable
    /// work-error record. Cancellation is reported as such and is never
    /// recorded as a permanent failure by callers.
    pub fn error_code(&self) -> &'static str {
        crate::sync::work_errors::capture_code(self)
    }

    /// The safe detail text of this failure (static descriptions and
    /// structured error codes only — never tokens, URLs or payload bytes).
    pub fn detail(&self) -> String {
        self.to_string()
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
/// `begin_snapshot` (Capturing) -> `bind_snapshot_operation` (capture bound
/// to its operation) -> flushed staged file -> `complete_snapshot`
/// (Ready) -> transfer journal with capture evidence. Nothing external is
/// referenced before the staged file is flushed.
pub async fn capture_local_change(
    state: &AccountStore,
    scheduler: &Scheduler,
    drive: uuid::Uuid,
    request: &CaptureRequest,
    cancel: &CancellationToken,
) -> Result<CapturedPayload, CaptureFailure> {
    // 1. Observed state, ownership gate and materialization gate.
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
    // Ownership gate: only a verified owned HFDR placeholder of this
    // connection's workspace, carrying this very item's identity, is ever
    // recaptured in place. A foreign link — junction, symlink, another
    // provider's placeholder, a corrupt or cross-workspace HFDR record — is
    // rejected without being followed or read. The identity lookup is
    // consulted only for reparse points.
    let lookup = if live.identity.is_reparse_point() {
        hfdrive_windows::cfapi::ops::read_placeholder_identity(
            &request.source,
            Some(request.workspace),
        )
        .map_err(|_| ())
    } else {
        Ok(None)
    };
    let approved = gate_source(&live, lookup, request.workspace, request.item_id)?;
    materialize_first(&request.source, &live)?;
    if cancel.is_cancelled() {
        return Err(CaptureFailure::Cancelled);
    }

    // 2. Staging admission: bounded staging + always keep minimum free space.
    let _admission = scheduler
        .reserve_staging(
            WorkClass::LocalEdit,
            drive,
            &request.root,
            live.size,
            cancel,
        )
        .await
        .map_err(|error| CaptureFailure::Admission {
            code: crate::sync::work_errors::schedule_code(&error),
            detail: error.to_string(),
        })?;

    // 3. Durable capture intent, then the coherent read. The snapshot row is
    //    bound to its operation immediately after creation so the activity
    //    projection can prove this capture is really in flight for this work.
    state
        .begin_snapshot(
            request.connection_id,
            request.snapshot_id,
            request.staging_dir.join(format!("{}.snap", request.snapshot_id)),
        )
        .await
        .map_err(|error| CaptureFailure::Blocked(leak_state_error(&error)))?;
    state
        .bind_snapshot_operation(
            request.connection_id,
            request.snapshot_id,
            request.operation_id,
        )
        .await
        .map_err(|error| CaptureFailure::Blocked(leak_state_error(&error)))?;

    // 3b. Bind the capture to a **real** expected observation taken at this
    //     boundary after materialization — never to `expected: None`'s "accept
    //     anything". The coherent read may only ever come from the file this
    //     observation describes: a replacement in the window since the gate —
    //     a substituted plain file or a link at the path — fails the identity
    //     binding before any payload byte is read or staged. The policy binds
    //     the read to the exact placeholder identity the gate approved, or
    //     refuses every reparse point for an ordinary file.
    seams::before_coherent_capture(&request.source);
    let observed = query_file_state(&request.source).map_err(classify_missing)?;
    let lookup_now = if observed.identity.is_reparse_point() {
        hfdrive_windows::cfapi::ops::read_placeholder_identity(
            &request.source,
            Some(request.workspace),
        )
        .map_err(|_| ())
    } else {
        Ok(None)
    };
    let policy = bind_capture_source(
        approved,
        &live,
        &observed,
        lookup_now,
        request.workspace,
        request.item_id,
    )?;

    let staging_dir = request.staging_dir.clone();
    let source = request.source.clone();
    let snapshot_id = request.snapshot_id;
    // The coherent capture is bound to the **real** observation taken at step
    // 3b (the capture boundary, after materialization) — never to `expected:
    // None`'s "accept anything". The policy additionally binds the read to the
    // exact placeholder identity the gate approved (or refuses every reparse
    // point for an ordinary file), so a replacement — a substituted plain file
    // or a link at the path — fails before any payload byte is read or staged.
    let captured = tokio::task::spawn_blocking(move || {
        capture_snapshot_with(
            &source,
            &staging_dir,
            snapshot_id,
            Some(&observed),
            policy,
        )
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

    // 3c. The captured source must still be the one the ownership gate
    //     approved: an owned placeholder that turned into something else
    //     mid-capture is drift, and its staged bytes are never bound to this
    //     work.
    if captured.evidence.placeholder != approved {
        return Err(CaptureFailure::Retry(FsError::IdentityChanged));
    }

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

/// Ownership gate at the capture boundary. Pure decision over the observed
/// state and the (reparse-only) identity lookup result:
///
/// * EFS and multiply linked sources are refused outright;
/// * a plain local file passes with no placeholder identity;
/// * a reparse point passes **only** as a verified owned HFDR placeholder of
///   this connection's workspace carrying this item's identity. A foreign
///   link, an unreadable identity, a cross-workspace record or a placeholder
///   of another item is rejected — a foreign link permanently, a stale
///   binding as retryable drift so the intent is re-observed, never rebound.
fn gate_source(
    live: &FileState,
    lookup: Result<Option<PlaceholderIdentity>, ()>,
    workspace: WorkspaceId,
    item_id: ItemId,
) -> Result<Option<PlaceholderIdentity>, CaptureFailure> {
    if live.identity.is_encrypted() {
        return Err(CaptureFailure::Blocked("EFS-encrypted content is not synchronized"));
    }
    if live.identity.has_multiple_links() {
        return Err(CaptureFailure::Blocked("multiply linked files are not uploaded"));
    }
    if !live.identity.is_reparse_point() {
        return Ok(None);
    }
    let placeholder = lookup
        .map_err(|_| CaptureFailure::Blocked("placeholder identity could not be verified"))?
        .ok_or(CaptureFailure::Blocked("foreign reparse points are never uploaded"))?;
    if placeholder.workspace != workspace {
        // An HFDR record from another workspace is never re-bound to this
        // connection's work.
        return Err(CaptureFailure::Retry(FsError::IdentityChanged));
    }
    if placeholder.item != item_id {
        // The path holds a different item's placeholder now: the intent is
        // stale and must be re-observed, never rebound to this work.
        return Err(CaptureFailure::Retry(FsError::IdentityChanged));
    }
    Ok(Some(placeholder))
}

/// Binds the coherent capture to the gate's verdict and the boundary
/// observation, and returns the placeholder policy the capture is checked
/// against ([`PlaceholderPolicy::RecaptureBound`] for the one approved
/// identity, [`PlaceholderPolicy::Refuse`] for an ordinary file).
///
/// The capture boundary re-observes the source after materialization; this
/// decision refuses anything that observation no longer shares with the
/// step-1 gate:
///
/// * the path must still name the same file (identity only: materialization
///   legitimately advances the USN and clears recall attributes). A
///   replacement since the gate — **even an ordinary file** — is
///   [`FsError::IdentityChanged`] drift: retried after re-observation,
///   never captured as this work's bytes;
/// * the ownership gate must reach the identical verdict for the boundary
///   observation. A plain target that became a placeholder or the reverse,
///   a placeholder of another item/workspace, or an identity that cannot be
///   verified right now is never rebound — the gate's own classification
///   applies, and a stale binding is retried as drift.
fn bind_capture_source(
    approved: Option<PlaceholderIdentity>,
    live: &FileState,
    observed: &FileState,
    lookup_now: Result<Option<PlaceholderIdentity>, ()>,
    workspace: WorkspaceId,
    item_id: ItemId,
) -> Result<PlaceholderPolicy, CaptureFailure> {
    if live.identity.file_id != observed.identity.file_id
        || live.identity.volume_serial_number != observed.identity.volume_serial_number
    {
        // The path was replaced since the gate: re-observe instead of
        // capturing against a stale identity.
        return Err(CaptureFailure::Retry(FsError::IdentityChanged));
    }
    let boundary = gate_source(observed, lookup_now, workspace, item_id)?;
    if boundary != approved {
        // Same file, different verdict: plain/placeholder switched in place
        // or the inline record changed. Stale binding — re-observe, never
        // rebound to this work.
        return Err(CaptureFailure::Retry(FsError::IdentityChanged));
    }
    Ok(match approved {
        // The coherent read is bound to exactly the gate-approved
        // placeholder; nothing else may supply its bytes.
        Some(identity) => PlaceholderPolicy::RecaptureBound(identity),
        // An ordinary file stays ordinary: every reparse point is refused
        // before it is read.
        None => PlaceholderPolicy::Refuse,
    })
}

fn leak_state_error(error: &hfdrive_state::StateError) -> &'static str {
    // State errors are structured and non-secret; the classification is all
    // the capture path needs.
    let _ = error;
    "durable state rejected the snapshot journal update"
}

/// Deterministic interleaving seam for the capture regressions. The hook is
/// thread-local (the capture runs on the calling task's thread between these
/// calls, so parallel tests can never share a hook) and one-shot. Production
/// code calls the empty stub and pays nothing.
#[cfg(test)]
pub(crate) mod seams {
    use std::cell::RefCell;
    use std::path::Path;

    thread_local! {
        static BEFORE_SNAPSHOT: RefCell<Option<Box<dyn FnMut(&Path)>>> = RefCell::new(None);
    }

    /// Runs (and clears) the pre-capture hook: it observes the source after
    /// the initial observation and ownership/materialization gates and just
    /// **before** the coherent capture binds to that observation, so a test
    /// can replace the path inside that exact window.
    pub(crate) fn before_coherent_capture(source: &Path) {
        if let Some(mut hook) = BEFORE_SNAPSHOT.with(|slot| slot.borrow_mut().take()) {
            hook(source);
        }
    }

    /// Registers a one-shot hook for the next capture boundary.
    pub(crate) fn install_before_coherent_capture(hook: Box<dyn FnMut(&Path)>) {
        BEFORE_SNAPSHOT.with(|slot| *slot.borrow_mut() = Some(hook));
    }
}

#[cfg(not(test))]
mod seams {
    use std::path::Path;

    #[inline]
    pub(super) fn before_coherent_capture(_source: &Path) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use hfdrive_windows::filesystem::volume::FileIdentity;

    fn plain_state() -> FileState {
        FileState {
            identity: FileIdentity {
                volume_serial_number: 1,
                file_id: [7; 16],
                link_count: 1,
                attributes: 0x20,
                reparse_tag: 0,
            },
            size: 8,
            last_write_time_100ns: 5,
            usn: Some(3),
        }
    }

    #[test]
    fn plain_files_pass_the_gate_without_a_placeholder_identity() {
        let approved = gate_source(&plain_state(), Err(()), WorkspaceId::new(), ItemId::new())
            .expect("a plain file is never identity-gated");
        assert_eq!(approved, None);
    }

    #[test]
    fn foreign_reparse_points_and_unreadable_identities_are_rejected() {
        let workspace = WorkspaceId::new();
        let mut foreign = plain_state();
        foreign.identity.attributes |= 0x400; // FILE_ATTRIBUTE_REPARSE_POINT
        // A foreign link (junction/symlink/other provider's placeholder):
        // the lookup finds no HFDR record. Blocked, never uploaded.
        let result = gate_source(&foreign, Ok(None), workspace, ItemId::new());
        assert!(
            matches!(result, Err(CaptureFailure::Blocked(_))),
            "foreign links are rejected at the gate"
        );
        // An unreadable/corrupt identity is blocked the same way.
        let result = gate_source(&foreign, Err(()), workspace, ItemId::new());
        assert!(matches!(result, Err(CaptureFailure::Blocked(_))));
    }

    #[test]
    fn owned_placeholders_recapture_only_for_the_bound_item_and_workspace() {
        let workspace = WorkspaceId::new();
        let item = ItemId::new();
        let mut placeholder_state = plain_state();
        placeholder_state.identity.attributes |= 0x400;
        let identity = PlaceholderIdentity::file(
            workspace,
            item,
            hfdrive_core::ids::VersionId::new(),
        );

        // The bound item: approved for in-place recapture.
        let approved =
            gate_source(&placeholder_state, Ok(Some(identity)), workspace, item).expect("bound");
        assert_eq!(approved, Some(identity));

        // A placeholder of a different item: stale intent, re-observe. Never
        // rebound to this work.
        let result = gate_source(&placeholder_state, Ok(Some(identity)), workspace, ItemId::new());
        assert!(matches!(result, Err(CaptureFailure::Retry(FsError::IdentityChanged))));

        // A record from another workspace is never re-bound either.
        let result = gate_source(&placeholder_state, Ok(Some(identity)), WorkspaceId::new(), item);
        assert!(matches!(result, Err(CaptureFailure::Retry(FsError::IdentityChanged))));
    }

    #[test]
    fn efs_and_multiply_linked_sources_are_refused() {
        let workspace = WorkspaceId::new();
        let item = ItemId::new();
        let mut encrypted = plain_state();
        encrypted.identity.attributes |= 0x4000; // FILE_ATTRIBUTE_ENCRYPTED
        let result = gate_source(&encrypted, Err(()), workspace, item);
        assert!(matches!(result, Err(CaptureFailure::Blocked(_))));
        let mut linked = plain_state();
        linked.identity.link_count = 2;
        let result = gate_source(&linked, Err(()), workspace, item);
        assert!(matches!(result, Err(CaptureFailure::Blocked(_))));
    }

    /// The capture boundary binds the coherent read to the gate's observation
    /// and the exact approved placeholder identity. A substituted plain target
    /// or another item's placeholder is drift, refused before payload use even
    /// when `expected` is `None`; a foreign link is refused at the gate; an
    /// ordinary-file capture never adopts a placeholder at the reopen.
    #[test]
    fn the_capture_boundary_binds_to_the_gate_observation_and_identity() {
        let workspace = WorkspaceId::new();
        let item = ItemId::new();
        let identity = PlaceholderIdentity::file(
            workspace,
            item,
            hfdrive_core::ids::VersionId::new(),
        );
        let mut placeholder = plain_state();
        placeholder.identity.attributes |= 0x400; // FILE_ATTRIBUTE_REPARSE_POINT

        // The gate approved this placeholder and the boundary still observes
        // it: the coherent read is bound to exactly that identity.
        let policy = bind_capture_source(
            Some(identity),
            &placeholder,
            &placeholder,
            Ok(Some(identity)),
            workspace,
            item,
        )
        .expect("the bound placeholder keeps its identity");
        assert_eq!(policy, PlaceholderPolicy::RecaptureBound(identity));

        // A substituted plain target at the boundary is drift: refused before
        // any payload byte is read or staged, even though a plain file
        // "looks capturable" and no intent-time expectation exists.
        let result = bind_capture_source(
            Some(identity),
            &placeholder,
            &plain_state(),
            Ok(None),
            workspace,
            item,
        );
        assert!(matches!(result, Err(CaptureFailure::Retry(FsError::IdentityChanged))));

        // A placeholder of another item is drift as well — never rebound.
        let other = PlaceholderIdentity::file(
            workspace,
            ItemId::new(),
            hfdrive_core::ids::VersionId::new(),
        );
        let result = bind_capture_source(
            Some(identity),
            &placeholder,
            &placeholder,
            Ok(Some(other)),
            workspace,
            item,
        );
        assert!(matches!(result, Err(CaptureFailure::Retry(FsError::IdentityChanged))));

        // A foreign link appearing at the boundary after a plain gate is
        // refused at the ownership gate itself, never followed.
        let mut foreign = plain_state();
        foreign.identity.attributes |= 0x400;
        let result =
            bind_capture_source(None, &plain_state(), &foreign, Ok(None), workspace, item);
        assert!(matches!(result, Err(CaptureFailure::Blocked(_))));

        // An ordinary file capture refuses every reparse point at the reopen
        // too: a link substituted after this boundary fails before payload use.
        let policy = bind_capture_source(None, &plain_state(), &plain_state(), Ok(None), workspace, item)
            .expect("plain binding");
        assert_eq!(policy, PlaceholderPolicy::Refuse);
    }

    /// The regression: the coherent capture is bound to the observation taken
    /// at capture entry, never to `expected: None`'s "accept anything". A
    /// plain ordinary-file replacement made in the window between those two
    /// boundaries must come back as [`CaptureFailure::Retry`] /
    /// [`FsError::IdentityChanged`] with no accepted snapshot bytes, even
    /// when the replacement carries the original length and timestamp. The
    /// refusal surfaces at the boundary binding (step 3b), before the coherent
    /// read opens, so the replacement's bytes are never read into the staged
    /// file at all.
    #[tokio::test]
    async fn a_plain_replacement_before_the_coherent_capture_is_never_accepted() {
        let fixture = crate::sync::test_support::connection_fixture().await;
        let source = fixture.root.join("replaced.bin");
        std::fs::write(&source, b"AAAAAAAA").unwrap();
        let staging = fixture.directory.path().join("staging");

        // The replacement is as deceptive as a path replacement can be: the
        // same path and length, and the original modification time restored.
        let modified = std::fs::metadata(&source).unwrap().modified().unwrap();
        let replacement = fixture.root.join("replacement.bin");
        std::fs::write(&replacement, b"BBBBBBBB").unwrap();
        let original_state = query_file_state(&source).expect("initial observation");
        let replacement_state = query_file_state(&replacement).expect("replacement observation");
        assert_eq!(original_state.size, replacement_state.size, "same length");
        assert_ne!(
            original_state.identity.file_id, replacement_state.identity.file_id,
            "the replacement is a different file"
        );

        seams::install_before_coherent_capture(Box::new(move |path| {
            std::fs::rename(&replacement, path).expect("replace the path");
            let file = std::fs::OpenOptions::new().write(true).open(path).expect("open replacement");
            file.set_times(std::fs::FileTimes::new().set_modified(modified))
                .expect("restore the original timestamp");
        }));

        let request = CaptureRequest {
            connection_id: fixture.connection,
            source: source.clone(),
            staging_dir: staging.clone(),
            item_id: ItemId::new(),
            operation_id: OperationId::new(),
            snapshot_id: SnapshotId::new(),
            upload_id: hfdrive_core::ids::UploadId::new(),
            // No intent-time generation: exactly the caller that would
            // previously accept any later plain replacement.
            expected: None,
            workspace: fixture.workspace,
            root: fixture.root.clone(),
        };
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let error = match capture_local_change(
            &fixture.account,
            &scheduler,
            *request.workspace.as_uuid(),
            &request,
            &cancel,
        )
        .await
        {
            Ok(_) => panic!("a plain replacement between observation and capture is never accepted"),
            Err(error) => error,
        };
        assert!(
            matches!(error, CaptureFailure::Retry(FsError::IdentityChanged)),
            "the replacement must surface as IdentityChanged/Retry, got {error:?}"
        );
        // No snapshot bytes were accepted: nothing was staged and the durable
        // capture row is still an incomplete Capturing entry, not a Ready one.
        assert!(
            std::fs::read_dir(&staging).map(|mut entries| entries.next().is_none()).unwrap_or(true),
            "no staged bytes exist for the refused replacement"
        );
        let record = fixture
            .account
            .snapshot(fixture.connection, request.snapshot_id)
            .await
            .unwrap()
            .expect("the capture intent row is journaled");
        assert_eq!(record.status, hfdrive_state::SnapshotStatus::Capturing);
        assert_eq!(record.size, None);
        assert_eq!(record.sha256, None);

        // Control: the same source captured without the interleaving is
        // accepted — the entry observation is the file's own current state and
        // the coherent read matches it. The refusal above is therefore the
        // observation binding, not an unrelated capture failure.
        let control = CaptureRequest {
            snapshot_id: SnapshotId::new(),
            operation_id: OperationId::new(),
            ..request
        };
        let captured = capture_local_change(
            &fixture.account,
            &scheduler,
            *control.workspace.as_uuid(),
            &control,
            &cancel,
        )
        .await
        .expect("the replacement itself is capturable once it is the observed state");
        assert_eq!(std::fs::read(&captured.staged.staged_path).unwrap(), b"BBBBBBBB");
        fixture.state.close().await.unwrap();
    }

    /// The regression: a link at the source path is never read or staged. The
    /// ownership gate refuses the foreign reparse point before the payload
    /// boundary, so the foreign target's bytes are never accepted as this
    /// item's content — even with no intent-time expectation. Nothing is
    /// journaled: the refusal precedes the capture intent entirely.
    #[tokio::test]
    async fn a_final_link_at_the_source_path_is_refused_before_any_payload_use() {
        let fixture = crate::sync::test_support::connection_fixture().await;
        let foreign = fixture.root.join("foreign");
        std::fs::create_dir(&foreign).unwrap();
        std::fs::write(foreign.join("foreign.bin"), b"FOREIGN BYTES").unwrap();
        // A junction at the source path itself: the request names the link,
        // never the location its target lives at.
        let source = fixture.root.join("linked.bin");
        let created = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&source)
            .arg(&foreign)
            .output()
            .unwrap();
        assert!(created.status.success(), "failed to create isolated junction");

        let staging = fixture.directory.path().join("staging");
        let request = CaptureRequest {
            connection_id: fixture.connection,
            source: source.clone(),
            staging_dir: staging.clone(),
            item_id: ItemId::new(),
            operation_id: OperationId::new(),
            snapshot_id: SnapshotId::new(),
            upload_id: hfdrive_core::ids::UploadId::new(),
            // No intent-time generation: exactly the caller that would
            // previously accept anything present at the path.
            expected: None,
            workspace: fixture.workspace,
            root: fixture.root.clone(),
        };
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let error = match capture_local_change(
            &fixture.account,
            &scheduler,
            *request.workspace.as_uuid(),
            &request,
            &cancel,
        )
        .await
        {
            Ok(_) => panic!("a link at the source path is never captured"),
            Err(error) => error,
        };
        assert!(
            matches!(error, CaptureFailure::Blocked(_)),
            "the final link is refused at the ownership gate, got {error:?}"
        );
        assert!(
            std::fs::read_dir(&staging).map(|mut entries| entries.next().is_none()).unwrap_or(true),
            "no staged bytes exist for the refused link"
        );
        assert_eq!(
            std::fs::read(foreign.join("foreign.bin")).unwrap(),
            b"FOREIGN BYTES",
            "the foreign target is never touched or copied"
        );
        assert!(
            fixture
                .account
                .snapshot(fixture.connection, request.snapshot_id)
                .await
                .unwrap()
                .is_none(),
            "no capture intent is journaled past the ownership gate"
        );
        fixture.state.close().await.unwrap();
    }

    /// The regression: an ancestor junction redirect never supplies foreign
    /// bytes. The requested path names this connection's item, but the handle
    /// a naive open resolves through the junction to a different location; the
    /// capture's handle-bound path verification refuses that handle before any
    /// payload byte is read or staged. The error class belongs to that
    /// verification; what this regression pins is that the foreign bytes are
    /// never accepted and no snapshot becomes ready.
    #[tokio::test]
    async fn an_ancestor_junction_redirect_never_supplies_foreign_bytes() {
        let fixture = crate::sync::test_support::connection_fixture().await;
        let foreign = fixture.root.join("elsewhere");
        std::fs::create_dir(&foreign).unwrap();
        std::fs::write(foreign.join("child.bin"), b"FOREIGN BYTES").unwrap();
        let link = fixture.root.join("linked-dir");
        let created = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&link)
            .arg(&foreign)
            .output()
            .unwrap();
        assert!(created.status.success(), "failed to create isolated junction");
        // The final component is a plain file; only its ancestor is the link,
        // so the metadata pre-check sees ordinary content and the refused
        // handle's own final path is the only evidence of the redirection.
        let source = link.join("child.bin");

        let staging = fixture.directory.path().join("staging");
        let request = CaptureRequest {
            connection_id: fixture.connection,
            source: source.clone(),
            staging_dir: staging.clone(),
            item_id: ItemId::new(),
            operation_id: OperationId::new(),
            snapshot_id: SnapshotId::new(),
            upload_id: hfdrive_core::ids::UploadId::new(),
            expected: None,
            workspace: fixture.workspace,
            root: fixture.root.clone(),
        };
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let result = capture_local_change(
            &fixture.account,
            &scheduler,
            *request.workspace.as_uuid(),
            &request,
            &cancel,
        )
        .await;
        assert!(
            result.is_err(),
            "the redirected handle never supplies the foreign bytes as a snapshot"
        );
        assert!(
            std::fs::read_dir(&staging).map(|mut entries| entries.next().is_none()).unwrap_or(true),
            "no foreign bytes were staged"
        );
        // The capture intent is journaled but never completes with the
        // redirected content.
        let record = fixture
            .account
            .snapshot(fixture.connection, request.snapshot_id)
            .await
            .unwrap()
            .expect("the capture intent row is journaled");
        assert_eq!(record.status, hfdrive_state::SnapshotStatus::Capturing);
        assert_eq!(record.size, None);
        assert_eq!(record.sha256, None);
        fixture.state.close().await.unwrap();
    }
}
