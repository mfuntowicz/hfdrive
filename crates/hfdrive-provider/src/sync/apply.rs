//! Guarded remote-to-local application.
//!
//! Every local effect of a remote change is journaled **before** it runs
//! (`local_actions` rows carrying the expected file identity, generation and
//! USN), executed through the guarded CFAPI operations, and re-classified
//! against the real filesystem after an interruption. The guards are strict:
//! an unknown or changed expected USN is never a match, and a failed guard
//! keeps the old content plus the durable pending action — that is the
//! designed recovery path, not an error to paper over.
//!
//! Echo control: every successful application registers in the observer's
//! [`EchoTable`] so the watcher/USN fallout of our own writes is absorbed
//! and can never become a local upload echo.
//!
//! In-sync marking after publication is equally guarded: only the exact
//! capture evidence of the published bytes plus a matching local generation
//! may clear the dirty flag. A newer local edit keeps the file dirty and
//! schedules its own publication.

use std::path::{Path, PathBuf};

use hfdrive_core::ids::{ActionId, ItemId, VersionId};
use hfdrive_state::{
    AccountStore, CompletionOutcome, ConflictResolution, LocalActionState,
};
use hfdrive_windows::cfapi::ops::{
    FreeSpaceEvidence, GuardOutcome, MetadataSpec, PinOutcome, PinRequest, PlaceholderCreate,
    UpdateSpec,
};
use hfdrive_windows::cfapi::identity::PlaceholderIdentity;
use hfdrive_windows::filesystem::volume::FileState;

use crate::sync::observe::EchoTable;
use crate::sync::outbox::CaptureEvidence;

/// The outcome of one guarded local application step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Applied and journaled; the watcher fallout is an echo now.
    Applied { echo_path: PathBuf },
    /// The guard refused: the file keeps its old/dirty state and the durable
    /// action stays open for retry or re-planning.
    GuardRefused(&'static str),
    /// The action is not applicable anymore; it is closed as already done.
    AlreadySatisfied,
    /// The source/destination is temporarily unavailable; retry later.
    Retry(&'static str),
}

/// Expected local facts bound to a journaled action at planning time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedLocal {
    pub file_id: [u8; 16],
    pub volume_serial_number: u64,
    pub generation: u64,
    /// `None` means "USN unavailable on this volume": guarded transitions
    /// then refuse instead of guessing success.
    pub usn: Option<i64>,
}

/// Verifies the live file against the journaled expectation before any
/// guarded transition. This is the exact identity/generation/USN protection:
/// a drifted file keeps the pending action and stays dirty.
pub fn verify_expected(expected: &ExpectedLocal, live: &FileState, generation: u64) -> bool {
    if generation != expected.generation {
        return false;
    }
    if live.identity.file_id != expected.file_id
        || live.identity.volume_serial_number != expected.volume_serial_number
    {
        return false;
    }
    match (expected.usn, live.usn) {
        (Some(expected_usn), Some(live_usn)) => expected_usn == live_usn,
        // Unknown USNs never match: no fabricated in-sync success.
        _ => false,
    }
}

/// Builds the strict guard state for `CfSetInSyncState`/`CfUpdatePlaceholder`
/// from capture evidence.
pub fn guard_state(evidence: &CaptureEvidence) -> FileState {
    evidence.to_file_state()
}

/// Bind the committed version and mark it in-sync only for the captured local
/// generation. Normal files are converted; existing placeholders keep resident
/// bytes while their identity advances. Newer edits remain dirty.
pub fn mark_published_in_sync(
    path: &Path,
    identity: &PlaceholderIdentity,
    evidence: &CaptureEvidence,
    generation: u64,
    expected_generation: u64,
) -> Result<Option<i64>, &'static str> {
    if generation != expected_generation {
        // A newer local edit exists: the file stays dirty and gets its own
        // publication. This is the superseded-upload guard.
        return Ok(None);
    }
    let expected = guard_state(evidence);
    match hfdrive_windows::cfapi::ops::convert_published(path, identity, &expected) {
        Ok(GuardOutcome::Applied { usn }) => Ok(usn),
        Ok(GuardOutcome::Mismatch(_)) => Ok(None),
        Err(_) => Err("in-sync transition failed"),
    }
}

/// Creates placeholders for planned items. Every per-entry result is checked;
/// an existing local path is reconciled later, never overwritten.
pub fn create_placeholders(
    base: &Path,
    creates: &[PlaceholderCreate],
) -> Result<Vec<hfdrive_windows::cfapi::ops::PlaceholderOutcome>, &'static str> {
    if creates.is_empty() {
        return Ok(Vec::new());
    }
    hfdrive_windows::cfapi::ops::create_placeholders(base, creates)
        .map_err(|_| "placeholder creation failed")
}

/// Applies a new immutable version to an existing placeholder with the strict
/// guard. Old ranges are invalidated; the old content is never mixed with the
/// new version.
pub fn update_placeholder(
    path: &Path,
    spec: &UpdateSpec,
    expected: &FileState,
) -> Result<GuardOutcome, &'static str> {
    hfdrive_windows::cfapi::ops::update_placeholder(path, spec, expected)
        .map_err(|_| "placeholder update failed")
}

/// Renames/moves a local item by stable identity. Case-only renames go
/// through a journaled unique intermediate name so NTFS keeps the identity.
pub fn rename_local(
    root: &Path,
    from: &Path,
    to: &Path,
    case_only: bool,
    intermediate: &Path,
) -> Result<(), &'static str> {
    let from_abs = root.join(from);
    let to_abs = root.join(to);
    if case_only {
        std::fs::rename(&from_abs, root.join(intermediate))
            .map_err(|_| "case-only rename intermediate step failed")?;
        std::fs::rename(root.join(intermediate), &to_abs)
            .map_err(|_| "case-only rename final step failed")?;
    } else {
        std::fs::rename(&from_abs, &to_abs).map_err(|_| "rename failed")?;
    }
    Ok(())
}

/// Removes a local placeholder/file **after** any dirty bytes were preserved
/// by a [`preserve_dirty`] action. A missing path is already-satisfied.
pub fn delete_local(root: &Path, relative: &Path) -> Result<ApplyOutcome, &'static str> {
    let path = root.join(relative);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(ApplyOutcome::AlreadySatisfied),
    };
    let result = if metadata.is_dir() {
        std::fs::remove_dir(&path)
    } else {
        std::fs::remove_file(&path)
    };
    match result {
        Ok(()) => Ok(ApplyOutcome::Applied { echo_path: relative.to_path_buf() }),
        Err(_) => Ok(ApplyOutcome::Retry("local removal is in use or denied")),
    }
}

/// Preserves dirty local bytes into the recovery area before a destructive
/// local replacement or removal. The recovery area lives outside every sync
/// root, so preserved data survives both sync and uninstall.
///
/// The copy goes through the **verified** [`crate::sync::recovery`]
/// preservation path: unique exclusive reservation, source metadata
/// re-verification, digest verification and payload -> sidecar -> success
/// durability. There is no unverified copy fallback here. `Ok(Some(path))`
/// names the verified recovery copy; `Ok(None)` is the "nothing to lose" skip
/// (empty file, directory, verifiably gone source), never a preservation
/// proof; every preservation failure is propagated as `Err` and must block
/// the destructive work.
pub fn preserve_dirty(
    source: &Path,
    recovery_dir: &Path,
    action_id: ActionId,
) -> Result<Option<PathBuf>, &'static str> {
    std::fs::create_dir_all(recovery_dir).map_err(|_| "recovery area unavailable")?;
    let label = action_id.to_string();
    let display = source.to_string_lossy().into_owned();
    let preserved = crate::sync::recovery::preserve_item_bytes(source, recovery_dir, &label, &display)
        .map_err(|error| match error {
            crate::sync::recovery::RecoveryError::AreaUnavailable => "recovery area unavailable",
            crate::sync::recovery::RecoveryError::SourceGone => "the source file is gone",
            crate::sync::recovery::RecoveryError::SourceChanged => {
                "the source changed while being preserved"
            }
            crate::sync::recovery::RecoveryError::Unreadable => {
                "the source could not be read for preservation"
            }
            crate::sync::recovery::RecoveryError::WriteFailed => {
                "preserving dirty bytes failed"
            }
            crate::sync::recovery::RecoveryError::DigestMismatch => {
                "the recovery copy does not match the source bytes"
            }
        })?;
    // A skip (empty file, directory, verifiably gone source) has nothing to
    // preserve: `Ok(None)` is not a preservation proof, and the destructive
    // caller may proceed knowing there was nothing to lose.
    Ok(preserved.map(|copy| copy.path))
}

/// Pin/unpin request with separate requested-vs-resident reporting.
pub fn set_pin(path: &Path, request: PinRequest) -> Result<PinOutcome, &'static str> {
    hfdrive_windows::cfapi::ops::set_pin_state(path, request).map_err(|_| "pin state failed")
}

/// Frees local space only with complete evidence: committed, clean, unpinned,
/// conflict-free content with no staged snapshot dependency.
pub fn free_space(path: &Path, evidence: &FreeSpaceEvidence) -> Result<GuardOutcome, &'static str> {
    evidence.verify().map_err(|_| "free-space evidence incomplete")?;
    hfdrive_windows::cfapi::ops::dehydrate(path, evidence).map_err(|_| "dehydration failed")
}

/// Builds the free-space evidence from durable state. Every flag is checked
/// against real rows; nothing is assumed.
pub async fn free_space_evidence(
    state: &AccountStore,
    connection: hfdrive_core::ids::ConnectionId,
    item_id: ItemId,
    content_version_id: Option<VersionId>,
    pinned: bool,
    conflicts_open: bool,
) -> FreeSpaceEvidence {
    let dirty = state
        .observation(connection, item_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|observation| observation.dirty);
    let snapshot_dependency = state
        .list_snapshots(connection)
        .await
        .map(|snapshots| {
            snapshots.iter().any(|snapshot| {
                matches!(
                    snapshot.status,
                    hfdrive_state::SnapshotStatus::Capturing | hfdrive_state::SnapshotStatus::Ready
                )
            })
        })
        .unwrap_or(true); // Unknown dependencies block freeing, never allow it.
    FreeSpaceEvidence {
        committed: content_version_id.is_some(),
        clean: !dirty,
        unpinned: !pinned,
        conflict_free: !conflicts_open,
        no_snapshot_dependency: !snapshot_dependency,
    }
}

/// Closes an applied local action and registers the echo window so watcher
/// fallout of the provider's own write is absorbed.
pub async fn complete_action(
    state: &AccountStore,
    connection: hfdrive_core::ids::ConnectionId,
    action_id: ActionId,
    item_id: ItemId,
    echo_path: PathBuf,
    echo: &mut EchoTable,
) -> Result<(), hfdrive_state::StateError> {
    state
        .set_local_action_state(connection, action_id, LocalActionState::Applied)
        .await?;
    echo.note_applied(item_id, echo_path);
    Ok(())
}

/// Recovery classification of one interrupted action against the live
/// filesystem. This runs at startup and after crashes; it decides from real
/// file facts and never replays blindly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryDecision {
    /// The action already achieved its target state.
    Done,
    /// The action never ran (or half-ran safely); it may run again.
    Retry,
    /// The local state no longer matches anything the action knows; return
    /// the item to reconciliation as new local work.
    Requeue,
    /// Dirty bytes must be preserved before anything destructive happens.
    PreserveFirst,
}

/// Classifies an interrupted journaled action.
pub fn classify_recovered(
    action_kind: hfdrive_state::LocalActionKind,
    expected: Option<&ExpectedLocal>,
    live: Option<&FileState>,
    target_exists: bool,
) -> RecoveryDecision {
    match action_kind {
        hfdrive_state::LocalActionKind::CreatePlaceholder => {
            if target_exists {
                RecoveryDecision::Done
            } else {
                RecoveryDecision::Retry
            }
        }
        hfdrive_state::LocalActionKind::UpdatePlaceholder => match (expected, live) {
            (Some(expected), Some(live)) if verify_expected(expected, live, expected.generation) => {
                RecoveryDecision::Retry
            }
            (Some(_), Some(_)) => RecoveryDecision::Requeue,
            (_, None) => RecoveryDecision::Requeue,
            (None, Some(_)) => RecoveryDecision::Retry,
        },
        hfdrive_state::LocalActionKind::Rename => {
            if target_exists {
                RecoveryDecision::Done
            } else {
                RecoveryDecision::Retry
            }
        }
        hfdrive_state::LocalActionKind::DeletePlaceholder => match live {
            None => RecoveryDecision::Done,
            Some(state) if state.size > 0 => RecoveryDecision::PreserveFirst,
            Some(_) => RecoveryDecision::Retry,
        },
        hfdrive_state::LocalActionKind::Dehydrate => {
            if live.is_some_and(|state| state.size > 0) {
                RecoveryDecision::Retry
            } else {
                RecoveryDecision::Done
            }
        }
        hfdrive_state::LocalActionKind::SetPin
        | hfdrive_state::LocalActionKind::Hydrate
        | hfdrive_state::LocalActionKind::ConvertToNormal
        | hfdrive_state::LocalActionKind::Other => RecoveryDecision::Retry,
    }
}

/// Generation-guarded close of one completed publication's outbox entry.
/// The state worker clears the dirty flag only when the persisted entry's
/// observed generation still matches; a newer local generation completes the
/// entry but stays dirty with its own follow-up intent. Superseded uploads
/// never clear newer edits.
pub async fn complete_publication(
    state: &AccountStore,
    connection: hfdrive_core::ids::ConnectionId,
    operation: hfdrive_core::ids::OperationId,
) -> Result<CompletionOutcome, hfdrive_state::StateError> {
    state.complete_outbox(connection, operation).await
}

/// Records a conflict resolution and its preserved bytes. `keep_remote`
/// preserves dirty local bytes in recovery before anything destructive.
pub async fn resolve_conflict_resolution(
    state: &AccountStore,
    connection: hfdrive_core::ids::ConnectionId,
    conflict_id: hfdrive_core::ids::ConflictId,
    resolution: ConflictResolution,
) -> Result<hfdrive_state::ConflictRecord, hfdrive_state::StateError> {
    state.resolve_conflict(connection, conflict_id, resolution).await
}

/// Builds a placeholder identity record for a file item's current version.
pub fn file_identity(
    workspace: hfdrive_core::ids::WorkspaceId,
    item: ItemId,
    version: VersionId,
) -> PlaceholderIdentity {
    PlaceholderIdentity::file(workspace, item, version)
}

/// Builds a placeholder identity record for a directory item.
pub fn directory_identity(
    workspace: hfdrive_core::ids::WorkspaceId,
    item: ItemId,
) -> PlaceholderIdentity {
    PlaceholderIdentity::directory(workspace, item)
}

/// Display metadata for placeholder creation/update from captured facts.
pub fn metadata_spec(size: u64, last_write_time_100ns: i64, directory: bool) -> MetadataSpec {
    MetadataSpec {
        size: if directory { 0 } else { size },
        creation_time_100ns: last_write_time_100ns,
        last_write_time_100ns,
        attributes: if directory { 0x10 } else { 0x20 },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hfdrive_state::LocalActionKind;

    fn expected(generation: u64, usn: Option<i64>) -> ExpectedLocal {
        ExpectedLocal {
            file_id: [7; 16],
            volume_serial_number: 99,
            generation,
            usn,
        }
    }

    fn live(usn: Option<i64>) -> FileState {
        FileState {
            identity: hfdrive_windows::filesystem::volume::FileIdentity {
                volume_serial_number: 99,
                file_id: [7; 16],
                link_count: 1,
                attributes: 0x20,
                reparse_tag: 0,
            },
            size: 10,
            last_write_time_100ns: 5,
            usn,
        }
    }

    #[test]
    fn identity_generation_and_usn_all_guard_the_transition() {
        assert!(verify_expected(&expected(4, Some(11)), &live(Some(11)), 4));
        // Newer local generation: superseded upload must not clear it.
        assert!(!verify_expected(&expected(4, Some(11)), &live(Some(11)), 5));
        // USN drift: the file changed since planning.
        assert!(!verify_expected(&expected(4, Some(11)), &live(Some(12)), 4));
        // Unknown USN on either side is never a match (no fake success).
        assert!(!verify_expected(&expected(4, None), &live(None), 4));
        assert!(!verify_expected(&expected(4, Some(11)), &live(None), 4));
    }

    #[test]
    fn superseded_publication_leaves_newer_local_bytes_unconverted() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("edited.txt");
        std::fs::write(&path, b"captured bytes").unwrap();
        let captured = hfdrive_windows::filesystem::volume::query_file_state(&path).unwrap();
        let evidence = CaptureEvidence {
            volume_serial_number: captured.identity.volume_serial_number,
            file_id: captured.identity.file_id,
            size: captured.size,
            last_write_time_100ns: captured.last_write_time_100ns,
            usn: captured.usn,
        };
        std::fs::write(&path, b"newer local bytes").unwrap();
        let identity = PlaceholderIdentity::file(
            hfdrive_core::ids::WorkspaceId::new(),
            ItemId::new(),
            VersionId::new(),
        );
        assert_eq!(mark_published_in_sync(&path, &identity, &evidence, 2, 1).unwrap(), None);
        assert_eq!(std::fs::read(&path).unwrap(), b"newer local bytes");
        let after = hfdrive_windows::filesystem::volume::query_file_state(&path).unwrap();
        assert!(!hfdrive_windows::filesystem::volume::placeholder_state(
            after.identity.attributes,
            after.identity.reparse_tag,
        ).is_placeholder());
    }

    #[test]
    fn interrupted_actions_classify_against_real_file_facts() {
        assert_eq!(
            classify_recovered(LocalActionKind::CreatePlaceholder, None, None, true),
            RecoveryDecision::Done
        );
        assert_eq!(
            classify_recovered(LocalActionKind::CreatePlaceholder, None, None, false),
            RecoveryDecision::Retry
        );
        let expected = expected(2, Some(5));
        assert_eq!(
            classify_recovered(
                LocalActionKind::UpdatePlaceholder,
                Some(&expected),
                Some(&live(Some(5))),
                true
            ),
            RecoveryDecision::Retry
        );
        assert_eq!(
            classify_recovered(
                LocalActionKind::UpdatePlaceholder,
                Some(&expected),
                Some(&live(Some(6))),
                true
            ),
            RecoveryDecision::Requeue
        );
        // A delete with unsynchronized bytes must preserve them first.
        let dirty = FileState { size: 42, ..live(Some(6)) };
        assert_eq!(
            classify_recovered(LocalActionKind::DeletePlaceholder, None, Some(&dirty), true),
            RecoveryDecision::PreserveFirst
        );
        assert_eq!(
            classify_recovered(LocalActionKind::DeletePlaceholder, None, None, true),
            RecoveryDecision::Done
        );
    }

    #[test]
    fn free_space_requires_every_flag() {
        let full = FreeSpaceEvidence {
            committed: true,
            clean: true,
            unpinned: true,
            conflict_free: true,
            no_snapshot_dependency: true,
        };
        assert!(full.verify().is_ok());
        let dirty = FreeSpaceEvidence { clean: false, ..full };
        assert!(dirty.verify().is_err());
        let pending = FreeSpaceEvidence { no_snapshot_dependency: false, ..full };
        assert!(pending.verify().is_err());
    }
}
