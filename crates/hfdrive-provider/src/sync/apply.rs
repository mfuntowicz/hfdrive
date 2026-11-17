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

use hfdrive_core::ids::{ActionId, ItemId, VersionId, WorkspaceId};
use hfdrive_state::{
    AccountStore, CompletionOutcome, ConflictResolution, LocalActionState,
};
use hfdrive_windows::cfapi::ops::{
    FreeSpaceEvidence, GuardOutcome, MetadataSpec, PinOutcome, PinRequest, PlaceholderCreate,
    PlaceholderRequestOutcome, UpdateSpec,
};
use hfdrive_windows::cfapi::identity::PlaceholderIdentity;
use hfdrive_windows::filesystem::FsError;
use hfdrive_windows::filesystem::volume::{FileState, placeholder_state};

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
    if live.identity.file_id != expected.file_id {
        return false;
    }
    // `0` means "the state schema does not journal a volume serial"; every
    // compared path lives under one sync root, so the 128-bit NTFS file
    // identity alone binds the object. When a serial was journaled, it must
    // match.
    if expected.volume_serial_number != 0
        && live.identity.volume_serial_number != expected.volume_serial_number
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

// ---------------------------------------------------------------------------
// Object proofs shared by the guarded local actions and recovery
// ---------------------------------------------------------------------------

/// A filesystem probe at one path. [`Probe::Missing`] is **proven** absence:
/// the open failed with `NotFound`. [`Probe::Unreadable`] is every other
/// failure (locked, ACL-denied, invalid path) and is never treated as
/// absence — "cannot see it" is not "it is gone".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    Missing,
    Present(FileState),
    Unreadable,
}

/// Probes the real state of one local path without following reparse points.
pub fn probe(path: &Path) -> Probe {
    match hfdrive_windows::filesystem::volume::query_file_state(path) {
        Ok(state) => Probe::Present(state),
        Err(FsError::NotFound { .. }) => Probe::Missing,
        Err(_) => Probe::Unreadable,
    }
}

/// The identity proof of an object that already moved. A rename advances the
/// USN, so a resumed or already-landed move proves the NTFS object identity
/// and the journaled generation — never "a file exists at the destination".
/// Every compared path lives under one sync root, so a matching 128-bit NTFS
/// file identity is the same object on the same volume; a journaled volume
/// serial must match too. An unknown or drifted generation is never a match.
pub fn relocated_object(live: &FileState, expected: &ExpectedLocal, generation: u64) -> bool {
    if generation != expected.generation || live.identity.file_id != expected.file_id {
        return false;
    }
    // `0` means "the volume serial is not journaled" (the source was already
    // gone at bind time): every compared path lives under one sync root, so
    // the 128-bit NTFS file identity alone binds the object. When a serial
    // was journaled, it must match.
    expected.volume_serial_number == 0
        || live.identity.volume_serial_number == expected.volume_serial_number
}

/// Ownership proof for the placeholder a destructive action is about to
/// touch: a cloud placeholder must carry the **exact** expected HFDR
/// identity. A placeholder without a readable HFDR record (plain item,
/// another provider's placeholder, corrupt record) is never ours and is never
/// mutated. A non-placeholder object has no inline identity to compare and is
/// protected by the NTFS same-object proof alone.
pub fn owns_placeholder(
    live: &FileState,
    occupant: Option<PlaceholderIdentity>,
    identity: &PlaceholderIdentity,
) -> bool {
    let placeholder =
        placeholder_state(live.identity.attributes, live.identity.reparse_tag).is_placeholder();
    match (placeholder, occupant) {
        (true, Some(occupant)) => occupant == *identity,
        // A placeholder whose identity cannot be read back is never ours.
        (true, None) => false,
        (false, _) => true,
    }
}

/// What occupies a local path that already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Occupant {
    /// The occupant is this item's exact expected HFDR placeholder: the
    /// planned effect already landed here.
    Owned,
    /// The occupant is not this item's placeholder: a plain item, another
    /// provider's placeholder or a different HFDR identity. It is preserved
    /// untouched and never overwritten.
    Foreign,
    /// The occupant's identity could not be read back (a corrupt record or a
    /// failed query). Never assumed ours.
    Unverifiable,
}

/// Classifies the occupant of an existing local path against the exact HFDR
/// identity a journaled action expects there. Mere existence is never proof
/// of ownership.
pub fn occupant_at(
    path: &Path,
    workspace: WorkspaceId,
    expected: &PlaceholderIdentity,
) -> Occupant {
    match hfdrive_windows::cfapi::ops::read_placeholder_identity(path, Some(workspace)) {
        Ok(Some(identity)) if identity == *expected => Occupant::Owned,
        Ok(Some(_)) | Ok(None) => Occupant::Foreign,
        Err(_) => Occupant::Unverifiable,
    }
}

/// The exact HFDR identity of an item's object at one journaled content
/// version: a file always binds its immutable version, a directory binds
/// none. The identity is fully determined by the journaled version.
pub fn journaled_identity(
    workspace: WorkspaceId,
    item: ItemId,
    version: Option<VersionId>,
) -> PlaceholderIdentity {
    match version {
        Some(version) => PlaceholderIdentity::file(workspace, item, version),
        None => PlaceholderIdentity::directory(workspace, item),
    }
}

/// The verdict of one placeholder-creation entry. Every
/// [`PlaceholderRequestOutcome`] maps to exactly one verdict; only
/// [`CreationOutcome::Created`] and [`CreationOutcome::AlreadyCreated`] ever
/// succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreationOutcome {
    /// The placeholder was created now.
    Created { echo_path: PathBuf },
    /// The target already holds this item's exact expected HFDR placeholder
    /// identity: the planned creation had already landed.
    AlreadyCreated,
    /// The target is occupied by a different or unverifiable object: it is
    /// preserved untouched and never overwritten.
    Occupied(&'static str),
    /// The entry itself failed with this OS error code; never reported as
    /// created.
    EntryFailed { code: i32 },
}

/// Classifies one per-entry placeholder-creation outcome. `occupant` proves
/// who holds an already-existing target and is consulted **only** for
/// `AlreadyExists`; a real `Created` and a per-entry failure never look at
/// the path. Mere target existence is never success: only `Created` and an
/// `AlreadyExists` carrying the exact expected HFDR identity are.
pub fn classify_creation(
    echo: &Path,
    outcome: &PlaceholderRequestOutcome,
    occupant: impl FnOnce() -> Occupant,
) -> CreationOutcome {
    match outcome {
        PlaceholderRequestOutcome::Created { .. } => {
            CreationOutcome::Created { echo_path: echo.to_path_buf() }
        }
        PlaceholderRequestOutcome::AlreadyExists { .. } => match occupant() {
            Occupant::Owned => CreationOutcome::AlreadyCreated,
            Occupant::Foreign => CreationOutcome::Occupied(
                "the creation target is occupied by a different local object",
            ),
            Occupant::Unverifiable => CreationOutcome::Occupied(
                "the creation target's occupant cannot be verified",
            ),
        },
        PlaceholderRequestOutcome::Failed { code } => {
            CreationOutcome::EntryFailed { code: *code }
        }
    }
}

/// The journaled unique intermediate name of a case-only rename. NTFS keeps
/// the file identity across the two-step move, and the name is bound to this
/// action, so a half-done move is found again at startup instead of being
/// mistaken for a new local file.
pub fn rename_intermediate(to: &Path, action_id: ActionId) -> PathBuf {
    to.with_file_name(format!(
        "{}.hfdrive-rename-{}",
        to.file_name().and_then(|name| name.to_str()).unwrap_or("item"),
        action_id
    ))
}

/// Only a case-only rename owns an intermediate, deterministically bound to
/// its action UUID. A matching spelling alone is never an ownership proof.
pub(crate) fn case_rename_intermediate(action: &hfdrive_state::LocalAction) -> Option<PathBuf> {
    if action.kind != hfdrive_state::LocalActionKind::Rename {
        return None;
    }
    let (source, target) = (action.source_path.as_ref()?, action.target_path.as_ref()?);
    (source != target && hfdrive_windows::filesystem::names::windows_case_equivalent(
        &source.to_string_lossy(), &target.to_string_lossy(),
    )).then(|| rename_intermediate(target, action.action_id))
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

/// A rename whose journaled expectation cannot be proven: the action stays
/// pending and nothing is mutated.
pub const RENAME_UNPROVEN: &str =
    "the rename source does not match its journaled identity; it stays pending";
/// A rename whose destination is occupied by another local object.
pub const RENAME_OCCUPIED: &str =
    "the rename destination is occupied by a different local object";
/// A rename whose source cannot be inspected right now (locked, denied, an
/// unreadable path) — never "already moved".
pub const RENAME_SOURCE_UNREADABLE: &str =
    "the rename source cannot be inspected right now";
/// A delete whose expected placeholder identity cannot be proven.
pub const DELETE_UNPROVEN: &str =
    "the delete target does not match its journaled identity; it stays pending";
/// A delete that would remove a local object this action does not own.
pub const DELETE_NOT_OURS: &str =
    "the delete target is not this item's placeholder; it is preserved untouched";

/// Outcome of a guarded rename: [`RenameOutcome::Applied`] on success and
/// [`RenameOutcome::AlreadyMoved`] when the journaled object is provably at
/// its destination already (the move landed before an interruption).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenameOutcome {
    Applied { echo_path: PathBuf },
    AlreadyMoved { echo_path: PathBuf },
}

/// Renames/moves a local item by stable NTFS identity. Case-only renames go
/// through the journaled unique intermediate name so NTFS keeps the identity.
///
/// The guard is strict and re-established at every step:
///
/// * the **source** must still be the journaled object (file id + volume
///   serial + generation + USN); a drifted source stays pending;
/// * the **destination** may only be absent or hold that same object (a
///   landed move); any other occupant is preserved untouched and refuses the
///   rename;
/// * for a case-only rename the destination aliases the live source on
///   case-insensitive NTFS, so the exact spelling is fixed through the
///   journaled intermediate instead of being mistaken for a landed move;
/// * an unreadable source is never treated as "already moved".
///
/// The move itself is a **same-handle** operation: the source object is
/// opened once (denying delete sharing), revalidated through that open, and
/// renamed through it with `ReplaceIfExists = false`. The path is never
/// re-resolved between the final probe and the mutation, so an object B
/// that replaced A at the path is never moved by A's journaled rename — the
/// rename is refused and the action stays pending.
pub fn rename_local(
    root: &Path,
    from: &Path,
    to: &Path,
    case_only: bool,
    intermediate: &Path,
    expected: Option<&ExpectedLocal>,
    generation: u64,
) -> Result<RenameOutcome, &'static str> {
    let from_abs = root.join(from);
    let to_abs = root.join(to);
    // 1. The source must still be the journaled object. Without a journaled
    //    expectation nothing is proven and nothing is mutated.
    let Some(expected) = expected else {
        return Err(RENAME_UNPROVEN);
    };
    let live = match probe(&from_abs) {
        Probe::Present(live) => live,
        Probe::Missing => {
            // Proven absence of the source: only the journaled object proven
            // at the destination (or the journaled intermediate) can be the
            // moved object — never "a file exists there".
            return moved_object_outcome(root, to, intermediate, expected, generation, case_only);
        }
        Probe::Unreadable => return Err(RENAME_SOURCE_UNREADABLE),
    };
    if !verify_expected(expected, &live, generation) {
        return Err(RENAME_UNPROVEN);
    }
    if case_only {
        // 2a. The destination aliases this very source on case-insensitive
        //     NTFS, so a destination probe cannot prove the spelling. Only
        //     the journaled intermediate may hold a foreign object here: a
        //     half-done move finishes through it, and anything else refuses.
        let intermediate_abs = root.join(intermediate);
        match probe(&intermediate_abs) {
            Probe::Present(object) => {
                if !relocated_object(&object, expected, generation) {
                    return Err(RENAME_OCCUPIED);
                }
                // The object is already at the journaled intermediate: finish
                // the move. Its own first hop advanced the USN, so the
                // identity+generation proof is the correct one here.
                return rename_same_handle(
                    &intermediate_abs,
                    &to_abs,
                    expected,
                    generation,
                    to,
                    false,
                );
            }
            Probe::Unreadable => return Err(RENAME_OCCUPIED),
            Probe::Missing => {}
        }
    } else {
        // 2b. The destination may only be absent or hold this same object
        //     (a move that landed before the interruption). Anything else is
        //     preserved.
        match probe(&to_abs) {
            Probe::Present(target) => {
                if !relocated_object(&target, expected, generation) {
                    return Err(RENAME_OCCUPIED);
                }
                // The move already landed: proof is the NTFS identity plus
                // the journaled generation, never mere destination existence.
                return Ok(RenameOutcome::AlreadyMoved { echo_path: to.to_path_buf() });
            }
            Probe::Unreadable => return Err(RENAME_OCCUPIED),
            Probe::Missing => {}
        }
    }
    // 3. Move the verified object through the same handle that revalidates
    //    it: `ReplaceIfExists` stays false, so a destination reappearing
    //    between the probe and this call fails the move and keeps the action
    //    pending with the source intact.
    if case_only {
        rename_same_handle(
            &from_abs,
            &root.join(intermediate),
            expected,
            generation,
            to,
            true,
        )?;
        rename_same_handle(&root.join(intermediate), &to_abs, expected, generation, to, false)
    } else {
        rename_same_handle(&from_abs, &to_abs, expected, generation, to, true)
    }
}

/// Rename one object through the **same handle** that proves it: the object
/// is opened denying delete sharing, its NTFS identity, size, mtime and USN
/// are revalidated through that open, and only then is the rename issued on
/// it. The path is never re-resolved between the check and the mutation, so
/// a replacement object B at the source path can never be moved by A's
/// journaled rename.
///
/// `strict_usn` selects the proof the revalidation uses:
///
/// * `true` — the full journaled expectation, **including the exact USN**.
///   Used for a plain rename and for the first hop of a case-only move, where
///   the object was probed immediately before and has not moved since.
/// * `false` — identity (file id + volume serial) and generation only. Used
///   for the second hop of a case-only move, whose own first hop necessarily
///   advanced the USN; the object is still provably the same NTFS object, so
///   the spelling fix proceeds. A *different* object at the path has a
///   different file id and is still refused, never replaced.
fn rename_same_handle(
    from_abs: &Path,
    to_abs: &Path,
    expected: &ExpectedLocal,
    generation: u64,
    echo: &Path,
    strict_usn: bool,
) -> Result<RenameOutcome, &'static str> {
    // The seam fires after the outer probe proved the journaled object and
    // **before** the same-handle open: a test replaces the object here, so
    // the handle-based revalidation below sees B and refuses.
    seams::before_mutation(from_abs);
    let handle = hfdrive_windows::filesystem::volume::open_rename(from_abs)
        .map_err(|_| "the rename source could not be opened")?;
    let live = hfdrive_windows::filesystem::volume::state_on_handle(&handle)
        .map_err(|_| RENAME_SOURCE_UNREADABLE)?;
    let proven = if strict_usn {
        verify_expected(expected, &live, generation)
    } else {
        relocated_object(&live, expected, generation)
    };
    if !proven {
        // The object changed between the probe and this open: refuse instead
        // of moving whatever now occupies the path.
        return Err(RENAME_UNPROVEN);
    }
    hfdrive_windows::filesystem::volume::rename_to(&handle, to_abs)
        .map_err(|_| "the rename could not be applied to the verified object")?;
    Ok(RenameOutcome::Applied { echo_path: echo.to_path_buf() })
}

/// Deterministic interleaving seam for the same-handle destructive-action
/// regressions. The hook is thread-local (the guarded action runs on the
/// calling task's thread between the final probe and the mutation, so
/// parallel tests can never share a hook) and one-shot. Production code
/// calls the empty stub below and pays nothing.
///
/// The seam fires **after** the final probe has proven the journaled object
/// and **before** the mutation is issued on the verified handle. A test can
/// replace the object at the path inside that exact window and prove the
/// guarded action refuses instead of mutating the replacement.
#[cfg(test)]
pub(crate) mod seams {
    use std::cell::RefCell;
    use std::path::Path;

    thread_local! {
        static BEFORE_MUTATION: RefCell<Option<Box<dyn FnMut(&Path)>>> = RefCell::new(None);
    }

    /// Runs (and clears) the pre-mutation hook: it observes the verified
    /// source path after the final probe and just **before** the rename or
    /// disposition is issued on the same handle.
    pub(crate) fn before_mutation(path: &Path) {
        if let Some(mut hook) = BEFORE_MUTATION.with(|slot| slot.borrow_mut().take()) {
            hook(path);
        }
    }

    /// Registers a one-shot hook for the next guarded mutation boundary.
    pub(crate) fn install_before_mutation(hook: Box<dyn FnMut(&Path)>) {
        BEFORE_MUTATION.with(|slot| *slot.borrow_mut() = Some(hook));
    }
}

#[cfg(not(test))]
mod seams {
    use std::path::Path;

    #[inline]
    pub(super) fn before_mutation(_path: &Path) {}
}

/// Closes a rename whose source is proven absent. Only the exact journaled
/// object at the destination is proof of a landed move; a case-only rename
/// that stopped at its journaled intermediate is finished instead of being
/// reported done under the intermediate name.
fn moved_object_outcome(
    root: &Path,
    to: &Path,
    intermediate: &Path,
    expected: &ExpectedLocal,
    generation: u64,
    case_only: bool,
) -> Result<RenameOutcome, &'static str> {
    let to_abs = root.join(to);
    if let Probe::Present(live) = probe(&to_abs) {
        return if relocated_object(&live, expected, generation) {
            Ok(RenameOutcome::AlreadyMoved { echo_path: to.to_path_buf() })
        } else {
            Err(RENAME_UNPROVEN)
        };
    }
    // For a case-only rename the destination aliases the (absent) source, so
    // the object can only be waiting at the journaled intermediate.
    let intermediate_abs = root.join(intermediate);
    if case_only {
        if let Probe::Present(object) = probe(&intermediate_abs) {
            return if relocated_object(&object, expected, generation) {
                rename_same_handle(&intermediate_abs, &to_abs, expected, generation, to, false)
            } else {
                Err(RENAME_OCCUPIED)
            };
        }
    }
    Err(RENAME_UNPROVEN)
}

/// Removes a local placeholder/file **after** any dirty bytes were preserved
/// by a [`preserve_dirty`] action.
///
/// The target must be the exact journaled object (file id + volume serial +
/// journaled generation) and, when `identity` is supplied, carry that exact
/// expected HFDR identity when it is a placeholder. A replacement at the
/// path — or a foreign occupant — is preserved untouched: the old item's
/// deletion never removes bytes it does not own. Proven absence satisfies the
/// action; a path that merely cannot be inspected keeps it pending.
///
/// The removal is a **same-handle** operation: the object is opened once
/// (denying write and delete sharing), its identity/size/mtime/USN are
/// revalidated through that open, and only then is the delete disposition
/// issued on it. The path is never re-resolved between the final probe and
/// the mutation, so a replacement object B is never removed by A's journaled
/// delete — the delete is refused and the action stays pending.
pub fn delete_local(
    root: &Path,
    relative: &Path,
    expected: Option<&ExpectedLocal>,
    generation: u64,
    identity: Option<&PlaceholderIdentity>,
) -> Result<ApplyOutcome, &'static str> {
    let path = root.join(relative);
    let Some(expected) = expected else {
        return Err(DELETE_UNPROVEN);
    };
    let live = match probe(&path) {
        Probe::Present(live) => live,
        Probe::Missing => return Ok(ApplyOutcome::AlreadySatisfied),
        Probe::Unreadable => return Ok(ApplyOutcome::Retry("local metadata is unavailable")),
    };
    // Same-object proof: the journaled NTFS identity, generation **and** USN
    // must all still match. A local replacement (a new file identity) or a
    // newer local edit is never deleted by the old item's removal.
    if !verify_expected(expected, &live, generation) {
        return Err(DELETE_UNPROVEN);
    }
    // Ownership proof: a placeholder must carry the exact expected HFDR
    // identity. A plain local file has no inline identity and is protected by
    // the same-object proof alone.
    if placeholder_state(live.identity.attributes, live.identity.reparse_tag).is_placeholder() {
        let Some(identity) = identity else {
            return Err(DELETE_NOT_OURS);
        };
        let occupant =
            hfdrive_windows::cfapi::ops::read_placeholder_identity(&path, Some(identity.workspace))
                .map_err(|_| DELETE_NOT_OURS)?;
        if !owns_placeholder(&live, occupant, identity) {
            return Err(DELETE_NOT_OURS);
        }
    }
    // The removal runs on the **same handle** that revalidates the object:
    // the path is never re-resolved between this proof and the disposition,
    // so a replacement object B at the path is never removed by A's
    // journaled delete. Proven absence (NotFound) satisfies the action.
    // The seam fires after the outer probe proved the journaled object and
    // **before** the same-handle open: a test replaces the object here, so
    // the handle-based revalidation below sees B and refuses.
    seams::before_mutation(&path);
    let handle = match hfdrive_windows::filesystem::volume::open_delete(&path) {
        Ok(handle) => handle,
        Err(FsError::NotFound { .. }) => return Ok(ApplyOutcome::AlreadySatisfied),
        Err(_) => return Ok(ApplyOutcome::Retry("local metadata is unavailable")),
    };
    let live = match hfdrive_windows::filesystem::volume::state_on_handle(&handle) {
        Ok(live) => live,
        Err(_) => return Ok(ApplyOutcome::Retry("local metadata is unavailable")),
    };
    if !verify_expected(expected, &live, generation) {
        return Err(DELETE_UNPROVEN);
    }
    match hfdrive_windows::filesystem::volume::mark_deleted(&handle) {
        Ok(()) => Ok(ApplyOutcome::Applied { echo_path: relative.to_path_buf() }),
        // Not-Found during removal is proven absence of the target object.
        Err(FsError::NotFound { .. }) => Ok(ApplyOutcome::AlreadySatisfied),
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
///
/// The snapshot-dependency flag considers **only** staged captures that
/// unfinished work for this exact item still references as its payload
/// source. Unrelated retained captures (other items' staged or retired
/// snapshots) and captures whose durable consumers already finished never
/// block freeing this item's local space.
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
        .snapshot_dependencies(connection, item_id)
        .await
        .map(|dependencies| !dependencies.is_empty())
        .unwrap_or(true); // Unknown dependencies block freeing, never allow it.
    FreeSpaceEvidence {
        committed: content_version_id.is_some(),
        clean: !dirty,
        unpinned: !pinned,
        conflict_free: !conflicts_open,
        no_snapshot_dependency: !snapshot_dependency,
    }
}

/// Closes an applied local action and registers all of its echo paths,
/// including a rename's old/intermediate names and a deletion's absent path.
/// The caller holds the observer's echo lock across this durable handoff:
/// observers see either `InProgress` or the completed echo, never a gap.
pub async fn complete_action(
    state: &AccountStore,
    action: &hfdrive_state::LocalAction,
    root: &Path,
    echo: &mut EchoTable,
) -> Result<(), hfdrive_state::StateError> {
    state
        .set_local_action_state(action.connection_id, action.action_id, LocalActionState::Applied)
        .await?;
    echo.note_applied(action, root);
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

/// What recovery may prove about an action's target location. Only
/// [`TargetProof::JournaledObject`] is ever evidence that a Create or Rename
/// already achieved its target: mere existence is [`TargetProof::ForeignObject`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetProof {
    /// The target path is proven absent (`NotFound`).
    Missing,
    /// The target holds exactly the journaled object: the journaled NTFS file
    /// identity and generation match, and a placeholder there also carries
    /// the exact expected HFDR identity.
    JournaledObject,
    /// Something else holds the target (a replacement, a foreign placeholder,
    /// or a plain occupant where a placeholder is required). It is preserved
    /// untouched and never counts as the action's result.
    ForeignObject,
    /// The target could not be inspected (a non-`NotFound` failure). Never
    /// treated as absence and never as success.
    Unreadable,
}

/// Proves what holds one action's target location at recovery time.
///
/// * `expected` + `generation` bind the journaled source object (a rename's
///   moved file); when supplied, the target must hold that exact object;
/// * `identity` + `require_placeholder` bind the placeholder identity the
///   action materializes; a required placeholder must be a placeholder of
///   this item exactly, and any placeholder there must carry the exact HFDR
///   identity;
/// * with neither proof available the target can never be
///   [`TargetProof::JournaledObject`], and **an ordinary (non-placeholder)
///   occupant is never provable at all**: without a placeholder there is no
///   inline HFDR record to compare, so the journaled NTFS object proof
///   (`expected` + `generation`) is the only thing that can make it the
///   action's result. `expected = None` with `identity = Some` on an ordinary
///   object is [`TargetProof::ForeignObject`] — the identity proves nothing
///   about what actually holds the path.
pub fn target_proof(
    path: &Path,
    expected: Option<&ExpectedLocal>,
    generation: u64,
    workspace: Option<WorkspaceId>,
    identity: Option<&PlaceholderIdentity>,
    require_placeholder: bool,
) -> TargetProof {
    let live = match probe(path) {
        Probe::Present(live) => live,
        Probe::Missing => return TargetProof::Missing,
        Probe::Unreadable => return TargetProof::Unreadable,
    };
    let placeholder =
        placeholder_state(live.identity.attributes, live.identity.reparse_tag).is_placeholder();
    if require_placeholder && !placeholder {
        return TargetProof::ForeignObject;
    }
    // A journaled source object must be exactly at the target (a landed move).
    if let Some(expected) = expected {
        if !relocated_object(&live, expected, generation) {
            return TargetProof::ForeignObject;
        }
    }
    // A placeholder at the target must carry the exact expected HFDR identity.
    if placeholder {
        let Some((workspace, identity)) = workspace.zip(identity) else {
            return TargetProof::ForeignObject;
        };
        if occupant_at(path, workspace, identity) != Occupant::Owned {
            return TargetProof::ForeignObject;
        }
    } else if expected.is_none() {
        // An ordinary object has no inline identity to compare: an expected
        // HFDR identity proves nothing about what holds this path, so
        // existence is never the action's result.
        return TargetProof::ForeignObject;
    }
    if expected.is_none() && identity.is_none() {
        // Nothing journaled proves this object: existence is not proof.
        return TargetProof::ForeignObject;
    }
    TargetProof::JournaledObject
}

/// Classifies an interrupted journaled action. `live` is the probe of the
/// action's own path (only proven `NotFound` counts as absence) and `target`
/// is the proof (never a bare existence flag) of the action's target
/// location.
pub fn classify_recovered(
    action_kind: hfdrive_state::LocalActionKind,
    expected: Option<&ExpectedLocal>,
    live: &Probe,
    generation: u64,
    target: TargetProof,
) -> RecoveryDecision {
    match action_kind {
        hfdrive_state::LocalActionKind::CreatePlaceholder => match target {
            // The exact expected placeholder is there: the creation landed.
            TargetProof::JournaledObject => RecoveryDecision::Done,
            // Nothing there yet (or it cannot be inspected yet): create it.
            TargetProof::Missing | TargetProof::Unreadable => RecoveryDecision::Retry,
            // A different object occupies the target; it is preserved and the
            // item returns to reconciliation (a collision, never an overwrite).
            TargetProof::ForeignObject => RecoveryDecision::Requeue,
        },
        hfdrive_state::LocalActionKind::UpdatePlaceholder => match live {
            Probe::Present(state) => match expected {
                Some(expected) if verify_expected(expected, state, generation) => {
                    RecoveryDecision::Retry
                }
                Some(_) => RecoveryDecision::Requeue,
                // No journaled expectation: retry, and the guarded executor
                // refuses until one is proven.
                None => RecoveryDecision::Retry,
            },
            // The item is gone locally; only reconciliation may decide what
            // that means.
            Probe::Missing => RecoveryDecision::Requeue,
            // "Cannot inspect" is never "gone": retry later.
            Probe::Unreadable => RecoveryDecision::Retry,
        },
        hfdrive_state::LocalActionKind::Rename => match target {
            // The journaled object is provably at its destination: the move
            // landed. Mere target existence is never this proof.
            TargetProof::JournaledObject => RecoveryDecision::Done,
            TargetProof::Missing => match live {
                // The source object is still exactly the journaled one: the
                // move never started and may run again.
                Probe::Present(state)
                    if expected
                        .is_some_and(|expected| verify_expected(expected, state, generation)) =>
                {
                    RecoveryDecision::Retry
                }
                // Neither a live journaled source nor a proven destination:
                // the moved object is unknown to this action.
                Probe::Present(_) | Probe::Missing => RecoveryDecision::Requeue,
                Probe::Unreadable => RecoveryDecision::Retry,
            },
            TargetProof::ForeignObject => RecoveryDecision::Requeue,
            TargetProof::Unreadable => RecoveryDecision::Retry,
        },
        hfdrive_state::LocalActionKind::DeletePlaceholder => match live {
            // Proven absence: the removal already happened.
            Probe::Missing => RecoveryDecision::Done,
            // "Cannot inspect" is never "deleted".
            Probe::Unreadable => RecoveryDecision::Retry,
            Probe::Present(state) => match expected {
                // A replacement (or any object failing the same-object proof)
                // is preserved untouched: the old item's delete never removes
                // it, and the item returns to reconciliation as local work.
                Some(expected) if !verify_expected(expected, state, generation) => {
                    RecoveryDecision::Requeue
                }
                _ if state.size > 0 => RecoveryDecision::PreserveFirst,
                _ => RecoveryDecision::Retry,
            },
        },
        hfdrive_state::LocalActionKind::Dehydrate => match live {
            Probe::Present(state) if state.size > 0 => RecoveryDecision::Retry,
            Probe::Present(_) | Probe::Missing => RecoveryDecision::Done,
            Probe::Unreadable => RecoveryDecision::Retry,
        },
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
    fn deletion_maps_only_not_found_metadata_to_already_satisfied() {
        use std::os::windows::fs::OpenOptionsExt;

        let directory = tempfile::tempdir().unwrap();
        let expected = expected(1, Some(11));
        assert!(matches!(
            delete_local(
                directory.path(),
                Path::new("missing.txt"),
                Some(&expected),
                1,
                None,
            ),
            Ok(ApplyOutcome::AlreadySatisfied)
        ));

        // A handle that denies all sharing makes the metadata query fail with
        // a sharing violation. That is not evidence that the path is absent.
        let locked = directory.path().join("locked.txt");
        std::fs::write(&locked, b"must survive").unwrap();
        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&locked)
            .unwrap();
        assert!(matches!(
            delete_local(
                directory.path(),
                Path::new("locked.txt"),
                Some(&expected),
                1,
                None,
            ),
            Ok(ApplyOutcome::Retry(_))
        ));
        drop(held);
        assert_eq!(std::fs::read(&locked).unwrap(), b"must survive");
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
            classify_recovered(
                LocalActionKind::CreatePlaceholder,
                None,
                &Probe::Missing,
                0,
                TargetProof::JournaledObject,
            ),
            RecoveryDecision::Done
        );
        assert_eq!(
            classify_recovered(
                LocalActionKind::CreatePlaceholder,
                None,
                &Probe::Missing,
                0,
                TargetProof::Missing,
            ),
            RecoveryDecision::Retry
        );
        let expected = expected(2, Some(5));
        assert_eq!(
            classify_recovered(
                LocalActionKind::UpdatePlaceholder,
                Some(&expected),
                &Probe::Present(live(Some(5))),
                2,
                TargetProof::Missing,
            ),
            RecoveryDecision::Retry
        );
        assert_eq!(
            classify_recovered(
                LocalActionKind::UpdatePlaceholder,
                Some(&expected),
                &Probe::Present(live(Some(6))),
                2,
                TargetProof::Missing,
            ),
            RecoveryDecision::Requeue
        );
        // A delete with unsynchronized bytes must preserve them first.
        let dirty = FileState { size: 42, ..live(Some(6)) };
        assert_eq!(
            classify_recovered(
                LocalActionKind::DeletePlaceholder,
                None,
                &Probe::Present(dirty),
                0,
                TargetProof::Missing,
            ),
            RecoveryDecision::PreserveFirst
        );
        assert_eq!(
            classify_recovered(
                LocalActionKind::DeletePlaceholder,
                None,
                &Probe::Missing,
                0,
                TargetProof::Missing,
            ),
            RecoveryDecision::Done
        );
    }

    #[test]
    fn per_entry_creation_outcomes_are_each_inspected() {
        use hfdrive_windows::cfapi::ops::PlaceholderRequestOutcome;
        use hfdrive_windows::filesystem::volume::PlaceholderState;
        use std::cell::Cell;

        let echo = Path::new("child.txt");
        let consulted = Cell::new(0);
        // A real `Created` succeeds without ever consulting the occupant.
        assert_eq!(
            classify_creation(echo, &PlaceholderRequestOutcome::Created { usn: 7 }, || {
                consulted.set(consulted.get() + 1);
                Occupant::Foreign
            }),
            CreationOutcome::Created { echo_path: echo.to_path_buf() }
        );
        assert_eq!(consulted.get(), 0, "a created entry never probes the path");

        // `AlreadyExists` succeeds only for the exact expected identity.
        let exists = PlaceholderRequestOutcome::AlreadyExists {
            state: PlaceholderState(0),
        };
        assert_eq!(
            classify_creation(echo, &exists, || Occupant::Owned),
            CreationOutcome::AlreadyCreated
        );
        // A foreign occupant and an unverifiable one are never success: the
        // occupant is preserved untouched and the action stays pending.
        assert_eq!(
            classify_creation(echo, &exists, || Occupant::Foreign),
            CreationOutcome::Occupied(
                "the creation target is occupied by a different local object"
            )
        );
        assert_eq!(
            classify_creation(echo, &exists, || Occupant::Unverifiable),
            CreationOutcome::Occupied(
                "the creation target's occupant cannot be verified"
            )
        );

        // A per-entry failure is a real failure with its OS code, never
        // "created" and never a silent success — and it never probes either.
        assert_eq!(
            classify_creation(echo, &PlaceholderRequestOutcome::Failed { code: -123 }, || {
                consulted.set(consulted.get() + 1);
                Occupant::Owned
            }),
            CreationOutcome::EntryFailed { code: -123 }
        );
        assert_eq!(consulted.get(), 0, "a failed entry never probes the path");
    }

    #[test]
    fn startup_identity_checks_prove_the_journaled_object() {
        use std::os::windows::fs::OpenOptionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("moved.bin");
        std::fs::write(&path, b"journaled bytes").unwrap();
        let live = hfdrive_windows::filesystem::volume::query_file_state(&path).unwrap();
        let expected = ExpectedLocal {
            file_id: live.identity.file_id,
            volume_serial_number: live.identity.volume_serial_number,
            generation: 4,
            usn: live.usn,
        };

        // Proven absence is Missing; existence alone is never proof.
        assert_eq!(
            target_proof(
                &directory.path().join("absent.bin"),
                Some(&expected),
                4,
                None,
                None,
                false,
            ),
            TargetProof::Missing
        );
        assert_eq!(
            target_proof(&path, None, 0, None, None, false),
            TargetProof::ForeignObject,
            "with nothing journaled, an existing object is never the action's result"
        );

        // The exact journaled object at the target is the only "already
        // moved" proof: identity + generation, never mere existence.
        assert_eq!(
            target_proof(&path, Some(&expected), 4, None, None, false),
            TargetProof::JournaledObject
        );
        // A newer local generation at the target (or a drifted file identity)
        // is a replacement, not the moved journaled object.
        assert_eq!(
            target_proof(&path, Some(&expected), 5, None, None, false),
            TargetProof::ForeignObject,
            "a different generation at the target is a replacement, not the moved object"
        );
        let other_object = ExpectedLocal { file_id: [9; 16], ..expected.clone() };
        assert_eq!(
            target_proof(&path, Some(&other_object), 4, None, None, false),
            TargetProof::ForeignObject
        );

        // A required placeholder that is a plain file is foreign.
        let item = ItemId::new();
        let identity = PlaceholderIdentity::directory(
            hfdrive_core::ids::WorkspaceId::new(),
            item,
        );
        assert_eq!(
            target_proof(
                &path,
                Some(&expected),
                4,
                Some(identity.workspace),
                Some(&identity),
                true,
            ),
            TargetProof::ForeignObject
        );

        // A path that cannot be inspected is never absence and never success.
        let locked = directory.path().join("locked.bin");
        std::fs::write(&locked, b"held").unwrap();
        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&locked)
            .unwrap();
        assert_eq!(
            target_proof(&locked, Some(&expected), 4, None, None, false),
            TargetProof::Unreadable
        );
        drop(held);
    }

    /// The P2-R2 regression: an **ordinary** (non-placeholder) object at the
    /// target is never provable by an expected HFDR identity alone. Without a
    /// placeholder there is no inline record to compare, so `expected = None`
    /// with `identity = Some` and `require_placeholder = false` must be
    /// [`TargetProof::ForeignObject`] — mere existence is not the action's
    /// result, and a Create/Rename must return to reconciliation instead of
    /// claiming it landed.
    #[test]
    fn an_ordinary_target_is_never_proven_by_an_expected_identity_alone() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ordinary.bin");
        std::fs::write(&path, b"ordinary bytes").unwrap();
        let live = hfdrive_windows::filesystem::volume::query_file_state(&path).unwrap();
        assert!(
            !hfdrive_windows::filesystem::volume::placeholder_state(
                live.identity.attributes,
                live.identity.reparse_tag,
            )
            .is_placeholder(),
            "the fixture occupant is an ordinary file"
        );

        let workspace = hfdrive_core::ids::WorkspaceId::new();
        let item = ItemId::new();
        let identity = PlaceholderIdentity::file(workspace, item, VersionId::new());

        // The exact regression: expected=None, identity=Some, ordinary target,
        // no placeholder requirement. The identity proves nothing about what
        // holds the path, so this is foreign — never JournaledObject.
        assert_eq!(
            target_proof(&path, None, 0, Some(workspace), Some(&identity), false),
            TargetProof::ForeignObject,
            "an ordinary occupant is never proven by an expected identity alone"
        );
        // Same occupant, still ordinary, with a generation supplied: the
        // identity still proves nothing without the journaled object proof.
        assert_eq!(
            target_proof(&path, None, 9, Some(workspace), Some(&identity), false),
            TargetProof::ForeignObject
        );
        // And with no identity either: nothing journaled proves this object.
        assert_eq!(
            target_proof(&path, None, 0, None, None, false),
            TargetProof::ForeignObject
        );

        // Control — the journaled NTFS object proof still proves an ordinary
        // target (a landed move of a plain file), so the fix does not weaken
        // valid recovery: identity + generation of the very object at the path.
        let expected = ExpectedLocal {
            file_id: live.identity.file_id,
            volume_serial_number: live.identity.volume_serial_number,
            generation: 4,
            usn: live.usn,
        };
        assert_eq!(
            target_proof(&path, Some(&expected), 4, Some(workspace), Some(&identity), false),
            TargetProof::JournaledObject,
            "a proven journaled ordinary object is still the action's result"
        );
        // A foreign object at the target stays foreign under the same proof.
        let other = ExpectedLocal { file_id: [9; 16], ..expected.clone() };
        assert_eq!(
            target_proof(&path, Some(&other), 4, Some(workspace), Some(&identity), false),
            TargetProof::ForeignObject
        );

        // The recovery verdicts follow: an unproven ordinary occupant requeues
        // the item as fresh local work, never closes the action as done.
        for kind in [LocalActionKind::CreatePlaceholder, LocalActionKind::Rename] {
            assert_eq!(
                classify_recovered(kind, None, &Probe::Missing, 0, TargetProof::ForeignObject),
                RecoveryDecision::Requeue
            );
        }
    }

    #[test]
    fn recovery_never_reads_target_existence_as_done() {
        let expected = expected(2, Some(5));
        let live = live(Some(5));
        let missing = Probe::Missing;

        // A Create or Rename whose target merely exists (a foreign occupant)
        // is never "Done": the occupant is preserved and the item returns to
        // reconciliation. Only the proven journaled object closes the action.
        for kind in [LocalActionKind::CreatePlaceholder, LocalActionKind::Rename] {
            assert_eq!(
                classify_recovered(kind, Some(&expected), &missing, 2, TargetProof::ForeignObject),
                RecoveryDecision::Requeue
            );
            assert_eq!(
                classify_recovered(kind, Some(&expected), &missing, 2, TargetProof::JournaledObject),
                RecoveryDecision::Done
            );
        }
        // A Create whose target is proven absent creates it; a Rename whose
        // source AND destination are both unknown re-observes instead.
        assert_eq!(
            classify_recovered(
                LocalActionKind::CreatePlaceholder,
                Some(&expected),
                &missing,
                2,
                TargetProof::Missing,
            ),
            RecoveryDecision::Retry
        );
        assert_eq!(
            classify_recovered(
                LocalActionKind::Rename,
                Some(&expected),
                &missing,
                2,
                TargetProof::Missing,
            ),
            RecoveryDecision::Requeue
        );
        // A rename whose source is still the journaled object may run again.
        assert_eq!(
            classify_recovered(
                LocalActionKind::Rename,
                Some(&expected),
                &Probe::Present(live.clone()),
                2,
                TargetProof::Missing,
            ),
            RecoveryDecision::Retry
        );
        // A delete whose path holds a different object (a local replacement)
        // preserves it and re-observes: never PreserveFirst, never Done.
        let mut replacement = live.clone();
        replacement.identity.file_id = [9; 16];
        assert_eq!(
            classify_recovered(
                LocalActionKind::DeletePlaceholder,
                Some(&expected),
                &Probe::Present(replacement),
                2,
                TargetProof::Missing,
            ),
            RecoveryDecision::Requeue
        );
    }

    #[test]
    fn rename_refuses_drift_and_unreadable_sources_without_touching_bytes() {
        use std::os::windows::fs::OpenOptionsExt;

        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let from = Path::new("from.txt");
        let to = Path::new("to.txt");
        std::fs::write(root.join(from), b"source A").unwrap();
        std::fs::write(root.join(to), b"destination B").unwrap();
        let live = hfdrive_windows::filesystem::volume::query_file_state(&root.join(from)).unwrap();
        let expected = ExpectedLocal {
            file_id: live.identity.file_id,
            volume_serial_number: live.identity.volume_serial_number,
            generation: 2,
            usn: live.usn,
        };
        let intermediate = rename_intermediate(&to.to_path_buf(), ActionId::new());

        // The destination is occupied by a different object: the rename is
        // refused and both files keep their bytes.
        assert_eq!(
            rename_local(root, from, to, false, &intermediate, Some(&expected), 2),
            Err(RENAME_OCCUPIED)
        );
        assert_eq!(std::fs::read(root.join(from)).unwrap(), b"source A");
        assert_eq!(std::fs::read(root.join(to)).unwrap(), b"destination B");

        // A drifted journaled expectation refuses the move entirely.
        let drifted = ExpectedLocal { usn: live.usn.map(|usn| usn + 1), ..expected.clone() };
        let free = Path::new("free.txt");
        assert_eq!(
            rename_local(root, from, free, false, &intermediate, Some(&drifted), 2),
            Err(RENAME_UNPROVEN)
        );
        assert!(!root.join(free).exists());
        assert_eq!(std::fs::read(root.join(from)).unwrap(), b"source A");

        // A source that cannot be inspected (a non-NotFound failure) is never
        // "already moved": the action stays pending and nothing is renamed.
        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(root.join(from))
            .unwrap();
        assert_eq!(
            rename_local(root, from, free, false, &intermediate, Some(&expected), 2),
            Err(RENAME_SOURCE_UNREADABLE)
        );
        drop(held);
        assert!(!root.join(free).exists());
        assert_eq!(std::fs::read(root.join(from)).unwrap(), b"source A");
    }

    #[test]
    fn a_case_only_rename_fixes_the_spelling_through_the_journaled_intermediate() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let from = Path::new("report.txt");
        let to = Path::new("Report.txt");
        std::fs::write(root.join(from), b"spelling bytes").unwrap();
        let live = hfdrive_windows::filesystem::volume::query_file_state(&root.join(from)).unwrap();
        let expected = ExpectedLocal {
            file_id: live.identity.file_id,
            volume_serial_number: live.identity.volume_serial_number,
            generation: 2,
            usn: live.usn,
        };
        let intermediate = rename_intermediate(&to.to_path_buf(), ActionId::new());

        // On case-insensitive NTFS the destination aliases the live source,
        // so this must fix the spelling — not report the move as already done
        // and not refuse it as "occupied by itself".
        let outcome = rename_local(root, from, to, true, &intermediate, Some(&expected), 2).unwrap();
        assert_eq!(outcome, RenameOutcome::Applied { echo_path: to.to_path_buf() });
        assert_eq!(std::fs::read(root.join(to)).unwrap(), b"spelling bytes");
        assert!(!root.join(&intermediate).exists(), "the intermediate is consumed");

        // A half-done case-only move waiting at the journaled intermediate is
        // finished rather than left under the intermediate name.
        let from2 = Path::new("second.txt");
        let to2 = Path::new("Second.txt");
        std::fs::write(root.join(&intermediate), b"half-moved bytes").unwrap();
        let half = hfdrive_windows::filesystem::volume::query_file_state(&root.join(&intermediate)).unwrap();
        let half_expected = ExpectedLocal {
            file_id: half.identity.file_id,
            volume_serial_number: half.identity.volume_serial_number,
            generation: 3,
            usn: half.usn,
        };
        let outcome = rename_local(
            root,
            from2,
            to2,
            true,
            &intermediate,
            Some(&half_expected),
            3,
        )
        .unwrap();
        assert_eq!(outcome, RenameOutcome::Applied { echo_path: to2.to_path_buf() });
        assert_eq!(std::fs::read(root.join(to2)).unwrap(), b"half-moved bytes");
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

    #[tokio::test]
    async fn free_space_dependency_scopes_to_the_item_and_allows_completed_work() {
        use hfdrive_core::ids::{OperationId, SnapshotId, UploadId};
        use hfdrive_core::storage::{ObjectRef, PayloadKey, XetFileId};
        use hfdrive_state::{
            ItemKind, ItemRecord, OutboxEntry, OutboxTransition, SnapshotStatus,
        };

        let fixture = crate::sync::test_support::connection_fixture().await;
        let state = &fixture.account;
        let connection = fixture.connection;
        let staging = fixture.directory.path().join("staging");
        std::fs::create_dir_all(&staging).unwrap();

        let item = ItemId::new();
        let other = ItemId::new();
        let version = VersionId::new();
        for (id, name) in [(item, "a.txt"), (other, "b.txt")] {
            state
                .upsert_item(ItemRecord {
                    connection_id: connection,
                    item_id: id,
                    parent_id: Some(fixture.root_item),
                    name: name.to_owned(),
                    name_key: name.to_owned(),
                    kind: ItemKind::File,
                    revision: OperationId::new(),
                    content_version_id: Some(VersionId::new()),
                    deleted: false,
                    metadata_json: serde_json::json!({}),
                })
                .await
                .unwrap();
            state.bump_observation(connection, id, None).await.unwrap();
        }

        // Staged captures: one per item plus one nobody references at all.
        let mut snapshots = Vec::new();
        for name in ["a", "b", "orphan"] {
            let snapshot_id = SnapshotId::new();
            let path = staging.join(format!("{name}.snap"));
            std::fs::write(&path, b"payload").unwrap();
            state.begin_snapshot(connection, snapshot_id, path).await.unwrap();
            state
                .complete_snapshot(connection, snapshot_id, 7, hfdrive_core::storage::Sha256Digest::of(b"payload"))
                .await
                .unwrap();
            snapshots.push(snapshot_id);
        }
        let (own_snapshot, other_snapshot, orphan_snapshot) =
            (snapshots[0], snapshots[1], snapshots[2]);

        let intent = |item_id: ItemId| serde_json::json!({"kind": "content", "item_id": item_id.to_string()});
        let own_operation = OperationId::new();
        state
            .record_outbox(OutboxEntry::observed(connection, own_operation, Some(item), 1, intent(item)))
            .await
            .unwrap();
        state
            .transition_outbox(connection, own_operation, OutboxTransition::SnapshotReady { snapshot_id: own_snapshot })
            .await
            .unwrap();
        let other_operation = OperationId::new();
        state
            .record_outbox(OutboxEntry::observed(connection, other_operation, Some(other), 1, intent(other)))
            .await
            .unwrap();
        state
            .transition_outbox(connection, other_operation, OutboxTransition::SnapshotReady { snapshot_id: other_snapshot })
            .await
            .unwrap();

        // The item's own unfinished staged capture blocks freeing it.
        let evidence = free_space_evidence(state, connection, item, Some(version), false, false).await;
        assert!(
            !evidence.no_snapshot_dependency,
            "the item's own staged capture with unfinished work must block"
        );
        // The unrelated retained capture never shows up as this item's
        // dependency, and an unreferenced capture blocks nobody.
        assert_eq!(
            state.snapshot_dependencies(connection, item).await.unwrap().len(),
            1,
            "only this item's own staged capture counts"
        );
        let other_dependencies = state.snapshot_dependencies(connection, other).await.unwrap();
        assert_eq!(other_dependencies.len(), 1);
        assert_eq!(other_dependencies[0].snapshot_id, other_snapshot);
        for id in [item, other] {
            assert!(
                !state
                    .snapshot_dependencies(connection, id)
                    .await
                    .unwrap()
                    .iter()
                    .any(|snapshot| snapshot.snapshot_id == orphan_snapshot),
                "an unreferenced retained capture must never block free space"
            );
        }

        // Freeing the *other* item (not requested here) is unaffected by this
        // item's work: its only dependency is its own, still unfinished.
        let other_evidence = free_space_evidence(state, connection, other, Some(version), false, false).await;
        assert!(!other_evidence.no_snapshot_dependency);

        // Once the item's work completes, only *its* dependency is gone: the
        // completed item passes Free Space evidence end to end while the
        // other item stays blocked by its own unfinished work.
        state
            .transition_outbox(
                connection,
                own_operation,
                OutboxTransition::PayloadReady {
                    object_ref: ObjectRef {
                        key: PayloadKey::new(UploadId::new()),
                        sha256: hfdrive_core::storage::Sha256Digest::of(b"payload"),
                        size: 7,
                        xet_file_id: XetFileId::new("ab".repeat(32)).unwrap(),
                    },
                },
            )
            .await
            .unwrap();
        state
            .transition_outbox(
                connection,
                own_operation,
                OutboxTransition::MetadataReady {
                    candidate_commit: hfdrive_core::ids::CommitId::new(),
                    candidate_head_json: serde_json::json!({}),
                    expected_etag: "e".to_owned(),
                },
            )
            .await
            .unwrap();
        state.transition_outbox(connection, own_operation, OutboxTransition::Published).await.unwrap();
        state
            .transition_outbox(connection, own_operation, OutboxTransition::LocalApplyPending)
            .await
            .unwrap();
        let outcome = state.complete_outbox(connection, own_operation).await.unwrap();
        assert!(
            matches!(outcome, hfdrive_state::CompletionOutcome::Completed { generation: 1 }),
            "found {outcome:?}"
        );
        assert_eq!(
            state.snapshot(connection, own_snapshot).await.unwrap().unwrap().status,
            SnapshotStatus::Consumed,
            "the finished consumer's capture retires"
        );

        let evidence = free_space_evidence(state, connection, item, Some(version), false, false).await;
        assert!(
            evidence.verify().is_ok(),
            "a completed item frees local space: {evidence:?}"
        );
        let other_evidence = free_space_evidence(state, connection, other, Some(version), false, false).await;
        assert!(
            !other_evidence.no_snapshot_dependency,
            "the unrelated item's own unfinished work still blocks only it"
        );
    }

    // -- K03: same-handle destructive actions survive a replacement -------

    /// A rename whose journaled source object A is replaced by a different
    /// object B **after** the final probe but **before** the mutation must be
    /// refused: B survives untouched at the source path, the destination is
    /// never created, and the action stays pending.
    ///
    /// The seam fires inside that exact window, so the interleaving is
    /// deterministic instead of relying on a race.
    #[test]
    fn a_replacement_after_the_final_probe_refuses_the_rename() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let from = Path::new("from.txt");
        let to = Path::new("to.txt");
        let source = root.join(from);
        std::fs::write(&source, b"journaled A").unwrap();
        let original = hfdrive_windows::filesystem::volume::query_file_state(&source).unwrap();
        let expected = ExpectedLocal {
            file_id: original.identity.file_id,
            volume_serial_number: original.identity.volume_serial_number,
            generation: 2,
            usn: original.usn,
        };
        let intermediate = rename_intermediate(&to.to_path_buf(), ActionId::new());

        // Replace A with B inside the probe -> mutation window.
        let replacement = source.clone();
        seams::install_before_mutation(Box::new(move |path| {
            assert_eq!(path, &replacement);
            std::fs::remove_file(path).unwrap();
            std::fs::write(path, b"replacement B").unwrap();
        }));

        let result = rename_local(root, from, to, false, &intermediate, Some(&expected), 2);
        assert_eq!(result, Err(RENAME_UNPROVEN));
        // B survives: A's journaled rename never moved the replacement.
        assert_eq!(std::fs::read(&source).unwrap(), b"replacement B");
        assert!(!root.join(to).exists(), "the destination is never created");
    }

    /// The same window for deletion: a replacement B must survive A's
    /// journaled delete, which is refused and stays pending.
    #[test]
    fn a_replacement_after_the_final_probe_refuses_the_delete() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let relative = Path::new("report.txt");
        let path = root.join(relative);
        std::fs::write(&path, b"journaled A").unwrap();
        let original = hfdrive_windows::filesystem::volume::query_file_state(&path).unwrap();
        let expected = ExpectedLocal {
            file_id: original.identity.file_id,
            volume_serial_number: original.identity.volume_serial_number,
            generation: 3,
            usn: original.usn,
        };

        let replacement = path.clone();
        seams::install_before_mutation(Box::new(move |target| {
            assert_eq!(target, &replacement);
            std::fs::remove_file(target).unwrap();
            std::fs::write(target, b"replacement B").unwrap();
        }));

        let result = delete_local(root, relative, Some(&expected), 3, None);
        assert_eq!(result, Err(DELETE_UNPROVEN));
        // B survives: A's journaled delete never removed the replacement.
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement B");
    }

    /// A case-only rename fixes the spelling through the journaled
    /// intermediate even when the object is replaced in the probe -> mutation
    /// window: the replacement is preserved, never renamed.
    #[test]
    fn a_replacement_after_the_final_probe_refuses_the_case_only_rename() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let from = Path::new("report.txt");
        let to = Path::new("Report.txt");
        let source = root.join(from);
        std::fs::write(&source, b"journaled A").unwrap();
        let original = hfdrive_windows::filesystem::volume::query_file_state(&source).unwrap();
        let expected = ExpectedLocal {
            file_id: original.identity.file_id,
            volume_serial_number: original.identity.volume_serial_number,
            generation: 2,
            usn: original.usn,
        };
        let intermediate = rename_intermediate(&to.to_path_buf(), ActionId::new());

        let replacement = source.clone();
        seams::install_before_mutation(Box::new(move |path| {
            // The seam must fire at the journaled source: the case-only move
            // starts from there, before the intermediate is ever involved.
            assert_eq!(path, &replacement);
            std::fs::remove_file(path).unwrap();
            std::fs::write(path, b"replacement B").unwrap();
        }));

        let result = rename_local(root, from, to, true, &intermediate, Some(&expected), 2);
        assert_eq!(result, Err(RENAME_UNPROVEN));
        assert_eq!(std::fs::read(&source).unwrap(), b"replacement B");
        assert!(
            !root.join(&intermediate).exists(),
            "no intermediate is left behind"
        );
    }

    /// Without a seam the guarded rename still lands normally: the seam is a
    /// test-only interleaving point, not a behavior change.
    #[test]
    fn a_guarded_rename_still_applies_without_a_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let from = Path::new("from.txt");
        let to = Path::new("to.txt");
        let source = root.join(from);
        std::fs::write(&source, b"journaled A").unwrap();
        let original = hfdrive_windows::filesystem::volume::query_file_state(&source).unwrap();
        let expected = ExpectedLocal {
            file_id: original.identity.file_id,
            volume_serial_number: original.identity.volume_serial_number,
            generation: 2,
            usn: original.usn,
        };
        let intermediate = rename_intermediate(&to.to_path_buf(), ActionId::new());

        let outcome = rename_local(root, from, to, false, &intermediate, Some(&expected), 2).unwrap();
        assert_eq!(outcome, RenameOutcome::Applied { echo_path: to.to_path_buf() });
        assert!(!source.exists());
        assert_eq!(std::fs::read(root.join(to)).unwrap(), b"journaled A");
    }

    /// A guarded delete still removes the verified object normally when
    /// nothing replaces it in the window.
    #[test]
    fn a_guarded_delete_still_applies_without_a_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let relative = Path::new("report.txt");
        let path = root.join(relative);
        std::fs::write(&path, b"journaled A").unwrap();
        let original = hfdrive_windows::filesystem::volume::query_file_state(&path).unwrap();
        let expected = ExpectedLocal {
            file_id: original.identity.file_id,
            volume_serial_number: original.identity.volume_serial_number,
            generation: 3,
            usn: original.usn,
        };

        let outcome = delete_local(root, relative, Some(&expected), 3, None).unwrap();
        assert_eq!(outcome, ApplyOutcome::Applied { echo_path: relative.to_path_buf() });
        assert!(!path.exists());
    }
}
