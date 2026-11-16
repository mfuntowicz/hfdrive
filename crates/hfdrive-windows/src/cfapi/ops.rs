//! Guarded placeholder operations.
//!
//! Every operation here states its preconditions in types and re-checks the
//! verifiable ones through handles before touching CFAPI:
//!
//! * [`set_in_sync`] / [`update_placeholder`] / [`convert_published`] bind to
//!   the caller's observed [`FileState`] **including the expected USN**. A
//!   missing expected USN (`None`) is never a successful match — the guard
//!   returns [`GuardMismatch::UsnUnknown`] and the file stays dirty/old.
//! * [`update_placeholder`] uses `VERIFY_IN_SYNC | MARK_IN_SYNC` and
//!   invalidates exactly the supplied old ranges.
//! * [`dehydrate`] requires a [`FreeSpaceEvidence`] with every flag true
//!   (committed, clean, unpinned, conflict-free, no snapshot dependency) and
//!   then verifies the live pin/in-sync state before touching anything.
//! * [`set_pin_state`] reports requested pin state and full hydration
//!   **separately**; a failed pin never claims availability.
//! * [`create_placeholders`] runs bounded batches and returns every
//!   per-placeholder outcome; an existing local path is reported
//!   [`PlaceholderRequestOutcome::AlreadyExists`] for reconciliation and is
//!   never overwritten.
//!
//! None of these functions fabricate in-sync/offline/complete state: all
//! mismatches surface as [`GuardOutcome::Mismatch`] with content preserved.

use std::path::Path;

use hfdrive_core::storage::ByteRange;

use crate::ffi::cfapi::{self as raw, MetadataBytes, PendingCreate};
use crate::ffi::volume as raw_volume;

use super::identity::PlaceholderIdentity;
use super::{CfError, CfResult};

/// Display filesystem metadata for placeholder creation/update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataSpec {
    pub size: u64,
    pub creation_time_100ns: i64,
    pub last_write_time_100ns: i64,
    pub attributes: u32,
}

/// One placeholder to create (bounded batches).
#[derive(Clone, Debug)]
pub struct PlaceholderCreate {
    /// Single final-component name (validated).
    pub name: String,
    pub metadata: MetadataSpec,
    pub identity: PlaceholderIdentity,
    /// Create already marked in-sync (the item is committed and no local
    /// content exists yet).
    pub mark_in_sync: bool,
}

/// Per-placeholder creation outcome (never inferred from a batch HRESULT).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlaceholderRequestOutcome {
    Created { usn: i64 },
    /// A path already exists here; the provider reconciles it (its own
    /// placeholder, a foreign placeholder or a plain file) instead of
    /// overwriting.
    AlreadyExists { state: crate::filesystem::volume::PlaceholderState },
    /// The entry failed with this HRESULT.
    Failed { code: i32 },
}

/// A named per-placeholder outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlaceholderOutcome {
    pub name: String,
    pub outcome: PlaceholderRequestOutcome,
}

/// Update specification: new immutable version metadata + identity and the
/// old ranges to invalidate.
#[derive(Clone, Debug)]
pub struct UpdateSpec {
    pub metadata: MetadataSpec,
    pub identity: PlaceholderIdentity,
    /// Old ranges whose cached bytes become invalid (half-open).
    pub invalidate: Vec<ByteRange>,
}

/// Why a guarded operation refused to apply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardMismatch {
    IdentityChanged,
    SizeChanged,
    TimeChanged,
    /// The expected USN is unknown on either side. Never treated as a match.
    UsnUnknown,
    UsnChanged,
    NotInSync,
    Pinned,
    NotPlaceholder,
    StateChanged,
}

/// Outcome of a guarded operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardOutcome {
    /// Applied; `usn` is the USN the transition landed at when known.
    Applied { usn: Option<i64> },
    /// Not applied; the file keeps its old/dirty state and the caller keeps
    /// its durable pending action.
    Mismatch(GuardMismatch),
}

/// Pin request values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinRequest {
    Pinned,
    Unpinned,
    Excluded,
}

/// Result of a pin action: the requested state and, separately, whether the
/// content is now fully resident. A failed pin returns `Err` and never
/// reports availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinOutcome {
    pub requested: PinRequest,
    pub fully_hydrated: bool,
}

/// Evidence bundle for free-space/dehydration actions. All flags must be
/// true; the API refuses otherwise and never deletes dirty/pinned data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreeSpaceEvidence {
    /// The content is committed remotely.
    pub committed: bool,
    /// No uncommitted local changes (clean generation).
    pub clean: bool,
    /// Not pinned / not required offline.
    pub unpinned: bool,
    /// No unresolved conflict.
    pub conflict_free: bool,
    /// No staged snapshot or durable work references this content.
    pub no_snapshot_dependency: bool,
}

impl FreeSpaceEvidence {
    /// Every precondition must hold; the error names the missing ones.
    pub fn verify(&self) -> CfResult<()> {
        if self.committed
            && self.clean
            && self.unpinned
            && self.conflict_free
            && self.no_snapshot_dependency
        {
            Ok(())
        } else {
            Err(CfError::Precondition(
                "free-space requires committed, clean, unpinned, conflict-free content with no snapshot dependency",
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Shared guard machinery
// ---------------------------------------------------------------------------

fn guard_check(
    handle: &crate::ffi::handle::OwnedHandle,
    expect: &crate::filesystem::volume::FileState,
    strict_usn: bool,
) -> Result<(), GuardMismatch> {
    // CFAPI oplock handles are opaque and cannot service Win32 metadata or
    // USN calls. `handle` is a separate normal query handle opened before
    // the CFAPI transition handle, never the opaque CFAPI handle itself.
    let id = raw_volume::id_info(&handle).map_err(|_| GuardMismatch::StateChanged)?;
    let std = raw_volume::standard_info(&handle).map_err(|_| GuardMismatch::StateChanged)?;
    let basic = raw_volume::basic_info(&handle).map_err(|_| GuardMismatch::StateChanged)?;
    if id.volume_serial_number != expect.identity.volume_serial_number
        || id.file_id != expect.identity.file_id
    {
        return Err(GuardMismatch::IdentityChanged);
    }
    if std.size != expect.size {
        return Err(GuardMismatch::SizeChanged);
    }
    if basic.last_write_time_100ns != expect.last_write_time_100ns {
        return Err(GuardMismatch::TimeChanged);
    }
    let current = crate::ffi::usn::file_usn(&handle).map_err(|_| GuardMismatch::UsnUnknown)?;
    if strict_usn {
        // A missing expected USN or a missing current USN is never a match.
        match (expect.usn, current) {
            (Some(expected), Some(current)) if expected == current => Ok(()),
            (Some(_), Some(_)) => Err(GuardMismatch::UsnChanged),
            _ => Err(GuardMismatch::UsnUnknown),
        }
    } else {
        Ok(())
    }
}

fn map_open(code: u32) -> CfError {
    CfError::Win32 {
        operation: "CfOpenFileWithOplock/CreateFileW",
        code,
    }
}

fn map_fs(error: super::super::filesystem::FsError) -> CfError {
    use super::super::filesystem::FsError;
    match error {
        FsError::Win32 { operation, code } => CfError::Win32 { operation, code },
        FsError::NotFound { .. } => CfError::Precondition("unlink target was not found"),
        FsError::SharingViolation => {
            CfError::Precondition("unlink target is in use by another writer")
        }
        _ => CfError::Precondition("placeholder state could not be observed"),
    }
}

// ---------------------------------------------------------------------------
// Guarded transitions
// ---------------------------------------------------------------------------

/// Mark a placeholder in-sync **only** when the local state still matches
/// `expect` (identity, size, mtime and exactly the expected USN). A mismatch
/// (including any unknown USN) leaves the file dirty.
pub fn set_in_sync(path: &Path, expect: &crate::filesystem::volume::FileState) -> Result<GuardOutcome, CfError> {
    let metadata_handle = raw_volume::open_query(path, true).map_err(map_open)?;
    if let Err(mismatch) = guard_check(&metadata_handle, expect, true) {
        return Ok(GuardOutcome::Mismatch(mismatch));
    }
    drop(metadata_handle);
    let handle = raw::open_with_oplock(path, true, true).map_err(map_open)?;
    let usn = raw::set_in_sync(&handle).map_err(|code| CfError::Win32 {
        operation: "CfSetInSyncState",
        code,
    })?;
    Ok(GuardOutcome::Applied { usn: Some(usn) })
}

/// Apply a new immutable version to a placeholder:
/// `CfUpdatePlaceholder` with `VERIFY_IN_SYNC | MARK_IN_SYNC`, new metadata,
/// new identity and invalidated old ranges. Requires the strict guard
/// (identity, size, mtime, exact expected USN); old-version fetch requests
/// must already be drained by the caller's scheduler.
pub fn update_placeholder(
    path: &Path,
    spec: &UpdateSpec,
    expect: &crate::filesystem::volume::FileState,
) -> Result<GuardOutcome, CfError> {
    let metadata_handle = raw_volume::open_query(path, true).map_err(map_open)?;
    if let Err(mismatch) = guard_check(&metadata_handle, expect, true) {
        return Ok(GuardOutcome::Mismatch(mismatch));
    }
    drop(metadata_handle);
    let handle = raw::open_with_oplock(path, true, true).map_err(map_open)?;
    let identity = spec.identity.encode();
    let mut invalidate = Vec::with_capacity(spec.invalidate.len());
    for range in &spec.invalidate {
        let start = i64::try_from(range.start()).map_err(|_| CfError::InvalidChunk)?;
        let len = i64::try_from(range.len()).map_err(|_| CfError::InvalidChunk)?;
        invalidate.push((start, len));
    }
    let usn = raw::update_placeholder(
        &handle,
        Some(&to_metadata(&spec.metadata)),
        &identity,
        &invalidate,
        expect.usn.expect("the strict guard verified a known USN"),
        true,
    )
    .map_err(|code| CfError::Win32 {
        operation: "CfUpdatePlaceholder",
        code,
    })?;
    Ok(GuardOutcome::Applied { usn: Some(usn) })
}

/// Bind a verified, already-published local version without invalidating bytes.
/// Normal files become resident placeholders; existing placeholders receive
/// the newly committed identity. A drifted capture is never marked in-sync.
pub fn convert_published(
    path: &Path,
    identity: &PlaceholderIdentity,
    expect: &crate::filesystem::volume::FileState,
) -> Result<GuardOutcome, CfError> {
    let handle = raw_volume::open_read_write(path).map_err(map_open)?;
    if let Err(mismatch) = guard_check(&handle, expect, true) {
        return Ok(GuardOutcome::Mismatch(mismatch));
    }
    let tag = raw_volume::attr_tag(&handle).map_err(map_open)?;
    let placeholder = crate::filesystem::volume::placeholder_state(tag.attributes, tag.reparse_tag);
    let bytes = identity.encode();
    let (result, operation) = if placeholder.is_placeholder() {
        (
            raw::update_placeholder(
                &handle,
                None,
                &bytes,
                &[],
                expect.usn.expect("the strict guard verified a known USN"),
                false,
            ),
            "CfUpdatePlaceholder(published identity)",
        )
    } else {
        (raw::convert_to_placeholder(&handle, &bytes), "CfConvertToPlaceholder")
    };
    let usn = result.map_err(|code| CfError::Win32 { operation, code })?;
    Ok(GuardOutcome::Applied { usn: Some(usn) })
}

/// Convert a placeholder back into a normal, unmanaged file — the safe
/// unlink step, the documented inverse of [`convert_published`].
///
/// The SDK defines no `CfUninitializePlaceholder`; the supported clearing
/// path is `CfRevertPlaceholder(handle, CF_REVERT_FLAG_NONE, NULL)` (the
/// documented inverse of `CfConvertToPlaceholder` in `cldapi.dll`).
///
/// Preconditions, all enforced here — failure preserves the placeholder and
/// its content exactly as-is:
///
/// 1. The target is classified first. An already-normal file is the desired
///    unlink end state and counts as applied **without any OS call** (the
///    function is idempotent for reconnect/unlink loops).
/// 2. Strict guard against `expect`: identity, size, modification time and
///    **exactly the expected USN** (a missing expected or current USN is
///    `GuardOutcome::Mismatch(UsnUnknown)`, never success). Content that
///    changed since the caller's observation — including dirty local edits —
///    therefore stays a placeholder for the caller's recovery path.
/// 3. Full residency is proven from real on-disk ranges before the call:
///    online-only content must be hydrated or exported first
///    ([`CfError::Precondition`]). No bytes are ever discarded, so this
///    function has no remote effects and never fabricates offline state.
///
/// Pin state is deliberately not a precondition: a pinned placeholder that
/// is fully resident converts to a normal file with all bytes kept; it just
/// stops being managed. The caller (`execute_unlink`) owns the surrounding
/// policy (preserve dirty/recovered snapshots, disconnect, unregister).
pub fn revert_to_normal(
    path: &Path,
    expect: &crate::filesystem::volume::FileState,
) -> Result<GuardOutcome, CfError> {
    // 1. Classify without touching any CFAPI state.
    let state = crate::filesystem::volume::query_file_state(path).map_err(map_fs)?;
    let placeholder = crate::filesystem::volume::placeholder_state(
        state.identity.attributes,
        state.identity.reparse_tag,
    );
    if !placeholder.is_placeholder() {
        // Already a plain file: the desired unlink end state, reached.
        return Ok(GuardOutcome::Applied { usn: state.usn });
    }

    // 2. Strict identity/size/mtime/USN guard through a normal metadata
    //    handle, closed before the write+exclusive CFAPI oplock is acquired.
    let metadata_handle = raw_volume::open_query(path, true).map_err(map_open)?;
    if let Err(mismatch) = guard_check(&metadata_handle, expect, true) {
        return Ok(GuardOutcome::Mismatch(mismatch));
    }
    drop(metadata_handle);
    let handle = raw::open_with_oplock(path, true, true).map_err(map_open)?;

    // 3. Proof of full residency (empty files are trivially resident).
    if !is_fully_resident(&handle, expect.size)? {
        return Err(CfError::Precondition(
            "unlink requires fully resident content; hydrate or export before conversion",
        ));
    }

    raw::revert_to_normal(&handle).map_err(|code| CfError::Win32 {
        operation: "CfRevertPlaceholder",
        code,
    })?;
    Ok(GuardOutcome::Applied { usn: None })
}

/// Set pin state and report, separately, whether the content is now fully
/// resident. The residency answer is computed from the real on-disk ranges;
/// it is never assumed.
pub fn set_pin_state(path: &Path, request: PinRequest) -> Result<PinOutcome, CfError> {
    let handle = raw::open_with_oplock(path, false, false).map_err(map_open)?;
    let pin = match request {
        PinRequest::Pinned => raw::PinRequest::Pinned,
        PinRequest::Unpinned => raw::PinRequest::Unpinned,
        PinRequest::Excluded => raw::PinRequest::Excluded,
    };
    raw::set_pin(&handle, pin).map_err(|code| CfError::Win32 {
        operation: "CfSetPinState",
        code,
    })?;
    let std = raw_volume::standard_info(&handle).map_err(|code| CfError::Win32 {
        operation: "GetFileInformationByHandleEx(FileStandardInfo)",
        code,
    })?;
    let fully_hydrated = is_fully_resident(&handle, std.size)?;
    Ok(PinOutcome {
        requested: request,
        fully_hydrated,
    })
}

/// Hydrate one range of a placeholder through the provider's fetch pipeline.
pub fn hydrate_range(path: &Path, range: ByteRange) -> CfResult<()> {
    let handle = raw::open_with_oplock(path, false, false).map_err(map_open)?;
    let std = raw_volume::standard_info(&handle).map_err(|code| CfError::Win32 {
        operation: "GetFileInformationByHandleEx(FileStandardInfo)",
        code,
    })?;
    if range.end_exclusive() > std.size {
        return Err(CfError::InvalidChunk);
    }
    let start = i64::try_from(range.start()).map_err(|_| CfError::InvalidChunk)?;
    let len = i64::try_from(range.len()).map_err(|_| CfError::InvalidChunk)?;
    raw::hydrate(&handle, start, len).map_err(|code| CfError::Win32 {
        operation: "CfHydratePlaceholder",
        code,
    })
}

/// Dehydrate the whole file to free local space. Requires the full
/// [`FreeSpaceEvidence`] **and** live verification (placeholder, unpinned,
/// in-sync) before `CfDehydratePlaceholder` runs. Dirty or pinned content is
/// preserved: the call fails instead.
pub fn dehydrate(path: &Path, evidence: &FreeSpaceEvidence) -> Result<GuardOutcome, CfError> {
    evidence.verify()?;
    let handle = raw::open_with_oplock(path, false, true).map_err(map_open)?;
    let info = raw::placeholder_info(&handle).map_err(|code| CfError::Win32 {
        operation: "CfGetPlaceholderInfo",
        code,
    })?;
    // CF_PIN_STATE_PINNED = 1; anything pinned is preserved.
    if info.pin_state == 1 {
        return Ok(GuardOutcome::Mismatch(GuardMismatch::Pinned));
    }
    // CF_IN_SYNC_STATE_IN_SYNC = 1; dirty content is preserved.
    if info.in_sync_state != 1 {
        return Ok(GuardOutcome::Mismatch(GuardMismatch::NotInSync));
    }
    raw::dehydrate(&handle).map_err(|code| CfError::Win32 {
        operation: "CfDehydratePlaceholder",
        code,
    })?;
    Ok(GuardOutcome::Applied { usn: None })
}

/// Counts unique resident bytes reported by `CfGetPlaceholderRangeInfo`.
/// Overlapping ranges are coalesced and any out-of-file range is rejected.
pub fn resident_bytes(path: &Path, size: u64) -> CfResult<u64> {
    if size == 0 {
        return Ok(0);
    }
    let handle = raw::open_with_oplock(path, false, false).map_err(map_open)?;
    let ranges = raw::on_disk_ranges(&handle, 0, size as i64).map_err(|code| CfError::Win32 {
        operation: "CfGetPlaceholderRangeInfo",
        code,
    })?;
    let mut cursor = 0u64;
    let mut total = 0u64;
    for (offset, length) in ranges {
        let end = offset.checked_add(length).ok_or(CfError::InvalidChunk)?;
        if end > size {
            return Err(CfError::InvalidChunk);
        }
        let start = offset.max(cursor);
        if end > start {
            total = total.checked_add(end - start).ok_or(CfError::InvalidChunk)?;
            cursor = end;
        }
    }
    Ok(total)
}

fn is_fully_resident(handle: &crate::ffi::handle::OwnedHandle, size: u64) -> CfResult<bool> {
    if size == 0 {
        return Ok(true);
    }
    let ranges = raw::on_disk_ranges(handle, 0, size as i64).map_err(|code| CfError::Win32 {
        operation: "CfGetPlaceholderRangeInfo",
        code,
    })?;
    let mut cursor = 0u64;
    for (offset, length) in ranges {
        if offset > cursor {
            break;
        }
        cursor = cursor.max(offset + length);
        if cursor >= size {
            return Ok(true);
        }
    }
    Ok(cursor >= size)
}

// ---------------------------------------------------------------------------
// Placeholder creation
// ---------------------------------------------------------------------------

/// Maximum entries per `CfCreatePlaceholders` batch.
pub(crate) const CREATE_BATCH: usize = 1000;

/// Create placeholders under `base` in bounded batches, returning one
/// outcome per entry. Existing paths are probed first and reported as
/// [`PlaceholderRequestOutcome::AlreadyExists`] — never overwritten.
pub fn create_placeholders(
    base: &Path,
    items: &[PlaceholderCreate],
) -> CfResult<Vec<PlaceholderOutcome>> {
    let mut outcomes = Vec::with_capacity(items.len());
    let mut pending: Vec<PlaceholderCreate> = Vec::new();
    for item in items {
        validate_placeholder_name(&item.name)?;
        let target = base.join(&item.name);
        let existing = raw_volume::file_attributes(&target).map_err(|code| CfError::Win32 {
            operation: "GetFileAttributesW",
            code,
        })?;
        if let Some(attrs) = existing {
            let state = crate::filesystem::volume::placeholder_state(attrs, 0);
            outcomes.push(PlaceholderOutcome {
                name: item.name.clone(),
                outcome: PlaceholderRequestOutcome::AlreadyExists { state },
            });
        } else {
            pending.push(item.clone());
        }
        if pending.len() >= CREATE_BATCH {
            run_create_batch(base, &pending, &mut outcomes)?;
            pending.clear();
        }
    }
    if !pending.is_empty() {
        run_create_batch(base, &pending, &mut outcomes)?;
    }
    Ok(outcomes)
}

fn run_create_batch(
    base: &Path,
    batch: &[PlaceholderCreate],
    outcomes: &mut Vec<PlaceholderOutcome>,
) -> CfResult<()> {
    let pending = to_pending(batch)?;
    let results = raw::create_placeholders(base, &pending).map_err(|code| CfError::Win32 {
        operation: "CfCreatePlaceholders",
        code,
    })?;
    outcomes.extend(from_entry_results(batch, results));
    Ok(())
}

pub(crate) fn to_pending(items: &[PlaceholderCreate]) -> CfResult<Vec<PendingCreate>> {
    items
        .iter()
        .map(|item| {
            validate_placeholder_name(&item.name)?;
            Ok(PendingCreate {
                name: wide_nul(&item.name),
                metadata: to_metadata(&item.metadata),
                identity: item.identity.encode().to_vec(),
                mark_in_sync: item.mark_in_sync,
            })
        })
        .collect()
}

pub(crate) fn from_entry_results(
    items: &[PlaceholderCreate],
    results: Vec<raw::EntryResult>,
) -> Vec<PlaceholderOutcome> {
    items
        .iter()
        .zip(results)
        .map(|(item, result)| PlaceholderOutcome {
            name: item.name.clone(),
            outcome: if result.result >= 0 {
                PlaceholderRequestOutcome::Created {
                    usn: result.create_usn,
                }
            } else {
                PlaceholderRequestOutcome::Failed {
                    code: result.result,
                }
            },
        })
        .collect()
}

fn to_metadata(spec: &MetadataSpec) -> MetadataBytes {
    MetadataBytes {
        size: spec.size,
        creation_time_100ns: spec.creation_time_100ns,
        last_write_time_100ns: spec.last_write_time_100ns,
        attributes: spec.attributes,
    }
}

fn wide_nul(name: &str) -> Vec<u16> {
    name.encode_utf16().chain(Some(0)).collect()
}

/// Validate one placeholder name with the portable final-component rules
/// before it can reach `CfCreatePlaceholders`.
fn validate_placeholder_name(name: &str) -> CfResult<()> {
    crate::filesystem::names::validate_component(name).map_err(|_| {
        CfError::Precondition("placeholder name is not a supported final component")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hfdrive_core::ids::{ItemId, VersionId, WorkspaceId};

    #[test]
    fn published_binding_preserves_a_file_when_capture_identity_is_wrong() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("replacement.txt");
        std::fs::write(&path, b"newer local bytes").unwrap();
        let mut expected = crate::filesystem::volume::query_file_state(&path).unwrap();
        let actual_id = expected.identity.file_id;
        expected.identity.file_id[0] ^= 1;
        let identity = PlaceholderIdentity::file(WorkspaceId::new(), ItemId::new(), VersionId::new());
        assert_eq!(
            convert_published(&path, &identity, &expected).unwrap(),
            GuardOutcome::Mismatch(GuardMismatch::IdentityChanged)
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"newer local bytes");
        let after = crate::filesystem::volume::query_file_state(&path).unwrap();
        assert_eq!(after.identity.file_id, actual_id);
        assert!(!crate::filesystem::volume::placeholder_state(
            after.identity.attributes,
            after.identity.reparse_tag,
        ).is_placeholder());
    }
}
