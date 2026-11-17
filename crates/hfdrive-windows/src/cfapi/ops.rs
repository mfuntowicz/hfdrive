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
    resident_bytes_on_handle(&handle, size)
}

fn resident_bytes_on_handle(
    handle: &crate::ffi::handle::OwnedHandle,
    size: u64,
) -> CfResult<u64> {
    if size == 0 {
        return Ok(0);
    }
    let ranges = raw::on_disk_ranges(handle, 0, size as i64).map_err(|code| CfError::Win32 {
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
// Placeholder identity read-back
// ---------------------------------------------------------------------------

/// Read the HFDR placeholder identity stored at `path`.
///
/// Safe read-back used before any unlink conversion/deletion: it only opens
/// metadata and queries `CfGetPlaceholderInfo`, never mutating the file.
///
/// * `Ok(Some(identity))` — the placeholder carries a valid HFDR record
///   (magic, schema, non-nil ids) that belongs to `expect_workspace` when one
///   is given. The record's length must be exactly `IDENTITY_LEN`.
/// * `Ok(None)` — the path is **not** an HFDR placeholder: a plain file or
///   directory, a placeholder of another sync provider, or a placeholder
///   with no/foreign/unreadable identity bytes. These are never converted or
///   deleted by the unlink flow and never decoded leniently.
/// * `Err` — the query itself failed (open failure, corrupt placeholder
///   metadata) or the record is HFDR-shaped but invalid: a wrong length,
///   unsupported schema or a different workspace. A record from another
///   workspace is [`CfError::IdentityMismatch`], never re-bound.
///
/// The metadata handle is a plain query handle (the CFAPI call needs only
/// `READ_ATTRIBUTES`) owned by RAII for the whole query.
pub fn read_placeholder_identity(
    path: &Path,
    expect_workspace: Option<hfdrive_core::ids::WorkspaceId>,
) -> Result<Option<PlaceholderIdentity>, CfError> {
    // 1. Classify the path without touching CFAPI: a plain file, a foreign
    //    reparse point or the sync root itself is not a placeholder at all
    //    and yields `None` without an OS placeholder query.
    let state = crate::filesystem::volume::query_file_state(path).map_err(map_fs)?;
    if !crate::filesystem::volume::placeholder_state(
        state.identity.attributes,
        state.identity.reparse_tag,
    )
    .is_placeholder()
    {
        return Ok(None);
    }
    // 2. Read the inline identity through the generated CFAPI metadata.
    let handle = raw_volume::open_query(path, true).map_err(map_open)?;
    let bytes = match raw::placeholder_identity(&handle) {
        Ok(bytes) => bytes,
        // Not a cloud placeholder at all (plain file or foreign item), or
        // the provider stored no identity: distinguishable from an owned
        // HFDR placeholder without any handwritten ABI.
        Err(code) if code == raw::ERROR_NOT_A_CLOUD_FILE => return Ok(None),
        Err(code) => {
            return Err(CfError::Win32 {
                operation: "CfGetPlaceholderInfo(FileIdentity)",
                code,
            })
        }
    };
    decode_readback(&bytes, expect_workspace)
}

/// Classify raw `FileIdentity` bytes read back from the OS. Pure and
/// deterministic — no OS call — so the foreign/owned boundary is testable
/// without a registered sync root.
///
/// * Empty or any length other than the exact HFDR record: foreign/unknown
///   placeholder or plain item → `Ok(None)`, never decoded leniently.
/// * Wrong magic: not HFDR at all → `Ok(None)`.
/// * HFDR-shaped but invalid: unsupported schema or nil identifier →
///   [`CfError::Identity`]; a record from another workspace →
///   [`CfError::IdentityMismatch`], never re-bound.
fn decode_readback(
    bytes: &[u8],
    expect_workspace: Option<hfdrive_core::ids::WorkspaceId>,
) -> Result<Option<PlaceholderIdentity>, CfError> {
    use super::identity::{IdentityError, IDENTITY_LEN};

    // A foreign provider's identity has whatever length it stored; only the
    // exact HFDR record continues to the strict decoder.
    if bytes.is_empty() || bytes.len() != IDENTITY_LEN {
        return Ok(None);
    }
    match PlaceholderIdentity::decode(bytes, expect_workspace) {
        Ok(identity) => Ok(Some(identity)),
        Err(error) => match error {
            // HFDR-shaped but not ours (or not HFDR at all): no lenient
            // read-back path, just "not an owned HFDR placeholder".
            IdentityError::BadLength | IdentityError::BadMagic => Ok(None),
            // An HFDR record from another workspace is never re-bound; it is
            // an explicit mismatch the unlink flow must refuse.
            IdentityError::WorkspaceMismatch => Err(CfError::IdentityMismatch),
            // A corrupt owned record (bad schema/nil identifier) is an error,
            // not silence.
            other => Err(CfError::Identity(other)),
        },
    }
}

/// Delete an owned, clean, zero-resident placeholder through the same handle
/// used for every verification. Write/delete sharing is denied from open
/// through disposition, so the checked object cannot be replaced by a path
/// race. Any mismatch or failed query leaves the object untouched.
pub fn delete_owned_placeholder(
    path: &Path,
    expect: &crate::filesystem::volume::FileState,
    identity: &PlaceholderIdentity,
) -> Result<GuardOutcome, CfError> {
    let handle = raw_volume::open_delete(path).map_err(map_open)?;
    let id = raw_volume::id_info(&handle).map_err(|code| CfError::Win32 {
        operation: "GetFileInformationByHandleEx(FileIdInfo)",
        code,
    })?;
    if id.volume_serial_number != expect.identity.volume_serial_number
        || id.file_id != expect.identity.file_id
    {
        return Ok(GuardOutcome::Mismatch(GuardMismatch::IdentityChanged));
    }
    let standard = raw_volume::standard_info(&handle).map_err(|code| CfError::Win32 {
        operation: "GetFileInformationByHandleEx(FileStandardInfo)",
        code,
    })?;
    if standard.size != expect.size {
        return Ok(GuardOutcome::Mismatch(GuardMismatch::SizeChanged));
    }
    let basic = raw_volume::basic_info(&handle).map_err(|code| CfError::Win32 {
        operation: "GetFileInformationByHandleEx(FileBasicInfo)",
        code,
    })?;
    if basic.last_write_time_100ns != expect.last_write_time_100ns {
        return Ok(GuardOutcome::Mismatch(GuardMismatch::TimeChanged));
    }
    let attrs = raw_volume::attr_tag(&handle).map_err(|code| CfError::Win32 {
        operation: "GetFileInformationByHandleEx(FileAttributeTagInfo)",
        code,
    })?;
    let is_directory = attrs.attributes & raw_volume::ATTR_DIRECTORY != 0;
    if is_directory != identity.is_directory() {
        return Ok(GuardOutcome::Mismatch(GuardMismatch::StateChanged));
    }
    let bytes = match raw::placeholder_identity(&handle) {
        Ok(bytes) => bytes,
        Err(code) if code == raw::ERROR_NOT_A_CLOUD_FILE => {
            return Ok(GuardOutcome::Mismatch(GuardMismatch::NotPlaceholder));
        }
        Err(code) => {
            return Err(CfError::Win32 {
                operation: "CfGetPlaceholderInfo(FileIdentity)",
                code,
            });
        }
    };
    if decode_readback(&bytes, Some(identity.workspace))? != Some(*identity) {
        return Ok(GuardOutcome::Mismatch(GuardMismatch::IdentityChanged));
    }
    if resident_bytes_on_handle(&handle, standard.size)? != 0 {
        return Ok(GuardOutcome::Mismatch(GuardMismatch::StateChanged));
    }
    raw_volume::mark_deleted(&handle).map_err(|code| CfError::Win32 {
        operation: "SetFileInformationByHandle(FileDispositionInfo)",
        code,
    })?;
    Ok(GuardOutcome::Applied { usn: None })
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
    use crate::cfapi::identity::IdentityError;
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

    // -- placeholder identity read-back (no registration required) ------

    #[test]
    fn readback_of_a_plain_file_is_not_an_hfdr_placeholder() {
        // End-to-end through the real handle path (no registration or
        // placeholder needed): a normal file yields `None`, not an error and
        // not a decoded identity.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("plain.txt");
        std::fs::write(&path, b"plain bytes").unwrap();
        assert_eq!(read_placeholder_identity(&path, None).unwrap(), None);
        assert_eq!(
            read_placeholder_identity(&path, Some(WorkspaceId::new())).unwrap(),
            None
        );
    }

    #[test]
    fn readback_returns_owned_identity_for_an_exact_hfdr_record() {
        let workspace = WorkspaceId::new();
        let id = PlaceholderIdentity::file(workspace, ItemId::new(), VersionId::new());
        assert_eq!(
            decode_readback(&id.encode(), Some(workspace)).unwrap(),
            Some(id)
        );
        let dir = PlaceholderIdentity::directory(workspace, ItemId::new());
        assert_eq!(decode_readback(&dir.encode(), Some(workspace)).unwrap(), Some(dir));
        // Unknown workspace expectation still validates the record strictly.
        assert_eq!(decode_readback(&id.encode(), None).unwrap(), Some(id));
    }

    #[test]
    fn readback_treats_foreign_and_wrong_length_records_as_not_hfdr() {
        let workspace = WorkspaceId::new();
        let id = PlaceholderIdentity::file(workspace, ItemId::new(), VersionId::new());
        let bytes = id.encode();
        // No identity at all, or a foreign provider's identity of any other
        // length: never an HFDR placeholder, never decoded leniently.
        assert_eq!(decode_readback(&[], Some(workspace)).unwrap(), None);
        assert_eq!(decode_readback(&bytes[..52], Some(workspace)).unwrap(), None);
        let mut foreign = bytes.to_vec();
        foreign.extend_from_slice(&[0xA5; 7]);
        assert_eq!(decode_readback(&foreign, Some(workspace)).unwrap(), None);
    }

    #[test]
    fn readback_distinguishes_foreign_magic_from_invalid_hfdr_records() {
        let workspace = WorkspaceId::new();
        let id = PlaceholderIdentity::file(workspace, ItemId::new(), VersionId::new());
        let bytes = id.encode();
        // Wrong magic: another provider's record — foreign, not an error.
        let mut foreign = bytes;
        foreign[0] = b'X';
        assert_eq!(decode_readback(&foreign, Some(workspace)).unwrap(), None);
        // HFDR magic with an unsupported schema is a corrupt owned record.
        let mut bad_schema = bytes;
        bad_schema[4] = 2;
        assert!(matches!(
            decode_readback(&bad_schema, Some(workspace)),
            Err(CfError::Identity(IdentityError::UnsupportedSchema { schema: 2 }))
        ));
        // HFDR magic with a nil item id is likewise corrupt, not foreign.
        let mut nil_item = bytes;
        nil_item[21..37].copy_from_slice(&[0u8; 16]);
        assert!(matches!(
            decode_readback(&nil_item, Some(workspace)),
            Err(CfError::Identity(IdentityError::NilIdentifier))
        ));
    }

    #[test]
    fn readback_rejects_a_foreign_workspace_without_rebinding() {
        let workspace = WorkspaceId::new();
        let id = PlaceholderIdentity::file(workspace, ItemId::new(), VersionId::new());
        // The record is valid HFDR but belongs to another workspace: this is
        // an identity mismatch the unlink flow must refuse, not "not ours".
        assert!(matches!(
            decode_readback(&id.encode(), Some(WorkspaceId::new())),
            Err(CfError::IdentityMismatch)
        ));
    }

    #[test]
    fn a_replacement_object_survives_a_stale_delete_review() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("report.txt");
        std::fs::write(&path, b"reviewed object").unwrap();
        let expected = crate::filesystem::volume::query_file_state(&path).unwrap();
        let identity = PlaceholderIdentity::file(
            WorkspaceId::new(),
            ItemId::new(),
            VersionId::new(),
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"replacement object must survive").unwrap();
        let result = delete_owned_placeholder(&path, &expected, &identity).unwrap();
        assert_eq!(result, GuardOutcome::Mismatch(GuardMismatch::IdentityChanged));
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement object must survive");
    }
}
