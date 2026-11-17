//! Coherent snapshot capture: the one boundary where local bytes become an
//! immutable, hashed, staged copy.
//!
//! The contract (also stated in `docs/filesystem-semantics.md`):
//!
//! * The source is opened for read **denying concurrent write and delete**
//!   (`FILE_SHARE_READ` only), so no other writer can change the bytes mid
//!   capture. If another writer is present the capture fails
//!   [`FsError::SharingViolation`] and is retried later — intent is kept.
//! * Sources that are not fully materialized on disk (partial placeholders,
//!   recall-on-access data) are refused with [`FsError::NotMaterialized`];
//!   the provider materializes content before calling in. There is no
//!   fallback that reads holes as zeroes.
//! * Identity (volume serial + file ID), size and modification time are
//!   verified against the caller's observed [`FileState`] before **and**
//!   after the read, and — when both observations carry one — the file's
//!   **USN** as well. Equality of identity, size and timestamp is not proof
//!   of equal content: a same-size, same-timestamp replacement advances the
//!   USN and is drift ([`FsError::SourceChanged`] /
//!   [`FsError::IdentityChanged`]), never a stale capture. The staged
//!   partial file is deleted on drift so a torn copy can never be published.
//! * A reparse point is captured **only** as a verified owned HFDR
//!   placeholder (its inline identity decodes as this provider's record).
//!   Foreign links — junctions, mount points, symlinks, another provider's
//!   placeholder, or an HFDR record that fails validation — are rejected and
//!   never followed or read.
//! * The source is opened on the **final reparse point itself**
//!   (`FILE_FLAG_OPEN_REPARSE_POINT`) and never followed into a target. The
//!   handle's normalized final path must name the requested path (an ancestor
//!   junction redirection is refused), and identity, attributes and the inline
//!   HFDR record are verified **from that very handle** before any byte is
//!   read. When the caller supplies an expected [`FileState`], the handle must
//!   match it, so a replacement — plain or link — fails before payload use.
//! * A verified owned placeholder is recaptured **in place** from its local
//!   bytes: the capture never re-fetches its bound immutable version, and a
//!   placeholder with non-resident ranges is refused
//!   ([`FsError::NotMaterialized`]) so holes are never staged as zeroes. Its
//!   HFDR identity is carried in [`SnapshotEvidence::placeholder`] so the
//!   publisher can bind the recapture to the right item and version.
//! * The bytes are streamed in bounded chunks, hashed with SHA-256 and
//!   written to the staging directory, then flushed to stable storage before
//!   the snapshot is reported ready.
//! * When the volume has a USN journal, the file's USN at capture time is
//!   recorded as evidence. Hard-link, EFS and alternate-stream findings are
//!   recorded (the latter as warnings; EFS/multi-link sources are refused
//!   outright for upload).

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use hfdrive_core::ids::SnapshotId;
use hfdrive_core::storage::Sha256Digest;
use sha2::{Digest, Sha256};

use crate::cfapi::identity::PlaceholderIdentity;
use crate::ffi::volume as raw;

use super::volume::FileState;
use super::{FsError, FsResult};

/// Why a source is refused for upload, or what the caller should know about
/// a captured source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotWarning {
    /// The file has non-default alternate data streams. They are preserved
    /// locally by V1 but not replicated to the remote namespace.
    AlternateStreams { streams: Vec<String> },
    /// The volume has no usable USN journal; capture evidence has no USN.
    UsnUnavailable,
}

/// Whether a capture may recapture an owned HFDR placeholder in place.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlaceholderPolicy {
    /// Refuse every reparse point. Used where ordinary local files are
    /// expected (import, setup): a placeholder appearing there is never
    /// silently re-captured as new content.
    Refuse,
    /// Recapture a **verified owned** HFDR placeholder's local bytes in
    /// place. Foreign links are still rejected.
    RecaptureOwned,
    /// Recapture exactly one **verified owned** HFDR placeholder in place: the
    /// opened handle must verify as `identity`'s HFDR record before any byte is
    /// read. A substituted plain target, another item's placeholder or a
    /// foreign link is refused without being read. This is the boundary the
    /// provider's capture gate uses: it approved one placeholder identity, and
    /// nothing else may ever supply the bytes.
    RecaptureBound(PlaceholderIdentity),
}

/// What the capture boundary may do with the source it observes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceKind {
    /// Ordinary local content; never a reparse point.
    Plain,
    /// A verified owned HFDR placeholder: its inline identity decoded as
    /// this provider's record. Eligible for in-place recapture.
    OwnedPlaceholder(PlaceholderIdentity),
    /// Any other reparse point: junction, mount point, symlink, another
    /// provider's placeholder, or an HFDR record that failed validation.
    /// Refused; never followed or read.
    ForeignLink,
}

/// Pure classification of a reparse-point source from its observed evidence.
///
/// A source is a verified owned HFDR placeholder only when the OS classifies
/// it as a cloud placeholder of the cloud reparse family **and** its inline
/// identity decodes as a valid HFDR record. Everything else — a junction or
/// symlink (wrong tag), a placeholder of another sync provider (cloud tag but
/// foreign/absent identity), or an HFDR record that failed validation — is a
/// [`SourceKind::ForeignLink`] and is never followed. No OS call is made
/// here, so the owned/foreign boundary is testable without a registered sync
/// root.
pub fn classify_reparse(
    attributes: u32,
    reparse_tag: u32,
    identity: Option<PlaceholderIdentity>,
) -> SourceKind {
    let cloud_placeholder = super::volume::placeholder_state(attributes, reparse_tag).is_placeholder()
        && super::volume::is_cloud_family_tag(reparse_tag);
    match (cloud_placeholder, identity) {
        (true, Some(identity)) => SourceKind::OwnedPlaceholder(identity),
        _ => SourceKind::ForeignLink,
    }
}

/// The capture policy's explicit verdict for one classified source.
///
/// Every (kind, policy) pair has its own arm — nothing is wildcard-accepted:
/// ordinary-file callers refuse every reparse point, recapture callers accept
/// only a verified owned HFDR placeholder, and [`PlaceholderPolicy::RecaptureBound`]
/// accepts exactly the one placeholder identity its caller approved. A
/// substituted plain target or another item's placeholder is
/// [`FsError::IdentityChanged`]; a foreign link is never followed or read.
/// Returns the owned placeholder identity to carry in the evidence.
fn policy_allows(
    source: &Path,
    kind: &SourceKind,
    policy: PlaceholderPolicy,
) -> FsResult<Option<PlaceholderIdentity>> {
    match (kind, policy) {
        // Ordinary local content: ordinary-file callers and in-place
        // recapture both accept it.
        (SourceKind::Plain, PlaceholderPolicy::Refuse) => Ok(None),
        (SourceKind::Plain, PlaceholderPolicy::RecaptureOwned) => Ok(None),
        // The gate approved one placeholder identity and the path now names
        // an ordinary file: a substituted plain target never supplies the
        // bound bytes.
        (SourceKind::Plain, PlaceholderPolicy::RecaptureBound(_)) => Err(FsError::IdentityChanged),
        // Callers that capture ordinary files keep refusing every reparse
        // point; a placeholder appearing there is never silently adopted.
        (SourceKind::OwnedPlaceholder(_), PlaceholderPolicy::Refuse) => {
            Err(FsError::UnsupportedFileType)
        }
        (SourceKind::ForeignLink, PlaceholderPolicy::Refuse) => {
            Err(FsError::UnsupportedFileType)
        }
        // A foreign link is never followed or read under any recapture policy.
        (SourceKind::ForeignLink, PlaceholderPolicy::RecaptureOwned) => {
            Err(FsError::ReparsePoint {
                path: source.to_path_buf(),
            })
        }
        (SourceKind::ForeignLink, PlaceholderPolicy::RecaptureBound(_)) => {
            Err(FsError::ReparsePoint {
                path: source.to_path_buf(),
            })
        }
        (SourceKind::OwnedPlaceholder(identity), PlaceholderPolicy::RecaptureOwned) => {
            Ok(Some(*identity))
        }
        // Exactly one approved identity may be recaptured; another item's
        // placeholder is drift, refused before any byte is read.
        (SourceKind::OwnedPlaceholder(identity), PlaceholderPolicy::RecaptureBound(bound)) => {
            if *identity == bound {
                Ok(Some(*identity))
            } else {
                Err(FsError::IdentityChanged)
            }
        }
    }
}

/// Evidence recorded alongside the staged bytes.
#[derive(Clone, Debug)]
pub struct SnapshotEvidence {
    pub state_before: FileState,
    pub state_after: FileState,
    /// File USN observed via `FSCTL_READ_FILE_USN_DATA` while the coherent
    /// handle was held; `None` when the volume has no journal (see
    /// [`SnapshotWarning::UsnUnavailable`]).
    pub usn: Option<i64>,
    /// The verified owned HFDR placeholder identity when the captured source
    /// was an owned placeholder recaptured in place. The publisher binds the
    /// recapture to this item and workspace; `None` for ordinary files.
    pub placeholder: Option<PlaceholderIdentity>,
    pub warnings: Vec<SnapshotWarning>,
}

/// A fully staged, flushed, hash-verified immutable snapshot.
#[derive(Clone)]
pub struct CapturedSnapshot {
    pub snapshot_id: SnapshotId,
    pub staged_path: PathBuf,
    pub size: u64,
    pub sha256: Sha256Digest,
    pub evidence: SnapshotEvidence,
}

/// Capture a coherent snapshot of `source` into `staging_dir`, refusing every
/// reparse point ([`PlaceholderPolicy::Refuse`]).
///
/// `expect` is the state the caller observed before deciding to capture (its
/// generation binding); passing `None` captures whatever the file is at
/// capture time and simply records it — the caller then binds its durable
/// generation to the returned evidence itself. The staged file name is
/// `<snapshot-id>.snap` and is only reported ready after `FlushFileBuffers`.
pub fn capture_snapshot(
    source: &Path,
    staging_dir: &Path,
    snapshot_id: SnapshotId,
    expect: Option<&FileState>,
) -> FsResult<CapturedSnapshot> {
    capture_snapshot_with(
        source,
        staging_dir,
        snapshot_id,
        expect,
        PlaceholderPolicy::Refuse,
    )
}

/// Capture a coherent snapshot under `policy`'s placeholder rules.
///
/// The source is classified **before** any read handle opens: classification
/// and the residency gate are metadata-only, so a partially hydrated
/// placeholder is refused without ever triggering a fetch, and a foreign link
/// is rejected without being followed. The coherent open then verifies the
/// exact object its handle names — normalized final path, attributes, and the
/// inline HFDR record read from that very handle — **before any byte is
/// read** and before the staging sink is even created. A replacement between
/// validation and the open is therefore refused without ever staging or
/// reading its bytes.
pub fn capture_snapshot_with(
    source: &Path,
    staging_dir: &Path,
    snapshot_id: SnapshotId,
    expect: Option<&FileState>,
    policy: PlaceholderPolicy,
) -> FsResult<CapturedSnapshot> {
    // 1. Metadata-only pre-classification: decide what the source is before a
    //    read handle can fetch or follow anything.
    let pre = super::volume::query_file_state(source)?;
    let kind = classify_source(source, &pre)?;

    // Explicit per-(kind, policy) verdict: no wildcard acceptance. The
    // returned placeholder identity is the one the policy approved; the
    // reopened handle must verify it again before any byte is read.
    let approved = policy_allows(source, &kind, policy)?;

    if pre.identity.is_encrypted() {
        return Err(FsError::EncryptedFile);
    }
    if pre.identity.has_multiple_links() {
        return Err(FsError::HardLinked);
    }
    match &approved {
        Some(_) => {
            // A recapture reads the placeholder's own local bytes. Every one
            // of them must be resident first — the fetch pipeline already
            // materialized them, and this read never re-fetches the bound
            // immutable version.
            ensure_resident(source, &pre)?;
        }
        None => {
            if pre.identity.may_not_be_materialized() {
                // A partial/cloud file has holes that must be hydrated first;
                // reading it here could otherwise stage zero-filled holes.
                return Err(FsError::NotMaterialized);
            }
        }
    }

    // Bind to the caller's observed generation.
    if let Some(expect) = expect {
        if !same_observation(&pre, expect) {
            return Err(FsError::IdentityChanged);
        }
    }

    let warnings = collect_warnings(source, pre.usn);

    // Open and verify the exact source object before touching the staging
    // sink: the final path, handle attributes/HFDR identity and the caller's
    // observed generation all validate before any byte is read, so a
    // replacement in that window is never read or staged.
    let (mut reader, state_before, handle_kind) = open_coherent_verified(
        source,
        &SourceBinding {
            pre: &pre,
            kind: &kind,
            expect,
            policy,
        },
    )?;

    // Stage the bytes: the coherent read (write and delete sharing denied)
    // is streamed in bounded chunks with incremental SHA-256.
    std::fs::create_dir_all(staging_dir)?;
    let staged_path = staging_dir.join(format!("{}.snap", snapshot_id));
    let mut writer = File::create(&staged_path)?;
    let (digest, total) =
        match stream_hashed(&mut reader, Some(&mut writer), state_before.size) {
            Ok(hashed) => hashed,
            Err(error) => {
                let _ = std::fs::remove_file(&staged_path);
                return Err(match error {
                    CopyError::Source(error) => error,
                    CopyError::Sink(error) => map_write_error(error),
                });
            }
        };

    // Flush to stable storage before the snapshot is reported ready; the
    // provider only references staged paths that survive a crash.
    writer.flush()?;
    raw_fsync(&writer)?;
    drop(writer);

    // Re-verify identity/size/mtime/USN after the read using a fresh query.
    let state_after = super::volume::query_file_state(source)?;
    if !same_observation(&state_after, &state_before) {
        let _ = std::fs::remove_file(&staged_path);
        return Err(FsError::SourceChanged);
    }

    // The evidence carries the identity read from the coherent handle itself
    // — never a path re-query — so the publisher binds the recapture to the
    // object whose bytes were actually staged.
    let placeholder = match handle_kind {
        SourceKind::OwnedPlaceholder(identity) => Some(identity),
        SourceKind::Plain | SourceKind::ForeignLink => None,
    };

    Ok(CapturedSnapshot {
        snapshot_id,
        staged_path,
        size: total,
        sha256: Sha256Digest::from_bytes(digest),
        evidence: SnapshotEvidence {
            state_before,
            state_after,
            usn: pre.usn,
            placeholder,
            warnings,
        },
    })
}

/// Why one coherent copy failed: the **source** side (open, sharing, drift,
/// mid-read failures) or the **sink** side (the staged/preserved write). A
/// caller can then report "the source could not be read" and "the copy could
/// not be written" truthfully instead of guessing from one merged error.
#[derive(Debug, thiserror::Error)]
pub enum CopyError {
    #[error(transparent)]
    Source(#[from] FsError),
    #[error("the copy could not be written: {0}")]
    Sink(#[from] std::io::Error),
}

/// Open `source` for one coherent read and stream it into `sink` while
/// hashing exactly the bytes read. The handle denies concurrent write and
/// delete from open to EOF, so the returned digest describes one immutable
/// view of the file. Returns the handle-bound observation, the SHA-256 of
/// the read bytes and their count (verified against the observed size).
pub fn copy_hashed_coherent(
    source: &Path,
    sink: &mut std::fs::File,
) -> Result<(FileState, [u8; 32], u64), CopyError> {
    let (mut reader, state) = open_coherent_state(source)?;
    let (digest, total) = stream_hashed(&mut reader, Some(sink), state.size)?;
    Ok((state, digest, total))
}

/// Hash `source`'s **current** bytes through one coherent read handle (write
/// and delete sharing denied). This is the content proof a reuse or binding
/// decision needs: identity, size and timestamps alone cannot tell a file
/// from a same-size, same-timestamp replacement.
pub fn read_hashed_coherent(source: &Path) -> FsResult<(FileState, [u8; 32], u64)> {
    let (mut reader, state) = open_coherent_state(source)?;
    let (digest, total) = stream_hashed(&mut reader, None, state.size)
        .map_err(|error| match error {
            CopyError::Source(error) => error,
            CopyError::Sink(error) => map_write_error(error),
        })?;
    Ok((state, digest, total))
}

/// What the reopened handle must prove before its bytes are read.
struct SourceBinding<'a> {
    /// The metadata pre-query observation the open must still match.
    pre: &'a FileState,
    /// The classification the policy already ruled on; the reopened handle's
    /// own classification must agree with it exactly.
    kind: &'a SourceKind,
    /// The caller's expected observation (`None` = bind to whatever the
    /// handle shows, recorded as the capture's own generation).
    expect: Option<&'a FileState>,
    /// The capture policy, re-applied to the handle-derived kind.
    policy: PlaceholderPolicy,
}

/// Open `source` for a coherent read (write and delete sharing denied) and
/// take the observation from that very handle. The handle opens the **final
/// reparse point itself** and is never followed into another location; a
/// foreign link never supplies bytes here — only plain content or a verified
/// owned HFDR placeholder is read.
fn open_coherent_state(source: &Path) -> FsResult<(std::fs::File, FileState)> {
    #[cfg(test)]
    let _seam_guard = seams::CaptureGuard::new();
    let (handle, state, _kind) = open_coherent_handle(source)?;
    Ok((raw::handle_into_file(handle), state))
}

/// Open `source` on the final reparse point itself and observe it from the
/// very handle whose bytes may later be read. Before the handle is returned
/// (and therefore before any byte can be read) three things must hold: the
/// handle's normalized final path names the requested path (a junction, mount
/// point or symlink in any position may not redirect this open — and
/// therefore the read — to another object), the handle is a regular file (a
/// directory has no capturable content), and the object is not a foreign
/// link — a reparse point is classified from this very handle and refused
/// right here, never followed or read.
fn open_coherent_handle(source: &Path) -> FsResult<(crate::ffi::handle::OwnedHandle, FileState, SourceKind)> {
    let handle = raw::open_read_coherent(source).map_err(|code| {
        if code == 32 || code == 33 {
            FsError::SharingViolation
        } else if code == 2 || code == 3 {
            FsError::NotFound {
                path: source.to_path_buf(),
            }
        } else {
            FsError::Win32 {
                operation: "CreateFileW",
                code,
            }
        }
    })?;
    // The handle must name exactly the requested object. The handle
    // classifier compares this normalized final path with the requested
    // path, so an ancestor redirection (junction/mount point resolving
    // elsewhere) is refused before any byte is read.
    let final_path = raw::final_path(&handle).map_err(op("final_path"))?;
    let attrs = raw::attr_tag(&handle).map_err(op("attr_tag"))?;
    if attrs.attributes & raw::ATTR_DIRECTORY != 0 {
        // The capture boundary stages regular file content only.
        return Err(FsError::UnsupportedFileType);
    }
    // Classification comes from the reopened handle itself: the inline HFDR
    // record is read through this very handle, never a path re-open. A
    // foreign link is refused right here — before the identity/USN queries
    // and long before any byte is read — and its target is never followed.
    let kind = classify_handle(
        source,
        &final_path,
        attrs.attributes,
        attrs.reparse_tag,
        &handle,
    );
    if kind == SourceKind::ForeignLink {
        return Err(FsError::ReparsePoint {
            path: source.to_path_buf(),
        });
    }
    let id = raw::id_info(&handle).map_err(op("id_info"))?;
    let std = raw::standard_info(&handle).map_err(op("standard_info"))?;
    let basic = raw::basic_info(&handle).map_err(op("basic_info"))?;
    let usn = crate::ffi::usn::file_usn(&handle).map_err(op("file_usn"))?;
    let state = FileState {
        identity: super::volume::FileIdentity {
            volume_serial_number: id.volume_serial_number,
            file_id: id.file_id,
            link_count: std.link_count,
            attributes: attrs.attributes,
            reparse_tag: attrs.reparse_tag,
        },
        size: std.size,
        last_write_time_100ns: basic.last_write_time_100ns,
        usn,
    };
    Ok((handle, state, kind))
}

/// Open `source` on the final reparse point itself and verify everything the
/// capture boundary needs **from that very handle** before any byte is read:
/// the normalized final path names the requested path, the handle's
/// observation matches the metadata pre-query and the caller's expected
/// generation (a replacement in that window is drift), the handle's own
/// classification agrees with the pre-open one, and the policy verdict holds
/// for the handle-derived kind — including that a bound recapture's inline
/// HFDR record decodes to exactly the approved identity.
fn open_coherent_verified(
    source: &Path,
    binding: &SourceBinding<'_>,
) -> FsResult<(File, FileState, SourceKind)> {
    let (handle, state, kind) = open_coherent_handle(source)?;
    if kind != *binding.kind {
        // The object at the path changed between the metadata query and the
        // open: a substituted plain target or a different placeholder never
        // supplies the bound bytes.
        return Err(FsError::IdentityChanged);
    }
    if !same_observation(&state, binding.pre) {
        return Err(FsError::SourceChanged);
    }
    if let Some(expect) = binding.expect {
        if !same_observation(&state, expect) {
            return Err(FsError::IdentityChanged);
        }
    }
    // The policy verdict must hold for the handle-derived kind too, so a
    // bound recapture is bound to the identity decoded from this handle.
    policy_allows(source, &kind, binding.policy)?;
    Ok((raw::handle_into_file(handle), state, kind))
}

/// Classify the object the coherent handle names, from that very handle: its
/// normalized final path must name the requested path, and the inline HFDR
/// record is read through the open handle (never a path re-open), so the
/// classification describes exactly the object whose bytes may be read.
fn classify_handle(
    path: &Path,
    final_path: &str,
    attributes: u32,
    reparse_tag: u32,
    handle: &crate::ffi::handle::OwnedHandle,
) -> SourceKind {
    if !final_path_matches(path, final_path) {
        return SourceKind::ForeignLink;
    }
    #[cfg(test)]
    if let Some(kind) = seams::classification(path) {
        return kind;
    }
    if attributes & raw::ATTR_REPARSE_POINT == 0 {
        return SourceKind::Plain;
    }
    let identity = crate::ffi::cfapi::placeholder_identity(handle)
        .ok()
        .and_then(|bytes| decode_handle_identity(&bytes));
    classify_reparse(attributes, reparse_tag, identity)
}

/// Decode an inline HFDR record read from a handle. Only an exactly valid
/// record of this provider decodes; anything else (wrong length, foreign
/// magic, invalid identifiers) is `None` and never decoded leniently.
fn decode_handle_identity(bytes: &[u8]) -> Option<PlaceholderIdentity> {
    use crate::cfapi::identity::IDENTITY_LEN;
    if bytes.len() != IDENTITY_LEN {
        return None;
    }
    PlaceholderIdentity::decode(bytes, None).ok()
}

/// True when the normalized DOS final path of the opened handle names the
/// requested path. Extended-length (`\\?\`) and UNC (`\\?\UNC\`) spellings,
/// separators and case are normalized first; anything else — notably an
/// ancestor junction redirect, which resolves to the target's real path —
/// does not match and is refused.
fn final_path_matches(requested: &Path, final_path: &str) -> bool {
    let requested = canonical_dos_path(&requested.to_string_lossy());
    let final_path = canonical_dos_path(final_path);
    super::names::windows_case_equivalent(&requested, &final_path)
}

/// Strip the Win32 extended-length/UNC prefixes, unify separators and drop
/// trailing separators so two spellings of one DOS path compare equal.
fn canonical_dos_path(text: &str) -> String {
    let text = text.replace('/', r"\");
    let text = match text.strip_prefix(r"\\?\UNC\") {
        Some(rest) => format!(r"\\{rest}"),
        None => match text.strip_prefix(r"\\?\") {
            Some(rest) => rest.to_owned(),
            None => text,
        },
    };
    text.trim_end_matches(['\\', '/']).to_owned()
}

/// Stream `reader` to EOF (and into `sink` when given) while hashing the
/// bytes read. The read count is bounded by and must equal `expected_size`:
/// a coherent handle cannot grow or shrink under the reader, so any other
/// count is drift and never a staged copy.
fn stream_hashed(
    reader: &mut std::fs::File,
    mut sink: Option<&mut std::fs::File>,
    expected_size: u64,
) -> Result<([u8; 32], u64), CopyError> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut total: u64 = 0;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        if let Some(writer) = sink.as_deref_mut() {
            writer.write_all(&buffer[..read]).map_err(map_write_error)?;
        }
        total += read as u64;
        if total > expected_size {
            // The file grew mid-capture despite the exclusive share mode
            // being held since open (e.g. a self-modifying writer). Treat as
            // drift and discard.
            return Err(CopyError::Source(FsError::SourceChanged));
        }
    }
    if total != expected_size {
        return Err(CopyError::Source(FsError::SourceChanged));
    }
    Ok((hasher.finalize().into(), total))
}

/// Classify `source` at the capture boundary: plain local content, a verified
/// owned HFDR placeholder, or a foreign link that is never followed. The
/// identity lookup is metadata-only and never fetches or follows.
fn classify_source(path: &Path, state: &FileState) -> FsResult<SourceKind> {
    #[cfg(test)]
    if let Some(kind) = seams::classification(path) {
        return Ok(kind);
    }
    if !state.identity.is_reparse_point() {
        return Ok(SourceKind::Plain);
    }
    // A reparse point is acceptable only as a verified owned HFDR
    // placeholder. `read_placeholder_identity` returns `Ok(None)` for a
    // plain item, a foreign provider's placeholder or missing identity bytes,
    // and `Err` for an HFDR-shaped record that failed validation — both are
    // unverified and therefore foreign here.
    let identity = crate::cfapi::ops::read_placeholder_identity(path, None)
        .ok()
        .flatten();
    Ok(classify_reparse(
        state.identity.attributes,
        state.identity.reparse_tag,
        identity,
    ))
}

/// Refuse any source whose bytes are not provably on local disk. A verified
/// owned placeholder is recaptured from its **resident** bytes only; a
/// partial one is [`FsError::NotMaterialized`] and is materialized by the
/// caller before capture. The CF query is authoritative for placeholders;
/// when CF reports the path is not a cloud item at all, the attribute
/// evidence (no recall attributes, no cloud tag) is the only residency signal
/// left and must show plain local content.
fn ensure_resident(source: &Path, state: &FileState) -> FsResult<()> {
    if state.size == 0 {
        return Ok(());
    }
    match crate::cfapi::ops::resident_bytes(source, state.size) {
        Ok(resident) if resident >= state.size => Ok(()),
        Ok(_) => Err(FsError::NotMaterialized),
        Err(crate::cfapi::CfError::Win32 { code, .. })
            if code == crate::ffi::cfapi::ERROR_NOT_A_CLOUD_FILE =>
        {
            if state.identity.may_not_be_materialized() {
                Err(FsError::NotMaterialized)
            } else {
                Ok(())
            }
        }
        Err(crate::cfapi::CfError::Win32 { code, .. }) if code == 2 || code == 3 => {
            Err(FsError::NotFound {
                path: source.to_path_buf(),
            })
        }
        Err(crate::cfapi::CfError::Win32 { code, .. }) if code == 32 || code == 33 => {
            Err(FsError::SharingViolation)
        }
        Err(_) => Err(FsError::NotMaterialized),
    }
}

/// Two observations belong to the same local generation only when identity,
/// size, modification time **and** the USN (when both carry one) agree. None
/// of identity, size and timestamp alone proves equal content; a USN change
/// with identical metadata is exactly a same-size, same-timestamp
/// replacement.
fn same_observation(a: &FileState, b: &FileState) -> bool {
    a.identity == b.identity
        && a.size == b.size
        && a.last_write_time_100ns == b.last_write_time_100ns
        && a.usn == b.usn
}

fn collect_warnings(source: &Path, usn: Option<i64>) -> Vec<SnapshotWarning> {
    let mut warnings = Vec::new();
    match super::volume::alternate_data_streams(source) {
        Ok(streams) if !streams.is_empty() => warnings.push(SnapshotWarning::AlternateStreams {
            streams: streams.into_iter().map(|(name, _)| name).collect(),
        }),
        _ => {}
    }
    if usn.is_none() {
        warnings.push(SnapshotWarning::UsnUnavailable);
    }
    warnings
}

fn raw_fsync(file: &File) -> FsResult<()> {
    file.sync_all()?;
    Ok(())
}

fn map_write_error(error: std::io::Error) -> FsError {
    // 112 = ERROR_DISK_FULL.
    if matches!(error.kind(), std::io::ErrorKind::WriteZero) || error.raw_os_error() == Some(112) {
        FsError::DiskFull
    } else {
        FsError::Io(error)
    }
}

fn op(operation: &'static str) -> impl Fn(u32) -> FsError {
    move |code: u32| FsError::Win32 { operation, code }
}

/// Deterministic seams for the capture regressions. The hook is thread-local
/// (the capture runs on the calling thread, so parallel tests can never share
/// one) and applies to **every** classification point of a capture — the
/// metadata pre-classification and the reopened-handle verification — so a
/// test can present a consistent owned placeholder or foreign link without
/// registering a sync root, or a substituted target by returning a different
/// kind per call. Production code pays nothing.
#[cfg(test)]
pub(crate) mod seams {
    use std::cell::{Cell, RefCell};
    use std::path::Path;

    use super::SourceKind;

    thread_local! {
        static CLASSIFY: RefCell<Option<Box<dyn FnMut(&Path) -> SourceKind>>> =
            RefCell::new(None);
        static BYPASS_CLASSIFICATION: Cell<bool> = Cell::new(false);
    }

    /// Suspends the classification override while a raw coherent read opens
    /// its handle. The previous flag is restored on drop, so nested reads and
    /// early returns cannot leak the bypass into the surrounding capture.
    pub(crate) struct CaptureGuard {
        previous: bool,
    }

    impl CaptureGuard {
        pub(crate) fn new() -> Self {
            let previous = BYPASS_CLASSIFICATION.with(|bypass| bypass.replace(true));
            Self { previous }
        }
    }

    impl Drop for CaptureGuard {
        fn drop(&mut self) {
            BYPASS_CLASSIFICATION.with(|bypass| bypass.set(self.previous));
        }
    }

    /// Runs the classification override hook (if installed): it replaces the
    /// OS identity lookup at the capture boundary so a test can present an
    /// owned placeholder or a foreign link without registering a sync root.
    /// The hook is consulted at every classification point and may return a
    /// different kind per call — exactly the shape of a source replaced
    /// between the metadata query and the reopened handle.
    pub(crate) fn classification(path: &Path) -> Option<SourceKind> {
        if BYPASS_CLASSIFICATION.with(Cell::get) {
            return None;
        }
        CLASSIFY.with(|slot| {
            let mut slot = slot.borrow_mut();
            slot.as_mut().map(|hook| hook(path))
        })
    }

    /// Registers a classification override for captures on this thread until
    /// it is replaced. Install a fresh hook before every capture a test
    /// performs.
    pub(crate) fn install_classification(hook: Box<dyn FnMut(&Path) -> SourceKind>) {
        CLASSIFY.with(|slot| *slot.borrow_mut() = Some(hook));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_state(path: &Path) -> FileState {
        super::super::volume::query_file_state(path).expect("query file state")
    }

    fn synthetic_state(size: u64, usn: Option<i64>) -> FileState {
        FileState {
            identity: super::super::volume::FileIdentity {
                volume_serial_number: 1,
                file_id: [7; 16],
                link_count: 1,
                attributes: 0,
                reparse_tag: 0,
            },
            size,
            last_write_time_100ns: 5,
            usn,
        }
    }

    #[test]
    fn observation_matching_requires_identity_size_mtime_and_usn() {
        let state = synthetic_state(10, Some(3));
        assert!(same_observation(&state, &state));
        let mut drift = state.clone();
        drift.size = 11;
        assert!(!same_observation(&state, &drift));
        let mut drift = state.clone();
        drift.identity.link_count = 2;
        assert!(!same_observation(&state, &drift));
        // A same-size, same-timestamp replacement advances the USN: metadata
        // equality is not content equality and must never look like one.
        let mut drift = state.clone();
        drift.usn = Some(4);
        assert!(!same_observation(&state, &drift));
        // `None` is evidence of "no journal", never a match-anything wildcard.
        let mut drift = state.clone();
        drift.usn = None;
        assert!(!same_observation(&state, &drift));
        let no_journal = synthetic_state(10, None);
        assert!(same_observation(&no_journal, &synthetic_state(10, None)));
    }

    #[test]
    fn only_verified_hfdr_placeholders_are_owned() {
        let workspace = hfdrive_core::ids::WorkspaceId::new();
        let identity = PlaceholderIdentity::file(
            workspace,
            hfdrive_core::ids::ItemId::new(),
            hfdrive_core::ids::VersionId::new(),
        );
        let reparse = raw::ATTR_REPARSE_POINT;
        let cloud = super::super::volume::IO_REPARSE_TAG_CLOUD;

        // Cloud-family placeholder carrying a valid HFDR record: owned.
        assert_eq!(
            classify_reparse(reparse, cloud, Some(identity)),
            SourceKind::OwnedPlaceholder(identity)
        );
        // Another sync provider's cloud placeholder: cloud tag but no HFDR
        // identity. Foreign, never read or recaptured.
        assert_eq!(
            classify_reparse(reparse, cloud, None),
            SourceKind::ForeignLink
        );
        // Junctions, mount points and symlinks are never cloud family.
        for tag in [0xA000_0003, 0xA000_000C, 0xA000_0010] {
            assert_eq!(
                classify_reparse(reparse, tag, Some(identity)),
                SourceKind::ForeignLink,
                "tag {tag:#x} is a foreign link even with HFDR-looking bytes"
            );
        }
    }

    #[test]
    fn foreign_links_are_rejected_and_owned_placeholders_recaptured_in_place() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("edited.bin");
        // The edited local bytes of an owned placeholder: same length as the
        // file it replaces, still exactly what the recapture must stage.
        std::fs::write(&source, b"local edited bytes").unwrap();
        let staging = root.path().join("staging");
        let workspace = hfdrive_core::ids::WorkspaceId::new();
        let identity = PlaceholderIdentity::file(
            workspace,
            hfdrive_core::ids::ItemId::new(),
            hfdrive_core::ids::VersionId::new(),
        );

        // A foreign link is rejected at the boundary, never followed.
        seams::install_classification(Box::new(|_| SourceKind::ForeignLink));
        let refused = SnapshotId::new();
        let result = capture_snapshot_with(
            &source,
            &staging,
            refused,
            None,
            PlaceholderPolicy::RecaptureOwned,
        );
        assert!(
            matches!(result, Err(FsError::ReparsePoint { .. })),
            "foreign links are refused, never read"
        );
        assert!(
            !staging.join(format!("{refused}.snap")).exists(),
            "no staged file is produced for a foreign link"
        );

        // An owned placeholder is recaptured in place from its local bytes,
        // and its identity rides along so the publisher binds the recapture.
        seams::install_classification(Box::new(move |_| SourceKind::OwnedPlaceholder(identity)));
        let captured = capture_snapshot_with(
            &source,
            &staging,
            SnapshotId::new(),
            None,
            PlaceholderPolicy::RecaptureOwned,
        )
        .expect("owned placeholder recaptured in place");
        assert_eq!(captured.size, 18);
        assert_eq!(std::fs::read(&captured.staged_path).unwrap(), b"local edited bytes");
        assert_eq!(captured.sha256, Sha256Digest::of(b"local edited bytes"));
        assert_eq!(
            captured.evidence.placeholder,
            Some(identity),
            "the recapture carries the placeholder's own identity"
        );

        // Callers that capture ordinary files keep refusing placeholders.
        seams::install_classification(Box::new(move |_| SourceKind::OwnedPlaceholder(identity)));
        let result = capture_snapshot(&source, &staging, SnapshotId::new(), None);
        assert!(
            matches!(result, Err(FsError::UnsupportedFileType)),
            "an ordinary-file capture never silently adopts a placeholder"
        );
    }

    #[test]
    fn equal_length_same_timestamp_content_is_captured_not_stale_metadata() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("src.bin");
        std::fs::write(&source, b"AAAAAAAA").unwrap();
        let observed = file_state(&source);

        // Same length, same modification time, different bytes. `FileTimes`
        // is a consuming builder — the value `set_modified` returns is what
        // `File::set_times` applies, so it is passed straight through.
        let modified = std::fs::metadata(&source).unwrap().modified().unwrap();
        std::fs::write(&source, b"BBBBBBBB").unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&source).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(modified)).unwrap();
        drop(file);
        let replaced = file_state(&source);
        assert_eq!(observed.size, replaced.size, "same length");
        assert_eq!(
            observed.last_write_time_100ns, replaced.last_write_time_100ns,
            "the replacement carries the original timestamp"
        );
        assert_eq!(observed.identity.file_id, replaced.identity.file_id, "same identity");

        if replaced.usn.is_some() && observed.usn != replaced.usn {
            // The volume journals USNs: the replacement is drift, never a
            // stale capture that would stage the old bytes.
            let result = capture_snapshot(
                &source,
                &root.path().join("staging"),
                SnapshotId::new(),
                Some(&observed),
            );
            assert!(
                matches!(
                    result,
                    Err(FsError::IdentityChanged) | Err(FsError::SourceChanged)
                ),
                "same-size/same-timestamp replacement is detected as drift"
            );
        } else {
            // No USN evidence on this volume: the capture must still stage
            // the content it read (from the coherent handle), never a stale
            // copy, and the digest must describe those exact bytes.
            let captured = capture_snapshot(
                &source,
                &root.path().join("staging"),
                SnapshotId::new(),
                Some(&observed),
            )
            .expect("capture of the current content");
            assert_eq!(std::fs::read(&captured.staged_path).unwrap(), b"BBBBBBBB");
            assert_eq!(captured.sha256, Sha256Digest::of(b"BBBBBBBB"));
        }
    }

    #[test]
    fn a_live_writer_refuses_the_coherent_capture() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("busy.bin");
        std::fs::write(&source, b"busy").unwrap();
        let staging = root.path().join("staging");
        // Hold the file with write access: the capture's coherent open denies
        // write sharing and must fail instead of staging a torn copy.
        let holder = std::fs::OpenOptions::new().write(true).open(&source).unwrap();
        let result = capture_snapshot(&source, &staging, SnapshotId::new(), None);
        drop(holder);
        assert!(
            matches!(result, Err(FsError::SharingViolation)),
            "capture refuses concurrent writers instead of staging a torn copy"
        );
        assert_eq!(std::fs::read(&source).unwrap(), b"busy", "the source is untouched");
        assert!(std::fs::read_dir(&staging).map(|mut e| e.next().is_none()).unwrap_or(true));
    }

    #[test]
    fn coherent_hashing_reads_the_current_content() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("src.bin");
        std::fs::write(&source, b"first contents").unwrap();
        let (state, digest, total) = read_hashed_coherent(&source).expect("coherent digest");
        assert_eq!(total, 14);
        assert_eq!(digest, *Sha256Digest::of(b"first contents").as_bytes());
        assert_eq!(state.size, 14);

        let mut sink = File::create(root.path().join("copy.bin")).unwrap();
        let (state, digest, total) =
            copy_hashed_coherent(&source, &mut sink).expect("coherent copy");
        sink.flush().unwrap();
        assert_eq!(total, 14);
        assert_eq!(digest, *Sha256Digest::of(b"first contents").as_bytes());
        assert_eq!(std::fs::read(root.path().join("copy.bin")).unwrap(), b"first contents");
        assert_eq!(state.size, 14);
    }
}

/// Manual smoke scenario: a real owned placeholder edited in place is
/// recaptured from its local bytes. Requires `HFDRIVE_SMOKE_SYNC_ROOT`, an
/// already registered and connected dev sync root, and is ignored by default
/// like every CFAPI scenario.
#[cfg(test)]
#[ignore = "manual smoke: run on a registered dev sync root (HFDRIVE_SMOKE_SYNC_ROOT)"]
#[test]
fn smoke_edited_owned_placeholder_is_recaptured_in_place() {
    use crate::cfapi::{create_placeholders, MetadataSpec, PlaceholderCreate, PlaceholderIdentity, PlaceholderRequestOutcome};

    let root = PathBuf::from(
        std::env::var("HFDRIVE_SMOKE_SYNC_ROOT")
            .expect("set HFDRIVE_SMOKE_SYNC_ROOT to a registered dev sync root"),
    );
    let workspace = hfdrive_core::ids::WorkspaceId::new();
    let identity = PlaceholderIdentity::file(
        workspace,
        hfdrive_core::ids::ItemId::new(),
        hfdrive_core::ids::VersionId::new(),
    );
    let created = create_placeholders(
        &root,
        &[PlaceholderCreate {
            name: "recapture.bin".to_owned(),
            metadata: MetadataSpec {
                size: 0,
                creation_time_100ns: 0,
                last_write_time_100ns: 0,
                attributes: 0x20,
            },
            identity,
            mark_in_sync: false,
        }],
    )
    .expect("create the scenario placeholder");
    assert!(matches!(created[0].outcome, PlaceholderRequestOutcome::Created { .. }));

    // Edit the placeholder in place: its local bytes are what a recapture
    // must stage — never the bound immutable version.
    let source = root.join("recapture.bin");
    std::fs::write(&source, b"edited placeholder bytes").unwrap();

    let staging = tempfile::tempdir().expect("create test-owned staging outside the sync root");
    let captured = capture_snapshot_with(
        &source,
        staging.path(),
        SnapshotId::new(),
        None,
        PlaceholderPolicy::RecaptureOwned,
    )
    .expect("owned placeholder recaptured in place");
    assert_eq!(std::fs::read(&captured.staged_path).unwrap(), b"edited placeholder bytes");
    assert_eq!(captured.evidence.placeholder, Some(identity));
    let _ = std::fs::remove_file(&source);
}
