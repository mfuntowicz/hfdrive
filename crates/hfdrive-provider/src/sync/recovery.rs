//! Durable preservation copies for dirty local bytes, taken before any
//! destructive unlink or delete work.
//!
//! Contract of one recovery copy:
//!
//! * it lives **outside every sync root**, in the connection's recovery area,
//!   so it survives unlink, disconnect and package removal;
//! * its name is unique (`<hint>.<n>.<label-hash>.recovered`): a colliding
//!   name never overwrites a previously preserved copy;
//! * it is **metadata-checked**: the source's NTFS identity (volume serial +
//!   128-bit file id), size and modification time are captured before the
//!   copy and re-verified after it, so a source that changed mid-copy is
//!   never reported as preserved;
//! * it is **content-checked**: every preservation and every reuse re-reads
//!   the source's current bytes through one coherent read (write and delete
//!   sharing denied) and compares SHA-256 digests. Identity, size and
//!   timestamps alone cannot tell a file from a same-size, same-timestamp
//!   replacement — a stale copy is never bound to content it does not hold;
//! * it is **hash-verified**: the copy's bytes on disk in the recovery area
//!   are re-hashed and must equal the digest of the bytes read from the
//!   source. A truncated or corrupted copy is a preservation error and never
//!   counts as preserved;
//! * a sidecar records the source label, path, identity, size, modification
//!   time and content digest so a later recovery can match the copy against
//!   the file it came from;
//! * an existing sidecar whose recorded metadata still matches the source and
//!   whose copy still hashes correctly is preserved content already — the
//!   copy is reused instead of duplicated. Anything else (missing sidecar,
//!   stale metadata, tampered bytes) is never trusted and never overwritten:
//!   the next free collision slot is used instead. A reuse additionally
//!   re-hashes the source's **current** bytes and requires them to equal the
//!   copy's digest before the copy counts as this source's preservation;
//! * both names of one copy are **reserved with `create_new`**, so a copy
//!   never overwrites an occupant and no two attempts can take one slot; a
//!   reservation conflict moves to the next slot, and a failed attempt
//!   retains its unverified remnants without deleting by path — a replacement
//!   or foreign occupant is never removed;
//! * the durability order is **payload -> sidecar -> success**: the payload is
//!   flushed to stable storage before the sidecar is written, and the sidecar
//!   is flushed before the copy is reported as preserved. A crash in between
//!   leaves at most an orphan payload, which no sidecar ever vouches for;
//! * a source that changes between the candidate check and the reuse — or
//!   during the copy — is rejected, never reported preserved.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use hfdrive_windows::filesystem::snapshot::{classify_reparse, copy_hashed_coherent, read_hashed_coherent, CopyError, SourceKind};
use hfdrive_windows::filesystem::volume::query_file_state;
use hfdrive_windows::filesystem::FsError;
use sha2::{Digest, Sha256};

/// Why a preservation copy could not be produced or verified.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("recovery area unavailable")]
    AreaUnavailable,
    #[error("the source file is no longer available")]
    SourceGone,
    #[error("the source changed while it was being preserved")]
    SourceChanged,
    #[error("the source could not be read")]
    Unreadable,
    #[error("the recovery copy could not be written")]
    WriteFailed,
    #[error("the recovery copy does not match the source bytes")]
    DigestMismatch,
}

/// Exact identity and content facts one recovery copy is bound to. This is
/// the sidecar record; `sha256` is the digest computed while reading the
/// source.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySource {
    /// Caller-supplied stable identity of the preserved content (the item or
    /// action UUID). Opaque here; it is what a later recovery matches on.
    pub label: String,
    /// Source path at preservation time (display provenance).
    pub path: String,
    /// NTFS volume serial of the source file.
    pub volume_serial_number: u64,
    /// NTFS 128-bit file identity of the source file.
    pub file_id: [u8; 16],
    /// Logical size in bytes.
    pub size: u64,
    /// Last write time in Windows 100ns units since 1601.
    pub last_write_time_100ns: i64,
    /// SHA-256 of the exact bytes preserved.
    pub sha256: [u8; 32],
}

/// A verified recovery copy on disk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCopy {
    pub path: PathBuf,
    pub source: RecoverySource,
}

/// Preserves one dirty source when it holds resident bytes. Directories,
/// empty files and vanished sources have nothing to lose and are skipped
/// (`Ok(None)`); the destructive caller proceeds for those without treating
/// the skip as a preservation proof. **Only** a source the metadata query
/// reports missing is such a skip: any other metadata failure is propagated
/// as a preservation error, so a locked/unreadable file is never mistaken for
/// one with nothing to lose.
pub fn preserve_item_bytes(
    source: &Path,
    recovery_dir: &Path,
    label: &str,
    display_path: &str,
) -> Result<Option<RecoveryCopy>, RecoveryError> {
    match std::fs::symlink_metadata(source) {
        Ok(metadata) if metadata.is_file() && metadata.len() > 0 => {
            preserve_dirty_copy(source, recovery_dir, label, display_path).map(Some)
        }
        // Nothing resident to lose: a directory, an empty file, or a source
        // that is verifiably gone. Anything else is a real metadata error.
        Ok(_) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(RecoveryError::Unreadable),
    }
}

/// Copies `source` to the recovery area with the full metadata and digest
/// proof described at the module root. The source is read through one
/// coherent handle (write and delete sharing denied) and its current content
/// digest is part of the proof: metadata equality never vouches for content.
pub fn preserve_dirty_copy(
    source: &Path,
    recovery_dir: &Path,
    label: &str,
    display_path: &str,
) -> Result<RecoveryCopy, RecoveryError> {
    std::fs::create_dir_all(recovery_dir).map_err(|_| RecoveryError::AreaUnavailable)?;
    guard_source(source)?;
    let before = capture(source)?;
    let record = RecoverySource {
        label: label.to_owned(),
        path: display_path.to_owned(),
        volume_serial_number: before.volume_serial_number,
        file_id: before.file_id,
        size: before.size,
        last_write_time_100ns: before.last_write_time_100ns,
        sha256: before.sha256,
    };

    // Reuse a fully verified previous copy before writing a new one.
    let hint = base_name_hint(display_path);
    let label_hash = hex::encode(&Sha256::digest(label.as_bytes())[..8]);
    for existing in existing_candidates(recovery_dir, &hint, &label_hash) {
        if let Some(copy) = verified_existing(&existing, &record, source, &before)? {
            return Ok(copy);
        }
    }

    let mut counter = 0u32;
    loop {
        let stem = format!("{hint}.{counter}.{label_hash}.recovered");
        let target = recovery_dir.join(&stem);
        let sidecar = recovery_dir.join(format!("{stem}.json"));
        // Reserve both names exclusively before writing a byte: a colliding
        // occupant is never overwritten, and no two attempts can take one
        // slot. A reservation race is just another collision — the next free
        // slot is tried.
        let (payload, sidecar_file) = match reserve_pair(&target, &sidecar) {
            Ok(handles) => handles,
            Err(ReserveError::AlreadyExists) => {
                counter = counter.checked_add(1).ok_or(RecoveryError::WriteFailed)?;
                if counter > 4096 {
                    return Err(RecoveryError::WriteFailed);
                }
                continue;
            }
            Err(ReserveError::WriteFailed) => return Err(RecoveryError::WriteFailed),
        };
        match write_verified(source, payload, sidecar_file, &target, &sidecar, &before, &record) {
            Ok(source_record) => {
                return Ok(RecoveryCopy {
                    path: target,
                    source: RecoverySource { sha256: source_record, ..record },
                });
            }
            Err(error) => {
                // No partially written or unverifiable copy counts as
                // preserved. Retain the reserved remnants for reconciliation;
                // deleting by path here could remove a replacement object.
                return Err(error);
            }
        }
    }
}

/// A name that was already taken when the exclusive reservation ran.
enum ReserveError {
    AlreadyExists,
    WriteFailed,
}

/// Reserves one copy slot: both the payload name and its sidecar name are
/// created exclusively (`create_new`) and the owned handles are returned for
/// the writers. A reservation is never built on `exists()` checks — two
/// racing attempts cannot both believe a slot is free.
fn reserve_pair(
    target: &Path,
    sidecar: &Path,
) -> Result<(std::fs::File, std::fs::File), ReserveError> {
    let reserve = |path: &Path| {
        std::fs::OpenOptions::new().write(true).create_new(true).open(path)
    };
    let payload = reserve(target).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            ReserveError::AlreadyExists
        } else {
            ReserveError::WriteFailed
        }
    })?;
    match reserve(sidecar) {
        Ok(handle) => Ok((payload, handle)),
        Err(error) => {
            // The empty reserved payload is only an unverified remnant. Keep
            // it rather than deleting a path that could have been replaced.
            drop(payload);
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Err(ReserveError::AlreadyExists)
            } else {
                Err(ReserveError::WriteFailed)
            }
        }
    }
}

/// The captured pre-copy facts the copy is verified against: identity,
/// size, modification time **and** the SHA-256 of the source's current
/// bytes. Metadata alone cannot tell a file from a same-size,
/// same-timestamp replacement; the digest is what binds the copy to content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Captured {
    volume_serial_number: u64,
    file_id: [u8; 16],
    size: u64,
    last_write_time_100ns: i64,
    sha256: [u8; 32],
}

/// Deterministic interleaving seams for the preservation regressions. Both
/// hooks are thread-local (the preservation calls run on the calling thread,
/// so parallel tests can never share a hook) and one-shot. Production code
/// calls the empty stubs below and pays nothing.
#[cfg(test)]
pub(crate) mod seams {
    use std::cell::RefCell;
    use std::path::Path;

    thread_local! {
        static BEFORE_RECHECK: RefCell<Option<Box<dyn FnMut(&Path)>>> = RefCell::new(None);
        static AFTER_PAYLOAD: RefCell<Option<Box<dyn FnMut(&Path, &Path)>>> = RefCell::new(None);
    }

    /// Runs (and clears) the source-recheck hook: it observes the source just
    /// **before** the post-copy / pre-reuse identity/size/mtime re-read (F06),
    /// so a test can change the source inside that exact window.
    pub(crate) fn before_source_recheck(source: &Path) {
        if let Some(mut hook) = BEFORE_RECHECK.with(|slot| slot.borrow_mut().take()) {
            hook(source);
        }
    }

    /// Runs (and clears) the post-flush hook: it observes the pair **after**
    /// the payload is flushed and **before** the sidecar record is written
    /// (F08's payload -> sidecar ordering).
    pub(crate) fn after_payload_flush(target: &Path, sidecar: &Path) {
        if let Some(mut hook) = AFTER_PAYLOAD.with(|slot| slot.borrow_mut().take()) {
            hook(target, sidecar);
        }
    }

    /// Registers a one-shot hook for the next source re-check.
    pub(crate) fn install_before_source_recheck(hook: Box<dyn FnMut(&Path)>) {
        BEFORE_RECHECK.with(|slot| *slot.borrow_mut() = Some(hook));
    }

    /// Registers a one-shot hook for the next post-flush boundary.
    pub(crate) fn install_after_payload_flush(hook: Box<dyn FnMut(&Path, &Path)>) {
        AFTER_PAYLOAD.with(|slot| *slot.borrow_mut() = Some(hook));
    }
}

#[cfg(not(test))]
mod seams {
    use std::path::Path;

    #[inline]
    pub(super) fn before_source_recheck(_source: &Path) {}

    #[inline]
    pub(super) fn after_payload_flush(_target: &Path, _sidecar: &Path) {}
}

fn capture(path: &Path) -> Result<Captured, RecoveryError> {
    // One coherent read (write and delete sharing denied) yields both the
    // identity/size/mtime facts and the SHA-256 of the exact bytes a copy
    // would hold. Metadata alone cannot tell a file from a same-size,
    // same-timestamp replacement, so the content digest is part of every
    // later comparison.
    let (state, sha256, _size) = read_hashed_coherent(path).map_err(map_source_error)?;
    Ok(Captured {
        volume_serial_number: state.identity.volume_serial_number,
        file_id: state.identity.file_id,
        size: state.size,
        last_write_time_100ns: state.last_write_time_100ns,
        sha256,
    })
}

/// Refuses sources that must never be read or followed: a reparse point that
/// is not a verified owned HFDR placeholder (junction, mount point, symlink,
/// another provider's placeholder) is rejected, never followed into another
/// location. Ordinary files and verified owned placeholders (whose local
/// dirty bytes are preservable) pass.
fn guard_source(source: &Path) -> Result<(), RecoveryError> {
    let state = query_file_state(source).map_err(map_source_error)?;
    if !state.identity.is_reparse_point() {
        return Ok(());
    }
    let identity = hfdrive_windows::cfapi::ops::read_placeholder_identity(source, None)
        .map_err(|_| RecoveryError::Unreadable)?;
    match classify_reparse(state.identity.attributes, state.identity.reparse_tag, identity) {
        SourceKind::Plain | SourceKind::OwnedPlaceholder(_) => Ok(()),
        SourceKind::ForeignLink => Err(RecoveryError::Unreadable),
    }
}

fn map_source_error(error: FsError) -> RecoveryError {
    // Only a source the OS reports missing is "gone". Every other failure
    // (sharing violation, access denied, an unreadable volume) is an
    // unreadable source error, never a claim that nothing is there.
    match error {
        FsError::NotFound { .. } => RecoveryError::SourceGone,
        _ => RecoveryError::Unreadable,
    }
}

fn map_copy_error(error: CopyError) -> RecoveryError {
    match error {
        CopyError::Source(error) => map_source_error(error),
        CopyError::Sink(_) => RecoveryError::WriteFailed,
    }
}

fn base_name_hint(display_path: &str) -> String {
    let name = Path::new(display_path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unnamed".to_owned());
    // Keep the hint filename-safe and short; the label hash carries identity.
    let mut hint: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .take(64)
        .collect();
    if hint.is_empty() {
        hint.push_str("unnamed");
    }
    hint
}

fn existing_candidates(recovery_dir: &Path, hint: &str, label_hash: &str) -> Vec<PathBuf> {
    let prefix = format!("{hint}.");
    let suffix = format!(".{label_hash}.recovered");
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(recovery_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(&prefix) && name.ends_with(&suffix) {
                out.push(entry.path());
            }
        }
    }
    out.sort();
    out
}

/// A previous copy counts as already preserved only when its sidecar records
/// the exact same source identity/size/mtime **and content digest** and the
/// copy's current bytes hash to the recorded digest. Anything else is never
/// trusted. A candidate whose recorded digest differs from the source's
/// current content is not this content's preservation (a same-size,
/// same-timestamp replacement looks identical in metadata) — it is skipped,
/// never reused, and a fresh copy is written. Even a fully verified candidate
/// is reused only after the source is re-read and still matches: a source
/// that changed (or vanished) in the meantime is rejected, never silently
/// bound to a stale copy.
fn verified_existing(
    target: &Path,
    record: &RecoverySource,
    source: &Path,
    before: &Captured,
) -> Result<Option<RecoveryCopy>, RecoveryError> {
    let raw = match std::fs::read(sidecar_name(target)) {
        Ok(raw) => raw,
        Err(_) => return Ok(None),
    };
    let Ok(previous) = serde_json::from_slice::<RecoverySource>(&raw) else {
        return Ok(None);
    };
    let Some(digest) = file_digest(target) else {
        return Ok(None);
    };
    if previous.sha256 != digest || metadata_of(&previous) != metadata_of(record) {
        return Ok(None);
    }
    // Content binding: the copy must hold exactly the source's current
    // bytes, not merely share its identity, size and timestamp.
    if previous.sha256 != before.sha256 {
        return Ok(None);
    }
    // The candidate is proven — but the reuse claims this copy is the source's
    // preservation, so the source must still be what it was at capture time.
    // Re-read its identity, size and modification time and reject a changed
    // or vanished source before the stale copy is ever reused.
    seams::before_source_recheck(source);
    let now = capture(source)?;
    if now != *before {
        return Err(RecoveryError::SourceChanged);
    }
    Ok(Some(RecoveryCopy {
        path: target.to_path_buf(),
        source: previous,
    }))
}

/// The sidecar of one recovery copy: the copy's full name plus `.json`.
fn sidecar_name(target: &Path) -> PathBuf {
    let mut sidecar = target.as_os_str().to_owned();
    sidecar.push(".json");
    PathBuf::from(sidecar)
}

/// The identity/size/mtime projection a reuse decision compares on (the
/// digest and label are checked separately — and the digest is content
/// binding, not decoration: metadata equality alone never vouches for
/// equal bytes).
fn metadata_of(record: &RecoverySource) -> (&str, u64, [u8; 16], u64, i64) {
    (
        record.label.as_str(),
        record.volume_serial_number,
        record.file_id,
        record.size,
        record.last_write_time_100ns,
    )
}

/// Streams `source` into the reserved payload handle through one coherent
/// read (write and delete sharing denied), re-verifies the source's metadata
/// **and content digest**, then writes the reserved sidecar handle. The
/// durability order is **payload -> sidecar -> success**: the payload is
/// flushed to stable storage (`File::sync_all`, the same `FlushFileBuffers`
/// write-through the staged-capture path uses — a rename helper has no role
/// at these unique reserved names) before the sidecar record is written, and
/// the sidecar is flushed before the copy is reported as preserved. A crash
/// in between leaves at most an orphan payload that no sidecar vouches for.
/// On any failure the caller retains the unverified remnants rather than
/// risking a replacement-aware delete. Returns the digest.
fn write_verified(
    source: &Path,
    mut payload: std::fs::File,
    mut sidecar: std::fs::File,
    target: &Path,
    sidecar_path: &Path,
    before: &Captured,
    record: &RecoverySource,
) -> Result<[u8; 32], RecoveryError> {
    let (state, digest, written) =
        copy_hashed_coherent(source, &mut payload).map_err(map_copy_error)?;
    if written != before.size
        || state.identity.volume_serial_number != before.volume_serial_number
        || state.identity.file_id != before.file_id
        || state.last_write_time_100ns != before.last_write_time_100ns
    {
        // The source changed while it was being preserved: the partially
        // copied payload is never reported preserved and never keeps bytes
        // the caller believes belong to `before`.
        return Err(RecoveryError::SourceChanged);
    }
    if file_digest(target).as_ref() != Some(&digest) {
        return Err(RecoveryError::DigestMismatch);
    }
    // Content binding: the copied bytes must be exactly the source content
    // observed before the copy. A same-size, same-timestamp replacement shows
    // up here and is never reported preserved.
    if digest != before.sha256 {
        return Err(RecoveryError::SourceChanged);
    }
    // The payload is durable before the sidecar record vouches for it.
    payload.sync_all().map_err(|_| RecoveryError::WriteFailed)?;
    drop(payload);
    seams::after_payload_flush(target, sidecar_path);
    let sidecar_record = RecoverySource { sha256: digest, ..record.clone() };
    let encoded = serde_json::to_vec(&sidecar_record).map_err(|_| RecoveryError::WriteFailed)?;
    sidecar.write_all(&encoded).map_err(|_| RecoveryError::WriteFailed)?;
    // The sidecar is durable before the copy is reported as preserved.
    sidecar.sync_all().map_err(|_| RecoveryError::WriteFailed)?;
    Ok(digest)
}

fn file_digest(path: &Path) -> Option<[u8; 32]> {
    let mut input = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collision_slots_never_overwrite_an_existing_copy() {
        let root = tempfile::tempdir().unwrap();
        let recovery = root.path().join("recovery");
        let source = root.path().join("src.txt");
        let bytes = b"preserved bytes";
        std::fs::write(&source, bytes).unwrap();

        // An unrelated occupant already holds the first free slot of this
        // label: it must never be overwritten.
        std::fs::create_dir_all(&recovery).unwrap();
        let label_hash = hex::encode(&Sha256::digest("item-a".as_bytes())[..8]);
        let occupied = recovery.join(format!("src_txt.0.{label_hash}.recovered"));
        std::fs::write(&occupied, b"someone else's copy").unwrap();

        let copy = preserve_dirty_copy(&source, &recovery, "item-a", "docs\\src.txt").unwrap();
        assert_ne!(copy.path, occupied, "the colliding occupant is skipped, never reused");
        assert_eq!(std::fs::read(&occupied).unwrap(), b"someone else's copy", "the occupant is untouched");
        assert_eq!(std::fs::read(&copy.path).unwrap(), bytes, "the new copy holds the source bytes");
    }

    #[test]
    fn a_verified_copy_is_reused_and_a_changed_source_gets_a_new_one() {
        let root = tempfile::tempdir().unwrap();
        let recovery = root.path().join("recovery");
        let source = root.path().join("src.txt");
        std::fs::write(&source, b"first version").unwrap();

        let first = preserve_dirty_copy(&source, &recovery, "item-a", "src.txt").unwrap();
        let again = preserve_dirty_copy(&source, &recovery, "item-a", "src.txt").unwrap();
        assert_eq!(again.path, first.path, "an unchanged source reuses its verified copy");

        std::fs::write(&source, b"second version, longer").unwrap();
        let second = preserve_dirty_copy(&source, &recovery, "item-a", "src.txt").unwrap();
        assert_ne!(second.path, first.path, "a changed source is preserved separately");
        assert_eq!(std::fs::read(&first.path).unwrap(), b"first version", "the old copy is retained");
        assert_eq!(
            std::fs::read(&second.path).unwrap(),
            b"second version, longer",
            "the new copy holds the new bytes"
        );
    }

    #[test]
    fn a_tampered_copy_is_never_trusted_or_overwritten() {
        let root = tempfile::tempdir().unwrap();
        let recovery = root.path().join("recovery");
        let source = root.path().join("src.txt");
        let bytes = b"the real dirty bytes";
        std::fs::write(&source, bytes).unwrap();

        let first = preserve_dirty_copy(&source, &recovery, "item-a", "src.txt").unwrap();
        // Corrupt the preserved copy on disk.
        std::fs::write(&first.path, b"tampered").unwrap();

        let second = preserve_dirty_copy(&source, &recovery, "item-a", "src.txt").unwrap();
        assert_ne!(second.path, first.path, "an unverifiable copy is never reused");
        assert_eq!(std::fs::read(&first.path).unwrap(), b"tampered", "the tampered file is untouched");
        assert_eq!(std::fs::read(&second.path).unwrap(), bytes, "a fresh verified copy is written");
    }

    #[test]
    fn reuse_rechecks_the_source_after_verifying_the_candidate() {
        let root = tempfile::tempdir().unwrap();
        let recovery = root.path().join("recovery");
        let source = root.path().join("src.txt");
        std::fs::write(&source, b"first version").unwrap();
        let first = preserve_dirty_copy(&source, &recovery, "item-a", "src.txt").unwrap();
        seams::install_before_source_recheck(Box::new(|source| {
            std::fs::write(source, b"changed after candidate verification").unwrap();
        }));
        assert!(matches!(
            preserve_dirty_copy(&source, &recovery, "item-a", "src.txt"),
            Err(RecoveryError::SourceChanged)
        ));
        assert_eq!(std::fs::read(&first.path).unwrap(), b"first version");
        assert_eq!(std::fs::read(&source).unwrap(), b"changed after candidate verification");
    }

    #[test]
    fn payload_is_flushed_before_the_sidecar_vouches_for_it() {
        let root = tempfile::tempdir().unwrap();
        let recovery = root.path().join("recovery");
        let source = root.path().join("src.txt");
        std::fs::write(&source, b"durable payload").unwrap();
        let observed = std::rc::Rc::new(std::cell::Cell::new(false));
        let hook_observed = observed.clone();
        seams::install_after_payload_flush(Box::new(move |payload, sidecar| {
            assert_eq!(std::fs::read(payload).unwrap(), b"durable payload");
            assert_eq!(std::fs::metadata(sidecar).unwrap().len(), 0);
            hook_observed.set(true);
        }));
        let copy = preserve_dirty_copy(&source, &recovery, "item-a", "src.txt").unwrap();
        assert!(observed.get());
        assert!(!std::fs::read(sidecar_name(&copy.path)).unwrap().is_empty());
    }

    #[test]
    fn missing_or_empty_sources_never_claim_a_preservation_proof() {
        let root = tempfile::tempdir().unwrap();
        let recovery = root.path().join("recovery");
        let source = root.path().join("src.txt");
        // A vanished source is a preservation failure, never a silent skip of
        // a file that once had bytes.
        assert!(matches!(
            preserve_dirty_copy(&source, &recovery, "item-a", "src.txt"),
            Err(RecoveryError::SourceGone)
        ));
        // The skip shortcut covers only sources with nothing to lose.
        assert!(preserve_item_bytes(&source, &recovery, "item-a", "src.txt").unwrap().is_none());
        std::fs::write(&source, b"").unwrap();
        assert!(preserve_item_bytes(&source, &recovery, "item-a", "src.txt").unwrap().is_none());
        std::fs::write(&source, b"bytes").unwrap();
        let copy = preserve_item_bytes(&source, &recovery, "item-a", "src.txt").unwrap();
        assert!(copy.is_some(), "resident dirty bytes always produce a verified copy");
    }

    #[test]
    fn equal_length_same_timestamp_replacement_is_never_reused() {
        let root = tempfile::tempdir().unwrap();
        let recovery = root.path().join("recovery");
        let source = root.path().join("src.txt");
        std::fs::write(&source, b"AAAAAAAA").unwrap();
        let original =
            hfdrive_windows::filesystem::volume::query_file_state(&source).unwrap();
        let modified = std::fs::metadata(&source).unwrap().modified().unwrap();
        let first = preserve_dirty_copy(&source, &recovery, "item-a", "src.txt").unwrap();
        assert_eq!(std::fs::read(&first.path).unwrap(), b"AAAAAAAA");

        // Same file, same length, same modification time — different bytes.
        // Metadata equality alone cannot tell the two apart; only the content
        // binding can, and it must refuse to bind the stale copy.
        std::fs::write(&source, b"BBBBBBBB").unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&source).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(modified)).unwrap();
        drop(file);
        let replaced =
            hfdrive_windows::filesystem::volume::query_file_state(&source).unwrap();
        assert_eq!(replaced.size, original.size, "same length");
        assert_eq!(
            replaced.last_write_time_100ns, original.last_write_time_100ns,
            "the replacement carries the original timestamp"
        );
        assert_eq!(replaced.identity.file_id, original.identity.file_id, "same identity");

        let second = preserve_dirty_copy(&source, &recovery, "item-a", "src.txt").unwrap();
        assert_ne!(
            second.path, first.path,
            "a same-size/same-timestamp replacement never reuses the stale copy"
        );
        assert_eq!(std::fs::read(&first.path).unwrap(), b"AAAAAAAA", "the old copy is retained");
        assert_eq!(std::fs::read(&second.path).unwrap(), b"BBBBBBBB", "the new copy holds the new bytes");
        assert_ne!(
            first.source.sha256, second.source.sha256,
            "the sidecars bind different content digests"
        );
    }

    #[test]
    fn a_live_writer_never_produces_a_preserved_copy() {
        let root = tempfile::tempdir().unwrap();
        let recovery = root.path().join("recovery");
        let source = root.path().join("src.txt");
        std::fs::write(&source, b"live bytes").unwrap();
        // Hold the file with write access: every preservation read denies
        // write sharing, so a concurrent writer must fail the preservation
        // instead of yielding a torn or stale copy.
        let holder = std::fs::OpenOptions::new().write(true).open(&source).unwrap();
        let result = preserve_dirty_copy(&source, &recovery, "item-a", "src.txt");
        drop(holder);
        assert!(
            matches!(result, Err(RecoveryError::Unreadable)),
            "a source that cannot be read coherently is never reported preserved"
        );
        let claimed: Vec<_> = std::fs::read_dir(&recovery)
            .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default();
        assert!(
            claimed.is_empty(),
            "no copy slot holds bytes for a refused preservation: {claimed:?}"
        );
        assert_eq!(std::fs::read(&source).unwrap(), b"live bytes", "the source is untouched");
    }
}
