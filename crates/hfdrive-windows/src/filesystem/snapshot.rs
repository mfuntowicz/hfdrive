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
//!   after the read; any drift is [`FsError::SourceChanged`], and the staged
//!   partial file is deleted so a torn copy can never be published.
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

/// Evidence recorded alongside the staged bytes.
#[derive(Clone, Debug)]
pub struct SnapshotEvidence {
    pub state_before: FileState,
    pub state_after: FileState,
    /// File USN observed via `FSCTL_READ_FILE_USN_DATA` while the coherent
    /// handle was held; `None` when the volume has no journal (see
    /// [`SnapshotWarning::UsnUnavailable`]).
    pub usn: Option<i64>,
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

/// Capture a coherent snapshot of `source` into `staging_dir`.
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
    // Open first: the sharing mode below is the coherence guarantee.
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

    let id = raw::id_info(&handle).map_err(op("id_info"))?;
    let std = raw::standard_info(&handle).map_err(op("standard_info"))?;
    let basic = raw::basic_info(&handle).map_err(op("basic_info"))?;
    let attrs = raw::attr_tag(&handle).map_err(op("attr_tag"))?;
    let usn = crate::ffi::usn::file_usn(&handle).map_err(op("file_usn"))?;

    let state_before = FileState {
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

    // Refuse anything that is not plain, fully materialized local content.
    let identity = &state_before.identity;
    if identity.is_reparse_point() {
        return Err(FsError::UnsupportedFileType);
    }
    if identity.is_encrypted() {
        return Err(FsError::EncryptedFile);
    }
    if identity.has_multiple_links() {
        return Err(FsError::HardLinked);
    }
    if identity.may_not_be_materialized() {
        // A partial/cloud placeholder has holes that must be hydrated first;
        // reading it here could otherwise stage zero-filled holes.
        return Err(FsError::NotMaterialized);
    }

    // Bind to the caller's observed generation.
    if let Some(expect) = expect {
        if !same_observation(&state_before, expect) {
            return Err(FsError::IdentityChanged);
        }
    }

    let warnings = collect_warnings(source, usn);

    // Stage the bytes: bounded chunked copy + incremental SHA-256.
    std::fs::create_dir_all(staging_dir)?;
    let staged_path = staging_dir.join(format!("{}.snap", snapshot_id));
    let mut reader = raw::handle_into_file(handle);
    let mut writer = File::create(&staged_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut total: u64 = 0;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        writer.write_all(&buffer[..read]).map_err(map_write_error)?;
        total += read as u64;
        if total > state_before.size {
            // The file grew mid-capture despite the exclusive share mode
            // being held since open (e.g. a self-modifying writer). Treat as
            // drift and discard.
            let _ = std::fs::remove_file(&staged_path);
            return Err(FsError::SourceChanged);
        }
    }
    if total != state_before.size {
        let _ = std::fs::remove_file(&staged_path);
        return Err(FsError::SourceChanged);
    }

    // Flush to stable storage before the snapshot is reported ready; the
    // provider only references staged paths that survive a crash.
    writer.flush()?;
    raw_fsync(&writer)?;
    drop(writer);

    // Re-verify identity/size/mtime after the read using a fresh query.
    let state_after = super::volume::query_file_state(source)?;
    if !same_observation(&state_after, &FileState {
        identity: state_before.identity.clone(),
        size: state_before.size,
        last_write_time_100ns: state_before.last_write_time_100ns,
        usn: state_before.usn,
    }) {
        let _ = std::fs::remove_file(&staged_path);
        return Err(FsError::SourceChanged);
    }

    Ok(CapturedSnapshot {
        snapshot_id,
        staged_path,
        size: total,
        sha256: Sha256Digest::from_bytes(hasher.finalize().into()),
        evidence: SnapshotEvidence {
            state_before: state_before.clone(),
            state_after,
            usn,
            warnings,
        },
    })
}

fn same_observation(a: &FileState, b: &FileState) -> bool {
    a.identity == b.identity
        && a.size == b.size
        && a.last_write_time_100ns == b.last_write_time_100ns
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_matching_requires_identity_size_and_mtime() {
        let state = FileState {
            identity: super::super::volume::FileIdentity {
                volume_serial_number: 1,
                file_id: [7; 16],
                link_count: 1,
                attributes: 0,
                reparse_tag: 0,
            },
            size: 10,
            last_write_time_100ns: 5,
            usn: Some(3),
        };
        let mut drift = state.clone();
        drift.size = 11;
        assert!(same_observation(&state, &state));
        assert!(!same_observation(&state, &drift));
        let mut drift = state.clone();
        drift.identity.link_count = 2;
        assert!(!same_observation(&state, &drift));
    }
}
