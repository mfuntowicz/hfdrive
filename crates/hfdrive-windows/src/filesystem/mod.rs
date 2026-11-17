//! Safe Windows filesystem semantics for the HF Drive synchronization
//! provider: root validation, name rules, coherent snapshot capture, metadata
//! enumeration, change watching and USN journal catch-up.
//!
//! Nothing in this module (or its submodules) calls the `windows` crate
//! directly; every OS call is made through the private adapters in
//! [`crate::ffi`] (`volume`, `watchdir`, `usn`, `nls`, `cfapi`, `syncroot`),
//! which return plain data. See `docs/filesystem-semantics.md` for the
//! supported/unsupported semantics contract and the exact test boundaries.
//!
//! Coherence contract in one paragraph: a snapshot is captured through a
//! single read handle opened **denying concurrent write and delete**, so the
//! bytes cannot change while they are hashed and staged. Sources that are not
//! fully materialized on disk (partial/cloud placeholders, recall-on-access
//! data) are refused outright; the caller materializes them first. Identity
//! (volume serial + 128-bit file ID), size, timestamps and, when the volume
//! has a USN journal, the file's USN are recorded as evidence so the provider
//! can bind its database generation to what was actually read — metadata
//! equality alone never proves equal content. A reparse point is captured
//! only as a **verified owned HFDR placeholder** recaptured in place; every
//! foreign link is rejected and never followed.

use std::path::PathBuf;

pub mod enumerate;
pub mod names;
pub mod snapshot;
pub mod usn;
pub mod validate;
pub mod volume;
pub mod watch;

pub use enumerate::{scan_metadata, MetadataEntry, ScanBudget, ScanReport, VisitFlow};
pub use names::{decode_component, validate_component, windows_case_equivalent, windows_exact_equal, NameCheckError};
pub use snapshot::{
    capture_snapshot, capture_snapshot_with, classify_reparse, copy_hashed_coherent,
    read_hashed_coherent, CapturedSnapshot, CopyError, PlaceholderPolicy, SnapshotEvidence,
    SnapshotWarning, SourceKind,
};
pub use usn::{CatchUp, ResetReason, UsnChange, UsnCursor, UsnJournal, UsnReader};
pub use validate::{validate_sync_root, RootContext, ValidatedRoot};
pub use volume::{
    alternate_data_streams, placeholder_state, query_file_state, query_volume, FileIdentity,
    FileState, PlaceholderState, VolumeIdentity,
};
pub use watch::{DirectoryWatcher, WatchAction, WatchEvent};

/// Atomically replace a same-volume JSON/state file and flush the rename to
/// stable storage. Kept alongside the other safe filesystem contracts so
/// provider-owned cache journals do not depend on credential internals.
pub fn replace_file(source: &std::path::Path, destination: &std::path::Path) -> windows::core::Result<()> {
    crate::ffi::file::replace_file(source, destination)
}

/// Structured, non-secret filesystem error.
///
/// Every variant is safe to log and persist in diagnostics; OS failures carry
/// their Win32 error code so callers can classify retry-vs-fail without string
/// matching.
#[derive(Debug, thiserror::Error)]
pub enum FsError {
    /// The path does not exist (or its volume is gone).
    #[error("path not found: {path:?}")]
    NotFound { path: PathBuf },
    /// A Windows API call failed during `operation`.
    #[error("windows api failure during {operation} (win32={code})")]
    Win32 { operation: &'static str, code: u32 },
    /// The volume is not a fixed, writable NTFS volume as HF Drive requires.
    #[error("volume is not a fixed writable NTFS volume (file system {file_system:?}, fixed={is_fixed}, read_only={read_only})")]
    NotFixedNtfs {
        file_system: String,
        is_fixed: bool,
        read_only: bool,
    },
    /// The directory or one of its ancestors is a reparse point (junction,
    /// mount point, symlink, or any non-provider reparse tag).
    #[error("path or an ancestor is a reparse point: {path:?}")]
    ReparsePoint { path: PathBuf },
    /// The directory carries the case-sensitive NTFS flag; HF Drive's portable
    /// namespace requires case-insensitive directories.
    #[error("directory is case-sensitive; HF Drive requires case-insensitive NTFS directories")]
    CaseSensitiveDirectory,
    /// The candidate root overlaps a configured HF Drive root or the state,
    /// cache or staging directory.
    #[error("root overlaps an existing HF Drive path: {other:?}")]
    OverlapsConfiguredRoot { other: PathBuf },
    /// The candidate root overlaps a sync root already registered with
    /// Windows (from `GetCurrentSyncRoots`).
    #[error("root overlaps an already registered sync root: {other:?}")]
    OverlapsSyncRoot { other: PathBuf },
    /// The current user cannot write to the candidate root.
    #[error("root is not writable by the current user")]
    NotWritable,
    /// The root's volume differs from the volume recorded at validation time.
    #[error("path is not on the validated volume: {path:?}")]
    VolumeMismatch { path: PathBuf },
    /// A name in a path is not a supported Windows item name.
    #[error("unsupported item name: {0}")]
    InvalidName(#[from] NameCheckError),
    /// The source file changed while it was being captured; retry the capture.
    /// The intent is retained by the caller; nothing was uploaded.
    #[error("file changed during capture; retry capture")]
    SourceChanged,
    /// The source's identity (file ID/size/timestamps) does not match what the
    /// caller observed; retry after re-observing the file.
    #[error("file identity does not match the expected state")]
    IdentityChanged,
    /// Another writer holds the file; capture requires denying write/delete.
    #[error("file is in use by another writer (sharing violation)")]
    SharingViolation,
    /// The staging volume ran out of space while writing the snapshot.
    #[error("not enough disk space to stage the snapshot")]
    DiskFull,
    /// The source is not fully materialized on disk (a partial placeholder or
    /// recall-on-access data). The caller must materialize it before capture.
    #[error("file is not fully materialized on disk; materialize before capture")]
    NotMaterialized,
    /// The source is EFS-encrypted. Encrypted content is not synchronized.
    #[error("file is EFS-encrypted; encrypted content is not synchronized")]
    EncryptedFile,
    /// The source has multiple hard links. Multiply linked files are not
    /// uploaded (they are preserved locally with an actionable error).
    #[error("file has multiple hard links; linked files are not uploaded")]
    HardLinked,
    /// The source is not a regular file (symlink, junction, device, ...).
    #[error("unsupported file type")]
    UnsupportedFileType,
    /// A scan exceeded its configured budget; results are incomplete.
    #[error("metadata scan exceeded its budget")]
    BudgetExceeded,
    /// The USN journal can no longer answer from the stored cursor; a full
    /// rescan is required and deletion evidence is void.
    #[error("usn journal requires a full rescan: {0}")]
    UsnReset(#[from] ResetReason),
    /// The operation was cancelled through the caller's cancellation flag.
    #[error("operation cancelled")]
    Cancelled,
    /// An unexpected I/O error.
    #[error("filesystem io error: {0}")]
    Io(#[from] std::io::Error),
}

impl FsError {
    /// True when the failed capture/scan is safe to retry unchanged: the
    /// caller retains its durable intent and tries again later. Sharing,
    /// disk-space, identity and generation failures are retry classes; they
    /// are never treated as deletion or success.
    pub fn retryable(&self) -> bool {
        matches!(
            self,
            FsError::SharingViolation
                | FsError::DiskFull
                | FsError::SourceChanged
                | FsError::IdentityChanged
                | FsError::NotMaterialized
                | FsError::BudgetExceeded
        )
    }
}

/// Convenience alias used throughout the filesystem modules.
pub type FsResult<T> = Result<T, FsError>;
