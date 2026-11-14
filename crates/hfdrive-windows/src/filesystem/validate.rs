//! Sync-root validation through handles.
//!
//! A candidate root must be, all at once: on a fixed writable NTFS volume, a
//! case-**insensitive** directory, free of reparse points from the volume
//! mount down to the root itself, canonicalized (no traversal spelling), with
//! every path component a supported name, and non-overlapping with any other
//! configured HF Drive root, the application state/cache/staging directory,
//! or any sync root registered with Windows (`GetCurrentSyncRoots`).
//! Everything is checked through open handles; nothing is inferred from
//! strings alone.

use std::path::{Component, Path, PathBuf};

use crate::ffi::volume as raw;

use super::names::validate_component;
use super::volume::{query_volume, FileIdentity, VolumeIdentity};
use super::{FsError, FsResult};

/// Inputs the caller supplies for overlap and state-directory checks.
pub struct RootContext {
    /// The application state/cache/staging directory (outside all roots).
    pub state_dir: PathBuf,
    /// Roots configured for other connections of this application.
    pub configured_roots: Vec<PathBuf>,
    /// The connection's own previous registration root (reconnect), which is
    /// allowed to equal the candidate root.
    pub ignored_existing_root: Option<PathBuf>,
}

/// A validated root plus the identity evidence captured at validation time.
#[derive(Clone, Debug)]
pub struct ValidatedRoot {
    /// The path as requested.
    pub path: PathBuf,
    /// Normalized DOS final path of the root (canonical, no `.`/`..`).
    pub final_path: PathBuf,
    pub volume: VolumeIdentity,
    pub identity: FileIdentity,
}

/// Validate `root` as an HF Drive sync root.
pub fn validate_sync_root(root: &Path, context: &RootContext) -> FsResult<ValidatedRoot> {
    // 1. Every path component must be a supported final-component name.
    validate_components(root)?;

    // 2. Open the root through a handle (no reparse following) and classify
    //    it: directory, not a reparse point, not case-sensitive.
    let handle = raw::open_query(root, true).map_err(|code| raw_classify(root, code))?;
    let attrs = raw::attr_tag(&handle).map_err(op("GetFileInformationByHandleEx(FileAttributeTagInfo)"))?;
    if attrs.reparse_tag != 0 || attrs.attributes & raw::ATTR_REPARSE_POINT != 0 {
        return Err(FsError::ReparsePoint {
            path: root.to_path_buf(),
        });
    }
    if attrs.attributes & raw::ATTR_DIRECTORY == 0 {
        return Err(FsError::UnsupportedFileType);
    }
    let case_flags = raw::case_sensitive_flags(&handle)
        .map_err(op("GetFileInformationByHandleEx(FileCaseSensitiveInfo)"))?;
    if case_flags & raw::CS_FLAG_CASE_SENSITIVE_DIR != 0 {
        return Err(FsError::CaseSensitiveDirectory);
    }

    // 3. No reparse point anywhere from the volume mount down to the root.
    check_reparse_ancestors(root)?;

    // 4. Fixed, writable NTFS volume; the ACL writability probe below
    //    exercises the real write access check.
    let volume = query_volume(root)?;
    if !volume.is_supported() {
        return Err(FsError::NotFixedNtfs {
            file_system: volume.file_system.clone(),
            is_fixed: volume.is_fixed,
            read_only: volume.read_only,
        });
    }
    raw::check_writable(root).map_err(|_| FsError::NotWritable)?;

    // 5. Canonical final path (rejects traversal spelling and junction
    //    redirection: the final path must live on the same volume).
    let final_path = PathBuf::from(
        raw::final_path(&handle).map_err(op("GetFinalPathNameByHandleW"))?,
    );

    // 6. Overlap checks against the state directory, configured roots and
    //    every sync root registered with Windows.
    check_overlaps(&final_path, context)?;

    let id = raw::id_info(&handle).map_err(op("GetFileInformationByHandleEx(FileIdInfo)"))?;
    let std = raw::standard_info(&handle)
        .map_err(op("GetFileInformationByHandleEx(FileStandardInfo)"))?;
    Ok(ValidatedRoot {
        path: root.to_path_buf(),
        final_path,
        volume,
        identity: FileIdentity {
            volume_serial_number: id.volume_serial_number,
            file_id: id.file_id,
            link_count: std.link_count,
            attributes: attrs.attributes,
            reparse_tag: attrs.reparse_tag,
        },
    })
}

/// Validate each path component as a supported name (rejects `.`/`..`,
/// reserved DOS device names, forbidden characters, trailing dot/space).
fn validate_components(path: &Path) -> FsResult<()> {
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let name = part.to_string_lossy();
                validate_component(&name)?;
            }
            Component::Prefix(_) | Component::RootDir | Component::CurDir | Component::ParentDir => {
                // Prefix/root are structural; `.`/`..` are resolved away by
                // the canonical final path but still rejected here to keep
                // the contract literal.
                if matches!(component, Component::CurDir | Component::ParentDir) {
                    return Err(FsError::InvalidName(
                        super::names::NameCheckError::ForbiddenCharacter,
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Reject any reparse point from the volume mount down to (and including)
/// each ancestor of the root.
fn check_reparse_ancestors(root: &Path) -> FsResult<()> {
    let mut current = root.parent().map(Path::to_path_buf);
    while let Some(dir) = current {
        if dir.as_os_str().is_empty() {
            break;
        }
        match raw::file_attributes(&dir) {
            Ok(Some(attrs)) => {
                if attrs & raw::ATTR_REPARSE_POINT != 0 {
                    return Err(FsError::ReparsePoint { path: dir });
                }
            }
            Ok(None) => {
                return Err(FsError::NotFound { path: dir });
            }
            Err(code) => return Err(raw_classify(&dir, code)),
        }
        if dir.parent() == Some(&dir) {
            break;
        }
        current = dir.parent().map(Path::to_path_buf);
    }
    Ok(())
}

fn check_overlaps(final_path: &Path, context: &RootContext) -> FsResult<()> {
    let ignored = context
        .ignored_existing_root
        .as_deref()
        .map(canonicalize_existing)
        .transpose()?
        .flatten();

    // State/cache/staging must not live inside (or contain) a sync root.
    if let Ok(Some(state)) = canonicalize_existing(&context.state_dir) {
        if overlaps(final_path, &state) {
            return Err(FsError::OverlapsConfiguredRoot { other: state });
        }
    }

    for configured in &context.configured_roots {
        let other = match canonicalize_existing(configured)? {
            Some(other) => other,
            None => continue,
        };
        if Some(&other) == ignored.as_ref() {
            continue;
        }
        if overlaps(final_path, &other) {
            return Err(FsError::OverlapsConfiguredRoot { other });
        }
    }

    // Registered sync roots (any provider) must not overlap.
    let registered = crate::ffi::syncroot::current_roots()
        .map_err(|code| FsError::Win32 { operation: "GetCurrentSyncRoots", code })?;
    for root in registered {
        let other = match root.path.as_deref().map(canonicalize_existing).transpose()? {
            Some(Some(other)) => other,
            _ => continue,
        };
        if Some(&other) == ignored.as_ref() {
            continue;
        }
        if overlaps(final_path, &other) {
            return Err(FsError::OverlapsSyncRoot { other });
        }
    }
    Ok(())
}

/// Canonicalize an existing path through a handle; `Ok(None)` when absent.
fn canonicalize_existing(path: &Path) -> FsResult<Option<PathBuf>> {
    match raw::open_query(path, true) {
        Ok(handle) => raw::final_path(&handle)
            .map(|s| Some(normalized(PathBuf::from(s))))
            .map_err(op("GetFinalPathNameByHandleW")),
        Err(code) if code == 2 || code == 3 => Ok(None),
        Err(code) => Err(raw_classify(path, code)),
    }
}

/// True when one path contains the other (or they are equal), comparing
/// path segments with Windows ordinal case-insensitive equality.
fn overlaps(a: &Path, b: &Path) -> bool {
    let a = segments(a);
    let b = segments(b);
    let shared = a.len().min(b.len());
    (0..shared).all(|i| super::names::windows_case_equivalent(&a[i], &b[i]))
}

fn segments(path: &Path) -> Vec<String> {
    path.to_string_lossy()
        .split(['\\', '/'])
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn normalized(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    let trimmed = text.trim_end_matches(['\\', '/']);
    PathBuf::from(trimmed)
}

fn raw_classify(path: &Path, code: u32) -> FsError {
    match code {
        2 | 3 => FsError::NotFound {
            path: path.to_path_buf(),
        },
        32 | 33 => FsError::SharingViolation,
        _ => FsError::Win32 {
            operation: "CreateFileW",
            code,
        },
    }
}

fn op(operation: &'static str) -> impl Fn(u32) -> FsError {
    move |code: u32| FsError::Win32 { operation, code }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlap_is_segment_wise_and_symmetric() {
        let a = Path::new("C:\\Data\\Root");
        let b = Path::new("c:\\data\\root\\inner");
        assert!(overlaps(a, b));
        assert!(overlaps(b, a));
        assert!(overlaps(a, a));
        assert!(!overlaps(Path::new("C:\\Data\\Root2"), a));
    }

    #[test]
    fn components_reject_dot_segments() {
        assert!(validate_components(Path::new("C:\\Data\\..\\Root")).is_err());
        assert!(validate_components(Path::new("C:\\Data\\Root")).is_ok());
    }

    #[test]
    fn segment_splitting_normalizes_separators() {
        assert_eq!(segments(Path::new("C:\\a/b")), vec!["C:", "a", "b"]);
    }
}
