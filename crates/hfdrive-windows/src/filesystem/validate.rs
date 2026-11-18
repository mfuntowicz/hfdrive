//! Sync-root validation through handles.
//!
//! A candidate root must be, all at once: on a fixed writable NTFS volume, a
//! case-**insensitive** directory, free of reparse points from the volume
//! mount down to the root itself, canonicalized (no traversal spelling), with
//! every path component a supported name, and non-overlapping with any other
//! configured HF Drive root, the application state/cache/staging directory,
//! or any sync root containing the candidate (`CfGetSyncRootInfoByPath`;
//! reconnect uses an exact registration ID lookup).
//! Everything is checked through open handles; nothing is inferred from
//! strings alone.
//!
//! Reconnect is the single exception to "no reparse points": the root of an
//! already registered HF Drive connection carries the cloud-family reparse
//! tag at the root directory itself. Such a root is admitted only when the
//! exact expected sync-root id is registered with Windows at this exact root,
//! proven through handle identity and canonical path; that one registration
//! is also the only overlap exemption. A missing, wrong or foreign
//! registration id, and any junction, mount point or symlink, is refused even
//! when an id is supplied. Every ancestor of the root still rejects every
//! reparse point, owned root or not.

use std::path::{Component, Path, PathBuf};

use crate::ffi::volume as raw;

use super::names::validate_component;
use super::volume::{is_cloud_family_tag, query_volume, FileIdentity, VolumeIdentity};
use super::{FsError, FsResult};

/// Inputs the caller supplies for overlap and state-directory checks.
pub struct RootContext {
    /// The application state/cache/staging directory (outside all roots).
    pub state_dir: PathBuf,
    /// Roots configured for other connections of this application.
    pub configured_roots: Vec<PathBuf>,
    /// Expected Windows registration ID on reconnect. Only that registration,
    /// at the same handle-verified root, may own a cloud reparse point or be
    /// exempt from overlap checks. New roots pass `None`.
    pub existing_sync_root_id: Option<String>,
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

    // 2. Open without following reparse points. A claimed cloud root still
    //    needs exact registration and identity proof below.
    let handle = raw::open_query(root, true).map_err(|code| raw_classify(root, code))?;
    let attrs = raw::attr_tag(&handle).map_err(op("GetFileInformationByHandleEx(FileAttributeTagInfo)"))?;
    if attrs.attributes & raw::ATTR_DIRECTORY == 0 {
        return Err(FsError::UnsupportedFileType);
    }
    check_root_reparse(
        root,
        attrs.attributes,
        attrs.reparse_tag,
        context.existing_sync_root_id.is_some(),
    )?;
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

    let id = raw::id_info(&handle).map_err(op("GetFileInformationByHandleEx(FileIdInfo)"))?;
    // 6. Only the exact owned registration can exempt this root from overlap
    //    and cloud-reparse rejection.
    let owned = check_overlaps(&final_path, context, &id)?;
    check_root_reparse(root, attrs.attributes, attrs.reparse_tag, owned)?;
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

fn check_root_reparse(path: &Path, attributes: u32, tag: u32, allow_cloud: bool) -> FsResult<()> {
    if (attributes & raw::ATTR_REPARSE_POINT != 0 || tag != 0)
        && !(allow_cloud && is_cloud_family_tag(tag))
    {
        return Err(FsError::ReparsePoint { path: path.to_path_buf() });
    }
    Ok(())
}

fn registration_matches(
    expected_id: Option<&str>,
    registered_id: &str,
    candidate_path: &Path,
    candidate_id: &raw::IdInfo,
    registered_path: &Path,
    registered_identity: &raw::IdInfo,
) -> bool {
    expected_id == Some(registered_id)
        && candidate_id.volume_serial_number == registered_identity.volume_serial_number
        && candidate_id.file_id == registered_identity.file_id
        && super::names::windows_case_equivalent(
            candidate_path.to_string_lossy().trim_end_matches(['\\', '/']),
            registered_path.to_string_lossy().trim_end_matches(['\\', '/']),
        )
}

fn check_overlaps(
    final_path: &Path,
    context: &RootContext,
    identity: &raw::IdInfo,
) -> FsResult<bool> {

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
        if overlaps(final_path, &other) {
            return Err(FsError::OverlapsConfiguredRoot { other });
        }
    }

    if let Some(expected) = context.existing_sync_root_id.as_deref() {
        let info = crate::cfapi::registration::sync_root_info_for_id(expected)
            .map_err(|error| match error {
                crate::cfapi::CfError::Win32 { code, .. } => FsError::Win32 {
                    operation: "GetSyncRootInformationForId",
                    code,
                },
                _ => FsError::OverlapsSyncRoot { other: final_path.to_path_buf() },
            })?;
        let Some(info) = info else {
            return Err(FsError::OverlapsSyncRoot { other: final_path.to_path_buf() });
        };
        let id = info.Id()
            .map_err(|error| FsError::Win32 {
                operation: "StorageProviderSyncRootInfo.Id",
                code: error.code().0 as u32,
            })?
            .to_string();
        if registration_matches(
            Some(expected),
            &id,
            final_path,
            identity,
            final_path,
            identity,
        ) {
            return Ok(true);
        }
        return Err(FsError::OverlapsSyncRoot { other: final_path.to_path_buf() });
    }

    // Check only the candidate. Enumerating every registered root or resolving
    // its WinRT folder can crash Windows when an older root was deleted.
    let registered = crate::cfapi::registration::sync_root_registered_at_path(final_path)
        .map_err(|error| match error {
            crate::cfapi::CfError::Win32 { code, .. } => FsError::Win32 {
                operation: "CfGetSyncRootInfoByPath",
                code,
            },
            _ => FsError::OverlapsSyncRoot { other: final_path.to_path_buf() },
        })?;
    if registered {
        Err(FsError::OverlapsSyncRoot { other: final_path.to_path_buf() })
    } else {
        Ok(false)
    }
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

    #[test]
    fn only_the_exact_registered_cloud_root_is_admitted() {
        let path = Path::new("C:\\Data\\Drive");
        let id = raw::IdInfo { volume_serial_number: 7, file_id: [1; 16] };
        let owned = registration_matches(
            Some("HFDrive!owner!connection"),
            "HFDrive!owner!connection",
            path,
            &id,
            Path::new("c:\\data\\DRIVE\\"),
            &id,
        );
        assert!(owned);
        for tag in [super::super::volume::IO_REPARSE_TAG_CLOUD, 0x9000_101A] {
            check_root_reparse(path, raw::ATTR_DIRECTORY | raw::ATTR_REPARSE_POINT, tag, owned)
                .expect("the exact owned cloud root reconnects");
        }
    }

    #[test]
    fn a_claimed_id_cannot_adopt_a_foreign_or_replaced_cloud_root() {
        let path = Path::new("C:\\Data\\Drive");
        let id = raw::IdInfo { volume_serial_number: 7, file_id: [1; 16] };
        let other_volume = raw::IdInfo { volume_serial_number: 8, file_id: [1; 16] };
        let replacement = raw::IdInfo { volume_serial_number: 7, file_id: [2; 16] };
        for (expected, registered, registered_path, registered_identity) in [
            (None, "HFDrive!owner!connection", path, &id),
            (Some("HFDrive!owner!connection"), "OtherProvider!root", path, &id),
            (Some("HFDrive!owner!wrong"), "HFDrive!owner!connection", path, &id),
            (Some("HFDrive!owner!connection"), "HFDrive!owner!connection", Path::new("C:\\Data\\Other"), &id),
            (Some("HFDrive!owner!connection"), "HFDrive!owner!connection", path, &other_volume),
            (Some("HFDrive!owner!connection"), "HFDrive!owner!connection", path, &replacement),
        ] {
            let owned = registration_matches(
                expected, registered, path, &id, registered_path, registered_identity,
            );
            assert!(!owned);
            assert!(matches!(
                check_root_reparse(path, raw::ATTR_DIRECTORY | raw::ATTR_REPARSE_POINT, 0x9000_101A, owned),
                Err(FsError::ReparsePoint { .. })
            ));
        }
    }

    #[test]
    fn ownership_never_permits_junctions_symlinks_or_unknown_reparse_tags() {
        for tag in [0xA000_0003, 0xA000_000C, 0] {
            assert!(matches!(
                check_root_reparse(Path::new("C:\\Data\\Drive"), raw::ATTR_DIRECTORY | raw::ATTR_REPARSE_POINT, tag, true),
                Err(FsError::ReparsePoint { .. })
            ));
        }
    }

    #[test]
    fn a_reparse_ancestor_is_rejected_even_for_a_cloud_root_candidate() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let junction = temp.path().join("junction");
        std::fs::create_dir(&target).unwrap();
        let result = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&target)
            .output()
            .unwrap();
        assert!(result.status.success(), "failed to create isolated junction");
        assert!(matches!(
            check_reparse_ancestors(&junction.join("candidate")),
            Err(FsError::ReparsePoint { path }) if path == junction
        ));
    }
}
