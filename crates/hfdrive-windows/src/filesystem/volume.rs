//! File and volume identity queries used as capture/apply evidence.

use std::path::Path;

use crate::ffi::volume as raw;

use super::{FsError, FsResult};

/// Stable identity evidence for one local file.
///
/// `volume_serial_number` + `file_id` (128-bit, low 64 bits are the NTFS file
/// reference number) identify the file across renames; `link_count`,
/// `attributes` and `reparse_tag` classify hard links, EFS and reparse
/// types; `size` and `last_write_time_100ns` bind the observed generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileIdentity {
    pub volume_serial_number: u64,
    pub file_id: [u8; 16],
    pub link_count: u32,
    pub attributes: u32,
    pub reparse_tag: u32,
}

impl FileIdentity {
    /// True when the file has additional hard links (V1 refuses to upload
    /// multiply linked files).
    pub fn has_multiple_links(&self) -> bool {
        self.link_count > 1
    }

    /// True for EFS-encrypted content (not synchronized).
    pub fn is_encrypted(&self) -> bool {
        self.attributes & raw::ATTR_ENCRYPTED != 0
    }

    /// True when the file is a reparse point of any kind. Only this
    /// provider's own cloud placeholders are ever expected inside a sync
    /// root; anything else is rejected and never followed.
    pub fn is_reparse_point(&self) -> bool {
        self.attributes & raw::ATTR_REPARSE_POINT != 0
    }

    /// True when the content may live in the cloud (partial placeholder or
    /// recall-on-open/data-access data) instead of on local disk.
    pub fn may_not_be_materialized(&self) -> bool {
        self.attributes & (raw::ATTR_RECALL_ON_OPEN | raw::ATTR_RECALL_ON_DATA_ACCESS) != 0
            || is_cloud_family_tag(self.reparse_tag)
    }
}

/// `IO_REPARSE_TAG_CLOUD` (ntifs.h, 0x9000001A — matches the generated
/// `windows::Win32::System::SystemServices::IO_REPARSE_TAG_CLOUD` value).
pub const IO_REPARSE_TAG_CLOUD: u32 = 0x9000_001A;

/// True for the cloud-family reparse tags: the base `IO_REPARSE_TAG_CLOUD` or
/// any `IO_REPARSE_TAG_CLOUD_1..8` numbered alias (0x1000 steps from the base
/// tag). Junctions, mount points, symlinks and every other tag are never
/// cloud family.
///
/// This is the **single** source of the cloud-tag rule: root admission in
/// [`super::validate`] classifies through it instead of duplicating the tag
/// arithmetic.
pub(crate) fn is_cloud_family_tag(tag: u32) -> bool {
    tag == IO_REPARSE_TAG_CLOUD
        || match tag.checked_sub(IO_REPARSE_TAG_CLOUD) {
            Some(delta) => delta != 0 && delta <= 8 * 0x1000 && delta % 0x1000 == 0,
            None => false,
        }
}

/// The observed state a capture or guard check binds to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileState {
    pub identity: FileIdentity,
    pub size: u64,
    pub last_write_time_100ns: i64,
    /// File USN at observation time; `None` when the volume has no usable USN
    /// journal (never a "match anything" wildcard).
    pub usn: Option<i64>,
}

/// Placeholder state classification from `CfGetPlaceholderStateFromAttributeTag`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlaceholderState(pub u32);

impl PlaceholderState {
    pub fn is_placeholder(&self) -> bool {
        self.0 & crate::ffi::cfapi::STATE_PLACEHOLDER != 0
    }
    pub fn is_sync_root(&self) -> bool {
        self.0 & crate::ffi::cfapi::STATE_SYNC_ROOT != 0
    }
    pub fn is_in_sync(&self) -> bool {
        self.0 & crate::ffi::cfapi::STATE_IN_SYNC != 0
    }
    pub fn is_partial(&self) -> bool {
        self.0 & crate::ffi::cfapi::STATE_PARTIAL != 0
    }
    pub fn is_partially_on_disk(&self) -> bool {
        self.0 & crate::ffi::cfapi::STATE_PARTIALLY_ON_DISK != 0
    }
}

/// Classify placeholder state from the attribute/reparse-tag pair (pure
/// projection call, usable in tests with synthetic values).
pub fn placeholder_state(attributes: u32, reparse_tag: u32) -> PlaceholderState {
    PlaceholderState(crate::ffi::cfapi::placeholder_state_bits(
        attributes,
        reparse_tag,
    ))
}

/// Volume identity and acceptance facts for a sync root candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumeIdentity {
    pub serial_number: u32,
    /// GUID volume path (`\\?\Volume{...}\`).
    pub guid_path: String,
    pub file_system: String,
    pub is_fixed: bool,
    pub read_only: bool,
}

impl VolumeIdentity {
    /// Volumes HF Drive accepts: fixed, writable NTFS.
    pub fn is_supported(&self) -> bool {
        self.is_fixed && !self.read_only && self.file_system.eq_ignore_ascii_case("NTFS")
    }
}

/// Query the full observed state of `path` without following reparse points.
///
/// The returned state is exactly what a later [`super::snapshot::capture_snapshot`]
/// call is expected to match; identity drift raises
/// [`FsError::IdentityChanged`], never a silent overwrite.
pub fn query_file_state(path: &Path) -> FsResult<FileState> {
    let handle = raw::open_query(path, true).map_err(|code| classify_open(path, code))?;
    let id = raw::id_info(&handle).map_err(op("GetFileInformationByHandleEx(FileIdInfo)"))?;
    let std = raw::standard_info(&handle).map_err(op("GetFileInformationByHandleEx(FileStandardInfo)"))?;
    let basic = raw::basic_info(&handle).map_err(op("GetFileInformationByHandleEx(FileBasicInfo)"))?;
    let attrs = raw::attr_tag(&handle).map_err(op("GetFileInformationByHandleEx(FileAttributeTagInfo)"))?;
    let usn = crate::ffi::usn::file_usn(&handle).map_err(op("FSCTL_READ_FILE_USN_DATA"))?;
    Ok(FileState {
        identity: FileIdentity {
            volume_serial_number: id.volume_serial_number,
            file_id: id.file_id,
            link_count: std.link_count,
            attributes: attrs.attributes,
            reparse_tag: attrs.reparse_tag,
        },
        size: std.size,
        last_write_time_100ns: basic.last_write_time_100ns,
        usn,
    })
}

/// Query the volume that contains `path` (via a handle on that path).
pub fn query_volume(path: &Path) -> FsResult<VolumeIdentity> {
    let handle = raw::open_query(path, true).map_err(|code| classify_open(path, code))?;
    let info = raw::volume_info(&handle).map_err(op("GetVolumeInformationByHandleW"))?;
    let guid_path = raw::volume_guid_path(path).map_err(op("GetVolumeNameForVolumeMountPointW"))?;
    let mount_end = guid_path.rfind(['\\']).map(|i| i + 1).unwrap_or(0);
    let mount = &guid_path[..mount_end.max(1)];
    let drive_type = raw::drive_type(mount);
    Ok(VolumeIdentity {
        serial_number: info.serial_number,
        guid_path,
        file_system: info.file_system,
        is_fixed: drive_type == raw::DRIVE_FIXED_TYPE,
        read_only: info.flags & raw::FS_VOL_IS_READONLY != 0,
    })
}

/// Alternate data streams of `path` (excluding the default `::$DATA`).
/// Non-default streams are preserved locally but not replicated; the caller
/// surfaces a warning.
pub fn alternate_data_streams(path: &Path) -> FsResult<Vec<(String, i64)>> {
    let streams = raw::data_streams(path).map_err(op("FindFirstStreamW"))?;
    Ok(streams
        .into_iter()
        .filter(|(name, _)| {
            let name = String::from_utf16_lossy(name);
            !name.ends_with("::$DATA")
        })
        .map(|(name, size)| (String::from_utf16_lossy(&name), size))
        .collect())
}

pub(crate) fn classify_open(path: &Path, code: u32) -> FsError {
    match code {
        2 | 3 => FsError::NotFound {
            path: path.to_path_buf(),
        },
        32 | 33 => FsError::SharingViolation,
        112 => FsError::DiskFull,
        _ => FsError::Win32 {
            operation: "CreateFileW",
            code,
        },
    }
}

pub(crate) fn op(operation: &'static str) -> impl Fn(u32) -> FsError {
    move |code: u32| FsError::Win32 { operation, code }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_family_classification() {
        assert!(is_cloud_family_tag(IO_REPARSE_TAG_CLOUD));
        for step in 1..=8u32 {
            assert!(
                is_cloud_family_tag(IO_REPARSE_TAG_CLOUD + step * 0x1000),
                "cloud_{step} alias is cloud family"
            );
        }
        // Junctions, mount points, symlinks and other non-cloud tags are not
        // cloud family; neither is the tag past the numbered family or a gap.
        assert!(!is_cloud_family_tag(0xA000_0003));
        assert!(!is_cloud_family_tag(0));
        assert!(!is_cloud_family_tag(IO_REPARSE_TAG_CLOUD + 9 * 0x1000));
        assert!(!is_cloud_family_tag(IO_REPARSE_TAG_CLOUD + 0x800));
    }

    #[test]
    fn materialization_considers_the_whole_cloud_family() {
        let mut identity = FileIdentity {
            volume_serial_number: 1,
            file_id: [0; 16],
            link_count: 1,
            attributes: raw::ATTR_REPARSE_POINT,
            reparse_tag: IO_REPARSE_TAG_CLOUD + 3 * 0x1000,
        };
        assert!(identity.may_not_be_materialized());
        identity.reparse_tag = 0xA000_0003;
        assert!(!identity.may_not_be_materialized());
    }
}
