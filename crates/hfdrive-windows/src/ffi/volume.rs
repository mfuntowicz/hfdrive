//! Handle-based file and volume query adapters.
//!
//! Thin, buffer-owning wrappers over generated `windows` 0.62.2 projection
//! calls. Safe modules consume the plain-data structs below; no `windows`
//! type ever crosses out of this module tree. Failures are returned as raw
//! Win32/HRESULT codes (`u32`) so the safe layer can classify them without
//! importing the projection.

use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::os::windows::io::{FromRawHandle, IntoRawHandle};
use std::path::Path;

use windows::Win32::Foundation::{HANDLE, GENERIC_READ, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FindClose, FindFirstStreamW, FindNextStreamW, GetDriveTypeW,
    GetFileInformationByHandleEx, GetFinalPathNameByHandleW, GetFileAttributesW,
    GetVolumeInformationByHandleW, GetVolumeNameForVolumeMountPointW, GetVolumePathNameW,
    FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO, FILE_CASE_SENSITIVE_INFO, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN,
    FILE_ID_INFO, FILE_INFO_BY_HANDLE_CLASS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_STANDARD_INFO, FileAttributeTagInfo, FileBasicInfo, FileCaseSensitiveInfo, FileIdInfo,
    FileStandardInfo, FindStreamInfoStandard, OPEN_EXISTING, WIN32_FIND_STREAM_DATA,
};

use super::handle::OwnedHandle;
use super::{error_code, last_error_code};

/// `ERROR_INVALID_PARAMETER` (87).
const ERROR_INVALID_PARAMETER: u32 = 87;

/// `DRIVE_FIXED` — GetDriveTypeW result for a fixed hard disk.
pub(crate) const DRIVE_FIXED_TYPE: u32 = 3;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
pub(crate) const ATTR_REPARSE_POINT: u32 = 0x400;
/// `FILE_ATTRIBUTE_ENCRYPTED` (EFS).
pub(crate) const ATTR_ENCRYPTED: u32 = 0x4000;
/// `FILE_ATTRIBUTE_RECALL_ON_OPEN`.
pub(crate) const ATTR_RECALL_ON_OPEN: u32 = 0x40000;
/// `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`.
pub(crate) const ATTR_RECALL_ON_DATA_ACCESS: u32 = 0x400000;
/// `FILE_ATTRIBUTE_DIRECTORY`.
pub(crate) const ATTR_DIRECTORY: u32 = 0x10;
/// `FILE_CS_FLAG_CASE_SENSITIVE_DIR` (ntifs.h) — the case-sensitive directory
/// flag reported by `FileCaseSensitiveInfo`. The projection exposes the
/// structure but not this flag constant.
pub(crate) const CS_FLAG_CASE_SENSITIVE_DIR: u32 = 0x1;
/// `FILE_READ_ONLY_VOLUME`.
pub(crate) const FS_VOL_IS_READONLY: u32 = 0x0008_0000;

fn wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(path.as_os_str())
        .encode_wide()
        .chain(Some(0))
        .collect()
}

fn wide_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Open an existing file or directory for queries only (read attributes and
/// metadata; never triggers data recalls). `open_reparse_point` opens the
/// reparse point itself instead of following it.
pub(crate) fn open_query(path: &Path, open_reparse_point: bool) -> Result<OwnedHandle, u32> {
    let w = wide(path);
    let mut flags = FILE_FLAGS_AND_ATTRIBUTES(
        FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_SEQUENTIAL_SCAN.0,
    );
    if open_reparse_point {
        flags |= FILE_FLAG_OPEN_REPARSE_POINT;
    }
    // SAFETY: `w` is NUL-terminated and outlives the call; the returned
    // handle is owned by `OwnedHandle` exactly once.
    unsafe {
        let raw = CreateFileW(
            windows::core::PCWSTR(w.as_ptr()),
            GENERIC_READ.0 | windows::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
        .map_err(|e| error_code(&e))?;
        OwnedHandle::from_raw(raw).ok_or_else(last_error_code)
    }
}

/// Open an existing regular file for a coherent read: read access with
/// **write and delete sharing denied** (share mode = `FILE_SHARE_READ`
/// only), so no other writer can change or remove the file while it is
/// held. Never follows reparse points into other volumes.
pub(crate) fn open_read_coherent(path: &Path) -> Result<OwnedHandle, u32> {
    let w = wide(path);
    // SAFETY: as `open_query`.
    unsafe {
        let raw = CreateFileW(
            windows::core::PCWSTR(w.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_SEQUENTIAL_SCAN.0),
            None,
        )
        .map_err(|e| error_code(&e))?;
        OwnedHandle::from_raw(raw).ok_or_else(last_error_code)
    }
}

/// Consume an owned handle into a `std::fs::File` for buffered streaming on
/// the very same open (the sharing mode therefore still applies).
pub(crate) fn handle_into_file(handle: OwnedHandle) -> std::fs::File {
    // SAFETY: `OwnedHandle` owns a valid kernel handle; `File` takes that
    // ownership over exactly once via the raw handle conversion.
    unsafe { std::fs::File::from_raw_handle(handle.into_raw_handle()) }
}

/// Open metadata updates without following reparse points. Deny competing
/// writes/deletes while captured bytes are guarded and bound to publication.
pub(crate) fn open_read_write(path: &Path) -> Result<OwnedHandle, u32> {
    let w = wide(path);
    // SAFETY: `w` is NUL-terminated; the returned handle is owned exactly
    // once by `OwnedHandle`.
    unsafe {
        let raw = CreateFileW(
            windows::core::PCWSTR(w.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(
                FILE_FLAG_BACKUP_SEMANTICS.0
                    | windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT.0,
            ),
            None,
        )
        .map_err(|e| error_code(&e))?;
        OwnedHandle::from_raw(raw).ok_or_else(last_error_code)
    }
}

/// ACL writability probe: opens the path with write access (no data is
/// written). Fails when the user cannot write; the handle is dropped at once.
pub(crate) fn check_writable(path: &Path) -> Result<(), u32> {
    let w = wide(path);
    // SAFETY: `w` is NUL-terminated; the probe handle is closed immediately.
    unsafe {
        let raw = CreateFileW(
            windows::core::PCWSTR(w.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_BACKUP_SEMANTICS.0),
            None,
        )
        .map_err(|e| error_code(&e))?;
        if let Some(handle) = OwnedHandle::from_raw(raw) {
            drop(handle);
        }
        Ok(())
    }
}

fn file_info<T: Copy>(handle: &OwnedHandle, class: FILE_INFO_BY_HANDLE_CLASS) -> Result<T, u32> {
    let mut info: T = unsafe { zeroed() };
    // SAFETY: `info` is a valid, correctly sized buffer for `class`.
    unsafe {
        GetFileInformationByHandleEx(
            handle.as_win(),
            class,
            &mut info as *mut T as *mut c_void,
            size_of::<T>() as u32,
        )
        .map_err(|e| error_code(&e))?;
    }
    Ok(info)
}

/// Volume serial number and 128-bit file ID.
pub(crate) struct IdInfo {
    pub volume_serial_number: u64,
    pub file_id: [u8; 16],
}

pub(crate) fn id_info(handle: &OwnedHandle) -> Result<IdInfo, u32> {
    let info: FILE_ID_INFO = file_info(handle, FileIdInfo)?;
    Ok(IdInfo {
        volume_serial_number: info.VolumeSerialNumber,
        file_id: info.FileId.Identifier,
    })
}

/// Raw attributes and reparse tag.
pub(crate) struct AttrTag {
    pub attributes: u32,
    pub reparse_tag: u32,
}

pub(crate) fn attr_tag(handle: &OwnedHandle) -> Result<AttrTag, u32> {
    let info: FILE_ATTRIBUTE_TAG_INFO = file_info(handle, FileAttributeTagInfo)?;
    Ok(AttrTag {
        attributes: info.FileAttributes,
        reparse_tag: info.ReparseTag,
    })
}

/// Size and link count.
pub(crate) struct StandardInfo {
    pub size: u64,
    pub link_count: u32,
}

pub(crate) fn standard_info(handle: &OwnedHandle) -> Result<StandardInfo, u32> {
    let info: FILE_STANDARD_INFO = file_info(handle, FileStandardInfo)?;
    Ok(StandardInfo {
        size: info.EndOfFile as u64,
        link_count: info.NumberOfLinks,
    })
}

/// Last-write timestamp (100 ns since 1601 UTC).
pub(crate) struct BasicInfo {
    pub last_write_time_100ns: i64,
}

pub(crate) fn basic_info(handle: &OwnedHandle) -> Result<BasicInfo, u32> {
    let info: FILE_BASIC_INFO = file_info(handle, FileBasicInfo)?;
    Ok(BasicInfo {
        last_write_time_100ns: info.LastWriteTime,
    })
}

/// Case-sensitivity flags for the directory (`FILE_CASE_SENSITIVE_INFO`).
pub(crate) fn case_sensitive_flags(handle: &OwnedHandle) -> Result<u32, u32> {
    let info: FILE_CASE_SENSITIVE_INFO = file_info(handle, FileCaseSensitiveInfo)?;
    Ok(info.Flags)
}

/// Volume information from a handle on that volume.
pub(crate) struct VolumeInfo {
    pub serial_number: u32,
    pub file_system: String,
    pub flags: u32,
}

pub(crate) fn volume_info(handle: &OwnedHandle) -> Result<VolumeInfo, u32> {
    let mut name = vec![0u16; 261];
    let mut fs = vec![0u16; 261];
    let mut serial = 0u32;
    let mut max_component = 0u32;
    let mut flags = 0u32;
    // SAFETY: buffers are valid mutable slices for the call.
    unsafe {
        GetVolumeInformationByHandleW(
            handle.as_win(),
            Some(&mut name),
            Some(&mut serial),
            Some(&mut max_component),
            Some(&mut flags),
            Some(&mut fs),
        )
        .map_err(|e| error_code(&e))?;
    }
    Ok(VolumeInfo {
        serial_number: serial,
        file_system: super::nls::from_wide_nul(&fs),
        flags,
    })
}

/// Final normalized DOS path of an open handle (rejects `.`/`..` spelling
/// and reveals junction redirection).
pub(crate) fn final_path(handle: &OwnedHandle) -> Result<String, u32> {
    let mut buf = vec![0u16; 32768];
    // SAFETY: `buf` is a valid mutable buffer.
    let len = unsafe {
        GetFinalPathNameByHandleW(handle.as_win(), &mut buf, windows::Win32::Storage::FileSystem::VOLUME_NAME_DOS)
    };
    if len == 0 || len as usize >= buf.len() {
        return Err(last_error_code());
    }
    buf.truncate(len as usize);
    Ok(String::from_utf16(&buf).map_err(|_| ERROR_INVALID_PARAMETER)?)
}

/// Volume GUID path (`\\?\Volume{...}\`) for the volume containing `path`.
pub(crate) fn volume_guid_path(path: &Path) -> Result<String, u32> {
    let w = wide(path);
    let mut mount = vec![0u16; 32768];
    // SAFETY: buffers are NUL-terminated or valid mutable slices.
    unsafe {
        GetVolumePathNameW(windows::core::PCWSTR(w.as_ptr()), &mut mount)
            .map_err(|e| error_code(&e))?;
    }
    let mount_str = super::nls::from_wide_nul(&mount);
    let mut volume = vec![0u16; 32768];
    let m = wide_str(&mount_str);
    unsafe {
        GetVolumeNameForVolumeMountPointW(windows::core::PCWSTR(m.as_ptr()), &mut volume)
            .map_err(|e| error_code(&e))?;
    }
    Ok(super::nls::from_wide_nul(&volume))
}

/// `GetDriveTypeW` for a volume mount path (see `DRIVE_FIXED_TYPE`).
pub(crate) fn drive_type(mount: &str) -> u32 {
    let m = wide_str(mount);
    // SAFETY: `m` is NUL-terminated.
    unsafe { GetDriveTypeW(windows::core::PCWSTR(m.as_ptr())) }
}

/// Attributes of a path without following its reparse point.
/// `Ok(None)` when the path does not exist.
pub(crate) fn file_attributes(path: &Path) -> Result<Option<u32>, u32> {
    let w = wide(path);
    // SAFETY: `w` is NUL-terminated. The projection returns the raw
    // attribute bits as `u32`, with `INVALID_FILE_ATTRIBUTES` on failure.
    let attrs = unsafe { GetFileAttributesW(windows::core::PCWSTR(w.as_ptr())) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        let code = last_error_code();
        if code == 2 || code == 3 {
            return Ok(None);
        }
        return Err(code);
    }
    Ok(Some(attrs))
}

/// `INVALID_FILE_ATTRIBUTES` (0xFFFFFFFF) returned by `GetFileAttributesW`.
const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;

/// Named data streams of a file as `(wide name, size)` pairs. The default
/// stream (`::$DATA`) is included; callers filter it. Used to warn about
/// non-default alternate data streams that V1 does not replicate.
pub(crate) fn data_streams(path: &Path) -> Result<Vec<(Vec<u16>, i64)>, u32> {
    let w = wide(path);
    let mut out = Vec::new();
    let mut data: WIN32_FIND_STREAM_DATA = unsafe { zeroed() };
    // SAFETY: `data` is a valid output buffer; the find handle is closed.
    let find = unsafe {
        FindFirstStreamW(
            windows::core::PCWSTR(w.as_ptr()),
            FindStreamInfoStandard,
            &mut data as *mut WIN32_FIND_STREAM_DATA as *mut c_void,
            None,
        )
    };
    let find = match find {
        Ok(h) => h,
        Err(e) => {
            let code = error_code(&e);
            if code == 38 {
                return Ok(Vec::new());
            }
            return Err(code);
        }
    };
    let result = loop {
        out.push((nul_terminated(&data.cStreamName), data.StreamSize));
        let mut next: WIN32_FIND_STREAM_DATA = unsafe { zeroed() };
        let advanced = unsafe {
            FindNextStreamW(find, &mut next as *mut WIN32_FIND_STREAM_DATA as *mut c_void)
        };
        match advanced {
            Ok(()) => data = next,
            Err(e) => {
                let code = error_code(&e);
                if code == 38 {
                    break Ok(out);
                }
                break Err(code);
            }
        }
    };
    // SAFETY: `find` is a live find handle owned here.
    unsafe {
        let _ = FindClose(find);
    }
    result
}

fn nul_terminated(units: &[u16]) -> Vec<u16> {
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    units[..end].to_vec()
}

/// Borrow a `HANDLE` view of an owned handle for cross-adapter calls.
pub(crate) fn as_handle(handle: &OwnedHandle) -> HANDLE {
    handle.as_win()
}
