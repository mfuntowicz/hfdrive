//! File and lock helpers: atomic record replacement and the state-owner lock.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, DeleteFileW, FILE_ATTRIBUTE_NORMAL, FILE_CREATION_DISPOSITION,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_MODE, FILE_SHARE_NONE, FILE_SHARE_READ, FlushFileBuffers,
    FILE_WRITE_DATA, LOCK_FILE_FLAGS, LockFileEx, MOVE_FILE_FLAGS, MoveFileExW, ReadFile,
    SetFilePointerEx, WriteFile, CREATE_NEW, FILE_ALL_ACCESS, FILE_BEGIN,
    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, OPEN_EXISTING,
};
use windows::Win32::System::IO::{OVERLAPPED, OVERLAPPED_0};

use super::handle::OwnedHandle;

/// Create a new file exclusively, applying `security` on creation.
pub(crate) fn create_exclusive(
    path: &Path,
    security: Option<&SECURITY_ATTRIBUTES>,
) -> windows::core::Result<OwnedHandle> {
    open_with(path, CREATE_NEW, security, FILE_SHARE_NONE)
}

/// Open an existing file without allowing writers to share it.
pub(crate) fn open_existing(path: &Path) -> windows::core::Result<OwnedHandle> {
    open_with(path, OPEN_EXISTING, None, FILE_SHARE_READ)
}

fn open_with(
    path: &Path,
    disposition: FILE_CREATION_DISPOSITION,
    security: Option<&SECURITY_ATTRIBUTES>,
    share: FILE_SHARE_MODE,
) -> windows::core::Result<OwnedHandle> {
    let wide: Vec<u16> = OsStr::new(path.as_os_str()).encode_wide().chain(Some(0)).collect();
    // SAFETY: `wide` is NUL-terminated; the returned handle is owned by
    // `OwnedHandle`. `security` outlives the call.
    unsafe {
        let raw = CreateFileW(
            windows::core::PCWSTR(wide.as_ptr()),
            FILE_ALL_ACCESS.0 | GENERIC_READ.0 | GENERIC_WRITE.0,
            share,
            security.map(|s| s as *const SECURITY_ATTRIBUTES),
            disposition,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )?;
        OwnedHandle::from_raw(raw).ok_or_else(windows::core::Error::from_thread)
    }
}

/// Write the whole buffer at the file's current position.
pub(crate) fn write_all(handle: HANDLE, mut data: &[u8]) -> windows::core::Result<()> {
    while !data.is_empty() {
        let mut written = 0u32;
        // SAFETY: `data` is valid for the call.
        unsafe { WriteFile(handle, Some(data), Some(&mut written), None)? };
        if written == 0 {
            return Err(windows::core::Error::from_thread());
        }
        data = &data[written as usize..];
    }
    Ok(())
}

/// Rewind the file pointer to the start.
pub(crate) fn rewind(handle: HANDLE) -> windows::core::Result<()> {
    // SAFETY: standard seek on an open handle; no new pointer needed.
    unsafe { SetFilePointerEx(handle, 0, None, FILE_BEGIN) }
}

/// Read the whole file from the current position, bounded by `max`.
pub(crate) fn read_all(handle: HANDLE, max: usize) -> windows::core::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let mut read = 0u32;
        // SAFETY: `chunk` is valid for the read size.
        unsafe { ReadFile(handle, Some(&mut chunk), Some(&mut read), None)? };
        if read == 0 {
            break;
        }
        if out.len() + read as usize > max {
            return Err(windows::core::Error::from_thread());
        }
        out.extend_from_slice(&chunk[..read as usize]);
    }
    Ok(out)
}

/// Read up to `max` bytes from the current position without failing when the
/// file is longer (used for the fixed-size owner record where a longer tail
/// is not corruption).
pub(crate) fn read_up_to(handle: HANDLE, max: usize) -> windows::core::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut chunk = vec![0u8; max.min(64 * 1024)];
    while out.len() < max {
        let want = (max - out.len()).min(chunk.len());
        let mut read = 0u32;
        // SAFETY: `chunk` is valid for the read size.
        unsafe { ReadFile(handle, Some(&mut chunk[..want]), Some(&mut read), None)? };
        if read == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..read as usize]);
    }
    Ok(out)
}

/// Flush file data and metadata to stable storage.
pub(crate) fn flush(handle: HANDLE) -> windows::core::Result<()> {
    // SAFETY: handle is open with write access.
    unsafe { FlushFileBuffers(handle) }
}

/// Replace `dst` with `src` atomically (same volume), flushed through to
/// disk. After this returns the old `dst` content is gone and the rename is
/// durable.
pub(crate) fn replace_file(src: &Path, dst: &Path) -> windows::core::Result<()> {
    let src_wide: Vec<u16> = OsStr::new(src.as_os_str()).encode_wide().chain(Some(0)).collect();
    let dst_wide: Vec<u16> = OsStr::new(dst.as_os_str()).encode_wide().chain(Some(0)).collect();
    // SAFETY: both wide strings are NUL-terminated.
    unsafe {
        MoveFileExW(
            windows::core::PCWSTR(src_wide.as_ptr()),
            windows::core::PCWSTR(dst_wide.as_ptr()),
            MOVE_FILE_FLAGS(MOVEFILE_REPLACE_EXISTING.0 | MOVEFILE_WRITE_THROUGH.0),
        )
    }
}

/// Delete a file; returns `false` when it was already absent.
pub(crate) fn delete_if_exists(path: &Path) -> windows::core::Result<bool> {
    let wide: Vec<u16> = OsStr::new(path.as_os_str()).encode_wide().chain(Some(0)).collect();
    // SAFETY: `wide` is NUL-terminated.
    match unsafe { DeleteFileW(windows::core::PCWSTR(wide.as_ptr())) } {
        Ok(()) => Ok(true),
        Err(e) => {
            if super::error_code(&e) == super::ERROR_FILE_NOT_FOUND {
                Ok(false)
            } else {
                Err(e)
            }
        }
    }
}

/// Take an exclusive byte-range lock over a reserved region of a file
/// without waiting. The lock is held until the handle closes.
///
/// The locked range is **not** the first bytes of the file: it is a reserved
/// 8-byte region at offset 1024 (`LOCK_REGION_START`), so the owner-record
/// bytes at the start of the file stay readable by other processes while the
/// lock is held. A locked range blocks other handles' reads *and* writes of
/// those bytes, so the record must live outside it.
///
/// Returns the Win32 error code when the range is already locked
/// (`ERROR_LOCK_VIOLATION`/`ERROR_BUSY`).
pub(crate) fn try_lock_exclusive(handle: HANDLE) -> Result<(), u32> {
    // SAFETY: `OVERLAPPED` with a null event; offset fields select the
    // reserved range `LOCK_REGION_START..LOCK_REGION_START + 8`.
    let mut overlapped = OVERLAPPED {
        Internal: 0,
        InternalHigh: 0,
        Anonymous: OVERLAPPED_0 {
            Anonymous: windows::Win32::System::IO::OVERLAPPED_0_0 {
                Offset: LOCK_REGION_START,
                OffsetHigh: 0,
            },
        },
        hEvent: HANDLE(std::ptr::null_mut()),
    };
    match unsafe {
        LockFileEx(
            handle,
            LOCK_FILE_FLAGS(LOCKFILE_EXCLUSIVE_LOCK.0 | LOCKFILE_FAIL_IMMEDIATELY.0),
            None,
            8,
            0,
            &mut overlapped,
        )
    } {
        Ok(()) => Ok(()),
        Err(_) => Err(super::last_error_code()),
    }
}

/// Start of the reserved lock region (see [`try_lock_exclusive`]).
const LOCK_REGION_START: u32 = 1024;

/// Open (creating when absent) the state-owner file with read/write data
/// access and full sharing, so other processes can still open it to read the
/// owner record while the exclusive range lock is held. Mutual exclusion is
/// enforced by the byte-range lock (see [`try_lock_exclusive`]), not by the
/// share mode; the share mode only decides whether the owner record can be
/// inspected at all.
pub(crate) fn open_state_file(path: &Path) -> windows::core::Result<OwnedHandle> {
    use windows::Win32::Storage::FileSystem::{FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_WRITE, OPEN_ALWAYS};
    let wide: Vec<u16> = std::ffi::OsStr::new(path.as_os_str())
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: `wide` is NUL-terminated; the returned handle is owned.
    unsafe {
        let raw = CreateFileW(
            windows::core::PCWSTR(wide.as_ptr()),
            FILE_READ_DATA.0 | FILE_WRITE_DATA.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )?;
        OwnedHandle::from_raw(raw).ok_or_else(windows::core::Error::from_thread)
    }
}
