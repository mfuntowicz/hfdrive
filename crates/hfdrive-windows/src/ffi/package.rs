//! Package-identity queries used for peer image/package validation.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows::Win32::Foundation::{HANDLE, WIN32_ERROR};
use windows::Win32::Storage::Packaging::Appx::{
    GetPackageFamilyName, GetPackageFullName, GetPackagePathByFullName,
    GetCurrentPackageFullName, GetCurrentPackageFamilyName,
};

use super::{APPMODEL_ERROR_NO_PACKAGE, ERROR_INSUFFICIENT_BUFFER};

/// The package identity of a process (absent for unpackaged processes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PackageIdentity {
    /// Package full name, e.g. `HFDrive_1.2.3.0_x64__<publisher-id>`.
    pub(crate) full_name: String,
    /// Package family name, e.g. `HFDrive_<publisher-id>`.
    pub(crate) family_name: String,
    /// Install directory of the package (canonical path form).
    pub(crate) install_path: Option<String>,
}

/// Package identity of the current process (None when unpackaged).
pub(crate) fn current_package() -> Result<Option<PackageIdentity>, u32> {
    // SAFETY: two-call sizing on the package name query.
    unsafe {
        let mut len = 0u32;
        let status = GetCurrentPackageFullName(&mut len, None);
        if status == WIN32_ERROR(APPMODEL_ERROR_NO_PACKAGE) {
            return Ok(None);
        }
        if status != WIN32_ERROR(ERROR_INSUFFICIENT_BUFFER) && status != WIN32_ERROR(0) {
            return Err(status.0);
        }
        if len == 0 {
            return Ok(None);
        }
        let mut buf = vec![0u16; len as usize];
        let status = GetCurrentPackageFullName(&mut len, Some(windows::core::PWSTR(buf.as_mut_ptr())));
        if status != WIN32_ERROR(0) {
            return Err(status.0);
        }
        let full_name = String::from_utf16_lossy(&buf[..buf.iter().position(|&c| c == 0).unwrap_or(buf.len())]);
        let mut family_len = 0u32;
        let mut fam = String::new();
        let status = GetCurrentPackageFamilyName(&mut family_len, None);
        if status == WIN32_ERROR(ERROR_INSUFFICIENT_BUFFER) && family_len > 0 {
            let mut fam_buf = vec![0u16; family_len as usize];
            let status =
                GetCurrentPackageFamilyName(&mut family_len, Some(windows::core::PWSTR(fam_buf.as_mut_ptr())));
            if status == WIN32_ERROR(0) {
                fam = String::from_utf16_lossy(
                    &fam_buf[..fam_buf.iter().position(|&c| c == 0).unwrap_or(fam_buf.len())],
                );
            }
        }
        let install_path = package_install_path(&full_name);
        Ok(Some(PackageIdentity {
            full_name,
            family_name: fam,
            install_path,
        }))
    }
}

/// Package identity of an open process handle (None when unpackaged).
pub(crate) fn process_package(process: HANDLE) -> Result<Option<PackageIdentity>, u32> {
    // SAFETY: two-call sizing; `process` is a queryable process handle.
    unsafe {
        let mut len = 0u32;
        let status = GetPackageFullName(process, &mut len, None);
        if status == WIN32_ERROR(APPMODEL_ERROR_NO_PACKAGE) {
            return Ok(None);
        }
        if status != WIN32_ERROR(ERROR_INSUFFICIENT_BUFFER) && status != WIN32_ERROR(0) {
            return Err(status.0);
        }
        if len == 0 {
            return Ok(None);
        }
        let mut buf = vec![0u16; len as usize];
        let status = GetPackageFullName(process, &mut len, Some(windows::core::PWSTR(buf.as_mut_ptr())));
        if status != WIN32_ERROR(0) {
            return Err(status.0);
        }
        let full_name = String::from_utf16_lossy(&buf[..buf.iter().position(|&c| c == 0).unwrap_or(buf.len())]);
        let mut family_len = 0u32;
        let mut fam = String::new();
        let status = GetPackageFamilyName(process, &mut family_len, None);
        if status == WIN32_ERROR(ERROR_INSUFFICIENT_BUFFER) && family_len > 0 {
            let mut fam_buf = vec![0u16; family_len as usize];
            let status =
                GetPackageFamilyName(process, &mut family_len, Some(windows::core::PWSTR(fam_buf.as_mut_ptr())));
            if status == WIN32_ERROR(0) {
                fam = String::from_utf16_lossy(
                    &fam_buf[..fam_buf.iter().position(|&c| c == 0).unwrap_or(fam_buf.len())],
                );
            }
        }
        let install_path = package_install_path(&full_name);
        Ok(Some(PackageIdentity {
            full_name,
            family_name: fam,
            install_path,
        }))
    }
}

/// Install directory of an installed package (canonical path form).
pub(crate) fn package_install_path(full_name: &str) -> Option<String> {
    let wide: Vec<u16> = OsStr::new(full_name).encode_wide().chain(Some(0)).collect();
    // SAFETY: two-call sizing; `wide` is NUL-terminated.
    unsafe {
        let mut len = 0u32;
        let status = GetPackagePathByFullName(
            windows::core::PCWSTR(wide.as_ptr()),
            &mut len,
            None,
        );
        if status != WIN32_ERROR(ERROR_INSUFFICIENT_BUFFER) || len == 0 {
            return None;
        }
        let mut buf = vec![0u16; len as usize];
        let status = GetPackagePathByFullName(
            windows::core::PCWSTR(wide.as_ptr()),
            &mut len,
            Some(windows::core::PWSTR(buf.as_mut_ptr())),
        );
        if status != WIN32_ERROR(0) {
            return None;
        }
        Some(String::from_utf16_lossy(
            &buf[..buf.iter().position(|&c| c == 0).unwrap_or(buf.len())],
        ))
    }
}
