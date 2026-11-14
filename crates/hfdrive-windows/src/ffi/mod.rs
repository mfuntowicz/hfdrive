//! Minimal unsafe Windows API surface used by this crate.
//!
//! All direct `windows` crate calls live here. Each submodule exposes small
//! safe wrappers that own their buffers and free OS resources with RAII.
//! No handwritten ABI definitions exist anywhere in this crate: every
//! structure and function comes from the generated `windows` 0.62.2
//! projection.

pub(crate) mod acl;
pub(crate) mod dpapi;
pub(crate) mod file;
pub(crate) mod handle;
pub(crate) mod package;
pub(crate) mod pipe;
pub(crate) mod process;
pub(crate) mod shell;
pub(crate) mod sid;
pub(crate) mod token;
pub(crate) mod cfapi;
pub(crate) mod nls;
pub(crate) mod syncroot;
pub(crate) mod usn;
pub(crate) mod volume;
pub(crate) mod watchdir;

/// Decode the Win32 error code embedded in a `windows::core::Error`.
///
/// The projection maps Win32 failures to `HRESULT_FROM_WIN32` values; the
/// original Win32 code is the low 16 bits of those (`0x8007xxxx`). Non-Win32
/// failures fall back to the raw HRESULT value so no information is lost.
pub(crate) fn error_code(err: &windows::core::Error) -> u32 {
    let hr = err.code().0 as u32;
    if hr & 0xFFFF_0000 == 0x8007_0000 {
        hr & 0xFFFF
    } else {
        hr
    }
}

/// Code of an error raised by the last Win32 call in this thread.
pub(crate) fn last_error_code() -> u32 {
    unsafe { windows::Win32::Foundation::GetLastError().0 }
}

/// `ERROR_INSUFFICIENT_BUFFER` is returned by the dynamic-size query APIs on
/// their first call and is not a failure by itself.
pub(crate) const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

/// `APPMODEL_ERROR_NO_PACKAGE` is returned by package identity queries for
/// unpackaged processes; it is an expected, informative outcome.
pub(crate) const APPMODEL_ERROR_NO_PACKAGE: u32 = 15700;

/// `ERROR_FILE_NOT_FOUND` (record absent).
pub(crate) const ERROR_FILE_NOT_FOUND: u32 = 2;

/// `ERROR_LOCK_VIOLATION` (byte-range lock held elsewhere).
pub(crate) const ERROR_LOCK_VIOLATION: u32 = 33;

/// `ERROR_BUSY`.
pub(crate) const ERROR_BUSY: u32 = 170;
