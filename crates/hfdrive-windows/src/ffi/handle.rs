//! RAII wrappers for Windows `HANDLE` values.

use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, IntoRawHandle, RawHandle};

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::CloudFilters::CfCloseHandle;

/// An owned kernel handle closed on drop.
///
/// Wraps the projection's `HANDLE` (`*mut c_void` newtype) in a safe wrapper
/// so callers never manipulate raw handle values outside this module.
#[derive(Debug)]
pub(crate) struct OwnedHandle {
    raw: HANDLE,
    close_kind: CloseKind,
}

#[derive(Clone, Copy, Debug)]
enum CloseKind {
    Win32,
    CfApi,
}

// SAFETY: `OwnedHandle` owns exactly one kernel handle and closes it exactly
// once (in `Drop`, via `mem::take`-style extraction). It is safe to move
// across threads; the kernel handle itself remains valid until closed.
unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    /// Take ownership of a raw handle returned by an OS call.
    ///
    /// # Safety
    /// `raw` must be a valid, uniquely owned handle (or null/invalid, which
    /// is rejected and yields `None`).
    pub(crate) unsafe fn from_raw(raw: HANDLE) -> Option<Self> {
        (!raw.is_invalid() && !raw.0.is_null()).then_some(Self { raw, close_kind: CloseKind::Win32 })
    }

    /// Take ownership of an opaque handle returned by
    /// `CfOpenFileWithOplock`, which requires `CfCloseHandle` rather than
    /// `CloseHandle`.
    pub(crate) unsafe fn from_cfapi_raw(raw: HANDLE) -> Option<Self> {
        (!raw.is_invalid() && !raw.0.is_null()).then_some(Self { raw, close_kind: CloseKind::CfApi })
    }

    /// Borrow the projection handle for further API calls.
    pub(crate) fn as_win(&self) -> HANDLE {
        self.raw
    }

    /// Consume and return the raw handle without closing it.
    #[allow(dead_code)]
    pub(crate) fn into_raw(self) -> HANDLE {
        let this = std::mem::ManuallyDrop::new(self);
        this.raw
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle is owned and not yet closed.
        unsafe {
            match self.close_kind {
                CloseKind::Win32 => {
                    let _ = CloseHandle(self.raw);
                }
                CloseKind::CfApi => {
                    let _ = CfCloseHandle(self.raw);
                }
            }
        }
    }
}

impl AsRawHandle for OwnedHandle {
    fn as_raw_handle(&self) -> RawHandle {
        self.raw.0 as RawHandle
    }
}

impl AsHandle for OwnedHandle {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        // SAFETY: the handle is alive for the borrow's lifetime.
        unsafe { BorrowedHandle::borrow_raw(self.as_raw_handle()) }
    }
}

impl FromRawHandle for OwnedHandle {
    unsafe fn from_raw_handle(raw: RawHandle) -> Self {
        // SAFETY: forwarded to the caller's ownership contract.
        match unsafe { OwnedHandle::from_raw(HANDLE(raw as *mut core::ffi::c_void)) } {
            Some(handle) => handle,
            None => panic!("null/invalid handle passed to OwnedHandle::from_raw_handle"),
        }
    }
}

impl IntoRawHandle for OwnedHandle {
    fn into_raw_handle(self) -> RawHandle {
        self.into_raw().0 as RawHandle
    }
}
