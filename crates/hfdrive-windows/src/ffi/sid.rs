//! SID helpers: allocation, comparison, formatting, and well-known SIDs.

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    CopySid, CreateWellKnownSid, GetLengthSid, GetSidSubAuthority, GetSidSubAuthorityCount, IsValidSid,
    PSID, SID_AND_ATTRIBUTES, WELL_KNOWN_SID_TYPE,
};
use windows::Win32::System::Memory::{LMEM_FIXED, LocalAlloc};
use windows::Win32::System::SystemServices::{SE_GROUP_LOGON_ID, SECURITY_MANDATORY_MEDIUM_RID};

/// An owned SID buffer (freed with `LocalFree` on drop).
pub(crate) struct OwnedSid(PSID);

// SAFETY: the SID buffer is uniquely owned; SIDs are immutable byte values.
unsafe impl Send for OwnedSid {}

impl OwnedSid {
    /// Allocate a buffer sized for `src` and copy the SID value into it.
    pub(crate) fn copy_from(src: PSID) -> windows::core::Result<Self> {
        // SAFETY: `src` must be a valid SID (checked by callers).
        unsafe {
            let len = GetLengthSid(src);
            if len == 0 {
                return Err(windows::core::Error::from_thread());
            }
            let buf = alloc_local(len)?;
            match CopySid(len, PSID(buf.cast()), src) {
                Ok(()) => Ok(Self(PSID(buf.cast()))),
                Err(e) => {
                    free_local(buf);
                    Err(e)
                }
            }
        }
    }

    /// Build a well-known SID of the given type.
    pub(crate) fn well_known(kind: WELL_KNOWN_SID_TYPE) -> windows::core::Result<Self> {
        // SAFETY: `SECURITY_MAX_SID_SIZE` (68) bounds every well-known SID.
        unsafe {
            let mut len = 68u32;
            let buf = alloc_local(len)?;
            match CreateWellKnownSid(kind, None, Some(PSID(buf.cast())), &mut len) {
                Ok(()) => Ok(Self(PSID(buf.cast()))),
                Err(e) => {
                    free_local(buf);
                    Err(e)
                }
            }
        }
    }

    /// Borrow as a raw `PSID`.
    pub(crate) fn as_psid(&self) -> PSID {
        self.0
    }

    /// Byte length of the SID value.
    pub(crate) fn len(&self) -> u32 {
        // SAFETY: `self.0` holds a valid SID produced by this module.
        unsafe { GetLengthSid(self.0) }
    }

    /// The low 32-bit RID of the SID (used for integrity-level SIDs).
    pub(crate) fn last_rid(&self) -> Option<u32> {
        // SAFETY: `self.0` is a valid SID.
        unsafe {
            if !IsValidSid(self.0).as_bool() {
                return None;
            }
            let count = *GetSidSubAuthorityCount(self.0);
            if count == 0 {
                return None;
            }
            GetSidSubAuthority(self.0, u32::from(count) - 1).as_ref().copied()
        }
    }

    /// String form of the SID (e.g. `S-1-5-21-...`). Safe to log: SIDs
    /// identify accounts, they are not secrets.
    pub(crate) fn to_string(&self) -> Option<String> {
        // SAFETY: `self.0` is valid; out pointer is freed with `LocalFree`.
        unsafe {
            let mut ptr = windows::core::PWSTR::null();
            if ConvertSidToStringSidW(self.0, &mut ptr).is_err() {
                return None;
            }
            let text = if ptr.is_null() {
                None
            } else {
                ptr.to_string().ok()
            };
            free_local(ptr.0 as *mut u8);
            text
        }
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        free_local(self.0.0 as *mut u8);
    }
}

/// SIDs are account identifiers (not secrets); the debug form prints the
/// string SID when available, otherwise just the length.
impl core::fmt::Debug for OwnedSid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.to_string() {
            Some(text) => f.write_str(&text),
            None => write!(f, "OwnedSid(<unprintable, {} bytes>)", self.len()),
        }
    }
}

/// Validate that a raw pointer really is a SID before exposing it.
pub(crate) fn is_valid_sid(psid: PSID) -> bool {
    // SAFETY: caller passes the PSID it received from a token query.
    unsafe { !psid.0.is_null() && IsValidSid(psid).as_bool() }
}

/// Find the logon SID (the per-logon authorization identifier) inside a
/// token's group list. Returns `None` when the token has none (e.g. some
/// service contexts).
pub(crate) fn find_logon_sid(groups: &[SID_AND_ATTRIBUTES]) -> Option<OwnedSid> {
    let logon_flag = SE_GROUP_LOGON_ID as u32;
    for group in groups {
        if group.Attributes & logon_flag == logon_flag && is_valid_sid(group.Sid) {
            if let Ok(owned) = OwnedSid::copy_from(group.Sid) {
                return Some(owned);
            }
        }
    }
    None
}

/// Copy a SID out of a raw pointer (validated).
pub(crate) fn sid_copy(src: PSID) -> Option<OwnedSid> {
    if !is_valid_sid(src) {
        return None;
    }
    OwnedSid::copy_from(src).ok()
}

/// The default minimum integrity level accepted from a peer: medium (an
/// ordinary interactive user process). Peers below this are refused.
pub(crate) const MIN_INTEGRITY_RID: u32 = SECURITY_MANDATORY_MEDIUM_RID as u32;

fn alloc_local(len: u32) -> windows::core::Result<*mut u8> {
    // SAFETY: `LocalAlloc`/`LMEM_FIXED` returns a raw pointer freed via
    // `LocalFree` (see `OwnedSid::drop` and `free_local`).
    unsafe {
        let hlocal = LocalAlloc(LMEM_FIXED, len as usize)?;
        let ptr = hlocal.0.cast::<u8>();
        std::ptr::write_bytes(ptr, 0, len as usize);
        Ok(ptr)
    }
}

fn free_local(ptr: *mut u8) {
    if !ptr.is_null() {
        // SAFETY: `ptr` was produced by `alloc_local` (or a LocalAlloc out
        // pointer from the same process).
        unsafe {
            let _ = LocalFree(Some(HLOCAL(ptr.cast())));
        }
    }
}
