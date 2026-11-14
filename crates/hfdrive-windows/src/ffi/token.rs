//! Token queries: user SID, logon SID, integrity level, and logon session.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    GetTokenInformation, SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY, TOKEN_USER, TokenGroups, TokenIntegrityLevel, TokenSessionId, TokenUser,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::handle::OwnedHandle;
use super::sid::{OwnedSid, find_logon_sid, sid_copy, MIN_INTEGRITY_RID};

/// The identity facts gathered from a Windows access token.
///
/// These are *identity* facts. They are used to refuse foreign users,
/// sessions, and integrity levels; they never grant access by themselves.
#[derive(Debug)]
pub(crate) struct TokenIdentity {
    /// The token's user SID.
    pub(crate) user_sid: OwnedSid,
    /// The token's logon SID (present for interactive logons).
    pub(crate) logon_sid: Option<OwnedSid>,
    /// The RID of the token's integrity-level SID (e.g. 8192 = medium).
    pub(crate) integrity_rid: u32,
    /// The logon session ID the token belongs to (`TokenSessionId`).
    pub(crate) session_id: u32,
}

impl TokenIdentity {
    /// Whether this token runs at or above the minimum accepted integrity.
    pub(crate) fn integrity_ok(&self, min_rid: u32) -> bool {
        self.integrity_rid >= min_rid
    }
}

/// Default policy: refuse peers below medium integrity.
pub(crate) const DEFAULT_MIN_INTEGRITY_RID: u32 = MIN_INTEGRITY_RID;

/// Open the current process token with `TOKEN_QUERY`.
pub(crate) fn current_process_token() -> windows::core::Result<OwnedHandle> {
    // SAFETY: `GetCurrentProcess` returns a pseudo handle that stays valid.
    unsafe {
        let mut raw = HANDLE(std::ptr::null_mut());
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw)?;
        OwnedHandle::from_raw(raw).ok_or_else(windows::core::Error::from_thread)
    }
}

/// The current process token's user SID.
pub(crate) fn current_process_user_sid() -> windows::core::Result<OwnedSid> {
    let token = current_process_token()?;
    token_user_sid(token.as_win())
}

/// Query the identity facts of a token.
pub(crate) fn token_identity(token: HANDLE) -> windows::core::Result<TokenIdentity> {
    let user_sid = token_user_sid(token)?;
    let logon_sid = token_logon_sid(token);
    let integrity_rid = token_integrity_rid(token)?;
    let session_id = token_session_id(token)?;
    Ok(TokenIdentity {
        user_sid,
        logon_sid,
        integrity_rid,
        session_id,
    })
}

/// The user SID carried by a token.
pub(crate) fn token_user_sid(token: HANDLE) -> windows::core::Result<OwnedSid> {
    let buf = query_token_info(token, TokenUser)?;
    // SAFETY: `query_token_info` returns at least `size_of::<TOKEN_USER>()`
    // bytes aligned for the structure.
    unsafe {
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        sid_copy(user.User.Sid).ok_or_else(windows::core::Error::from_thread)
    }
}

/// The logon SID of a token's group list, if the token has one.
pub(crate) fn token_logon_sid(token: HANDLE) -> Option<OwnedSid> {
    let buf = query_token_info(token, TokenGroups).ok()?;
    // SAFETY: buffer holds a `TOKEN_GROUPS` header plus `GroupCount` entries.
    unsafe {
        let groups = &*(buf.as_ptr() as *const TOKEN_GROUPS);
        let count = groups.GroupCount as usize;
        if count == 0 {
            return None;
        }
        let entries = core::slice::from_raw_parts(groups.Groups.as_ptr() as *const SID_AND_ATTRIBUTES, count);
        find_logon_sid(entries)
    }
}

/// The RID of the token's mandatory integrity-level SID.
pub(crate) fn token_integrity_rid(token: HANDLE) -> windows::core::Result<u32> {
    let buf = query_token_info(token, TokenIntegrityLevel)?;
    // SAFETY: buffer holds a `TOKEN_MANDATORY_LABEL`.
    unsafe {
        let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let sid = sid_copy(label.Label.Sid).ok_or_else(windows::core::Error::from_thread)?;
        sid.last_rid().ok_or_else(windows::core::Error::from_thread)
    }
}

/// The token's logon session ID.
pub(crate) fn token_session_id(token: HANDLE) -> windows::core::Result<u32> {
    let buf = query_token_info(token, TokenSessionId)?;
    if buf.len() < core::mem::size_of::<u32>() {
        return Err(windows::core::Error::from_thread());
    }
    let mut session = [0u8; 4];
    session.copy_from_slice(&buf[..4]);
    Ok(u32::from_le_bytes(session))
}

/// Generic `GetTokenInformation` query returning the raw buffer.
fn query_token_info(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> windows::core::Result<Vec<u8>> {
    // SAFETY: standard two-call sizing; `token` is an open query token.
    unsafe {
        let mut needed = 0u32;
        let _ = GetTokenInformation(token, class, None, 0, &mut needed);
        if needed == 0 {
            return Err(windows::core::Error::from_thread());
        }
        let mut buf = vec![0u8; needed as usize];
        GetTokenInformation(
            token,
            class,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            needed,
            &mut needed,
        )?;
        buf.truncate(needed as usize);
        Ok(buf)
    }
}
