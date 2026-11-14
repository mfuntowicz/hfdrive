//! Named-pipe creation and peer identification.
//!
//! The pipe is duplex, byte-mode, overlapped, and rejects remote clients at
//! the kernel level. Its DACL grants connect rights to exactly the provider's
//! logon SID and SYSTEM, excluding other users and other logon sessions.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{SECURITY_ATTRIBUTES, RevertToSelf, TOKEN_DUPLICATE, TOKEN_QUERY};
use windows::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    ImpersonateNamedPipeClient, NAMED_PIPE_MODE, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};

use super::handle::OwnedHandle;
use super::token::TokenIdentity;

/// Pipe name for this user: `\\.\pipe\LOCAL\HFDrive.<user-SID>.v1`.
///
/// The `LOCAL\` segment names the pipe's scope explicitly; remote clients
/// are additionally rejected at the kernel level via
/// `PIPE_REJECT_REMOTE_CLIENTS`.
pub fn pipe_name(user_sid: &str) -> String {
    format!(r"\\.\pipe\LOCAL\HFDrive.{user_sid}.v1")
}

/// Create the duplex byte-mode server pipe with the restricted DACL.
///
/// `first_instance` sets `FILE_FLAG_FIRST_PIPE_INSTANCE` so a second
/// provider process cannot bind the same pipe name.
pub(crate) fn create_server(
    name: &str,
    security: &SECURITY_ATTRIBUTES,
    first_instance: bool,
) -> windows::core::Result<OwnedHandle> {
    let wide: Vec<u16> = OsStr::new(name).encode_wide().chain(Some(0)).collect();
    // `FILE_FLAG_OVERLAPPED` is required: the handle is handed to Tokio's
    // overlapped-I/O named-pipe wrapper (`NamedPipeServer::from_raw_handle`).
    let open_mode = if first_instance {
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED
    } else {
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED
    };
    let pipe_mode =
        NAMED_PIPE_MODE(PIPE_TYPE_BYTE.0 | PIPE_READMODE_BYTE.0 | PIPE_WAIT.0 | PIPE_REJECT_REMOTE_CLIENTS.0);
    // SAFETY: `wide` is NUL-terminated; `security` outlives the call; the
    // returned handle is owned by `OwnedHandle`.
    unsafe {
        let raw = CreateNamedPipeW(
            windows::core::PCWSTR(wide.as_ptr()),
            open_mode,
            pipe_mode,
            8,         // max instances
            64 * 1024, // out buffer
            64 * 1024, // in buffer
            0,         // default timeout
            Some(security as *const SECURITY_ATTRIBUTES),
        );
        if raw.is_invalid() || raw.0.is_null() {
            return Err(windows::core::Error::from_thread());
        }
        OwnedHandle::from_raw(raw).ok_or_else(windows::core::Error::from_thread)
    }
}

/// The PID of the client connected to this pipe instance.
pub(crate) fn client_pid(pipe: HANDLE) -> windows::core::Result<u32> {
    // SAFETY: `pipe` is a server pipe handle with a connected client.
    unsafe {
        let mut pid = 0u32;
        GetNamedPipeClientProcessId(pipe, &mut pid)?;
        if pid == 0 {
            return Err(windows::core::Error::from_thread());
        }
        Ok(pid)
    }
}

/// The PID of the server owning this client-side pipe handle.
#[allow(dead_code)]
pub(crate) fn server_pid(pipe: HANDLE) -> windows::core::Result<u32> {
    // SAFETY: `pipe` is a connected client pipe handle.
    unsafe {
        let mut pid = 0u32;
        GetNamedPipeServerProcessId(pipe, &mut pid)?;
        Ok(pid)
    }
}

/// A scoped impersonation of the pipe client, reverted on drop.
///
/// Used to read the client's *token logon SID* (the per-logon authorization
/// identifier), which is otherwise only visible from the client's own token.
/// The guard reverts to self even on panic.
pub(crate) struct ImpersonationGuard {
    active: bool,
}

impl ImpersonationGuard {
    /// Impersonate the connected client on this thread.
    pub(crate) fn impersonate_client(pipe: HANDLE) -> windows::core::Result<Self> {
        // SAFETY: paired with `RevertToSelf` in `Drop`.
        unsafe {
            ImpersonateNamedPipeClient(pipe)?;
            Ok(Self { active: true })
        }
    }

    /// Read the identity of the impersonated client token.
    pub(crate) fn identity(&self) -> windows::core::Result<TokenIdentity> {
        use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
        // SAFETY: the calling thread is impersonating the client. `false` is
        // deliberate: if impersonation were somehow not active this must
        // fail rather than silently return *our own* process token as the
        // peer's identity.
        unsafe {
            let mut token = HANDLE(std::ptr::null_mut());
            OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE, false, &mut token)?;
            let handle = OwnedHandle::from_raw(token).ok_or_else(windows::core::Error::from_thread)?;
            super::token::token_identity(handle.as_win())
        }
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: we successfully impersonated on this thread.
            unsafe {
                let _ = RevertToSelf();
            }
        }
    }
}
