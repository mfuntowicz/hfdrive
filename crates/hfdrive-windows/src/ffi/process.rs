//! Process inspection used to authenticate IPC peers.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::TOKEN_QUERY;
use windows::Win32::System::Threading::{
    GetProcessId, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::handle::OwnedHandle;
use super::token::TokenIdentity;

/// A handle to a peer process, opened for identity queries only.
pub(crate) struct PeerProcess {
    handle: OwnedHandle,
    pid: u32,
}

impl PeerProcess {
    /// Open the process by PID with the minimum rights needed for identity
    /// queries (`PROCESS_QUERY_LIMITED_INFORMATION` + `TOKEN_QUERY`).
    pub(crate) fn open(pid: u32) -> windows::core::Result<Self> {
        // SAFETY: `OpenProcess` with limited query rights; the returned
        // handle is owned by `OwnedHandle`.
        unsafe {
            let raw = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?;
            let handle = OwnedHandle::from_raw(raw).ok_or_else(windows::core::Error::from_thread)?;
            let verified_pid = GetProcessId(handle.as_win());
            if verified_pid != pid {
                return Err(windows::core::Error::from_thread());
            }
            Ok(Self { handle, pid })
        }
    }

    /// The PID this handle was opened for.
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    /// Open the peer's process token for identity queries.
    pub(crate) fn token(&self) -> windows::core::Result<OwnedHandle> {
        // SAFETY: `self.handle` is an open process handle.
        unsafe {
            let mut token = HANDLE(std::ptr::null_mut());
            OpenProcessToken(self.handle.as_win(), TOKEN_QUERY, &mut token)?;
            OwnedHandle::from_raw(token).ok_or_else(windows::core::Error::from_thread)
        }
    }

    /// Identity facts of the peer's process token.
    pub(crate) fn identity(&self) -> windows::core::Result<TokenIdentity> {
        let token = self.token()?;
        super::token::token_identity(token.as_win())
    }

    /// Full Win32 image path of the peer process (e.g.
    /// `C:\...\hfdrive.exe`). Case is preserved by the OS.
    pub(crate) fn image_path(&self) -> windows::core::Result<String> {
        // SAFETY: single call into a buffer sized for the documented maximum
        // extended Win32 path (32767 UTF-16 units including the NUL).
        unsafe {
            let mut buf = vec![0u16; 32768];
            let mut len = buf.len() as u32;
            QueryFullProcessImageNameW(
                self.handle.as_win(),
                PROCESS_NAME_WIN32,
                windows::core::PWSTR(buf.as_mut_ptr()),
                &mut len,
            )?;
            Ok(String::from_utf16_lossy(&buf[..len as usize]))
        }
    }

    /// Borrow the underlying process handle (for package queries).
    pub(crate) fn handle(&self) -> HANDLE {
        self.handle.as_win()
    }
}
