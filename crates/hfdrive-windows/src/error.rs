//! Structured, non-secret error types for the Windows adapter layer.
//!
//! Every error variant is safe to log, persist in diagnostics, and display:
//! none carry secret bytes (token material, protected plaintext, or DPAPI
//! payloads). OS failures are reported with their Win32 error code so
//! integration code can make retry/no-retry decisions without string matching.

use std::io;

/// Error type for [`crate::credentials`].
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// The requested record name is not a validated record name (invalid
    /// characters, reserved components, traversal attempts, or a non-plain
    /// file name).
    #[error("invalid credential record name")]
    InvalidRecordName,
    /// The record exists but does not parse as a protected record envelope,
    /// or its self-describing header does not match the expected format.
    #[error("credential record is corrupt or in an unsupported format")]
    CorruptRecord,
    /// The requested credential record does not exist.
    #[error("credential record not found")]
    NotFound,
    /// DPAPI protection failed. `code` is the Win32 error code when known.
    #[error("DPAPI protect failed (win32={code})")]
    ProtectFailed { code: u32 },
    /// DPAPI unprotection failed. Ciphertext bound to a different user,
    /// different entropy, or tampered ciphertext ends here. `code` is the
    /// Win32 error code when known.
    #[error("DPAPI unprotect failed (win32={code})")]
    UnprotectFailed { code: u32 },
    /// A filesystem operation on the credential store failed.
    #[error("credential store io error: {0}")]
    Io(#[from] io::Error),
}

/// Error type for [`crate::ownership`].
#[derive(Debug, thiserror::Error)]
pub enum OwnershipError {
    /// Another HF Drive provider for this Windows user already holds the
    /// lease **in this session**. Connecting to it is the correct action.
    #[error("another HF Drive provider holds the lease in this session")]
    AlreadyRunning,
    /// An HF Drive provider for this Windows user is running, but in a
    /// different logon session. Starting a second writer is forbidden; the
    /// caller must report `ProviderInOtherSession`.
    #[error("an HF Drive provider is running in a different logon session")]
    OtherSession { session_id: u32 },
    /// The user-global mutex could not be created or its security descriptor
    /// could not be set to user/SYSTEM-only.
    #[error("failed to create secured provider mutex (win32={code})")]
    MutexUnavailable { code: u32 },
    /// The exclusive state-owner file lock could not be acquired. `code`
    /// is `ERROR_LOCK_VIOLATION`/`ERROR_BUSY` when the file is already locked
    /// by another process.
    #[error("failed to acquire state-owner file lock (win32={code})")]
    StateLockUnavailable { code: u32 },
    /// A Windows API call failed.
    #[error("windows api failure in ownership (win32={code})")]
    Win32 { code: u32 },
    /// A filesystem operation on the lease/state directory failed.
    #[error("ownership io error: {0}")]
    Io(#[from] io::Error),
}

/// Error type for [`crate::ipc`].
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// The peer token's user SID differs from the local user's SID.
    #[error("peer user SID does not match the current user")]
    ForeignUser,
    /// The peer runs in a different logon session.
    #[error("peer logon session does not match the current session (peer session {peer_session_id})")]
    ForeignSession { peer_session_id: u32 },
    /// The peer's token logon SID (the credential that identifies an
    /// interactive logon) does not match ours.
    #[error("peer logon SID does not match the current logon SID")]
    ForeignLogonSid,
    /// The peer's integrity level is below the configured minimum.
    #[error("peer integrity level {peer_rid} is below the required minimum {min_rid}")]
    InsufficientIntegrity { peer_rid: u32, min_rid: u32 },
    /// The peer is packaged but not in the expected package family, or the
    /// expected package is not installed.
    #[error("peer package identity does not match the expected HF Drive package")]
    PackageMismatch,
    /// The peer process could not be opened/inspected.
    #[error("peer process {pid} could not be opened (win32={code})")]
    PeerUnreachable { pid: u32, code: u32 },
    /// The peer's process image does not match the expected executable.
    #[error("peer image does not match the expected executable")]
    ImageMismatch,
    /// Development image allowlisting is enabled (Debug builds only) and the
    /// peer's canonical image path is not one of the exact expected build
    /// outputs.
    #[error("peer image is not an allowlisted development build output")]
    DevImageNotAllowed,
    /// The pipe client could not find the provider pipe or the provider
    /// rejected the connection.
    #[error("provider pipe unavailable or connection refused (win32={code})")]
    PipeUnavailable { code: u32 },
    /// Handshake or framing precondition failed (for example the connection
    /// was closed before the server finished peer authentication).
    #[error("connection closed during peer authentication")]
    ClosedDuringAuthentication,
    /// A Windows API call failed.
    #[error("windows api failure in ipc (win32={code})")]
    Win32 { code: u32 },
    /// An I/O error on the pipe stream.
    #[error("pipe io error: {0}")]
    Io(#[from] io::Error),
}
