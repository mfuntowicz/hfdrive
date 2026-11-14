//! Single-provider-per-user ownership: a secured global mutex plus an
//! exclusive state-owner file lock.
//!
//! # Lease model
//!
//! One HF Drive provider may run for a given Windows user, across all of
//! that user's logon sessions. Two independent mechanisms enforce this:
//!
//! 1. A named mutex `Global\HFDrive.Provider.<user-SID>` whose DACL grants
//!    access to exactly the current user and SYSTEM. Acquisition never
//!    waits: a held mutex is a reported condition, not a blocking one.
//! 2. An exclusive byte-range lock on a reserved region of the state-owner
//!    file `<state-root>\provider.lock`, held for the lifetime of the lease
//!    and released automatically when the file handle closes (including on
//!    process exit).
//!
//! The state file also carries a small owner record (PID, logon session ID,
//! timestamp) in its *unlocked* first bytes. When the lease cannot be
//! acquired the record is read to distinguish the two failure modes:
//!
//! * [`OwnershipError::AlreadyRunning`] — a provider runs **in this logon
//!   session**; the caller should connect to it over IPC.
//! * [`OwnershipError::OtherSession`] — a provider runs in a **different
//!   logon session** of the same user; the caller must report
//!   `ProviderInOtherSession` and must not start a second writer.
//!
//! The owner record is diagnostic, not authority: the byte-range lock and
//! the mutex are what enforce single-writer ownership. A stale record left
//! by a crashed provider is replaced on the next successful acquisition.
//!
//! # Lease lifetime
//!
//! [`ProviderLease`] owns both OS resources. Dropping it (or process exit)
//! releases the mutex and the byte-range lock, allowing the next provider to
//! start. There is no explicit release API: a lease cannot be released
//! accidentally while the process keeps running. The mutex and lock are
//! kernel objects, so an abrupt process kill releases them too.

use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

use crate::error::OwnershipError;
use crate::ffi::acl;
use crate::ffi::file;
use crate::ffi::handle::OwnedHandle;
use crate::ffi::sid::OwnedSid;
use crate::ffi::token;

/// Default directory name under `%LOCALAPPDATA%` for HF Drive state.
pub const STATE_DIR_NAME: &str = "HFDrive";

/// File name of the state-owner record inside the state root.
pub const OWNER_FILE_NAME: &str = "provider.lock";

/// The state-root directory used when the caller does not supply one:
/// `%LOCALAPPDATA%\HFDrive`, creating it when absent.
///
/// Callers should normally pass the provider's own `%LOCALAPPDATA%\HFDrive`
/// root so credentials, database, and lease state share one protected tree.
pub fn default_state_root() -> Result<PathBuf, OwnershipError> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| OwnershipError::Win32 { code: 203 })?; // ERROR_ENVVAR_NOT_FOUND
    let root = base.join(STATE_DIR_NAME);
    std::fs::create_dir_all(&root).map_err(OwnershipError::Io)?;
    Ok(root)
}

/// Name of the per-user provider mutex for a user SID string.
pub fn mutex_name(user_sid: &str) -> String {
    format!(r"Global\HFDrive.Provider.{user_sid}")
}

/// Magic + layout of the owner record: 8 magic bytes, LE u32 PID,
/// LE u32 session ID, LE u64 unix timestamp (24 bytes total).
const OWNER_FILE_MAGIC: &[u8; 8] = b"HFDPID\0\0";
const OWNER_RECORD_LEN: usize = 24;

/// Summary of the process that currently holds (or last held) the provider
/// lease. Safe to log: PIDs and session IDs are not secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerInfo {
    /// PID of the recorded provider process.
    pub pid: u32,
    /// Logon session ID of that process.
    pub session_id: u32,
    /// Unix timestamp (seconds) the record was written.
    pub recorded_at: u64,
}

/// An acquired provider lease: per-user mutex + exclusive state file lock.
pub struct ProviderLease {
    mutex: OwnedHandle,
    mutex_acquired: bool,
    state_file: OwnedHandle,
    user_sid: String,
    session_id: u32,
    state_root: PathBuf,
}

impl ProviderLease {
    /// Attempt to acquire the provider lease for the current user.
    ///
    /// `state_root` is the provider state directory; `provider.lock` is
    /// created inside it when absent. The directory's DACL is restricted to
    /// the current user and SYSTEM before use.
    ///
    /// Fails with [`OwnershipError::AlreadyRunning`] or
    /// [`OwnershipError::OtherSession`] when another provider holds the
    /// lease in the same or a different session respectively.
    pub fn acquire(state_root: &Path) -> Result<ProviderLease, OwnershipError> {
        let user = token::current_process_user_sid().map_err(win32)?;
        let user_sid = user.to_string().ok_or(OwnershipError::Win32 { code: 1337 })?;
        Self::acquire_with_mutex_name(state_root, &mutex_name(&user_sid))
    }

    /// Acquire the lease using an explicit mutex name.
    ///
    /// Production callers use [`ProviderLease::acquire`]; tests use this
    /// entry point with a per-test `Local\` mutex name so they never touch
    /// the real per-user `Global\` provider mutex.
    pub fn acquire_with_mutex_name(
        state_root: &Path,
        mutex: &str,
    ) -> Result<ProviderLease, OwnershipError> {
        std::fs::create_dir_all(state_root).map_err(OwnershipError::Io)?;
        let user = token::current_process_user_sid().map_err(win32)?;
        let user_sid = user.to_string().ok_or(OwnershipError::Win32 { code: 1337 })?;
        let session_id = current_session_id()?;

        // 1. Named mutex, secured to user + SYSTEM. Acquisition never waits:
        //    a held mutex means a provider is running somewhere in this user
        //    context.
        let lock = match acquire_mutex(mutex, &user) {
            Ok(handle) => handle,
            Err(OwnershipError::AlreadyRunning) => {
                return Err(classify_running(state_root, session_id));
            }
            Err(e) => return Err(e),
        };

        // 2. Exclusive state-owner file lock (reserved range at offset 1024,
        //    so the owner record at offset 0 stays readable by peers).
        let state_path = state_root.join(OWNER_FILE_NAME);
        let state_file = file::open_state_file(&state_path).map_err(|e| OwnershipError::Io(
            std::io::Error::other(format!(
                "failed opening state-owner file (win32={})",
                crate::ffi::error_code(&e)
            )),
        ))?;
        if let Err(code) = file::try_lock_exclusive(state_file.as_win()) {
            let lease = ProviderLease {
                mutex: lock,
                mutex_acquired: true,
                state_file,
                user_sid,
                session_id,
                state_root: state_root.to_path_buf(),
            };
            let owner = lease.read_owner_record().ok();
            return Err(categorize_lock_failure(owner, session_id, code));
        }

        // Record who holds the lock, then keep both resources for our life.
        let mut lease = ProviderLease {
            mutex: lock,
            mutex_acquired: true,
            state_file,
            user_sid,
            session_id,
            state_root: state_root.to_path_buf(),
        };
        lease.write_owner_record()?;
        Ok(lease)
    }

    /// The user SID string this lease protects.
    pub fn user_sid(&self) -> &str {
        &self.user_sid
    }

    /// The logon session this lease was acquired in.
    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    /// The state directory containing `provider.lock`.
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    /// Overwrite the owner record with this process's identity.
    fn write_owner_record(&mut self) -> Result<(), OwnershipError> {
        use windows::Win32::Storage::FileSystem::{FILE_BEGIN, SetEndOfFile, SetFilePointerEx};
        let pid = std::process::id();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut record = Vec::with_capacity(OWNER_RECORD_LEN);
        record.extend_from_slice(OWNER_FILE_MAGIC);
        record.extend_from_slice(&pid.to_le_bytes());
        record.extend_from_slice(&self.session_id.to_le_bytes());
        record.extend_from_slice(&now.to_le_bytes());
        // SAFETY: handle is open read/write; seek to start, write, then
        // truncate so a longer stale record cannot linger.
        unsafe {
            SetFilePointerEx(self.state_file.as_win(), 0, None, FILE_BEGIN).map_err(win32)?;
        }
        file::write_all(self.state_file.as_win(), &record).map_err(win32)?;
        unsafe {
            SetEndOfFile(self.state_file.as_win()).map_err(win32)?;
        }
        file::flush(self.state_file.as_win()).map_err(win32)?;
        Ok(())
    }

    /// Read the owner record from the unlocked prefix of the state file.
    fn read_owner_record(&self) -> Result<OwnerInfo, OwnershipError> {
        read_owner_info(&self.state_file)
    }
}

impl Drop for ProviderLease {
    fn drop(&mut self) {
        if self.mutex_acquired {
            // SAFETY: the mutex is owned by this thread's acquisition.
            unsafe {
                let _ = ReleaseMutex(self.mutex.as_win());
            }
            self.mutex_acquired = false;
        }
        // `state_file` closes on drop, releasing the byte-range lock. The
        // owner record stays on disk: it is diagnostic, not authority.
    }
}

/// Non-mutating probe: does a provider currently hold the lease, and if so,
/// who? Used by clients to report accurate status without acquiring
/// anything. Returns `None` when the lease is free (or unrecorded).
pub fn probe(state_root: &Path) -> Result<Option<OwnerInfo>, OwnershipError> {
    let state_path = state_root.join(OWNER_FILE_NAME);
    if !state_path.exists() {
        return Ok(None);
    }
    let handle = file::open_state_file(&state_path).map_err(|e| OwnershipError::Io(
        std::io::Error::other(format!(
            "failed opening state-owner file (win32={})",
            crate::ffi::error_code(&e)
        )),
    ))?;
    match file::try_lock_exclusive(handle.as_win()) {
        Ok(()) => {
            // Lock succeeded: nobody holds the lease. Drop releases it.
            drop(handle);
            Ok(None)
        }
        Err(_) => {
            let info = read_owner_info(&handle)?;
            drop(handle);
            Ok(Some(info))
        }
    }
}

/// The state-owner file path for a state root.
pub fn owner_file_path(state_root: &Path) -> PathBuf {
    state_root.join(OWNER_FILE_NAME)
}

/// Decide between same-session and other-session failure when we already
/// know a provider is running but have not yet read the record.
fn classify_running(state_root: &Path, our_session: u32) -> OwnershipError {
    match probe(state_root) {
        Ok(Some(info)) if info.session_id != our_session => OwnershipError::OtherSession {
            session_id: info.session_id,
        },
        _ => OwnershipError::AlreadyRunning,
    }
}

/// Categorize a state-lock failure into same-session vs other-session.
fn categorize_lock_failure(
    owner: Option<OwnerInfo>,
    our_session: u32,
    code: u32,
) -> OwnershipError {
    match owner {
        Some(info) if info.session_id != our_session => OwnershipError::OtherSession {
            session_id: info.session_id,
        },
        Some(_) => OwnershipError::AlreadyRunning,
        None => {
            if code == crate::ffi::ERROR_LOCK_VIOLATION || code == crate::ffi::ERROR_BUSY {
                // Held by a process whose record we cannot read (e.g. an old
                // build): report same-session so the caller reconnects
                // rather than assuming a foreign session.
                OwnershipError::AlreadyRunning
            } else {
                OwnershipError::StateLockUnavailable { code }
            }
        }
    }
}

/// Create/open the secured per-user mutex and acquire it without waiting.
fn acquire_mutex(name: &str, user: &OwnedSid) -> Result<OwnedHandle, OwnershipError> {
    let user_copy = OwnedSid::copy_from(user.as_psid()).map_err(win32)?;
    let mut dacl = acl::SecuredDacl::user_and_system(user_copy, false).map_err(win32)?;
    let attrs = dacl.attributes();
    // SAFETY: `attrs` outlives the creation call; `wide` is a NUL-terminated
    // UTF-16 name (the projection has no `&str -> PCWSTR` Param impl, so the
    // wide conversion is explicit).
    let wide: Vec<u16> = std::ffi::OsStr::new(name)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let handle = unsafe {
        CreateMutexW(
            Some(&attrs as *const windows::Win32::Security::SECURITY_ATTRIBUTES),
            false,
            windows::core::PCWSTR(wide.as_ptr()),
        )
        .map_err(|_| OwnershipError::MutexUnavailable {
            code: crate::ffi::last_error_code(),
        })?
    };
    // SAFETY: `handle` is a valid, uniquely owned mutex handle returned by
    // `CreateMutexW`; ownership transfers to `OwnedHandle` exactly once.
    let mutex = unsafe { OwnedHandle::from_raw(handle) }
        .ok_or(OwnershipError::MutexUnavailable { code: 6 })?;
    // Acquire without waiting. WAIT_ABANDONED still transfers ownership.
    let wait = unsafe { WaitForSingleObject(mutex.as_win(), 0) };
    match wait {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(mutex),
        WAIT_TIMEOUT => Err(OwnershipError::AlreadyRunning),
        _ => Err(OwnershipError::MutexUnavailable {
            code: crate::ffi::last_error_code(),
        }),
    }
}

/// The current logon session ID (via the process token).
fn current_session_id() -> Result<u32, OwnershipError> {
    let token = token::current_process_token().map_err(win32)?;
    token::token_session_id(token.as_win()).map_err(win32)
}

/// Read the owner record from an open state file handle.
fn read_owner_info(handle: &OwnedHandle) -> Result<OwnerInfo, OwnershipError> {
    use windows::Win32::Storage::FileSystem::{FILE_BEGIN, SetFilePointerEx};
    // SAFETY: handle is open read/write; the record region is never locked.
    unsafe {
        SetFilePointerEx(handle.as_win(), 0, None, FILE_BEGIN).map_err(win32)?;
    }
    let bytes = file::read_up_to(handle.as_win(), OWNER_RECORD_LEN).map_err(win32)?;
    parse_owner_record(&bytes)
}

/// Parse a raw owner-record buffer.
fn parse_owner_record(bytes: &[u8]) -> Result<OwnerInfo, OwnershipError> {
    if bytes.len() < OWNER_RECORD_LEN || &bytes[..8] != OWNER_FILE_MAGIC {
        return Err(OwnershipError::Win32 { code: 13 }); // ERROR_INVALID_DATA
    }
    Ok(OwnerInfo {
        pid: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        session_id: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        recorded_at: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
    })
}

fn win32(e: windows::core::Error) -> OwnershipError {
    OwnershipError::Win32 {
        code: crate::ffi::error_code(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_record_roundtrip() {
        let mut record = Vec::new();
        record.extend_from_slice(OWNER_FILE_MAGIC);
        record.extend_from_slice(&1234u32.to_le_bytes());
        record.extend_from_slice(&7u32.to_le_bytes());
        record.extend_from_slice(&1_700_000_000u64.to_le_bytes());
        let info = parse_owner_record(&record).unwrap();
        assert_eq!(
            info,
            OwnerInfo {
                pid: 1234,
                session_id: 7,
                recorded_at: 1_700_000_000,
            }
        );
    }

    #[test]
    fn owner_record_rejects_garbage() {
        assert!(parse_owner_record(b"short").is_err());
        let mut record = Vec::new();
        record.extend_from_slice(b"NOTMAGIC");
        record.extend_from_slice(&[0u8; 16]);
        assert!(parse_owner_record(&record).is_err());
    }

    #[test]
    fn mutex_name_is_stable() {
        assert_eq!(
            mutex_name("S-1-5-21-1"),
            r"Global\HFDrive.Provider.S-1-5-21-1"
        );
    }

    #[test]
    fn classify_same_session() {
        let info = OwnerInfo {
            pid: 1,
            session_id: 7,
            recorded_at: 0,
        };
        let err = categorize_lock_failure(Some(info), 7, crate::ffi::ERROR_LOCK_VIOLATION);
        assert!(matches!(err, OwnershipError::AlreadyRunning));
    }

    #[test]
    fn classify_other_session() {
        let info = OwnerInfo {
            pid: 1,
            session_id: 7,
            recorded_at: 0,
        };
        let err = categorize_lock_failure(Some(info), 3, crate::ffi::ERROR_LOCK_VIOLATION);
        assert!(matches!(
            err,
            OwnershipError::OtherSession { session_id: 7 }
        ));
    }
}
