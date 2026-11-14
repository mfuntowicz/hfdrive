//! `ReadDirectoryChangesW` adapter: one overlapped watch session per sync
//! root, with a completion event and a bounded batch buffer.
//!
//! The session never blocks a callback thread and never allocates per event:
//! the OS writes whole `FILE_NOTIFY_INFORMATION` chains into the fixed
//! buffer, which this module decodes into plain `RawNotify` records. A zero
//! byte completion means the directory changed faster than the buffer could
//! report and is surfaced as an overflow outcome — never silently dropped.

use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::path::Path;

use windows::Win32::Foundation::WAIT_OBJECT_0;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadDirectoryChangesW, FILE_ACTION, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED, FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE,
    FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_NOTIFY_CHANGE_CREATION, FILE_NOTIFY_CHANGE_DIR_NAME,
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE,
    FILE_NOTIFY_INFORMATION, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED, OVERLAPPED_0};
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

use super::handle::OwnedHandle;
use super::{error_code, last_error_code};

/// Buffer size for one `ReadDirectoryChangesW` batch (64 KiB is the classic
/// directory-watch buffer size; overflow is surfaced, never hidden).
const WATCH_BUFFER_BYTES: usize = 64 * 1024;

/// One decoded change notification: the raw `FILE_ACTION` code and the
/// relative wide name.
pub(crate) struct RawNotify {
    pub action: u32,
    pub name: Vec<u16>,
}

/// Outcome of one `next_batch` wait.
pub(crate) enum BatchOutcome {
    Events(Vec<RawNotify>),
    /// The directory changed faster than the buffer could report: deletion
    /// evidence is void until a rescan.
    Overflow,
    TimedOut,
}

/// An armed directory watch. Methods are `&mut self`: one outstanding
/// overlapped request at a time keeps ordering prompt and total memory
/// bounded.
pub(crate) struct WatchSession {
    dir: OwnedHandle,
    event: OwnedHandle,
    overlapped: Box<OVERLAPPED>,
    buffer: Vec<u8>,
    pending: bool,
}

impl WatchSession {
    /// Open `root` and arm the first notification request (whole subtree).
    pub(crate) fn start(root: &Path) -> Result<WatchSession, u32> {
        use std::os::windows::ffi::OsStrExt;
        let w: Vec<u16> = std::ffi::OsStr::new(root.as_os_str())
            .encode_wide()
            .chain(Some(0))
            .collect();
        // SAFETY: `w` is NUL-terminated; the handle is owned exactly once.
        let dir = unsafe {
            let raw = CreateFileW(
                windows::core::PCWSTR(w.as_ptr()),
                FILE_LIST_DIRECTORY.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(
                    FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OVERLAPPED.0,
                ),
                None,
            )
            .map_err(|e| error_code(&e))?;
            OwnedHandle::from_raw(raw).ok_or_else(last_error_code)?
        };
        // SAFETY: unnamed auto-reset event; owned exactly once.
        let event = unsafe {
            let raw = CreateEventW(None, false, false, windows::core::PCWSTR::null())
                .map_err(|e| error_code(&e))?;
            OwnedHandle::from_raw(raw).ok_or_else(last_error_code)?
        };
        let mut session = WatchSession {
            dir,
            event,
            overlapped: Box::new(unsafe { zeroed::<OVERLAPPED>() }),
            buffer: vec![0u8; WATCH_BUFFER_BYTES],
            pending: false,
        };
        session.overlapped.Anonymous = OVERLAPPED_0 {
            Pointer: std::ptr::null_mut(),
        };
        session.overlapped.hEvent = session.event.as_win();
        session.arm()?;
        Ok(session)
    }

    fn arm(&mut self) -> Result<(), u32> {
        let filter = FILE_NOTIFY_CHANGE(FILE_NOTIFY_CHANGE_FILE_NAME.0
            | FILE_NOTIFY_CHANGE_DIR_NAME.0
            | FILE_NOTIFY_CHANGE_ATTRIBUTES.0
            | FILE_NOTIFY_CHANGE_SIZE.0
            | FILE_NOTIFY_CHANGE_LAST_WRITE.0
            | FILE_NOTIFY_CHANGE_CREATION.0);
        // SAFETY: buffer and overlapped stay alive until completion; the
        // event in `self.overlapped` signals when the batch lands.
        unsafe {
            ReadDirectoryChangesW(
                super::volume::as_handle(&self.dir),
                self.buffer.as_mut_ptr() as *mut c_void,
                self.buffer.len() as u32,
                true,
                filter,
                None,
                Some(&mut *self.overlapped),
                None,
            )
            .map_err(|e| error_code(&e))?;
        }
        self.pending = true;
        Ok(())
    }

    /// Wait up to `timeout_ms` for the next batch.
    ///
    /// `Events` is a decoded change batch; `Overflow` is a buffer overflow —
    /// the caller must invalidate its deletion evidence and rescan;
    /// `TimedOut` means nothing happened within the timeout.
    pub(crate) fn next_batch(&mut self, timeout_ms: u32) -> Result<BatchOutcome, u32> {
        if !self.pending {
            self.arm()?;
        }
        // SAFETY: event handle is valid and owned by this session.
        let wait = unsafe {
            WaitForSingleObject(
                super::volume::as_handle(&self.event),
                timeout_ms,
            )
        };
        if wait != WAIT_OBJECT_0 {
            // Auto-reset event: timeout or failure leaves the request armed.
            return Ok(BatchOutcome::TimedOut);
        }
        let mut transferred = 0u32;
        // SAFETY: the overlapped request just completed via its event.
        unsafe {
            GetOverlappedResult(
                super::volume::as_handle(&self.dir),
                &*self.overlapped,
                &mut transferred,
                true,
            )
            .map_err(|e| {
                self.pending = false;
                error_code(&e)
            })?;
        }
        self.pending = false;
        if transferred == 0 {
            // Directory overflow: no records retained.
            self.arm()?;
            return Ok(BatchOutcome::Overflow);
        }
        let batch = decode_batch(&self.buffer[..transferred as usize]);
        self.arm()?;
        Ok(BatchOutcome::Events(batch))
    }

    /// Cancel the outstanding request (shutdown path). Safe to call twice.
    pub(crate) fn cancel(&mut self) {
        if self.pending {
            // SAFETY: cancels only this session's overlapped request.
            unsafe {
                let _ = CancelIoEx(
                    super::volume::as_handle(&self.dir),
                    Some(&*self.overlapped as *const OVERLAPPED),
                );
            }
            let mut transferred = 0u32;
            // SAFETY: draining the cancelled request keeps the buffer valid.
            unsafe {
                let _ = GetOverlappedResult(
                    super::volume::as_handle(&self.dir),
                    &*self.overlapped,
                    &mut transferred,
                    true,
                );
            }
            self.pending = false;
        }
    }
}

impl Drop for WatchSession {
    fn drop(&mut self) {
        self.cancel();
        // The `OwnedHandle`s close their kernel handles exactly once on drop.
    }
}

/// Decode a `FILE_NOTIFY_INFORMATION` chain. Malformed tails stop decoding.
fn decode_batch(buffer: &[u8]) -> Vec<RawNotify> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    let header = size_of::<FILE_NOTIFY_INFORMATION>();
    loop {
        if buffer.len() < offset + header {
            break;
        }
        // SAFETY: bounds checked; unaligned read of the generated struct.
        let info: FILE_NOTIFY_INFORMATION =
            unsafe { (buffer.as_ptr().add(offset) as *const FILE_NOTIFY_INFORMATION).read_unaligned() };
        let name_bytes = info.FileNameLength as usize;
        let name_offset = offset + header - size_of::<u16>();
        let name_end = name_offset.checked_add(name_bytes);
        let name = match name_end {
            Some(end) if end <= buffer.len() && name_bytes % 2 == 0 => buffer[name_offset..end]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect(),
            _ => break,
        };
        out.push(RawNotify {
            action: action_code(info.Action),
            name,
        });
        let step = info.NextEntryOffset as usize;
        if step == 0 {
            break;
        }
        if step < header || offset + step >= buffer.len() {
            break;
        }
        offset += step;
    }
    out
}

fn action_code(action: FILE_ACTION) -> u32 {
    action.0
}
