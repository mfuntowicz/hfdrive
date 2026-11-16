//! `ReadDirectoryChangesW` adapter: one overlapped watch session per sync
//! root, with a completion event and a bounded batch buffer.
//!
//! The OS writes whole `FILE_NOTIFY_INFORMATION` chains into the fixed
//! buffer, which this module decodes into plain `RawNotify` records; decoding
//! allocates only the per-batch record list and the per-name units. The buffer
//! and `OVERLAPPED` are heap-owned by the session, so their addresses stay
//! valid while the request is pending and through cancellation; the session is
//! created and lives entirely on its worker thread.
//!
//! Nothing is hidden: a zero-byte completion (`ERROR_NOTIFY_ENUM_DIR`) and any
//! malformed chain are surfaced as [`BatchOutcome::Overflow`], a genuine
//! completion failure is returned as an error, and only
//! `WaitForSingleObject`'s `WAIT_TIMEOUT` is reported as
//! [`BatchOutcome::TimedOut`].

use std::ffi::c_void;
use std::mem::{offset_of, zeroed};
use std::path::Path;

use windows::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadDirectoryChangesW, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OVERLAPPED, FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE, FILE_NOTIFY_CHANGE_ATTRIBUTES,
    FILE_NOTIFY_CHANGE_CREATION, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE, FILE_NOTIFY_INFORMATION,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED, OVERLAPPED_0};
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

use super::handle::OwnedHandle;
use super::{error_code, last_error_code};

/// Buffer size for one `ReadDirectoryChangesW` batch (64 KiB is the classic
/// directory-watch buffer size; overflow is surfaced, never hidden).
const WATCH_BUFFER_BYTES: usize = 64 * 1024;

/// Overflow completion for an overlapped `ReadDirectoryChangesW`: the
/// directory changed faster than the buffer could report. The request
/// completed successfully with zero bytes and must be re-armed; it is **not**
/// a watch failure.
const ERROR_NOTIFY_ENUM_DIR: u32 = 1022;

/// Layout of one `FILE_NOTIFY_INFORMATION` record, taken from the generated
/// projection struct with `offset_of!` (never restated by hand). A record ends
/// at `FileName` plus `FileNameLength` bytes, so the tail record of a batch
/// can be **shorter** than `size_of` (which counts the placeholder name unit
/// and tail padding): fields are read individually and never past the
/// transferred bytes.
const NOTIFY_NEXT_OFFSET: usize = offset_of!(FILE_NOTIFY_INFORMATION, NextEntryOffset);
const NOTIFY_ACTION_OFFSET: usize = offset_of!(FILE_NOTIFY_INFORMATION, Action);
const NOTIFY_LENGTH_OFFSET: usize = offset_of!(FILE_NOTIFY_INFORMATION, FileNameLength);
const NOTIFY_NAME_OFFSET: usize = offset_of!(FILE_NOTIFY_INFORMATION, FileName);

/// One decoded change notification: the raw `FILE_ACTION` code and the
/// root-relative wide name (`\`-separated components for subtree changes).
pub(crate) struct RawNotify {
    pub action: u32,
    pub name: Vec<u16>,
}

/// Outcome of one `next_batch` wait.
pub(crate) enum BatchOutcome {
    Events(Vec<RawNotify>),
    /// The directory changed faster than the buffer could report (or a chain
    /// was malformed): deletion evidence is void until a rescan.
    Overflow,
    /// Nothing happened within the timeout; the request stays armed.
    TimedOut,
}

/// An armed directory watch. Methods are `&mut self`: one outstanding
/// overlapped request at a time keeps ordering prompt and total memory
/// bounded.
pub(crate) struct WatchSession {
    dir: OwnedHandle,
    event: OwnedHandle,
    /// Heap-stable: the kernel holds this pointer while a request is pending,
    /// so it must not move with the session.
    overlapped: Box<OVERLAPPED>,
    /// Heap-stable for the same reason as `overlapped`.
    buffer: Vec<u8>,
    pending: bool,
}

impl WatchSession {
    /// Open `root` and arm the first notification request (whole subtree).
    ///
    /// `Ok` is returned **only** after the OS accepted the first overlapped
    /// request: an unarmed watch must surface as a start failure, never as a
    /// silently dead session.
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
    /// `Events` is a decoded batch; `Overflow` voids deletion evidence until
    /// rescan. Only `WAIT_TIMEOUT` is quiet; wait and completion failures stop
    /// the watch rather than silently retrying a failed handle.
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
        if wait == WAIT_OBJECT_0 {
            // The request completed; fall through to collecting it.
        } else if wait == WAIT_TIMEOUT {
            // Timeout: the request stays armed.
            return Ok(BatchOutcome::TimedOut);
        } else if wait == WAIT_FAILED {
            return Err(last_error_code());
        } else {
            // Abandoned/APC-type codes cannot happen for a plain event; the raw
            // code is surfaced rather than mistaken for a timeout.
            return Err(wait.0);
        }
        let mut transferred = 0u32;
        // SAFETY: the overlapped request just completed via its event; the
        // buffer and `overlapped` stay valid until the request is drained.
        let completed = unsafe {
            GetOverlappedResult(
                super::volume::as_handle(&self.dir),
                &*self.overlapped,
                &mut transferred,
                true,
            )
        };
        // Whatever the outcome, the request is complete now: the buffer and
        // `overlapped` may be re-armed.
        self.pending = false;
        if let Err(err) = completed {
            let code = error_code(&err);
            if code == ERROR_NOTIFY_ENUM_DIR && transferred == 0 {
                // Zero-byte completion = buffer overflow: the watch is healthy
                // but records were lost. Re-arm and surface the overflow.
                self.arm()?;
                return Ok(BatchOutcome::Overflow);
            }
            return Err(code);
        }
        if transferred == 0 {
            // Defensive: a successful zero-byte completion is still an
            // overflow, never an empty batch or a timeout.
            self.arm()?;
            return Ok(BatchOutcome::Overflow);
        }
        let (batch, complete) = decode_batch(&self.buffer[..transferred as usize]);
        self.arm()?;
        if !complete {
            // A malformed chain means records were lost: overflow semantics.
            return Ok(BatchOutcome::Overflow);
        }
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
            // SAFETY: draining the cancelled request keeps the buffer valid
            // until the kernel is done with it, before the handles close.
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

/// Decode a `FILE_NOTIFY_INFORMATION` chain.
///
/// Returns the decoded records plus whether the chain was complete (ended by a
/// `NextEntryOffset` of zero within the transferred bytes). A malformed tail
/// keeps the records decoded before it and reports `complete == false`, which
/// the caller surfaces as an overflow — a lost record must never be silently
/// ignored.
fn decode_batch(buffer: &[u8]) -> (Vec<RawNotify>, bool) {
    let mut out = Vec::new();
    let mut offset = 0usize;
    loop {
        let Some(header) = buffer
            .get(offset..)
            .filter(|rest| rest.len() >= NOTIFY_NAME_OFFSET)
        else {
            // Ran past the transferred bytes without a terminating record.
            return (out, false);
        };
        let action = read_u32(header, NOTIFY_ACTION_OFFSET);
        let name_bytes = read_u32(header, NOTIFY_LENGTH_OFFSET) as usize;
        let Some(name_end) = NOTIFY_NAME_OFFSET.checked_add(name_bytes) else {
            return (out, false);
        };
        if name_bytes % 2 != 0 || name_end > header.len() {
            return (out, false);
        }
        let name = header[NOTIFY_NAME_OFFSET..name_end]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        out.push(RawNotify { action, name });
        let step = read_u32(header, NOTIFY_NEXT_OFFSET) as usize;
        if step == 0 {
            return (out, true);
        }
        // A record must move strictly forward and stay inside the batch.
        if step < name_end || step > header.len() {
            return (out, false);
        }
        offset += step;
    }
}

/// Read one fixed field at its projection offset. `header` is always at least
/// [`NOTIFY_NAME_OFFSET`] bytes, which covers all three fixed fields.
fn read_u32(header: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(header[at..at + 4].try_into().expect("field inside record header"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode the documented 12-byte wire header independently of the decoder.
    /// Keeping fixture offsets separate catches flexible-array padding mistakes.
    fn record(action: u32, name: &str) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut bytes = vec![0u8; 12 + units.len() * 2];
        bytes[4..8].copy_from_slice(&action.to_le_bytes());
        bytes[8..12].copy_from_slice(&((units.len() * 2) as u32).to_le_bytes());
        for (slot, unit) in bytes[12..].chunks_exact_mut(2).zip(units) {
            slot.copy_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    /// Concatenate records with `NextEntryOffset` pointing at the next record
    /// (zero for the last, exactly as the OS terminates a chain).
    fn chain(mut records: Vec<Vec<u8>>) -> Vec<u8> {
        let mut out = Vec::new();
        let count = records.len();
        for (index, record) in records.iter_mut().enumerate() {
            let step = if index + 1 == count {
                0u32
            } else {
                let aligned = (record.len() + 3) & !3;
                record.resize(aligned, 0);
                aligned as u32
            };
            record[..4].copy_from_slice(&step.to_le_bytes());
            out.extend_from_slice(record);
        }
        out
    }

    fn names(records: &[RawNotify]) -> Vec<String> {
        records
            .iter()
            .map(|record| String::from_utf16(&record.name).expect("test names are valid UTF-16"))
            .collect()
    }

    #[test]
    fn record_layout_matches_the_flexible_name_field() {
        // The name begins immediately after `FileNameLength`, and a tail
        // record can be shorter than `size_of` (tail padding after the
        // placeholder name unit).
        assert_eq!(NOTIFY_NAME_OFFSET, NOTIFY_LENGTH_OFFSET + 4);
        assert!(std::mem::size_of::<FILE_NOTIFY_INFORMATION>() >= NOTIFY_NAME_OFFSET + 2);
    }

    #[test]
    fn decodes_the_single_record_batch_of_a_copied_file() {
        // Regression: `File.Copy` produces exactly one record; it must not
        // vanish at the end-of-batch boundary of the flexible `FileName` field.
        let batch = chain(vec![record(1, "hello.txt")]);
        let (records, complete) = decode_batch(&batch);
        assert!(complete, "a well-formed chain terminates its last record");
        assert_eq!(names(&records), ["hello.txt"]);
        assert_eq!(records[0].action, 1);
    }

    #[test]
    fn decodes_every_record_of_a_chain_with_subtree_names() {
        // Regression: each record's name starts at `FileName`'s offset — a
        // tail-padded offset would strip the first UTF-16 unit of every name.
        let batch = chain(vec![
            record(1, "sub\\file.bin"),
            record(3, "sub"),
            record(4, "old.txt"),
            record(5, "new.txt"),
        ]);
        let (records, complete) = decode_batch(&batch);
        assert!(complete);
        assert_eq!(names(&records), ["sub\\file.bin", "sub", "old.txt", "new.txt"]);
        assert_eq!(
            records.iter().map(|record| record.action).collect::<Vec<_>>(),
            [1, 3, 4, 5]
        );
    }

    #[test]
    fn short_tail_record_is_decoded() {
        // A one-unit name yields a 14-byte record, shorter than
        // `size_of::<FILE_NOTIFY_INFORMATION>()`; it must still decode.
        let batch = chain(vec![record(1, "a"), record(2, "b")]);
        let (records, complete) = decode_batch(&batch);
        assert!(complete);
        assert_eq!(names(&records), ["a", "b"]);
    }

    #[test]
    fn malformed_tail_keeps_prior_records_and_reports_loss() {
        // A record whose `NextEntryOffset` lands on a header cut after two
        // bytes: the good record survives, the tail is reported as incomplete
        // (the caller surfaces it as an overflow).
        let mut batch = record(1, "good.txt");
        let step = batch.len() as u32;
        batch[NOTIFY_NEXT_OFFSET..NOTIFY_NEXT_OFFSET + 4]
            .copy_from_slice(&step.to_le_bytes());
        batch.extend_from_slice(&[0, 0]);
        let (records, complete) = decode_batch(&batch);
        assert!(!complete);
        assert_eq!(names(&records), ["good.txt"]);

        // A name length that runs past the batch is malformed too.
        let mut lying = record(3, "xy");
        lying[NOTIFY_LENGTH_OFFSET..NOTIFY_LENGTH_OFFSET + 4]
            .copy_from_slice(&8u32.to_le_bytes()); // claims 4 units, carries 2
        let batch = chain(vec![lying]);
        let (records, complete) = decode_batch(&batch);
        assert!(!complete);
        assert!(records.is_empty());
    }
}
