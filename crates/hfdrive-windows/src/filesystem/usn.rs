//! Guarded USN journal catch-up and reset semantics.
//!
//! The USN journal is a hint stream with strict validity rules: a cursor
//! (journal id + USN) only answers while the journal identity is unchanged
//! and no records were lost below the cursor. Every failure mode that would
//! silently skip changes (journal id change, record loss, journal inactive,
//! USN wrap) surfaces as [`CatchUp::Reset`] and voids deletion evidence: the
//! provider must run a full metadata scan and rebuild its cursor, never
//! infer disappearance from the gap.

use std::fmt;

use crate::ffi::usn as raw;
use crate::ffi::volume as raw_volume;

use super::volume::VolumeIdentity;
use super::{FsError, FsResult};

/// A persisted position in one journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsnCursor {
    pub journal_id: u64,
    pub usn: i64,
}

/// Journal identity and bounds at query time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsnJournal {
    pub journal_id: u64,
    pub first_usn: i64,
    pub next_usn: i64,
    pub lowest_valid_usn: i64,
}

/// One observed change record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsnChange {
    /// 128-bit file identity (NTFS file reference in the low 8 bytes).
    pub file_id: [u8; 16],
    pub parent_id: [u8; 16],
    pub usn: i64,
    pub reason: u32,
    pub attributes: u32,
    pub name: String,
}

/// Why catch-up cannot continue from the stored cursor.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ResetReason {
    #[error("journal identity changed (was {previous}, now {current})")]
    JournalIdChanged { previous: u64, current: u64 },
    #[error("journal records at or below the cursor were lost (cursor {cursor}, lowest valid {lowest_valid})")]
    RecordsLost { cursor: i64, lowest_valid: i64 },
    #[error("the volume's USN journal is not active")]
    JournalNotActive,
    #[error("the USN sequence wrapped behind the cursor")]
    JournalWrapped,
}

/// Outcome of one bounded catch-up read.
#[derive(Clone, Debug)]
pub enum CatchUp {
    /// New cursor and the observed changes. `done` is true when no further
    /// records are currently journaled.
    Advanced {
        cursor: UsnCursor,
        changes: Vec<UsnChange>,
        done: bool,
    },
    /// The stored cursor is unusable; full rescan required and deletion
    /// evidence is void.
    Reset(ResetReason),
}

/// A volume handle with a validated journal, ready for catch-up reads.
pub struct UsnReader {
    volume: raw::VolumeHandle,
    journal: UsnJournal,
}

impl UsnReader {
    /// Open the volume backing `identity` (by its GUID path) and query the
    /// journal. Errors when the volume has no active journal; callers may
    /// fall back to directory enumeration and must then track USN evidence
    /// as unavailable (never as a wildcard match).
    pub fn open(identity: &VolumeIdentity) -> FsResult<Self> {
        let volume = raw::open_volume(&identity.guid_path)
            .map_err(|code| FsError::Win32 { operation: "CreateFileW(volume)", code })?;
        let data = raw::query_journal(&volume)
            .map_err(|code| FsError::Win32 { operation: "FSCTL_QUERY_USN_JOURNAL", code })?;
        Ok(UsnReader {
            volume,
            journal: UsnJournal {
                journal_id: data.journal_id,
                first_usn: data.first_usn,
                next_usn: data.next_usn,
                lowest_valid_usn: data.lowest_valid_usn,
            },
        })
    }

    pub fn journal(&self) -> UsnJournal {
        self.journal
    }

    /// Read changes from `from`, bounded by `max_bytes` of journal output.
    pub fn catch_up(&self, from: UsnCursor, max_bytes: usize) -> FsResult<CatchUp> {
        let current = raw::query_journal(&self.volume)
            .map_err(|code| FsError::Win32 { operation: "FSCTL_QUERY_USN_JOURNAL", code })?;
        if current.journal_id != from.journal_id {
            return Ok(CatchUp::Reset(ResetReason::JournalIdChanged {
                previous: from.journal_id,
                current: current.journal_id,
            }));
        }
        if from.usn < current.lowest_valid_usn {
            return Ok(CatchUp::Reset(ResetReason::RecordsLost {
                cursor: from.usn,
                lowest_valid: current.lowest_valid_usn,
            }));
        }
        let read = match raw::read_journal(&self.volume, from.usn, from.journal_id, max_bytes) {
            Ok(read) => read,
            Err(code) => return Ok(reset_for_error(code, from.usn, current.lowest_valid_usn)),
        };
        if read.next_usn < from.usn {
            return Ok(CatchUp::Reset(ResetReason::JournalWrapped));
        }
        let changes = read.records.into_iter().map(to_change).collect::<Vec<_>>();
        let done = changes.is_empty();
        Ok(CatchUp::Advanced {
            cursor: UsnCursor {
                journal_id: from.journal_id,
                usn: read.next_usn,
            },
            changes,
            done,
        })
    }

    /// Full MFT record enumeration starting at `start_frn` (bounded). Used
    /// for metadata completeness scans when the journal is available.
    pub fn enumerate(
        &self,
        start_frn: u64,
        max_bytes: usize,
    ) -> FsResult<(u64, Vec<UsnChange>)> {
        let read = raw::enum_records(
            &self.volume,
            start_frn,
            self.journal.first_usn,
            self.journal.next_usn,
            max_bytes,
        )
        .map_err(|code| FsError::Win32 { operation: "FSCTL_ENUM_USN_DATA", code })?;
        Ok((read.next_frn, read.records.into_iter().map(to_change).collect()))
    }
}

fn reset_for_error(code: u32, cursor: i64, lowest_valid: i64) -> CatchUp {
    // 1181 = ERROR_JOURNAL_ENTRY_DELETED, 1179 = ERROR_JOURNAL_NOT_ACTIVE,
    // 1178 = ERROR_JOURNAL_DELETE_IN_PROGRESS.
    let reason = match code {
        1181 => ResetReason::RecordsLost {
            cursor,
            lowest_valid,
        },
        1179 | 1178 => ResetReason::JournalNotActive,
        _ => ResetReason::JournalWrapped,
    };
    CatchUp::Reset(reason)
}

fn to_change(record: raw::RawUsnRecord) -> UsnChange {
    UsnChange {
        file_id: record.file_id,
        parent_id: record.parent_id,
        usn: record.usn,
        reason: record.reason,
        attributes: record.attributes,
        // Observation names are decoded leniently: they are hints for
        // reconciliation, never authoritative spellings.
        name: String::from_utf16_lossy(&record.name),
    }
}

impl fmt::Display for UsnCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.journal_id, self.usn)
    }
}

/// Current USN of an already-open file (evidence). `None` when the volume
/// has no usable journal — callers must treat this as "USN unknown", never
/// as "USN matches".
pub fn file_usn_of(path: &std::path::Path) -> FsResult<Option<i64>> {
    let handle = raw_volume::open_query(path, true)
        .map_err(|code| super::volume::classify_open(path, code))?;
    raw::file_usn(&handle).map_err(super::volume::op("FSCTL_READ_FILE_USN_DATA"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_formats_cursor() {
        let cursor = UsnCursor {
            journal_id: 7,
            usn: 42,
        };
        assert_eq!(cursor.to_string(), "7@42");
    }

    #[test]
    fn reset_reasons_are_distinct() {
        let a = ResetReason::JournalNotActive;
        let b = ResetReason::JournalWrapped;
        assert_ne!(a, b);
        assert!(a.to_string().contains("not active"));
    }
}
