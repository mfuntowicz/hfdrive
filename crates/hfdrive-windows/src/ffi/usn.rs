//! USN journal adapters: volume handles, journal queries, change read-back
//! and per-file USN evidence.
//!
//! Record parsing is done here (the layouts are generated projection
//! structs); safe modules only see the plain `RawUsnRecord` shape.

use std::ffi::c_void;
use std::mem::{size_of, zeroed};

use windows::Win32::Foundation::GENERIC_READ;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{
    MFT_ENUM_DATA_V0, READ_USN_JOURNAL_DATA_V0, USN_JOURNAL_DATA_V0, USN_RECORD_COMMON_HEADER,
    USN_RECORD_V2, USN_RECORD_V3, FSCTL_ENUM_USN_DATA, FSCTL_READ_FILE_USN_DATA,
    FSCTL_READ_USN_JOURNAL, FSCTL_QUERY_USN_JOURNAL,
};

use super::handle::OwnedHandle;
use super::{error_code, last_error_code};

/// `ERROR_INVALID_PARAMETER` (87).
const ERROR_INVALID_PARAMETER: u32 = 87;

/// `USN_REASON_ANY` (ntioapi.h): the journal reason mask selecting all
/// change reasons. The projection does not export this constant.
pub(crate) const USN_REASON_ANY: u32 = u32::MAX;

/// A handle on a volume, opened for USN journal queries.
pub(crate) struct VolumeHandle(OwnedHandle);

/// Open a volume by its GUID path (`\\?\Volume{...}\`) for USN access.
pub(crate) fn open_volume(guid_path: &str) -> Result<VolumeHandle, u32> {
    let w: Vec<u16> = guid_path.encode_utf16().chain(Some(0)).collect();
    // SAFETY: `w` is NUL-terminated; the returned handle is owned exactly
    // once by `OwnedHandle`.
    unsafe {
        let raw = CreateFileW(
            windows::core::PCWSTR(w.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_BACKUP_SEMANTICS.0),
            None,
        )
        .map_err(|e| error_code(&e))?;
        OwnedHandle::from_raw(raw)
            .map(VolumeHandle)
            .ok_or_else(last_error_code)
    }
}

/// Journal identity and USN range bounds.
pub(crate) struct JournalData {
    pub journal_id: u64,
    pub first_usn: i64,
    pub next_usn: i64,
    pub lowest_valid_usn: i64,
}

pub(crate) fn query_journal(volume: &VolumeHandle) -> Result<JournalData, u32> {
    let mut data: USN_JOURNAL_DATA_V0 = unsafe { zeroed() };
    let mut returned = 0u32;
    // SAFETY: `data` is a valid output buffer of its exact size.
    unsafe {
        DeviceIoControl(
            super::volume::as_handle(&volume.0),
            FSCTL_QUERY_USN_JOURNAL,
            None,
            0,
            Some(&mut data as *mut USN_JOURNAL_DATA_V0 as *mut c_void),
            size_of::<USN_JOURNAL_DATA_V0>() as u32,
            Some(&mut returned),
            None,
        )
        .map_err(|e| error_code(&e))?;
    }
    // The struct is `packed(1)`; copy fields by value.
    Ok(JournalData {
        journal_id: data.UsnJournalID,
        first_usn: data.FirstUsn,
        next_usn: data.NextUsn,
        lowest_valid_usn: data.LowestValidUsn,
    })
}

/// One decoded USN change record. 128-bit identifiers: NTFS 64-bit file
/// reference numbers are zero-extended exactly the way `FILE_ID_128` maps
/// them (low 8 bytes little-endian, upper 8 bytes zero).
pub(crate) struct RawUsnRecord {
    pub file_id: [u8; 16],
    pub parent_id: [u8; 16],
    pub usn: i64,
    pub reason: u32,
    pub attributes: u32,
    pub name: Vec<u16>,
}

/// Result of a bounded journal read.
pub(crate) struct JournalRead {
    pub next_usn: i64,
    pub records: Vec<RawUsnRecord>,
}

/// Read journal records from `start_usn` (bounded by `max_bytes` of output).
/// Does not wait (`BytesToWaitFor = 0`); returns promptly with whatever is
/// already journaled.
pub(crate) fn read_journal(
    volume: &VolumeHandle,
    start_usn: i64,
    journal_id: u64,
    max_bytes: usize,
) -> Result<JournalRead, u32> {
    let input = READ_USN_JOURNAL_DATA_V0 {
        StartUsn: start_usn,
        ReasonMask: USN_REASON_ANY,
        ReturnOnlyOnClose: 0,
        Timeout: 0,
        BytesToWaitFor: 0,
        UsnJournalID: journal_id,
    };
    let mut buffer = vec![0u8; max_bytes.max(size_of::<i64>())];
    let mut returned = 0u32;
    // SAFETY: `input` and `buffer` are valid for their declared sizes.
    unsafe {
        DeviceIoControl(
            super::volume::as_handle(&volume.0),
            FSCTL_READ_USN_JOURNAL,
            Some(&input as *const READ_USN_JOURNAL_DATA_V0 as *const c_void),
            size_of::<READ_USN_JOURNAL_DATA_V0>() as u32,
            Some(buffer.as_mut_ptr() as *mut c_void),
            buffer.len() as u32,
            Some(&mut returned),
            None,
        )
        .map_err(|e| error_code(&e))?;
    }
    let returned = returned as usize;
    if returned < size_of::<i64>() {
        return Err(ERROR_INVALID_PARAMETER);
    }
    // SAFETY: the first 8 output bytes are the next USN (documented shape).
    let next_usn: i64 = unsafe { (buffer.as_ptr() as *const i64).read_unaligned() };
    Ok(JournalRead {
        next_usn,
        records: parse_records(&buffer[..returned], size_of::<i64>()),
    })
}

/// Result of a bounded MFT enumeration.
pub(crate) struct EnumRead {
    pub next_frn: u64,
    pub records: Vec<RawUsnRecord>,
}

/// Enumerate USN records for every file with `file reference >= start_frn`
/// (bounded by `max_bytes` of output). Used for full metadata enumeration.
pub(crate) fn enum_records(
    volume: &VolumeHandle,
    start_frn: u64,
    low_usn: i64,
    high_usn: i64,
    max_bytes: usize,
) -> Result<EnumRead, u32> {
    let input = MFT_ENUM_DATA_V0 {
        StartFileReferenceNumber: start_frn,
        LowUsn: low_usn,
        HighUsn: high_usn,
    };
    let mut buffer = vec![0u8; max_bytes.max(size_of::<u64>())];
    let mut returned = 0u32;
    // SAFETY: `input` and `buffer` are valid for their declared sizes.
    unsafe {
        DeviceIoControl(
            super::volume::as_handle(&volume.0),
            FSCTL_ENUM_USN_DATA,
            Some(&input as *const MFT_ENUM_DATA_V0 as *const c_void),
            size_of::<MFT_ENUM_DATA_V0>() as u32,
            Some(buffer.as_mut_ptr() as *mut c_void),
            buffer.len() as u32,
            Some(&mut returned),
            None,
        )
        .map_err(|e| error_code(&e))?;
    }
    let returned = returned as usize;
    if returned < size_of::<u64>() {
        return Err(ERROR_INVALID_PARAMETER);
    }
    // SAFETY: the first 8 output bytes are the next start FRN.
    let next_frn: u64 = unsafe { (buffer.as_ptr() as *const u64).read_unaligned() };
    Ok(EnumRead {
        next_frn,
        records: parse_records(&buffer[..returned], size_of::<u64>()),
    })
}

/// Current USN of an open file as evidence (`FSCTL_READ_FILE_USN_DATA`).
/// `Ok(None)` when the volume has no usable USN journal for this file.
pub(crate) fn file_usn(handle: &OwnedHandle) -> Result<Option<i64>, u32> {
    let mut buffer = vec![0u8; 512];
    let mut returned = 0u32;
    // SAFETY: `buffer` is a valid output buffer.
    let outcome = unsafe {
        DeviceIoControl(
            super::volume::as_handle(handle),
            FSCTL_READ_FILE_USN_DATA,
            None,
            0,
            Some(buffer.as_mut_ptr() as *mut c_void),
            buffer.len() as u32,
            Some(&mut returned),
            None,
        )
    };
    match outcome {
        Ok(()) => {}
        Err(e) => {
            let code = error_code(&e);
            // No journal / not supported on this volume: evidence is simply
            // absent, which is honest and never treated as a USN match.
            // 1 = ERROR_INVALID_FUNCTION, 50 = ERROR_NOT_SUPPORTED,
            // 87 = ERROR_INVALID_PARAMETER, 1179 = ERROR_JOURNAL_NOT_ACTIVE.
            return if code == 1 || code == 50 || code == 87 || code == 1179 {
                Ok(None)
            } else {
                Err(code)
            };
        }
    }
    let records = parse_records(&buffer[..returned as usize], 0);
    Ok(records.first().map(|r| r.usn))
}

/// Parse a buffer of chained USN records starting at `first_record_offset`.
/// Malformed or truncated tails stop parsing; they never panic.
fn parse_records(buffer: &[u8], first_record_offset: usize) -> Vec<RawUsnRecord> {
    let mut out = Vec::new();
    let mut offset = first_record_offset;
    loop {
        if buffer.len() < offset + size_of::<USN_RECORD_COMMON_HEADER>() {
            break;
        }
        // SAFETY: bounds checked above; unaligned read of the generated
        // common header struct.
        let header: USN_RECORD_COMMON_HEADER = unsafe {
            (buffer.as_ptr().add(offset) as *const USN_RECORD_COMMON_HEADER).read_unaligned()
        };
        let length = header.RecordLength as usize;
        if length < size_of::<USN_RECORD_COMMON_HEADER>() || buffer.len() < offset + length {
            break;
        }
        let record = &buffer[offset..offset + length];
        match header.MajorVersion {
            2 => {
                // SAFETY: `length` is at least the V2 header size checked by
                // the record length contract; read unaligned.
                let v2: USN_RECORD_V2 = unsafe {
                    (record.as_ptr() as *const USN_RECORD_V2).read_unaligned()
                };
                if let Some(name) = record_name(record, v2.FileNameOffset as usize, v2.FileNameLength as usize) {
                    out.push(RawUsnRecord {
                        file_id: frn_to_id(v2.FileReferenceNumber),
                        parent_id: frn_to_id(v2.ParentFileReferenceNumber),
                        usn: v2.Usn,
                        reason: v2.Reason,
                        attributes: v2.FileAttributes,
                        name,
                    });
                }
            }
            3 => {
                // SAFETY: as above for the V3 layout.
                let v3: USN_RECORD_V3 = unsafe {
                    (record.as_ptr() as *const USN_RECORD_V3).read_unaligned()
                };
                if let Some(name) = record_name(record, v3.FileNameOffset as usize, v3.FileNameLength as usize) {
                    out.push(RawUsnRecord {
                        file_id: v3.FileReferenceNumber.Identifier,
                        parent_id: v3.ParentFileReferenceNumber.Identifier,
                        usn: v3.Usn,
                        reason: v3.Reason,
                        attributes: v3.FileAttributes,
                        name,
                    });
                }
            }
            // Major version 4 (range-tracking records) and unknown versions
            // are skipped, not misinterpreted.
            _ => {}
        }
        offset += length;
    }
    out
}

fn record_name(record: &[u8], offset: usize, length_bytes: usize) -> Option<Vec<u16>> {
    if length_bytes == 0 {
        return Some(Vec::new());
    }
    if offset < size_of::<USN_RECORD_COMMON_HEADER>()
        || offset.checked_add(length_bytes)? > record.len()
        || length_bytes % 2 != 0
    {
        return None;
    }
    let units: Vec<u16> = record[offset..offset + length_bytes]
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    Some(units)
}

fn frn_to_id(frn: u64) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&frn.to_le_bytes());
    id
}
