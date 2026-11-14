//! Transfer planning: aligned bounded chunks for `FETCH_DATA` completion.
//!
//! CFAPI requires transfer offsets/lengths to be 4096-aligned except when a
//! transfer ends at EOF; buffers must not exceed 1 MiB; the required range
//! must be fully covered; the OS's optional read-ahead is honored only up to
//! [`MAX_OPTIONAL_READAHEAD`]. The planner is pure (no I/O) and is the single
//! place these rules are decided, so completion calls can re-validate the
//! same contract before touching `CfExecute`.

use hfdrive_core::storage::ByteRange;

use super::events::AckToken;
use super::{CfError, CfResult};

/// Transfer alignment required by CFAPI (`CF_MINIMUM_ALIGNMENT`).
pub const TRANSFER_ALIGNMENT: u64 = 4096;
/// Maximum bytes per `TRANSFER_DATA` buffer (1 MiB).
pub const MAX_TRANSFER_BUFFER: u64 = 1024 * 1024;
/// Bound applied to the OS's optional read-ahead hint (4 MiB).
pub const MAX_OPTIONAL_READAHEAD: u64 = 4 * 1024 * 1024;

/// One planned chunk of a fetch request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferChunk {
    pub offset: u64,
    pub len: u64,
    /// True when the chunk covers part of the required range.
    pub required: bool,
}

/// Plan the ordered chunk list for one fetch request.
///
/// * The required range is fully covered; out-of-bounds ranges fail with
///   [`CfError::InvalidChunk`] before any SDK/OS use.
/// * Optional coverage is clipped to `file_size` and to
///   [`MAX_OPTIONAL_READAHEAD`] past the required range.
/// * Empty required ranges yield a single zero-length chunk at the request
///   offset ("empty ranges return no bytes").
/// * Every non-EOF chunk is aligned on both ends and at most 1 MiB; only a
///   chunk ending exactly at `file_size` may be unaligned.
pub fn plan_chunks(
    required: ByteRange,
    optional: Option<ByteRange>,
    file_size: u64,
) -> CfResult<Vec<TransferChunk>> {
    if required.end_exclusive() > file_size || required.start() > required.end_exclusive() {
        return Err(CfError::InvalidChunk);
    }
    if required.is_empty() {
        return Ok(vec![TransferChunk {
            offset: required.start(),
            len: 0,
            required: true,
        }]);
    }

    // Optional coverage: clipped to EOF and to the read-ahead bound.
    let optional = optional
        .filter(|o| !o.is_empty())
        .map(|o| {
            let start = o.start().max(required.end_exclusive());
            let end = o
                .end_exclusive()
                .min(file_size)
                .min(start.saturating_add(MAX_OPTIONAL_READAHEAD));
            (start, end)
        })
        .filter(|(start, end)| start < end);

    // Build merged, ordered, non-overlapping coverage intervals.
    let mut intervals: Vec<(u64, u64)> = vec![(required.start(), required.end_exclusive())];
    if let Some((o_start, o_end)) = optional {
        let last = intervals.last_mut().expect("nonempty");
        if o_start <= last.1 {
            last.1 = last.1.max(o_end);
        } else {
            intervals.push((o_start, o_end));
        }
    }

    let mut chunks = Vec::new();
    let mut boundary = 0u64;
    for (start, end) in intervals {
        let start = align_down(start).max(boundary);
        let end = if end == file_size {
            end
        } else {
            align_up(end).min(file_size)
        };
        let mut cursor = start;
        while cursor < end {
            let chunk_end = (cursor + MAX_TRANSFER_BUFFER).min(end);
            let chunk = TransferChunk {
                offset: cursor,
                len: chunk_end - cursor,
                required: overlaps(chunk_end, cursor, &required),
            };
            validate_chunk(&chunk, file_size)?;
            chunks.push(chunk);
            cursor = chunk_end;
        }
        boundary = cursor.max(boundary);
    }
    Ok(chunks)
}

fn overlaps(chunk_end: u64, chunk_start: u64, required: &ByteRange) -> bool {
    chunk_start < required.end_exclusive() && chunk_end > required.start()
}

fn align_down(value: u64) -> u64 {
    value - (value % TRANSFER_ALIGNMENT)
}

fn align_up(value: u64) -> u64 {
    match value % TRANSFER_ALIGNMENT {
        0 => value,
        r => value + (TRANSFER_ALIGNMENT - r),
    }
}

/// Re-validate one chunk right before completion (defense in depth).
pub fn validate_chunk(chunk: &TransferChunk, file_size: u64) -> CfResult<()> {
    if chunk.len > MAX_TRANSFER_BUFFER {
        return Err(CfError::InvalidChunk);
    }
    if chunk.offset > file_size || chunk.len > file_size.saturating_sub(chunk.offset) {
        return Err(CfError::InvalidChunk);
    }
    if chunk.len == 0 {
        return Ok(());
    }
    let aligned_start = chunk.offset % TRANSFER_ALIGNMENT == 0;
    let ends_at_eof = chunk.offset + chunk.len == file_size;
    let aligned_len = chunk.len % TRANSFER_ALIGNMENT == 0;
    if aligned_start && (aligned_len || ends_at_eof) {
        Ok(())
    } else {
        Err(CfError::InvalidChunk)
    }
}

/// A completion in flight: one validated chunk of one request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferCompletion {
    pub ack: AckToken,
    pub chunk: TransferChunk,
    /// The request's file size; needed to re-validate the EOF alignment
    /// exception at completion time.
    pub file_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(start: u64, end: u64, size: u64) -> ByteRange {
        ByteRange::new(start, end, size).unwrap()
    }

    #[test]
    fn out_of_bounds_fails_before_use() {
        assert!(matches!(
            plan_chunks(range(0, 100, 100), None, 50),
            Err(CfError::InvalidChunk)
        ));
    }

    #[test]
    fn empty_range_yields_one_zero_length_chunk() {
        let chunks = plan_chunks(range(7, 7, 50), None, 50).unwrap();
        assert_eq!(
            chunks,
            vec![TransferChunk {
                offset: 7,
                len: 0,
                required: true
            }]
        );
    }

    #[test]
    fn chunks_are_aligned_bounded_and_cover_required() {
        // 3 MiB file, required = [1000, 2_500_000), optional clipped.
        let file_size = 3 * 1024 * 1024;
        let required = range(1000, 2_500_000, file_size);
        let chunks = plan_chunks(required, Some(range(2_400_000, file_size, file_size)), file_size)
            .unwrap();
        assert!(!chunks.is_empty());
        let mut covered = 0u64;
        for chunk in &chunks {
            validate_chunk(chunk, file_size).unwrap();
            assert!(chunk.len <= MAX_TRANSFER_BUFFER);
            if chunk.len > 0 {
                assert_eq!(chunk.offset % TRANSFER_ALIGNMENT, 0);
                assert!(
                    chunk.len % TRANSFER_ALIGNMENT == 0
                        || chunk.offset + chunk.len == file_size
                );
            }
            if chunk.required {
                covered += chunk.len;
            }
        }
        // The required range must be fully inside the required chunks.
        let first = chunks.first().unwrap();
        assert!(first.offset <= 1000);
        let required_end = chunks
            .iter()
            .filter(|c| c.required)
            .map(|c| c.offset + c.len)
            .max()
            .unwrap();
        assert!(required_end >= 2_500_000);
        assert!(covered > 0);
    }

    #[test]
    fn eof_chunk_is_the_only_unaligned_one() {
        let file_size = 4096 * 2 + 100;
        let required = range(0, file_size, file_size);
        let chunks = plan_chunks(required, None, file_size).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len, file_size);
        validate_chunk(&chunks[0], file_size).unwrap();
    }

    #[test]
    fn optional_readahead_is_bounded() {
        let file_size = 20 * 1024 * 1024;
        let required = range(0, 4096, file_size);
        let chunks = plan_chunks(
            required,
            Some(range(4096, file_size, file_size)),
            file_size,
        )
        .unwrap();
        let optional_bytes: u64 = chunks
            .iter()
            .filter(|c| !c.required)
            .map(|c| c.len)
            .sum();
        assert!(optional_bytes <= MAX_OPTIONAL_READAHEAD + MAX_TRANSFER_BUFFER);
    }

    #[test]
    fn validate_rejects_unaligned_mid_file_chunks() {
        let chunk = TransferChunk {
            offset: 4096,
            len: 100,
            required: true,
        };
        assert!(matches!(
            validate_chunk(&chunk, 100_000),
            Err(CfError::InvalidChunk)
        ));
    }
}
