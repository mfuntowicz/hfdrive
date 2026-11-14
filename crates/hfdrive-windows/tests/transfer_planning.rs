//! Deterministic tests for CFAPI transfer planning: the 4096-alignment /
//! 1 MiB / EOF / read-ahead contract is pure logic and fully testable.

use hfdrive_core::storage::ByteRange;
use hfdrive_windows::cfapi::{
    plan_chunks, validate_chunk, CfError, TransferChunk, MAX_OPTIONAL_READAHEAD,
    MAX_TRANSFER_BUFFER, TRANSFER_ALIGNMENT,
};

fn range(start: u64, end: u64, size: u64) -> ByteRange {
    ByteRange::new(start, end, size).expect("valid range")
}

#[test]
fn out_of_bounds_ranges_fail_before_any_sdk_use() {
    // A range captured for a larger file must be rejected against the current EOF.
    assert!(matches!(
        plan_chunks(range(0, 100, 100), None, 50),
        Err(CfError::InvalidChunk)
    ));
    assert!(matches!(
        plan_chunks(range(0, 101, 101), None, 100),
        Err(CfError::InvalidChunk)
    ));
}

#[test]
fn empty_ranges_return_no_bytes() {
    let chunks = plan_chunks(range(7, 7, 50), None, 50).expect("plan");
    assert_eq!(
        chunks,
        vec![TransferChunk {
            offset: 7,
            len: 0,
            required: true,
        }]
    );
}

#[test]
fn chunks_cover_required_are_aligned_and_bounded() {
    let file_size = 3 * 1024 * 1024;
    let required = range(1000, 2_500_000, file_size);
    let chunks = plan_chunks(
        required,
        Some(range(2_400_000, file_size, file_size)),
        file_size,
    )
    .expect("plan");
    assert!(!chunks.is_empty());

    let mut cursor = chunks[0].offset;
    for chunk in &chunks {
        validate_chunk(chunk, file_size).expect("chunk satisfies the contract");
        assert!(chunk.len <= MAX_TRANSFER_BUFFER);
        assert_eq!(chunk.offset, cursor, "chunks are ordered and contiguous");
        cursor += chunk.len;
        if chunk.len > 0 {
            assert_eq!(chunk.offset % TRANSFER_ALIGNMENT, 0);
            assert!(
                chunk.len % TRANSFER_ALIGNMENT == 0 || chunk.offset + chunk.len == file_size,
                "only EOF chunks may be unaligned"
            );
        }
    }

    // Required coverage is complete.
    let first = chunks.first().unwrap();
    assert!(first.offset <= required.start());
    let required_end = chunks
        .iter()
        .filter(|c| c.required)
        .map(|c| c.offset + c.len)
        .max()
        .unwrap();
    assert!(required_end >= required.end_exclusive());
}

#[test]
fn only_the_eof_chunk_may_be_unaligned() {
    let file_size = 4096 * 2 + 100;
    let chunks = plan_chunks(range(0, file_size, file_size), None, file_size).expect("plan");
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].len, file_size);
    validate_chunk(&chunks[0], file_size).expect("EOF exception");
}

#[test]
fn optional_readahead_is_bounded_to_four_mib() {
    let file_size = 20 * 1024 * 1024;
    let chunks = plan_chunks(
        range(0, 4096, file_size),
        Some(range(4096, file_size, file_size)),
        file_size,
    )
    .expect("plan");
    let optional: u64 = chunks.iter().filter(|c| !c.required).map(|c| c.len).sum();
    assert!(
        optional <= MAX_OPTIONAL_READAHEAD + MAX_TRANSFER_BUFFER,
        "optional coverage stays bounded (alignment slack allowed)"
    );
}

#[test]
fn completion_validation_rejects_bad_chunks_against_the_real_file_size() {
    let chunk = TransferChunk {
        offset: 4096,
        len: 100,
        required: true,
    };
    assert!(matches!(
        validate_chunk(&chunk, 100_000),
        Err(CfError::InvalidChunk)
    ));
    let eof_chunk = TransferChunk {
        offset: 4096,
        len: 100,
        required: true,
    };
    assert!(validate_chunk(&eof_chunk, 4096 + 100).is_ok(), "EOF exception");
    let too_big = TransferChunk {
        offset: 0,
        len: MAX_TRANSFER_BUFFER + TRANSFER_ALIGNMENT,
        required: true,
    };
    assert!(matches!(
        validate_chunk(&too_big, u64::MAX),
        Err(CfError::InvalidChunk)
    ));
}
