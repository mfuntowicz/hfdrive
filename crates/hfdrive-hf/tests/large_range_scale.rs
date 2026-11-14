//! Full 4-GiB local stream and bounded range-cache acceptance. No network.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use hfdrive_core::ids::UploadId;
use hfdrive_core::storage::{ByteRange, ObjectRef, PayloadKey, Sha256Digest, XetFileId};
use hfdrive_hf::RangeCache;

const GIB: u64 = 1024 * 1024 * 1024;
const CHUNK: usize = 1024 * 1024;

#[ignore = "authorized owned 4-GiB fixture only"]
#[test]
fn full_four_gib_stream_respects_range_cache_bound() {
    let path = std::env::var("HFDRIVE_LARGE_FIXTURE")
        .expect("set HFDRIVE_LARGE_FIXTURE to the authorized owned 4-GiB file");
    let path = PathBuf::from(path);
    let result = std::panic::catch_unwind(|| {
        let mut file = OpenOptions::new().create(true).truncate(true).write(true).read(true)
            .open(&path).expect("create owned large fixture");
        file.set_len(4 * GIB).expect("size fixture to 4 GiB");
        write_pattern(&mut file, 0, 0x11);
        write_pattern(&mut file, 2 * GIB, 0x22);
        write_pattern(&mut file, 4 * GIB - CHUNK as u64, 0x33);
        file.flush().unwrap();

        let object = ObjectRef {
            key: PayloadKey::new(UploadId::new()),
            sha256: Sha256Digest::of(b"4-GiB range-cache acceptance"),
            size: 4 * GIB,
            xet_file_id: XetFileId::new("ab".repeat(32)).unwrap(),
        };
        let cache = RangeCache::new(4 * CHUNK as u64);
        let mut buffer = vec![0u8; CHUNK];
        let mut offset = 0u64;
        file.seek(SeekFrom::Start(0)).unwrap();
        while offset < 4 * GIB {
            let read = file.read(&mut buffer).expect("read full fixture");
            assert!(read > 0, "unexpected EOF at {offset}");
            cache.insert(&object, offset, bytes::Bytes::copy_from_slice(&buffer[..read]));
            assert!(cache.used_bytes() <= 4 * CHUNK as u64, "cache exceeded budget at {offset}");
            offset += read as u64;
        }
        assert_eq!(offset, 4 * GIB);
        assert_eq!(cache.used_bytes(), 4 * CHUNK as u64);
        assert!(cache.lookup(&object, ByteRange::new(0, CHUNK as u64, 4 * GIB).unwrap()).is_none(),
            "the oldest chunk was evicted under the hard bound");

        assert!(cache.lookup(&object, ByteRange::new(2 * GIB, 2 * GIB + CHUNK as u64, 4 * GIB).unwrap()).is_none(),
            "the middle chunk was also evicted by the rolling 4-MiB window");
        for (offset, expected) in [(4 * GIB - CHUNK as u64, 0x33)] {
            let hit = cache.lookup(&object, ByteRange::new(offset, offset + CHUNK as u64, 4 * GIB).unwrap())
                .expect("final chunk remains available");
            let mut parts = Vec::new();
            for segment in hit {
                parts.extend_from_slice(segment.as_ref());
            }
            assert_eq!(parts.len(), CHUNK);
            assert!(parts.iter().all(|byte| *byte == expected), "pattern mismatch at {offset}");
        }
    });
    let _ = std::fs::remove_file(&path);
    result.unwrap();
}

fn write_pattern(file: &mut File, offset: u64, value: u8) {
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&vec![value; CHUNK]).unwrap();
}
