use hfdrive_core::{ids::UploadId, storage::{ByteRange, ImmutableKey, PayloadKey, RelativeKey, RemotePrefix, Sha256Digest, XetFileId}};

#[test]
fn remote_references_cannot_escape_or_smuggle_a_url() {
    for value in ["/objects/a", "../objects/a", "a/../b", "a/./b", "a//b", "a/", "a\\b", "a%2fb", "a?b", "a#b", "https://hf.co/a", "a\0b"] {
        assert!(value.parse::<RelativeKey>().is_err(), "accepted {value:?}");
        assert!(value.parse::<RemotePrefix>().is_err(), "accepted prefix {value:?}");
    }
    let id = UploadId::new();
    let payload = PayloadKey::new(id);
    assert_eq!(payload.to_string().parse::<PayloadKey>().unwrap(), payload);
    for value in [format!("versions/{id}.json"), format!("objects/{id}/extra"), format!("objects/../{id}"), format!("https://hf.co/objects/{id}")] {
        assert!(value.parse::<PayloadKey>().is_err());
    }
    let uppercase = "A".repeat(64);
    assert!(uppercase.parse::<Sha256Digest>().is_err());
    assert!(uppercase.parse::<XetFileId>().is_err());
}

#[test]
fn prefix_budget_counts_utf8_bytes_and_overlap_respects_segments() {
    let prefix: RemotePrefix = "é".repeat(473).parse().unwrap();
    let key = prefix.immutable_key(ImmutableKey::Catalog(Sha256Digest::of(b"page")));
    assert_eq!(key.as_str().len(), 1024);
    assert!(format!("{}x", prefix.as_str()).parse::<RemotePrefix>().is_err());
    let root: RemotePrefix = "".parse().unwrap();
    let a: RemotePrefix = "a".parse().unwrap();
    let child: RemotePrefix = "a/b".parse().unwrap();
    let unrelated: RemotePrefix = "ab".parse().unwrap();
    assert!(root.overlaps(&child));
    assert!(a.overlaps(&child));
    assert!(child.overlaps(&a));
    assert!(!a.overlaps(&unrelated));
    assert_eq!(root.head_key().as_str(), "HEAD");
}

#[test]
fn half_open_ranges_reject_mismatched_objects_without_overflow() {
    assert!(ByteRange::new(5, 4, 10).is_err());
    assert!(ByteRange::new(0, 11, 10).is_err());
    let eof = ByteRange::new(10, 10, 10).unwrap();
    assert!(eof.is_empty());
    assert!(eof.validate_for(9).is_err());
    let maximal = ByteRange::new(0, u64::MAX, u64::MAX).unwrap();
    assert_eq!(maximal.len(), u64::MAX);
    assert_eq!(maximal.as_range(), 0..u64::MAX);
    assert!(maximal.validate_for(u64::MAX - 1).is_err());
}
