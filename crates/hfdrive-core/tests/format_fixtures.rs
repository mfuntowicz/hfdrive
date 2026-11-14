//! Golden-bytes tests for the HF Drive remote format v1 canonical codec.
//!
//! `spec/fixtures/remote-v1/` is the external pin: each record's exact
//! canonical bytes (hex) must decode to the typed model and re-encode
//! byte-for-byte, and the name-collision vectors must reproduce with the
//! frozen Unicode data versions. See `spec/remote-v1.md`.

use hfdrive_core::format::{
    from_commit_bytes, from_head_bytes, from_item_record_bytes, from_page_bytes, from_version_bytes,
    to_commit_bytes, to_head_bytes, to_item_record_bytes, to_page_bytes, to_version_bytes,
    BranchChild, CatalogPage, ChangeKind, CommitV1, DisplayMetadata, HeadV1, IndexValue, ItemChange,
    ItemKind, ItemRecord, LeafEntry, VersionV1,
};
use hfdrive_core::names;
use hfdrive_core::storage::PayloadKey;

const WORKSPACE: &str = "00000000-0000-4000-8000-000000000001";
const ROOT_ITEM: &str = "00000000-0000-4000-8000-000000000002";
const COMMIT: &str = "00000000-0000-4000-8000-000000000003";
const GENERATION: &str = "00000000-0000-4000-8000-000000000004";
const DEVICE: &str = "00000000-0000-4000-8000-000000000005";
const OP_LOCATION: &str = "00000000-0000-4000-8000-000000000006";
const OP_CONTENT: &str = "00000000-0000-4000-8000-000000000007";
const ITEM: &str = "00000000-0000-4000-8000-000000000009";
const VERSION: &str = "00000000-0000-4000-8000-00000000000a";
const UPLOAD: &str = "00000000-0000-4000-8000-00000000000b";
const CATALOG_ROOT: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const CHILD_TWO: &str = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
const PAYLOAD_SHA: &str = "2f2e2d2c2b2a292827262524232221201f1e1d1c1b1a19181716151413121110";
const XET_FILE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TIMESTAMP: &str = "2026-11-13T00:00:00Z";

fn typed<T: std::str::FromStr>(text: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    text.parse().expect("fixture identifier")
}

fn fixture_path(file: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/fixtures/remote-v1")
        .join(file)
}

fn decode_hex(text: &str) -> Vec<u8> {
    hex::decode(text).expect("golden fixture hex")
}

fn golden_bytes(name: &str) -> Vec<u8> {
    let text = std::fs::read_to_string(fixture_path("golden.json")).expect("read golden.json");
    let file: serde_json::Value = serde_json::from_str(&text).expect("parse golden.json");
    for record in file["records"].as_array().expect("records array") {
        if record["name"].as_str() == Some(name) {
            return decode_hex(record["hex"].as_str().expect("hex string"));
        }
    }
    panic!("golden record {name} missing");
}

fn expected_item() -> ItemRecord {
    ItemRecord {
        item_id: typed(ITEM),
        parent_id: Some(typed(ROOT_ITEM)),
        name: "hello.txt".to_owned(),
        kind: ItemKind::File,
        item_revision: typed(OP_CONTENT),
        content_version_id: Some(typed(VERSION)),
        deleted: false,
        content_operation: typed(OP_CONTENT),
        location_operation: typed(OP_LOCATION),
        deletion_operation: None,
    }
}

fn expected_head() -> HeadV1 {
    HeadV1 {
        format: "hfdrive".to_owned(),
        schema_version: 1,
        workspace_id: typed(WORKSPACE),
        root_item_id: typed(ROOT_ITEM),
        commit_id: typed(COMMIT),
        generation: typed(GENERATION),
        required_features: Vec::new(),
    }
}

fn expected_commit() -> CommitV1 {
    CommitV1 {
        format: "hfdrive".to_owned(),
        schema_version: 1,
        workspace_id: typed(WORKSPACE),
        commit_id: typed(COMMIT),
        parent_commit_id: None,
        catalog_root: typed(CATALOG_ROOT),
        operation_ids: vec![typed(OP_LOCATION), typed(OP_CONTENT)],
        changes: vec![ItemChange {
            item_id: typed(ITEM),
            change: ChangeKind::Create,
            old_revision: None,
            new_revision: typed(OP_CONTENT),
        }],
        device_id: typed(DEVICE),
        created_at: TIMESTAMP.to_owned(),
    }
}

fn expected_version() -> VersionV1 {
    VersionV1 {
        format: "hfdrive".to_owned(),
        schema_version: 1,
        workspace_id: typed(WORKSPACE),
        version_id: typed(VERSION),
        object_key: typed::<PayloadKey>(&format!("objects/{UPLOAD}")),
        size: 42,
        sha256: typed(PAYLOAD_SHA),
        xet_file_id: Some(typed(XET_FILE)),
        display: DisplayMetadata {
            name: "hello.txt".to_owned(),
            modified_at: TIMESTAMP.to_owned(),
        },
    }
}

#[test]
fn golden_head_round_trips_byte_for_byte() {
    let bytes = golden_bytes("head");
    let head = from_head_bytes(&bytes).expect("decode golden head");
    assert_eq!(head, expected_head());
    assert_eq!(to_head_bytes(&expected_head()).unwrap(), bytes);
}

#[test]
fn golden_commit_round_trips_byte_for_byte() {
    let bytes = golden_bytes("commit");
    let commit = from_commit_bytes(&bytes).expect("decode golden commit");
    assert_eq!(commit, expected_commit());
    assert_eq!(to_commit_bytes(&expected_commit()).unwrap(), bytes);
}

#[test]
fn golden_version_round_trips_byte_for_byte() {
    let bytes = golden_bytes("version");
    let version = from_version_bytes(&bytes).expect("decode golden version");
    assert_eq!(version, expected_version());
    assert_eq!(to_version_bytes(&expected_version()).unwrap(), bytes);
}

#[test]
fn golden_item_round_trips_byte_for_byte() {
    let bytes = golden_bytes("item");
    let item = from_item_record_bytes(&bytes).expect("decode golden item");
    assert_eq!(item, expected_item());
    assert_eq!(to_item_record_bytes(&expected_item()).unwrap(), bytes);
}

#[test]
fn golden_pages_round_trip_byte_for_byte() {
    let leaf_bytes = golden_bytes("catalog_leaf");
    let leaf = from_page_bytes(&leaf_bytes).expect("decode golden leaf");
    let expected_leaf = CatalogPage::leaf(vec![LeafEntry {
        key: format!("i/{ITEM}"),
        value: IndexValue::Item(expected_item()),
    }]);
    assert_eq!(leaf, expected_leaf);
    assert_eq!(to_page_bytes(&expected_leaf).unwrap(), leaf_bytes);

    let branch_bytes = golden_bytes("catalog_branch");
    let branch = from_page_bytes(&branch_bytes).expect("decode golden branch");
    let expected_branch = CatalogPage::branch(vec![
        BranchChild {
            first_key: format!("i/{ROOT_ITEM}"),
            page_id: typed(CATALOG_ROOT),
        },
        BranchChild {
            first_key: format!("i/{ITEM}"),
            page_id: typed(CHILD_TWO),
        },
    ]);
    assert_eq!(branch, expected_branch);
    assert_eq!(to_page_bytes(&expected_branch).unwrap(), branch_bytes);
}

#[test]
fn golden_head_rejects_unknown_features_and_newer_schemas() {
    let text = String::from_utf8(golden_bytes("head")).unwrap();
    let with_feature = text.replace("\"required_features\":[]", "\"required_features\":[\"xet-v2\"]");
    let err = from_head_bytes(with_feature.as_bytes()).unwrap_err();
    assert_eq!(err, hfdrive_core::format::FormatError::UnsupportedFeature);
    let with_schema = text.replace("\"schema_version\":1", "\"schema_version\":2");
    let err = from_head_bytes(with_schema.as_bytes()).unwrap_err();
    assert_eq!(err, hfdrive_core::format::FormatError::NewerSchema);
}

#[test]
fn name_collision_vectors_match_frozen_data_versions() {
    let text =
        std::fs::read_to_string(fixture_path("name-collisions.json")).expect("read collisions");
    let file: serde_json::Value = serde_json::from_str(&text).expect("parse collisions");
    let versions = &file["unicode_data_versions"];
    assert_eq!(
        versions["unicode_normalization_nfc"],
        serde_json::json!([names::NFC_DATA_VERSION.0, names::NFC_DATA_VERSION.1, names::NFC_DATA_VERSION.2])
    );
    assert_eq!(
        versions["unicode_casefold_default_full"],
        serde_json::json!([
            names::CASEFOLD_DATA_VERSION.0,
            names::CASEFOLD_DATA_VERSION.1,
            names::CASEFOLD_DATA_VERSION.2
        ])
    );
    for vector in file["vectors"].as_array().expect("vectors array") {
        let spelling = vector["spelling"].as_str().expect("spelling");
        let expected_hex = vector["collision_key_hex"].as_str().expect("hex");
        assert_eq!(
            hex::encode(names::collision_key(spelling)),
            expected_hex,
            "collision key for {spelling:?}"
        );
    }
}
