use hfdrive_protocol::PublicationProtectionContext;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
struct Vectors { vectors: Vec<Vector> }
#[derive(Deserialize)]
struct Vector { context: PublicationProtectionContext, operation_id: Uuid, entropy: [u8; 32] }

#[test]
fn protection_context_matches_cross_language_uuid_and_unicode_vectors() {
    let cases: Vectors = serde_json::from_slice(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec/fixtures/publication-protection.json"))).unwrap();
    for case in cases.vectors {
        assert_eq!(case.context.entropy(case.operation_id).unwrap(), case.entropy);
        assert!(case.context.entropy(Uuid::nil()).is_err());
    }
}
