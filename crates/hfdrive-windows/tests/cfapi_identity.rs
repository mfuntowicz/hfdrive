//! Deterministic tests for the HFDR v1 placeholder identity contract.
//! Pure data tests; runnable on any host with the pinned toolchain.

use hfdrive_windows::cfapi::{IdentityError, PlaceholderIdentity, IDENTITY_LEN};
use hfdrive_core::ids::{ItemId, VersionId, WorkspaceId};
use uuid::Uuid;

#[test]
fn file_identity_round_trips_through_the_wire_format() {
    let workspace = WorkspaceId::new();
    let id = PlaceholderIdentity::file(workspace, ItemId::new(), VersionId::new());
    let bytes = id.encode();
    assert_eq!(bytes.len(), IDENTITY_LEN);
    assert_eq!(&bytes[0..4], b"HFDR", "magic");
    assert_eq!(bytes[4], 1, "schema");
    assert_eq!(PlaceholderIdentity::decode(&bytes, Some(workspace)), Ok(id));
}

#[test]
fn directory_identity_uses_a_zero_version_field() {
    let workspace = WorkspaceId::new();
    let id = PlaceholderIdentity::directory(workspace, ItemId::new());
    let bytes = id.encode();
    assert!(bytes[37..53].iter().all(|&b| b == 0));
    assert!(id.is_directory());
    assert_eq!(PlaceholderIdentity::decode(&bytes, Some(workspace)), Ok(id));
}

#[test]
fn validation_precedes_decoding_on_every_reject_path() {
    let workspace = WorkspaceId::new();
    let bytes =
        PlaceholderIdentity::file(workspace, ItemId::new(), VersionId::new()).encode();

    // Wrong length.
    assert_eq!(
        PlaceholderIdentity::decode(&bytes[..IDENTITY_LEN - 1], Some(workspace)),
        Err(IdentityError::BadLength)
    );
    assert_eq!(
        PlaceholderIdentity::decode(&bytes[..IDENTITY_LEN + 1], Some(workspace)),
        Err(IdentityError::BadLength)
    );

    // Wrong magic.
    let mut wrong_magic = bytes;
    wrong_magic[1] = b'X';
    assert_eq!(
        PlaceholderIdentity::decode(&wrong_magic, Some(workspace)),
        Err(IdentityError::BadMagic)
    );

    // Unknown schema (newer format is refused, never guessed).
    let mut newer = bytes;
    newer[4] = 2;
    assert_eq!(
        PlaceholderIdentity::decode(&newer, Some(workspace)),
        Err(IdentityError::UnsupportedSchema { schema: 2 })
    );

    // Foreign workspace is never re-bound.
    assert_eq!(
        PlaceholderIdentity::decode(&bytes, Some(WorkspaceId::new())),
        Err(IdentityError::WorkspaceMismatch)
    );
}

#[test]
fn nil_identifiers_are_rejected() {
    let workspace = WorkspaceId::new();
    let mut bytes =
        PlaceholderIdentity::file(workspace, ItemId::new(), VersionId::new()).encode();
    bytes[21..37].copy_from_slice(&Uuid::nil().as_bytes());
    assert_eq!(
        PlaceholderIdentity::decode(&bytes, Some(workspace)),
        Err(IdentityError::NilIdentifier)
    );
}

#[test]
fn workspace_check_is_optional_for_decoding_but_still_validates_identity() {
    let workspace = WorkspaceId::new();
    let id = PlaceholderIdentity::directory(workspace, ItemId::new());
    let bytes = id.encode();
    assert_eq!(PlaceholderIdentity::decode(&bytes, None), Ok(id));
}
