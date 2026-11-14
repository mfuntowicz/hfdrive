//! Shared fixtures for hfdrive-state integration tests. Everything here builds
//! real typed records; nothing is mocked.

#![allow(dead_code)]

use hfdrive_core::ids::{AccountKey, WorkspaceId};
use hfdrive_core::storage::{
    BucketBinding, BucketId, BucketName, DriveBinding, Namespace, OwnerId, OwnerKind, RemotePrefix,
    Sha256Digest,
};
use hfdrive_state::{AccountRecord, AccountStatus, CredentialRef};

pub const ISSUER: &str = "https://huggingface.co";
pub const SUBJECT: &str = "test-subject-1";

pub fn account_key() -> AccountKey {
    AccountKey::from_subject(ISSUER, SUBJECT)
}

pub fn account_record(key: AccountKey) -> AccountRecord {
    AccountRecord {
        account_key: key,
        issuer: ISSUER.to_owned(),
        subject: SUBJECT.to_owned(),
        namespace: "test-user".to_owned(),
        credential_ref: CredentialRef("credentials/oauth.cred".to_owned()),
        auth_epoch: 0,
        status: AccountStatus::Active,
    }
}

pub fn binding(key: AccountKey) -> DriveBinding {
    DriveBinding {
        account_key: key,
        workspace_id: WorkspaceId::new(),
        bucket: BucketBinding {
            bucket_id: BucketId::new("bucket-stable-1".to_owned()).unwrap(),
            bucket_name: BucketName::new("bucket-test-1".to_owned()).unwrap(),
            owner_id: OwnerId::new("owner-stable-1".to_owned()).unwrap(),
            owner_kind: OwnerKind::Personal,
            owner_namespace: Namespace::new("test-user".to_owned()).unwrap(),
        },
        prefix: RemotePrefix::new("hfdrive/test-ws".to_owned()).unwrap(),
    }
}

/// The local-root proof attached at preview time.
pub fn preview_json(root: &std::path::Path) -> serde_json::Value {
    serde_json::json!({
        "root_path": root.to_str().expect("test paths are UTF-8"),
        "scan_generation": 1,
        "collisions": [],
    })
}

pub fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::of(bytes)
}
