//! Strict SQLite column conversions.
//!
//! UUID identifiers are 16-byte blobs, digests/Xet identifiers are 32-byte
//! blobs, and every integer column is a checked signed 64-bit value. A column
//! that does not match the expected shape is database corruption, not a value
//! to coerce.

use crate::error::StateError;
use hfdrive_core::ids::{
    AccountKey, ActionId, CommitId, ConflictId, ConnectionId, GenerationId, ItemId, OperationId,
    SetupId, SnapshotId, TransferId, VersionId, WorkspaceId,
};
use hfdrive_core::storage::Sha256Digest;
use rusqlite::types::ValueRef;
use std::{fmt::Write as _, path::PathBuf};

pub(crate) const UUID_BYTES: usize = 16;
pub(crate) const DIGEST_BYTES: usize = 32;

/// Reads an optional column, mapping a length mismatch to corruption.
pub(crate) fn blob_opt(
    value: ValueRef<'_>,
    entity: &'static str,
    expected: usize,
) -> Result<Option<Vec<u8>>, StateError> {
    match value {
        ValueRef::Null => Ok(None),
        ValueRef::Blob(bytes) if bytes.len() == expected => Ok(Some(bytes.to_vec())),
        ValueRef::Blob(bytes) => Err(StateError::InvalidBlob { entity, expected, found: bytes.len() }),
        other => Err(StateError::InvalidBlob {
            entity,
            expected,
            found: other.as_bytes().map(|bytes| bytes.len()).unwrap_or(0),
        }),
    }
}

pub(crate) fn blob(
    value: ValueRef<'_>,
    entity: &'static str,
    expected: usize,
) -> Result<Vec<u8>, StateError> {
    blob_opt(value, entity, expected)?
        .ok_or(StateError::InvalidBlob { entity, expected, found: 0 })
}

pub(crate) fn uuid_from(value: ValueRef<'_>, entity: &'static str) -> Result<uuid::Uuid, StateError> {
    let bytes = blob(value, entity, UUID_BYTES)?;
    uuid::Uuid::from_slice(&bytes).map_err(|_| StateError::InvalidBlob { entity, expected: UUID_BYTES, found: bytes.len() })
}

macro_rules! id_readers {
    ($($fn_req:ident, $fn_opt:ident => $ty:ty),+ $(,)?) => {$(
        pub(crate) fn $fn_req(value: ValueRef<'_>) -> Result<$ty, StateError> {
            let id = uuid_from(value, stringify!($ty))?;
            <$ty>::from_uuid(id).map_err(|_| StateError::InvalidId { entity: stringify!($ty) })
        }
        pub(crate) fn $fn_opt(value: ValueRef<'_>) -> Result<Option<$ty>, StateError> {
            match blob_opt(value, stringify!($ty), UUID_BYTES)? {
                None => Ok(None),
                Some(_) => Ok(Some($fn_req(value)?)),
            }
        }
    )+};
}

id_readers!(
    connection_id, connection_id_opt => ConnectionId,
    workspace_id, workspace_id_opt => WorkspaceId,
    item_id, item_id_opt => ItemId,
    version_id, version_id_opt => VersionId,
    operation_id, operation_id_opt => OperationId,
    commit_id, commit_id_opt => CommitId,
    generation_id, generation_id_opt => GenerationId,
    snapshot_id, snapshot_id_opt => SnapshotId,
    transfer_id, transfer_id_opt => TransferId,
    action_id, action_id_opt => ActionId,
    setup_id, setup_id_opt => SetupId,
    conflict_id, conflict_id_opt => ConflictId,
);

pub(crate) fn digest_from(value: ValueRef<'_>, entity: &'static str) -> Result<Sha256Digest, StateError> {
    let bytes = blob(value, entity, DIGEST_BYTES)?;
    let mut array = [0u8; DIGEST_BYTES];
    array.copy_from_slice(&bytes);
    Ok(Sha256Digest::from_bytes(array))
}

pub(crate) fn digest_opt(
    value: ValueRef<'_>,
    entity: &'static str,
) -> Result<Option<Sha256Digest>, StateError> {
    match blob_opt(value, entity, DIGEST_BYTES)? {
        None => Ok(None),
        Some(bytes) => {
            let mut array = [0u8; DIGEST_BYTES];
            array.copy_from_slice(&bytes);
            Ok(Some(Sha256Digest::from_bytes(array)))
        }
    }
}

pub(crate) fn account_key(value: ValueRef<'_>) -> Result<AccountKey, StateError> {
    let bytes = blob(value, "AccountKey", DIGEST_BYTES)?;
    Ok(account_key_from_bytes(&bytes))
}

pub(crate) fn account_key_opt(value: ValueRef<'_>) -> Result<Option<AccountKey>, StateError> {
    match blob_opt(value, "AccountKey", DIGEST_BYTES)? {
        None => Ok(None),
        Some(bytes) => Ok(Some(account_key_from_bytes(&bytes))),
    }
}

fn account_key_from_bytes(bytes: &[u8]) -> AccountKey {
    let mut hex = String::with_capacity(DIGEST_BYTES * 2);
    for byte in bytes {
        write!(&mut hex, "{byte:02x}").expect("writing into a String cannot fail");
    }
    hex.parse().expect("32 bytes always form a valid AccountKey")
}

pub(crate) fn text(value: ValueRef<'_>, entity: &'static str) -> Result<String, StateError> {
    match value {
        ValueRef::Text(bytes) => std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| StateError::invalid_state(entity, "?", "column is not valid UTF-8")),
        ValueRef::Null => Err(StateError::invalid_state(entity, "?", "expected text, found NULL")),
        _ => Err(StateError::invalid_state(entity, "?", "expected text column")),
    }
}

pub(crate) fn text_opt(value: ValueRef<'_>, entity: &'static str) -> Result<Option<String>, StateError> {
    match value {
        ValueRef::Null => Ok(None),
        _ => Ok(Some(text(value, entity)?)),
    }
}

pub(crate) fn path(value: ValueRef<'_>, entity: &'static str) -> Result<PathBuf, StateError> {
    text(value, entity).map(PathBuf::from)
}

pub(crate) fn path_opt(value: ValueRef<'_>, entity: &'static str) -> Result<Option<PathBuf>, StateError> {
    text_opt(value, entity).map(|text| text.map(PathBuf::from))
}

pub(crate) fn path_text(value: &PathBuf) -> Result<&str, StateError> {
    value
        .to_str()
        .ok_or_else(|| StateError::NonUtf8Path(value.clone()))
}

pub(crate) fn integer(value: ValueRef<'_>, entity: &'static str) -> Result<i64, StateError> {
    match value {
        ValueRef::Integer(n) => Ok(n),
        _ => Err(StateError::invalid_state(entity, "?", "expected integer column")),
    }
}

pub(crate) fn integer_opt(value: ValueRef<'_>, entity: &'static str) -> Result<Option<i64>, StateError> {
    match value {
        ValueRef::Null => Ok(None),
        _ => Ok(Some(integer(value, entity)?)),
    }
}

pub(crate) fn unsigned(value: ValueRef<'_>, entity: &'static str) -> Result<u64, StateError> {
    let n = integer(value, entity)?;
    u64::try_from(n).map_err(|_| StateError::invalid_state(entity, "?", format!("negative integer {n}")))
}

pub(crate) fn unsigned_opt(value: ValueRef<'_>, entity: &'static str) -> Result<Option<u64>, StateError> {
    match integer_opt(value, entity)? {
        None => Ok(None),
        Some(n) => Ok(Some(u64::try_from(n).map_err(|_| {
            StateError::invalid_state(entity, "?", format!("negative integer {n}"))
        })?)),
    }
}

pub(crate) fn boolean(value: ValueRef<'_>, entity: &'static str) -> Result<bool, StateError> {
    match integer(value, entity)? {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(StateError::invalid_state(entity, "?", format!("integer {other} is not 0 or 1"))),
    }
}

pub(crate) fn json(value: ValueRef<'_>, entity: &'static str) -> Result<serde_json::Value, StateError> {
    let raw = text(value, entity)?;
    serde_json::from_str(&raw)
        .map_err(|error| StateError::invalid_state(entity, "?", format!("invalid JSON column: {error}")))
}

pub(crate) fn json_opt(value: ValueRef<'_>, entity: &'static str) -> Result<Option<serde_json::Value>, StateError> {
    match value {
        ValueRef::Null => Ok(None),
        _ => Ok(Some(json(value, entity)?)),
    }
}

/// Serializes a typed record for a JSON column.
pub(crate) fn to_json<T: serde::Serialize>(entity: &'static str, value: &T) -> Result<String, StateError> {
    serde_json::to_string(value)
        .map_err(|error| StateError::invalid_state(entity, "?", format!("cannot serialize record: {error}")))
}

pub(crate) fn from_json<T: serde::de::DeserializeOwned>(entity: &'static str, raw: &str) -> Result<T, StateError> {
    serde_json::from_str(raw)
        .map_err(|error| StateError::invalid_state(entity, "?", format!("cannot deserialize record: {error}")))
}
