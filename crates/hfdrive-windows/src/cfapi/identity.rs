//! HFDR v1 placeholder identity: the compact, immutable, versioned binary
//! record CF API stores in every placeholder (`FileIdentity`).
//!
//! Layout (53 bytes, fixed):
//!
//! ```text
//! offset  size  field
//! 0       4     magic "HFDR"
//! 4       1     schema version (1)
//! 5       16    workspace UUID (lowercase canonical identity bytes)
//! 21      16    item UUID
//! 37      16    immutable content version UUID (all-zero only for a directory)
//! ```
//!
//! The record is validated **before** decoding: exact length, magic, known
//! schema and, when the connection's workspace is known, workspace match.
//! Anything else is rejected; there is no lenient path.

use hfdrive_core::ids::{ItemId, VersionId, WorkspaceId};
use uuid::Uuid;

/// Record magic.
pub const IDENTITY_MAGIC: [u8; 4] = *b"HFDR";
/// Record schema version.
pub const IDENTITY_SCHEMA: u8 = 1;
/// Exact encoded length in bytes.
pub const IDENTITY_LEN: usize = 53;

/// Decoded placeholder identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlaceholderIdentity {
    pub workspace: WorkspaceId,
    pub item: ItemId,
    /// `None` for directories; `Some` for files with an immutable content
    /// version.
    pub version: Option<VersionId>,
}

/// Identity decoding failure. Every variant is safe to log.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum IdentityError {
    #[error("identity record has an unexpected length")]
    BadLength,
    #[error("identity record has no HFDR magic")]
    BadMagic,
    #[error("identity record uses unsupported schema {schema}")]
    UnsupportedSchema { schema: u8 },
    #[error("identity record belongs to a different workspace")]
    WorkspaceMismatch,
    #[error("identity record contains a nil identifier")]
    NilIdentifier,
}

impl PlaceholderIdentity {
    /// File identity (immutable content version required).
    pub fn file(workspace: WorkspaceId, item: ItemId, version: VersionId) -> Self {
        Self {
            workspace,
            item,
            version: Some(version),
        }
    }

    /// Directory identity (no content version).
    pub fn directory(workspace: WorkspaceId, item: ItemId) -> Self {
        Self {
            workspace,
            item,
            version: None,
        }
    }

    pub const fn is_directory(&self) -> bool {
        self.version.is_none()
    }

    /// Encode to the fixed wire record.
    pub fn encode(&self) -> [u8; IDENTITY_LEN] {
        let mut out = [0u8; IDENTITY_LEN];
        out[0..4].copy_from_slice(&IDENTITY_MAGIC);
        out[4] = IDENTITY_SCHEMA;
        out[5..21].copy_from_slice(self.workspace.as_bytes());
        out[21..37].copy_from_slice(self.item.as_bytes());
        match self.version {
            Some(version) => out[37..53].copy_from_slice(version.as_bytes()),
            None => out[37..53].copy_from_slice(&[0u8; 16]),
        }
        out
    }

    /// Validate and decode. `expect_workspace` is the connection's workspace;
    /// records from another workspace are rejected, never re-bound.
    pub fn decode(
        bytes: &[u8],
        expect_workspace: Option<WorkspaceId>,
    ) -> Result<Self, IdentityError> {
        if bytes.len() != IDENTITY_LEN {
            return Err(IdentityError::BadLength);
        }
        if bytes[0..4] != IDENTITY_MAGIC {
            return Err(IdentityError::BadMagic);
        }
        if bytes[4] != IDENTITY_SCHEMA {
            return Err(IdentityError::UnsupportedSchema { schema: bytes[4] });
        }
        let workspace = Uuid::from_bytes(bytes[5..21].try_into().expect("fixed slice"));
        let item = Uuid::from_bytes(bytes[21..37].try_into().expect("fixed slice"));
        let version_bytes: [u8; 16] = bytes[37..53].try_into().expect("fixed slice");
        if workspace.is_nil() || item.is_nil() {
            return Err(IdentityError::NilIdentifier);
        }
        if let Some(expected) = expect_workspace {
            if workspace != *expected.as_uuid() {
                return Err(IdentityError::WorkspaceMismatch);
            }
        }
        let workspace = WorkspaceId::from_uuid(workspace).map_err(|_| IdentityError::NilIdentifier)?;
        let item = ItemId::from_uuid(item).map_err(|_| IdentityError::NilIdentifier)?;
        let version = if version_bytes == [0u8; 16] {
            None
        } else {
            let uuid = Uuid::from_bytes(version_bytes);
            if uuid.is_nil() {
                return Err(IdentityError::NilIdentifier);
            }
            Some(VersionId::from_uuid(uuid).map_err(|_| IdentityError::NilIdentifier)?)
        };
        Ok(Self {
            workspace,
            item,
            version,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (WorkspaceId, ItemId, VersionId) {
        (
            WorkspaceId::new(),
            ItemId::new(),
            VersionId::new(),
        )
    }

    #[test]
    fn file_identity_round_trips() {
        let (workspace, item, version) = ids();
        let id = PlaceholderIdentity::file(workspace, item, version);
        let bytes = id.encode();
        assert_eq!(bytes.len(), IDENTITY_LEN);
        assert_eq!(&bytes[0..4], b"HFDR");
        assert_eq!(bytes[4], 1);
        assert_eq!(
            PlaceholderIdentity::decode(&bytes, Some(workspace)),
            Ok(id),
            "round trip"
        );
    }

    #[test]
    fn directory_identity_round_trips_with_zero_version() {
        let (workspace, item, _) = ids();
        let id = PlaceholderIdentity::directory(workspace, item);
        let bytes = id.encode();
        assert!(bytes[37..53].iter().all(|&b| b == 0));
        assert_eq!(PlaceholderIdentity::decode(&bytes, Some(workspace)), Ok(id));
    }

    #[test]
    fn rejects_bad_length_magic_schema_and_workspace() {
        let (workspace, item, version) = ids();
        let bytes = PlaceholderIdentity::file(workspace, item, version).encode();
        assert_eq!(
            PlaceholderIdentity::decode(&bytes[..52], Some(workspace)),
            Err(IdentityError::BadLength)
        );
        let mut wrong_magic = bytes;
        wrong_magic[0] = b'X';
        assert_eq!(
            PlaceholderIdentity::decode(&wrong_magic, Some(workspace)),
            Err(IdentityError::BadMagic)
        );
        let mut wrong_schema = bytes;
        wrong_schema[4] = 2;
        assert_eq!(
            PlaceholderIdentity::decode(&wrong_schema, Some(workspace)),
            Err(IdentityError::UnsupportedSchema { schema: 2 })
        );
        assert_eq!(
            PlaceholderIdentity::decode(&bytes, Some(WorkspaceId::new())),
            Err(IdentityError::WorkspaceMismatch)
        );
    }

    #[test]
    fn rejects_nil_identifiers() {
        let (workspace, item, version) = ids();
        let mut bytes = PlaceholderIdentity::file(workspace, item, version).encode();
        bytes[21..37].copy_from_slice(&[0u8; 16]);
        assert_eq!(
            PlaceholderIdentity::decode(&bytes, Some(workspace)),
            Err(IdentityError::NilIdentifier)
        );
    }

    #[test]
    fn rejects_every_length_other_than_the_exact_record() {
        let (workspace, item, version) = ids();
        let bytes = PlaceholderIdentity::file(workspace, item, version).encode();
        for wrong in [0usize, 1, 4, IDENTITY_LEN - 1, IDENTITY_LEN + 1, IDENTITY_LEN * 2] {
            let mut buffer = bytes.to_vec();
            buffer.resize(wrong, 0);
            assert_eq!(
                PlaceholderIdentity::decode(&buffer, Some(workspace)),
                Err(IdentityError::BadLength),
                "length {wrong} must be rejected"
            );
        }
    }
}
