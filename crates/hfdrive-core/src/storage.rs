//! Validated resource bindings and immutable transfer descriptors; no SDK types.
use crate::ids::{AccountKey, CommitId, SnapshotId, UploadId, VersionId, WorkspaceId, deserialize_id};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::{fmt, fmt::Write, ops::Range, path::PathBuf, str::FromStr};

const MAX_KEY_BYTES: usize = 1024;
const MAX_IMMUTABLE_SUFFIX_BYTES: usize = 77;

#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
pub enum StorageValueError {
    #[error("invalid canonical relative storage key")]
    Key,
    #[error("invalid managed storage prefix")]
    Prefix,
    #[error("invalid canonical resource identity")]
    Identity,
    #[error("invalid lowercase hexadecimal digest or Xet identifier")]
    Digest,
    #[error("range is inverted or exceeds the immutable object")]
    Range,
}

fn validate_hex(value: &str) -> Result<(), StorageValueError> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(StorageValueError::Digest);
    }
    Ok(())
}

/// Application SHA-256, not an Xet identifier or an HTTP validator.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Sha256Digest([u8; 32]);
impl Sha256Digest {
    pub const fn from_bytes(value: [u8; 32]) -> Self { Self(value) }
    pub const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
    pub fn of(bytes: &[u8]) -> Self { Self(Sha256::digest(bytes).into()) }
}
impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 { write!(f, "{byte:02x}")?; }
        Ok(())
    }
}
impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(self, f) }
}
impl FromStr for Sha256Digest {
    type Err = StorageValueError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        validate_hex(value)?;
        let mut bytes = [0; 32];
        hex::decode_to_slice(value, &mut bytes).map_err(|_| StorageValueError::Digest)?;
        Ok(Self(bytes))
    }
}
impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_id(deserializer)
    }
}

macro_rules! text_value {
    ($name:ident, $validator:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);
        impl $name {
            pub fn new(value: String) -> Result<Self, StorageValueError> {
                $validator(&value)?;
                Ok(Self(value))
            }
            pub fn as_str(&self) -> &str { &self.0 }
            /// Validate a borrowed candidate without allocating an owned identifier.
            pub fn validate(value: &str) -> Result<(), StorageValueError> { $validator(value) }
        }
        impl FromStr for $name {
            type Err = StorageValueError;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                $validator(value)?;
                Ok(Self(value.to_owned()))
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

fn validate_resource_id(value: &str) -> Result<(), StorageValueError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(StorageValueError::Identity);
    }
    Ok(())
}
fn validate_namespace(value: &str) -> Result<(), StorageValueError> {
    if value.is_empty() || value.len() > 96 || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(StorageValueError::Identity);
    }
    Ok(())
}
fn validate_bucket_name(value: &str) -> Result<(), StorageValueError> {
    if value.is_empty() || value.len() > 96 || matches!(value, "." | "..")
        || !value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')) {
        return Err(StorageValueError::Identity);
    }
    Ok(())
}
fn key_shape_is_valid(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_KEY_BYTES
        && !value.chars().any(|c| c.is_control() || matches!(c, '\\' | ':' | '?' | '#' | '%'))
        && value.split('/').all(|part| !matches!(part, "" | "." | ".."))
}
fn validate_key(value: &str) -> Result<(), StorageValueError> {
    if key_shape_is_valid(value) { Ok(()) } else { Err(StorageValueError::Key) }
}
fn validate_prefix(value: &str) -> Result<(), StorageValueError> {
    // An explicit empty prefix means the bucket root. Reserve space for every v1 key.
    if value.len() > MAX_KEY_BYTES - MAX_IMMUTABLE_SUFFIX_BYTES - 1
        || (!value.is_empty() && !key_shape_is_valid(value)) {
        return Err(StorageValueError::Prefix);
    }
    Ok(())
}

text_value!(OwnerId, validate_resource_id, "Stable opaque HF owner identity, not its display namespace.");
text_value!(BucketId, validate_resource_id, "Stable opaque HF bucket identity, not its current name.");
text_value!(Namespace, validate_namespace, "Verified canonical namespace; safe as one URL/DNS component.");
text_value!(BucketName, validate_bucket_name, "Bare bucket name. The native adapter also applies the pinned SDK's creation rules.");
text_value!(RelativeKey, validate_key, "Canonical bucket-relative key; no URL, traversal, or encoded-delimiter ambiguity.");
text_value!(RemotePrefix, validate_prefix, "Canonical managed prefix, including an explicitly selected bucket root.");
text_value!(XetFileId, validate_hex, "Opaque native Xet file identifier in SDK hexadecimal spelling; never an application SHA-256.");

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerKind { Personal, Organization }

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BucketBinding {
    pub bucket_id: BucketId,
    pub bucket_name: BucketName,
    pub owner_id: OwnerId,
    pub owner_kind: OwnerKind,
    pub owner_namespace: Namespace,
}

/// Exact authorization/namespace binding. Mutable display locators never replace stable IDs.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriveBinding {
    pub account_key: AccountKey,
    pub bucket: BucketBinding,
    pub prefix: RemotePrefix,
    pub workspace_id: WorkspaceId,
}

/// The only four immutable v1 key shapes. HEAD cannot be passed as an immutable upload.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ImmutableKey {
    Payload(UploadId),
    Version(VersionId),
    Catalog(Sha256Digest),
    Commit(CommitId),
}
impl ImmutableKey {
    pub const fn encoded_len(self) -> usize {
        match self { Self::Payload(_) => 44, Self::Version(_) => 50, Self::Catalog(_) => 77, Self::Commit(_) => 49 }
    }
}
impl fmt::Display for ImmutableKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Payload(id) => write!(f, "objects/{id}"),
            Self::Version(id) => write!(f, "versions/{id}.json"),
            Self::Catalog(id) => write!(f, "catalog/{id}.json"),
            Self::Commit(id) => write!(f, "commits/{id}.json"),
        }
    }
}
impl RemotePrefix {
    fn start_key(&self, suffix_len: usize) -> String {
        let mut key = String::with_capacity(self.0.len() + usize::from(!self.0.is_empty()) + suffix_len);
        if !self.0.is_empty() { key.push_str(&self.0); key.push('/'); }
        key
    }
    pub fn immutable_key(&self, suffix: ImmutableKey) -> RelativeKey {
        let mut key = self.start_key(suffix.encoded_len());
        write!(&mut key, "{suffix}").expect("formatting into a String cannot fail");
        RelativeKey(key)
    }
    pub fn head_key(&self) -> RelativeKey {
        let mut key = self.start_key(4);
        key.push_str("HEAD");
        RelativeKey(key)
    }
    pub fn overlaps(&self, other: &Self) -> bool {
        fn contains(parent: &str, child: &str) -> bool {
            parent.is_empty() || parent == child
                || child.strip_prefix(parent).is_some_and(|suffix| suffix.starts_with('/'))
        }
        contains(&self.0, &other.0) || contains(&other.0, &self.0)
    }
}

/// A relative payload reference can only select objects/<validated-upload-uuid>.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PayloadKey(UploadId);
impl PayloadKey {
    pub const fn new(upload_id: UploadId) -> Self { Self(upload_id) }
    pub const fn upload_id(self) -> UploadId { self.0 }
    pub const fn immutable_key(self) -> ImmutableKey { ImmutableKey::Payload(self.0) }
}
impl fmt::Display for PayloadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "objects/{}", self.0) }
}
impl FromStr for PayloadKey {
    type Err = StorageValueError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let id = value.strip_prefix("objects/").ok_or(StorageValueError::Key)?;
        Ok(Self(id.parse().map_err(|_| StorageValueError::Key)?))
    }
}
impl Serialize for PayloadKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> { serializer.collect_str(self) }
}
impl<'de> Deserialize<'de> for PayloadKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> { deserialize_id(deserializer) }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRef {
    pub key: PayloadKey,
    pub sha256: Sha256Digest,
    pub size: u64,
    pub xet_file_id: XetFileId,
}

/// Construct only after coherent capture and durable flush; never points at the user's mutable source.
#[derive(Debug, Clone)]
pub struct StableSnapshot {
    pub snapshot_id: SnapshotId,
    pub upload_id: UploadId,
    pub path: PathBuf,
    pub size: u64,
    pub sha256: Sha256Digest,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ByteRange { start: u64, end_exclusive: u64 }
impl ByteRange {
    pub fn new(start: u64, end_exclusive: u64, object_size: u64) -> Result<Self, StorageValueError> {
        let value = Self { start, end_exclusive };
        value.validate_for(object_size)?;
        Ok(value)
    }
    pub fn validate_for(self, object_size: u64) -> Result<(), StorageValueError> {
        if self.start > self.end_exclusive || self.end_exclusive > object_size {
            return Err(StorageValueError::Range);
        }
        Ok(())
    }
    pub const fn start(self) -> u64 { self.start }
    pub const fn end_exclusive(self) -> u64 { self.end_exclusive }
    pub const fn len(self) -> u64 { self.end_exclusive - self.start }
    pub const fn is_empty(self) -> bool { self.start == self.end_exclusive }
    pub fn as_range(self) -> Range<u64> { self.start..self.end_exclusive }
}
