use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::{fmt, str::FromStr};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
#[error("expected a nonzero, lowercase, hyphenated UUID")]
pub struct InvalidId;

macro_rules! identifier {
    ($($name:ident),+ $(,)?) => {$(
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name(Uuid);

        impl $name {
            pub fn new() -> Self { Self(Uuid::new_v4()) }
            pub fn from_uuid(value: Uuid) -> Result<Self, InvalidId> {
                if value.is_nil() { Err(InvalidId) } else { Ok(Self(value)) }
            }
            pub const fn as_uuid(&self) -> &Uuid { &self.0 }
            pub const fn as_bytes(&self) -> &[u8; 16] { self.0.as_bytes() }
        }
        impl Default for $name {
            fn default() -> Self { Self::new() }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
        }
        impl FromStr for $name {
            type Err = InvalidId;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                if value.len() != 36 || value.bytes().any(|c| c.is_ascii_uppercase()) {
                    return Err(InvalidId);
                }
                let id = Uuid::parse_str(value).map_err(|_| InvalidId)?;
                let mut canonical = Uuid::encode_buffer();
                if id.hyphenated().encode_lower(&mut canonical) != value { return Err(InvalidId); }
                Self::from_uuid(id)
            }
        }
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.0.serialize(serializer)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserialize_id(deserializer)
            }
        }
    )+};
}

identifier!(ConnectionId, WorkspaceId, ItemId, VersionId, OperationId, CommitId,
    GenerationId, DeviceId, UploadId, SnapshotId, TransferId, ActionId, SetupId, ConflictId);

/// Stable credential partition; namespace display names never select an account.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AccountKey([u8; 32]);

impl AccountKey {
    pub fn from_subject(issuer: &str, subject: &str) -> Self {
        let mut digest = Sha256::new();
        digest.update(issuer.as_bytes());
        digest.update([0]);
        digest.update(subject.as_bytes());
        Self(digest.finalize().into())
    }
    pub const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}
impl fmt::Display for AccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 { write!(f, "{byte:02x}")?; }
        Ok(())
    }
}
impl fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(self, f) }
}
impl FromStr for AccountKey {
    type Err = InvalidId;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(InvalidId);
        }
        let mut bytes = [0; 32];
        hex::decode_to_slice(value, &mut bytes).map_err(|_| InvalidId)?;
        Ok(Self(bytes))
    }
}
impl Serialize for AccountKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
impl<'de> Deserialize<'de> for AccountKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_id(deserializer)
    }
}

pub(crate) fn deserialize_id<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: fmt::Display,
{
    struct ParseId<T>(std::marker::PhantomData<T>);
    impl<'de, T: FromStr> serde::de::Visitor<'de> for ParseId<T>
    where T::Err: fmt::Display {
        type Value = T;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a canonical HF Drive identifier")
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<T, E> {
            value.parse().map_err(E::custom)
        }
    }
    deserializer.deserialize_str(ParseId(std::marker::PhantomData))
}
