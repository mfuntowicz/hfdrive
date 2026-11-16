//! Supplemental S3 credential record: zeroizing, redacted, DPAPI-bound.
//!
//! The record is the plaintext payload the provider protects with user-scoped
//! DPAPI (composed over `hfdrive_protocol::PublicationProtectionContext::entropy`).
//! It contains the whole key pair plus the exact protection context. There is
//! no serialization path other than [`SupplementalCredentialRecord::encode`];
//! the plaintext never crosses IPC and the pair is never logged.

use hfdrive_protocol::PublicationProtectionContext;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

use crate::PublicationError;

const MAX_KEY_ID_BYTES: usize = 128;
const MAX_SECRET_BYTES: usize = 256;

/// Whole-pair supplemental credential record bound to one protection context.
///
/// Both pair fields are zeroizing and redacted in `Debug`. Access to the pair
/// is crate-internal so no IPC, status or diagnostics path can read it.
pub struct SupplementalCredentialRecord {
    context: PublicationProtectionContext,
    key_id: Zeroizing<String>,
    secret_key: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordWire {
    context: PublicationProtectionContext,
    key_id: Zeroizing<String>,
    secret_key: Zeroizing<String>,
}

#[derive(Serialize)]
struct RecordWireRef<'a> {
    context: &'a PublicationProtectionContext,
    key_id: &'a str,
    secret_key: &'a str,
}

impl SupplementalCredentialRecord {
    /// Validates and wraps a credential pair with its exact binding context.
    pub fn new(
        context: PublicationProtectionContext,
        key_id: String,
        secret_key: String,
    ) -> Result<Self, PublicationError> {
        validate_member(&key_id, MAX_KEY_ID_BYTES)?;
        validate_member(&secret_key, MAX_SECRET_BYTES)?;
        Ok(Self {
            context,
            key_id: Zeroizing::new(key_id),
            secret_key: Zeroizing::new(secret_key),
        })
    }

    /// The exact binding context stored with the pair.
    pub fn context(&self) -> &PublicationProtectionContext {
        &self.context
    }

    /// Rebinds the same zeroizing key pair to a different protection context.
    ///
    /// Internal credential repair only: the source record is decoded with its
    /// original entropy and context, then its pair moves into a record bound
    /// to the target's existing protection context so it can be re-protected
    /// there. The source record itself is never modified and the pair never
    /// leaves zeroizing storage.
    pub fn rebind(self, context: PublicationProtectionContext) -> Self {
        Self { context, key_id: self.key_id, secret_key: self.secret_key }
    }

    /// Requires exact equality with the expected context (including `connection_id`).
    pub fn validate_context(
        &self,
        expected: &PublicationProtectionContext,
    ) -> Result<(), PublicationError> {
        if &self.context == expected {
            Ok(())
        } else {
            Err(PublicationError::BindingMismatch)
        }
    }

    /// Serializes the whole record for DPAPI protection.
    ///
    /// The returned bytes are the DPAPI plaintext; the caller must protect and
    /// drop them. Entropy is composed by the provider and is never derived here.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, PublicationError> {
        let wire = RecordWireRef {
            context: &self.context,
            key_id: self.key_id.as_str(),
            secret_key: self.secret_key.as_str(),
        };
        let bytes =
            serde_json::to_vec(&wire).map_err(|_| PublicationError::InvalidCredentialRecord)?;
        Ok(Zeroizing::new(bytes))
    }

    /// Parses and re-validates a record produced by [`Self::encode`].
    pub fn decode(plaintext: &[u8]) -> Result<Self, PublicationError> {
        let wire: RecordWire =
            serde_json::from_slice(plaintext).map_err(|_| PublicationError::InvalidCredentialRecord)?;
        validate_member(wire.key_id.as_str(), MAX_KEY_ID_BYTES)?;
        validate_member(wire.secret_key.as_str(), MAX_SECRET_BYTES)?;
        Ok(Self {
            context: wire.context,
            key_id: wire.key_id,
            secret_key: wire.secret_key,
        })
    }

    pub(crate) fn key_id(&self) -> &str {
        self.key_id.as_str()
    }

    pub(crate) fn secret_key(&self) -> &str {
        self.secret_key.as_str()
    }
}

impl PartialEq for SupplementalCredentialRecord {
    fn eq(&self, other: &Self) -> bool {
        self.context == other.context
            && self.key_id.as_str() == other.key_id.as_str()
            && self.secret_key.as_str() == other.secret_key.as_str()
    }
}
impl Eq for SupplementalCredentialRecord {}

impl fmt::Debug for SupplementalCredentialRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SupplementalCredentialRecord")
            .field("context", &self.context)
            .field("key_id", &"<redacted>")
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

fn validate_member(value: &str, max_bytes: usize) -> Result<(), PublicationError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(PublicationError::InvalidCredentialRecord);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn context() -> PublicationProtectionContext {
        PublicationProtectionContext {
            connection_id: Uuid::from_bytes([7; 16]),
            account_key: "a".repeat(64),
            issuer: "https://huggingface.co".to_owned(),
            subject: "subject-1".to_owned(),
            owner_id: "owner-stable-1".to_owned(),
            owner_kind: hfdrive_protocol::OwnerKind::Personal,
            bucket_id: "bucket-stable-1".to_owned(),
            workspace_id: Uuid::from_bytes([9; 16]),
            prefix: "hfdrive/work".to_owned(),
        }
    }

    fn record() -> SupplementalCredentialRecord {
        SupplementalCredentialRecord::new(
            context(),
            "AKIAEXAMPLEKEYID1234".to_owned(),
            "secret-key-material-0123456789".to_owned(),
        )
        .unwrap()
    }

    #[test]
    fn encode_decode_round_trips_pair_and_context() {
        let record = record();
        let bytes = record.encode().unwrap();
        let decoded = SupplementalCredentialRecord::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded, record);
        assert_eq!(decoded.key_id(), "AKIAEXAMPLEKEYID1234");
        assert_eq!(decoded.secret_key(), "secret-key-material-0123456789");
    }

    #[test]
    fn debug_redacts_the_whole_pair() {
        let text = format!("{:?}", record());
        assert!(!text.contains("AKIAEXAMPLEKEYID1234"), "{text}");
        assert!(!text.contains("secret-key-material-0123456789"), "{text}");
    }

    #[test]
    fn rebind_moves_the_pair_to_the_new_context_only() {
        let source = context();
        let mut target = source.clone();
        target.connection_id = Uuid::from_bytes([8; 16]);
        target.workspace_id = Uuid::from_bytes([10; 16]);
        target.prefix = "hfdrive/repaired".to_owned();

        let rebound = record().rebind(target.clone());
        assert_eq!(rebound.key_id(), "AKIAEXAMPLEKEYID1234");
        assert_eq!(rebound.secret_key(), "secret-key-material-0123456789");
        assert_eq!(rebound.context(), &target);
        assert!(rebound.validate_context(&target).is_ok());
        assert!(rebound.validate_context(&source).is_err(), "rebinding must not leave the old binding accepted");

        // The re-protected record round-trips under the target context and its
        // encoded form carries the pair, never the source context.
        let decoded = SupplementalCredentialRecord::decode(rebound.encode().unwrap().as_slice()).unwrap();
        assert_eq!(decoded, rebound);
        assert!(decoded.validate_context(&source).is_err());
    }

    #[test]
    fn rejects_control_octets_and_oversized_members() {
        assert!(SupplementalCredentialRecord::new(
            context(),
            "key\nid".to_owned(),
            "secret".to_owned()
        )
        .is_err());
        assert!(SupplementalCredentialRecord::new(
            context(),
            "k".repeat(129),
            "secret".to_owned()
        )
        .is_err());
        assert!(SupplementalCredentialRecord::new(
            context(),
            "key".to_owned(),
            String::new()
        )
        .is_err());
    }

    #[test]
    fn validate_context_detects_any_tamper() {
        let record = record();
        assert!(record.validate_context(&context()).is_ok());
        let mut tampered = context();
        tampered.connection_id = Uuid::from_bytes([8; 16]);
        assert!(record.validate_context(&tampered).is_err());
        let mut tampered = context();
        tampered.prefix = "hfdrive/other".to_owned();
        assert!(record.validate_context(&tampered).is_err());
    }

    #[test]
    fn decode_rejects_unknown_fields_and_truncated_json() {
        // Truncated JSON must not half-parse into a record.
        let ok = record().encode().unwrap();
        let mut truncated = ok.to_vec();
        truncated.pop();
        assert!(SupplementalCredentialRecord::decode(&truncated).is_err());
        // Unknown top-level fields must be rejected.
        let mut with_extra = ok.to_vec();
        with_extra.pop();
        with_extra.extend_from_slice(b",\"extra\":1}");
        assert!(SupplementalCredentialRecord::decode(&with_extra).is_err());
    }
}
