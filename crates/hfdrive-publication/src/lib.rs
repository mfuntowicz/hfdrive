//! Conditional publication boundary; ETags are opaque and never content hashes.
//!
//! This crate owns exactly one thing: the explicitly credentialed HF S3
//! transport used for the managed `HEAD` compare-and-swap and for the
//! provider-owned probe namespace. Immutable metadata and payload bytes are
//! produced through the native Xet path (`hfdrive-hf`); this transport can only
//! read them back for ancestry/coherence and can only write the managed `HEAD`
//! or keys under an explicitly owned `hfdrive-probe/<run-id>/` namespace.
//!
//! Authorization model: the supplemental S3 key pair is a separate
//! authorization from native OAuth and is entered through the provider's DPAPI
//! setup. Every dispatch requires a live [`hfdrive_auth::AuthorizationLease`]
//! whose account matches the bound drive; that lease gate is an epoch check
//! only. The caller must verify current native resource authorization before
//! every publication transaction — an epoch is not resource permission.
#![forbid(unsafe_code)]

pub mod ancestry;
pub mod binding;
pub mod coordinator;
pub mod credentials;
pub mod probe;
pub mod transport;

pub use binding::{AccountIdentity, EndpointAddress, PublicationBinding};
pub use credentials::SupplementalCredentialRecord;
pub use transport::{
    BoundedRecord, HeadRecord, MetadataRecord, ProbeKey, ProbeNamespace, ProbeRecord,
    S3Transport, MAX_HEAD_BYTES, MAX_PROBE_READ_BYTES, MAX_PROBE_RECORD_BYTES,
};

/// A strong HTTP entity-tag exactly as returned or required on the wire.
///
/// Validation accepts exactly one strong quoted tag: `"..."` with `etagc`
/// octets only (RFC 9110 `opaque-tag`). Wildcards (`*`), lists (`"a", "b"`),
/// weak tags (`W/"..."`), unquoted values and control octets are rejected so a
/// validator can never broaden a conditional request or inject a header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpaqueEtag(String);
impl OpaqueEtag {
    /// Validates and wraps an entity-tag in its exact wire spelling.
    pub fn new(value: String) -> Result<Self, PublicationError> {
        let inner = value
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .ok_or(PublicationError::InvalidResponse)?;
        // Quotes are part of the validator: "*" is an opaque tag, never the wildcard *.
        // Enforce etagc = %x21 / %x23-7E / obs-text without interpreting its contents.
        if !inner.bytes().all(|b| b == 0x21 || (0x23..=0x7E).contains(&b) || b >= 0x80)
        {
            return Err(PublicationError::InvalidResponse);
        }
        Ok(Self(value))
    }
    /// The validator including its quotes, ready for `If-Match`.
    pub fn as_str(&self) -> &str { &self.0 }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishOutcome { Committed, PreconditionFailed, Ambiguous }

#[derive(Debug, thiserror::Error)]
pub enum PublicationError {
    #[error("publication HEAD is absent")]
    Absent,
    #[error("publication access was denied")]
    PermissionDenied,
    #[error("native authorization must be renewed")]
    NeedsSignIn,
    #[error("supplemental publication credentials are required")]
    StorageSetupRequired,
    #[error("managed format is unsupported")]
    UnsupportedFormat,
    #[error("publication response violated the storage contract")]
    InvalidResponse,
    #[error("publication transport failed")]
    Transport,
    #[error("publication was cancelled; accepted mutations require recovery")]
    Cancelled,
    #[error("publication identity, binding, and credentials do not agree")]
    BindingMismatch,
    #[error("publication record exceeds its size bound")]
    RecordTooLarge,
    #[error("publication key is outside the managed HEAD and owned probe namespaces")]
    KeyOutOfScope,
    #[error("publication credential record is malformed")]
    InvalidCredentialRecord,
    #[error("referenced managed content is unavailable; no deletion is inferred")]
    RemoteContentUnavailable,
    #[error("immutable publication identity or record bytes conflict")]
    ImmutableRecordConflict,
    #[error("committed ancestry search is incomplete")]
    SearchIncomplete,
    #[error("referenced payload lacks its native Xet identity")]
    XetRequired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etag_preserves_exact_quotes_and_does_not_interpret_hashes() {
        let etag = OpaqueEtag::new("\"opaque-value-7\"".into()).unwrap();
        assert_eq!(etag.as_str(), "\"opaque-value-7\"");
        assert!(OpaqueEtag::new("opaque\r\ninjected: header".into()).is_err());
    }

    #[test]
    fn etag_accepts_strong_quoted_shapes() {
        for value in ["\"0123456789abcdef\"", "\"1234567890abcdef-2\"", "\"\"", "\"*\"", "\"x-y_z.w!\""] {
            let etag = OpaqueEtag::new(value.to_owned()).unwrap();
            assert_eq!(etag.as_str(), value);
        }
    }

    #[test]
    fn etag_rejects_wildcard_weak_list_and_unquoted_inputs() {
        for value in ["*", "W/\"abc\"", "\"a\", \"b\"", "abc", "", "\"abc", "abc\"", "\"a\" \"b\""] {
            assert!(
                OpaqueEtag::new(value.to_owned()).is_err(),
                "must reject {value:?}"
            );
        }
    }

    #[test]
    fn etag_rejects_control_and_non_etagc_octets() {
        for value in ["\"a\tb\"", "\"a b\"", "\"a\u{7f}b\"", "\"a\u{0}b\"", "\"a\nb\""] {
            assert!(
                OpaqueEtag::new(value.to_owned()).is_err(),
                "must reject {value:?}"
            );
        }
    }

    #[test]
    fn etag_rejects_extra_quotes_inside_the_tag() {
        for value in ["\"\"\"", "\"a\"\"", "\"\"a\"", "\"a\"b\""] {
            assert!(
                OpaqueEtag::new(value.to_owned()).is_err(),
                "must reject {value:?}"
            );
        }
    }
}
