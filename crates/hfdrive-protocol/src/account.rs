//! Public identity and login progress only. Bearer credentials never enter this model.
use crate::{LoginFlow, LoginPurpose, OwnerKind, ProtocolError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Current provider-owned account session state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationState {
    /// No active account session.
    #[default]
    SignedOut,
    /// An explicitly started interactive grant is pending.
    SigningIn,
    /// A verified account has usable native authorization.
    SignedIn,
    /// A previously known account requires a new interactive grant.
    NeedsSignIn,
}

/// Terminal progress is retained so reconnecting clients can identify their attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginPhase {
    /// Awaiting user or authorization server response.
    Pending,
    /// Verified identity and protected credentials were persisted.
    Completed,
    /// Explicitly cancelled.
    Cancelled,
    /// Login lifetime ended.
    Expired,
    /// The user or server denied consent.
    Denied,
    /// A sanitized failure is available on the account status.
    Failed,
}

/// Immutable, previously verified public userinfo fields; not an access token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountProfile {
    /// SHA-256 of issuer, NUL, and subject.
    pub account_key: String,
    /// Verified OIDC issuer.
    pub issuer: String,
    /// Stable verified OIDC subject.
    pub subject: String,
    /// Current verified personal namespace.
    pub namespace: String,
    /// Display-only user name.
    pub display_name: String,
    /// Actual returned grants; absent means unknown, not a known empty grant set.
    pub granted_scopes: Option<Vec<String>>,
}

/// Sanitized progress; authorization codes, state, nonce and verifier are absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginProgress {
    /// Provider-issued attempt identity.
    pub session_id: Uuid,
    /// Explicit selected flow.
    pub flow: LoginFlow,
    /// Purpose of incremental consent.
    pub purpose: LoginPurpose,
    /// Current or terminal attempt phase.
    pub phase: LoginPhase,
    /// Display-only RFC 3339 expiry.
    pub expires_at: String,
}

/// Full account snapshot, carried even when connection deltas are coalesced.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountStatus {
    /// Authoritative local session state.
    pub state: AuthenticationState,
    /// Last verified identity, if known; state determines whether it is active.
    pub profile: Option<AccountProfile>,
    /// Current or most recent interactive attempt.
    pub login: Option<LoginProgress>,
    /// Sanitized actionable authentication failure.
    pub last_error: Option<ProtocolError>,
}

/// Canonical DPAPI IPC entropy input, followed by the operation UUID's 16 RFC bytes.
/// Display names and mutable endpoint locators are deliberately not identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationProtectionContext {
    /// Reserved or connected local connection identity.
    pub connection_id: Uuid,
    /// Exact issuer/subject digest.
    pub account_key: String,
    /// Verified OIDC issuer.
    pub issuer: String,
    /// Verified OIDC subject.
    pub subject: String,
    /// Stable owner identity.
    pub owner_id: String,
    /// Personal versus organization owner.
    pub owner_kind: OwnerKind,
    /// Stable bucket identity.
    pub bucket_id: String,
    /// Managed workspace identity.
    pub workspace_id: Uuid,
    /// Exact managed prefix.
    pub prefix: String,
}

impl PublicationProtectionContext {
    /// SHA-256(canonical context || operation UUID RFC bytes), identical on both pipe ends.
    pub fn entropy(&self, operation_id: Uuid) -> Result<[u8; 32], crate::ProtocolCodecError> {
        use sha2::{Digest, Sha256};
        if operation_id.is_nil() {
            return Err(crate::ProtocolCodecError::InvalidField("operation_id"));
        }
        let canonical = crate::envelope::canonical_body(self)?;
        let mut hash = Sha256::new();
        hash.update(canonical);
        hash.update(operation_id.as_bytes());
        Ok(hash.finalize().into())
    }
}

/// Complete preview category counts, independent of bounded representative path records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollisionCategorySummary {
    /// The category requiring review.
    pub kind: crate::CollisionKind,
    /// Number of affected entries in the complete persisted preview.
    #[serde(with = "crate::dec_u64")]
    pub count: u64,
}
