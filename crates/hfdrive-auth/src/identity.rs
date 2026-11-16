//! Immutable verified account identity snapshots.
//!
//! The personal namespace and organization candidates come from the verified
//! ID token plus userinfo after strict subject agreement. The personal
//! namespace must validate as a [`Namespace`]: absent or invalid
//! `preferred_username` rejects the identity — nothing is published or
//! persisted and no namespace is ever invented from the subject. Org display
//! names are optional display hints and never fabricated canonical
//! namespaces. Membership/role/restriction fields are **display hints only** —
//! they never authorize anything by themselves; real resource access is
//! probed separately.

use hfdrive_core::ids::AccountKey;
use hfdrive_core::storage::Namespace;
use serde::{Deserialize, Serialize};

/// Organization display hint: `orgs[].sub`, role and restriction data as
/// provided by the verified userinfo response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgCandidate {
    /// Verified organization subject (`orgs[].sub`), used for consent
    /// (`orgIds=`) and identity binding. Never a namespace display string.
    pub subject: String,
    /// Display name when provided by the provider. Optional and never a
    /// fabricated canonical namespace.
    pub name: Option<String>,
    /// Role display hint (e.g. `admin`, `member`). Not authorization.
    pub role: Option<String>,
    /// Restriction display hints (e.g. blocked features). Not authorization.
    pub restrictions: Vec<String>,
}

/// A verified organization connection within the current session.
///
/// Consent provenance is tracked explicitly: `consented_this_session` means
/// the login passed `orgIds=<this org sub>` for this subject and the provider
/// completed it. The single login remains authoritative for all earlier
/// verified orgs — additional org connections never silently drop earlier
/// grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedOrg {
    /// Verified organization subject.
    pub subject: String,
    /// Optional display name; never a canonical namespace.
    pub name: Option<String>,
    /// Role display hint.
    pub role: Option<String>,
    /// Restriction display hints.
    pub restrictions: Vec<String>,
    /// Whether this login carried an explicit `orgIds` re-consent for this
    /// subject that completed.
    pub consented_this_session: bool,
}

/// Trusted avatar host root: `huggingface.co` or any subdomain (the real
/// avatar CDN is `cdn-avatars.huggingface.co`).
const AVATAR_HOST: &str = "huggingface.co";

/// Validate a verified userinfo `picture` claim for display-only use.
///
/// Returns the URL string only when it is HTTPS, carries no embedded
/// username/password, and its host is exactly `huggingface.co` or a subdomain
/// of it. Anything else (including an external host) returns `None` — this is
/// never an identity or login failure. The URL is display-only and is never
/// fetched here or combined with any bearer credential.
pub(crate) fn validate_avatar_url(raw: Option<&str>) -> Option<String> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    let url = reqwest::Url::parse(raw).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    if url.username() != "" || url.password().is_some() {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    if host != AVATAR_HOST && !host.ends_with(&format!(".{AVATAR_HOST}")) {
        return None;
    }
    Some(raw.to_owned())
}

/// Immutable verified identity of one signed-in account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountProfile {
    /// Credential partition key: SHA-256(issuer, NUL, subject).
    pub account_key: AccountKey,
    /// Exact issuer (`https://huggingface.co` in production).
    pub issuer: String,
    /// Verified subject (`sub`, the same in ID token and userinfo).
    pub subject: String,
    /// Verified canonical personal namespace. Validated to
    /// [`Namespace`]: an absent or invalid `preferred_username` rejects the
    /// identity before publication or persistence.
    pub namespace: Namespace,
    /// Verified public avatar URL for display only (validated HTTPS
    /// `huggingface.co`/subdomain, no embedded credentials). `None` when the
    /// verified userinfo `picture` claim is absent or rejected — never a
    /// credential and never required for identity or login.
    #[serde(default)]
    pub avatar_url: Option<String>,
    /// Verified organization connections.
    pub orgs: Vec<VerifiedOrg>,
    /// Granted scopes, as returned by the token endpoint, or `None` when the
    /// provider omitted the `scope` field. `None` means **unknown**, never
    /// "proven empty".
    pub granted_scopes: Option<Vec<String>>,
    /// Whether the granted scopes (or their recorded unknown state) cover the
    /// purpose of the login session that produced this snapshot.
    pub purpose_covered: bool,
    /// True when an explicit org re-consent was requested and completed in
    /// the session that produced this snapshot.
    pub org_consent_requested: bool,
    /// True when the current credentials cannot perform interactive
    /// incremental consent (device-flow session or absent refresh
    /// capability): a purpose exceeding the granted scopes then requires a
    /// fresh PKCE re-consent rather than pretending access.
    pub reconsent_required_for_storage: bool,
}

impl AccountProfile {
    /// Whether `org_sub` is a verified organization subject of this identity.
    pub fn has_org_subject(&self, org_sub: &str) -> bool {
        self.orgs.iter().any(|o| o.subject == org_sub)
    }

    /// Authorization-relevant equality: every field **except** the
    /// display-only `avatar_url`.
    ///
    /// Credential refresh compares this, never derived equality, so a
    /// display-only avatar difference (an omitted `picture` claim on one
    /// userinfo response, or a restored-record backfill) can never count as an
    /// authorization change, advance the authorization epoch, or revoke
    /// leases.
    pub(crate) fn same_authorization(&self, other: &Self) -> bool {
        self.account_key == other.account_key
            && self.issuer == other.issuer
            && self.subject == other.subject
            && self.namespace == other.namespace
            && self.orgs == other.orgs
            && self.granted_scopes == other.granted_scopes
            && self.purpose_covered == other.purpose_covered
            && self.org_consent_requested == other.org_consent_requested
            && self.reconsent_required_for_storage == other.reconsent_required_for_storage
    }

    /// Sanitized projection suitable for protocol/status surfaces: contains
    /// no tokens, codes or verifiers by construction.
    pub fn summary(&self) -> AccountProfileSummary {
        AccountProfileSummary {
            account_key: self.account_key,
            issuer: self.issuer.clone(),
            subject: self.subject.clone(),
            namespace: self.namespace.as_str().to_owned(),
            avatar_url: validate_avatar_url(self.avatar_url.as_deref()),
            orgs: self
                .orgs
                .iter()
                .map(|o| OrgCandidate {
                    subject: o.subject.clone(),
                    name: o.name.clone(),
                    role: o.role.clone(),
                    restrictions: o.restrictions.clone(),
                })
                .collect(),
            granted_scopes: self.granted_scopes.clone(),
        }
    }
}

/// Sanitized display projection of an [`AccountProfile`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountProfileSummary {
    /// Credential partition key.
    pub account_key: AccountKey,
    /// Issuer.
    pub issuer: String,
    /// Verified subject.
    pub subject: String,
    /// Verified canonical personal namespace (validated).
    pub namespace: String,
    /// Validated display-only avatar URL (`https` `huggingface.co`/subdomain).
    /// Absent when unknown or rejected; never a credential.
    pub avatar_url: Option<String>,
    /// Verified organizations (display hints).
    pub orgs: Vec<OrgCandidate>,
    /// Granted scopes or `None` when unknown.
    pub granted_scopes: Option<Vec<String>>,
}

/// Raw additional claims accepted from HF ID tokens/userinfo. Everything here
/// is a display hint except `orgs[].sub`, which is a verified subject
/// identifier used only for consent/binding.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtraClaims {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub restrictions: Vec<String>,
    #[serde(default)]
    pub orgs: Vec<OrgClaim>,
}

/// One raw `orgs[]` entry from HF userinfo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgClaim {
    pub sub: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub restrictions: Vec<String>,
}

impl openidconnect::AdditionalClaims for ExtraClaims {}

impl ExtraClaims {
    /// Map to verified org candidates; empty/duplicate subjects are dropped
    /// (they cannot serve as consent identities).
    pub(crate) fn org_candidates(&self) -> Vec<OrgCandidate> {
        let mut out: Vec<OrgCandidate> = Vec::new();
        for org in &self.orgs {
            if org.sub.is_empty() || out.iter().any(|o: &OrgCandidate| o.subject == org.sub) {
                continue;
            }
            out.push(OrgCandidate {
                subject: org.sub.clone(),
                name: org.name.clone(),
                role: org.role.clone(),
                restrictions: org.restrictions.clone(),
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::validate_avatar_url;

    #[test]
    fn accepts_https_huggingface_root_and_avatar_cdn() {
        assert_eq!(
            validate_avatar_url(Some("https://huggingface.co/avatar.png")).as_deref(),
            Some("https://huggingface.co/avatar.png")
        );
        // The real avatar host observed in production.
        assert_eq!(
            validate_avatar_url(Some(
                "https://cdn-avatars.huggingface.co/v1/production/uploads/test-avatar.jpeg"
            ))
            .as_deref(),
            Some("https://cdn-avatars.huggingface.co/v1/production/uploads/test-avatar.jpeg")
        );
    }

    #[test]
    fn rejects_http_external_and_embedded_credentials() {
        // Plain HTTP is never accepted.
        assert_eq!(validate_avatar_url(Some("http://huggingface.co/avatar.png")), None);
        // External hosts are dropped, never fetched or authorized.
        assert_eq!(
            validate_avatar_url(Some("https://evil.example.com/avatar.png")),
            None
        );
        assert_eq!(
            validate_avatar_url(Some("https://huggingface.co.evil.example.com/a.png")),
            None
        );
        // Embedded username/password is rejected.
        assert_eq!(
            validate_avatar_url(Some("https://user:pass@huggingface.co/avatar.png")),
            None
        );
        assert_eq!(
            validate_avatar_url(Some("https://user@huggingface.co/avatar.png")),
            None
        );
    }

    #[test]
    fn missing_or_malformed_claim_is_none_not_an_error() {
        assert_eq!(validate_avatar_url(None), None);
        assert_eq!(validate_avatar_url(Some("")), None);
        assert_eq!(validate_avatar_url(Some("   ")), None);
        assert_eq!(validate_avatar_url(Some("not a url")), None);
    }
}
