//! Product OAuth client configuration and strict OIDC trust settings.
//!
//! The production build uses the product's **own public client** registered at
//! <https://huggingface.co/settings/applications/new> without a client secret
//! and with the exact callback `http://127.0.0.1:53643/oauth/callback`.
//! Production binds the same fixed loopback port because HF validates the
//! complete redirect URI, including its port. The registered client id is fixed
//! in this source file. There is no runtime override: environment variables
//! cannot redirect users to a different OAuth client or service.

use crate::error::AuthError;
use crate::login::LoginPurpose;

/// The product's registered public OAuth client id. This is public
/// configuration, not a secret or an access token.
pub const OAUTH_CLIENT_ID: &str = "fb5faab4-e580-4b13-84d6-1b9217966b8e";

/// Exact loopback callback path registered for the product client.
pub const CALLBACK_PATH: &str = "/oauth/callback";

/// Fixed loopback callback port registered for the product client. HF compares
/// the complete URI, so production cannot use an ephemeral listener port.
pub const CALLBACK_PORT: u16 = 53_643;

/// Default lifetime of a login session (five minutes).
pub const DEFAULT_LOGIN_LIFETIME_SECS: u64 = 300;

/// OIDC trust policy for discovery, endpoints and signatures.
///
/// Production ([`OidcSettings::huggingface`]) pins the issuer to
/// `https://huggingface.co`, requires HTTPS and the trusted host for every
/// endpoint, and accepts only RS256 ID tokens. Fixture construction is for
/// deterministic tests against a local fake provider.
#[derive(Debug, Clone)]
pub struct OidcSettings {
    pub(crate) issuer: String,
    pub(crate) discovery_url: String,
    pub(crate) trusted_hosts: Vec<String>,
    pub(crate) require_https: bool,
    pub(crate) required_issuer: Option<String>,
    pub(crate) login_lifetime_secs: u64,
    /// Fixed for production; zero selects an ephemeral port for local fixtures.
    pub(crate) callback_port: u16,
}

impl OidcSettings {
    /// The one production issuer.
    pub const HUGGINGFACE_ISSUER: &'static str = "https://huggingface.co";
    /// Production discovery document location.
    pub const HUGGINGFACE_DISCOVERY: &'static str =
        "https://huggingface.co/.well-known/openid-configuration";

    /// Production trust policy: issuer exactly `https://huggingface.co`,
    /// HTTPS on the trusted host only, 5-minute login sessions.
    pub fn huggingface() -> Self {
        Self {
            issuer: Self::HUGGINGFACE_ISSUER.to_owned(),
            discovery_url: Self::HUGGINGFACE_DISCOVERY.to_owned(),
            trusted_hosts: vec!["huggingface.co".to_owned()],
            require_https: true,
            required_issuer: Some(Self::HUGGINGFACE_ISSUER.to_owned()),
            login_lifetime_secs: DEFAULT_LOGIN_LIFETIME_SECS,
            callback_port: CALLBACK_PORT,
        }
    }

    /// Deterministic-test policy for a local fixture provider. Validation is
    /// identical apart from the pinned host/issuer and login lifetime.
    #[doc(hidden)]
    pub fn fixture(
        issuer: &str,
        discovery_url: &str,
        trusted_host: &str,
        login_lifetime_secs: u64,
    ) -> Self {
        Self {
            issuer: issuer.to_owned(),
            discovery_url: discovery_url.to_owned(),
            trusted_hosts: vec![trusted_host.to_owned()],
            require_https: false,
            required_issuer: Some(issuer.to_owned()),
            login_lifetime_secs: login_lifetime_secs.max(1),
            callback_port: 0,
        }
    }

    /// Validate a discovered endpoint URL against this policy.
    pub(crate) fn validate_endpoint(&self, url: &str) -> Result<(), AuthError> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or(AuthError::ProviderMetadata)?;
        if self.require_https && !scheme.eq_ignore_ascii_case("https") {
            return Err(AuthError::ProviderMetadata);
        }
        if !scheme.eq_ignore_ascii_case("https") && !scheme.eq_ignore_ascii_case("http") {
            return Err(AuthError::ProviderMetadata);
        }
        if url.chars().any(|c| c <= ' ' || c == '\u{7f}') {
            return Err(AuthError::ProviderMetadata);
        }
        let host_port = rest.split(['/', '?', '#']).next().unwrap_or("");
        let host = host_port.split(':').next().unwrap_or("");
        if host.is_empty() || !self.trusted_hosts.iter().any(|h| h == host) {
            return Err(AuthError::ProviderMetadata);
        }
        Ok(())
    }

    /// Validate the discovered issuer against this policy.
    pub(crate) fn validate_issuer(&self, issuer: &str) -> Result<(), AuthError> {
        if let Some(required) = &self.required_issuer {
            if issuer != required {
                return Err(AuthError::ProviderMetadata);
            }
        }
        self.validate_endpoint(issuer)
    }
}

/// Product OAuth client configuration.
#[derive(Debug, Clone, Default)]
pub struct AuthConfig {
    client_id: Option<String>,
}

impl AuthConfig {
    /// The only production OAuth configuration. No environment variable,
    /// command-line argument, IPC field, or user setting can replace it.
    pub fn production() -> Self {
        Self::with_client_id(Some(OAUTH_CLIENT_ID.to_owned()))
    }

    /// Explicit client id (None/blank = not configured).
    pub fn with_client_id(client_id: Option<String>) -> Self {
        let trimmed = client_id.filter(|id| !id.trim().is_empty());
        Self { client_id: trimmed }
    }

    /// Whether a usable client id is configured.
    pub fn is_configured(&self) -> bool {
        self.client_id.is_some()
    }

    pub(crate) fn require_client_id(&self) -> Result<&str, AuthError> {
        self.client_id
            .as_deref()
            .ok_or(AuthError::OAuthClientNotConfigured)
    }
}

/// Base scopes requested on every login.
pub const BASE_SCOPES: &[&str] = &["openid", "profile", "read-memberships"];
/// Additional scopes for read-only storage access.
pub const READ_STORAGE_SCOPES: &[&str] = &["read-repos"];
/// Additional scopes for read/write storage access.
pub const WRITE_STORAGE_SCOPES: &[&str] = &["read-repos", "write-repos"];
/// Additional scopes for bucket creation.
pub const CREATE_STORAGE_SCOPES: &[&str] = &["read-repos", "write-repos", "manage-repos"];

/// Scope set for a login purpose. Incremental consent: storage access adds
/// existing grants plus `read-repos`; writes add `write-repos`; only explicit
/// creation adds `manage-repos`. No `*-buckets` or `offline_access` scopes are
/// ever invented.
pub fn scopes_for(purpose: LoginPurpose) -> Vec<&'static str> {
    let mut scopes: Vec<&'static str> = BASE_SCOPES.to_vec();
    match purpose {
        LoginPurpose::Signin => {}
        LoginPurpose::ReadStorage => scopes.extend_from_slice(READ_STORAGE_SCOPES),
        LoginPurpose::WriteStorage => scopes.extend_from_slice(WRITE_STORAGE_SCOPES),
        LoginPurpose::CreateStorage => scopes.extend_from_slice(CREATE_STORAGE_SCOPES),
    }
    scopes
}

/// The exact requested scope strings (for consent parameter building).
pub fn scope_strings(purpose: LoginPurpose) -> Vec<String> {
    scopes_for(purpose).into_iter().map(str::to_owned).collect()
}

/// Whether `granted` covers `purpose`. `None` granted list = unknown
/// (provider omitted the `scope` response field): treated as covered but
/// recorded as unknown in the profile.
pub fn purpose_covered(purpose: LoginPurpose, granted: Option<&[String]>) -> bool {
    let Some(granted) = granted else {
        return true;
    };
    scopes_for(purpose)
        .iter()
        .all(|need| granted.iter().any(|g| g == need))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_uses_only_the_registered_public_client() {
        let production = AuthConfig::production();
        assert!(production.is_configured());
        assert_eq!(production.require_client_id().unwrap(), OAUTH_CLIENT_ID);
        assert_eq!(OAUTH_CLIENT_ID, "fb5faab4-e580-4b13-84d6-1b9217966b8e");
        assert_eq!(CALLBACK_PORT, 53_643);
        assert_eq!(OidcSettings::huggingface().callback_port, CALLBACK_PORT);
        assert_eq!(OidcSettings::fixture("http://fixture", "http://fixture/discovery", "127.0.0.1", 300).callback_port, 0);
        assert!(AuthConfig::default().require_client_id().is_err());
    }
}
