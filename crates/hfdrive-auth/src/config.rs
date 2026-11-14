//! Product OAuth client configuration and strict OIDC trust settings.
//!
//! The production build uses the product's **own public client** registered at
//! <https://huggingface.co/settings/applications/new> without a client secret
//! and with the exact callback `http://127.0.0.1/oauth/callback` (the runtime
//! listener binds `127.0.0.1:0`; only the port differs). The client id comes
//! from `HFDRIVE_OAUTH_CLIENT_ID` at process start. When it is absent, login
//! fails with [`AuthError::OAuthClientNotConfigured`](crate::AuthError) —
//! no borrowed, placeholder or fake client id is ever substituted.

use crate::error::AuthError;
use crate::login::LoginPurpose;

/// Environment variable holding the product OAuth client id (public client).
pub const OAUTH_CLIENT_ID_ENV: &str = "HFDRIVE_OAUTH_CLIENT_ID";

/// Exact loopback callback path registered for the product client.
pub const CALLBACK_PATH: &str = "/oauth/callback";

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
    /// Production configuration: read `HFDRIVE_OAUTH_CLIENT_ID` once at
    /// startup. Absent or blank means "not configured"; login then fails with
    /// [`AuthError::OAuthClientNotConfigured`] and nothing is sent anywhere.
    pub fn from_env() -> Self {
        Self::with_client_id(std::env::var(OAUTH_CLIENT_ID_ENV).ok())
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
