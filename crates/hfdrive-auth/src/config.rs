//! Product OAuth client configuration and strict OIDC trust settings.
//!
//! The production build uses the product's **own public client** registered at
//! <https://huggingface.co/settings/applications/new> without a client secret
//! and with the exact callback `http://127.0.0.1:53643/oauth/callback`.
//! Production binds the same fixed loopback port because HF validates the
//! complete redirect URI, including its port. The registered client id is fixed
//! in this source file. There is no runtime override: environment variables
//! cannot redirect users to a different OAuth client or service.

use openidconnect::url::Url;

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
/// `https://huggingface.co`, requires the exact HTTPS scheme, the exact
/// trusted host and the exact service port for every endpoint, and accepts
/// only RS256 ID tokens. Fixture construction is for deterministic tests
/// against a local fake provider; it authorizes exactly the scheme and port
/// its own issuer/discovery URLs name.
#[derive(Debug, Clone)]
pub struct OidcSettings {
    pub(crate) issuer: String,
    pub(crate) discovery_url: String,
    pub(crate) trusted_hosts: Vec<String>,
    /// Exact allowed URL scheme for every endpoint (lowercase): `https` for
    /// production, the fixture issuer's own scheme for local tests.
    pub(crate) scheme: String,
    /// Complete set of acceptable effective URL ports (an explicit port or the
    /// scheme's default). Production allows exactly the HTTPS service port.
    pub(crate) allowed_ports: Vec<u16>,
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

    /// Production trust policy: issuer exactly `https://huggingface.co`, the
    /// exact HTTPS scheme, trusted host and service port for every endpoint,
    /// 5-minute login sessions.
    pub fn huggingface() -> Self {
        Self {
            issuer: Self::HUGGINGFACE_ISSUER.to_owned(),
            discovery_url: Self::HUGGINGFACE_DISCOVERY.to_owned(),
            trusted_hosts: vec!["huggingface.co".to_owned()],
            scheme: "https".to_owned(),
            allowed_ports: vec![443],
            required_issuer: Some(Self::HUGGINGFACE_ISSUER.to_owned()),
            login_lifetime_secs: DEFAULT_LOGIN_LIFETIME_SECS,
            callback_port: CALLBACK_PORT,
        }
    }

    /// Deterministic-test policy for a local fixture provider. Validation is
    /// identical apart from the pinned host/issuer, the login lifetime, and
    /// the fixture's own scheme and port, which become the exact policy just
    /// as the HTTPS service port is the production policy.
    #[doc(hidden)]
    pub fn fixture(
        issuer: &str,
        discovery_url: &str,
        trusted_host: &str,
        login_lifetime_secs: u64,
    ) -> Self {
        let scheme = Url::parse(issuer)
            .map(|url| url.scheme().to_owned())
            .unwrap_or_else(|_| "http".to_owned());
        let mut allowed_ports: Vec<u16> = Vec::new();
        for candidate in [issuer, discovery_url] {
            if let Some(port) = Url::parse(candidate)
                .ok()
                .and_then(|url| url.port_or_known_default())
            {
                if port != 0 && !allowed_ports.contains(&port) {
                    allowed_ports.push(port);
                }
            }
        }
        Self {
            issuer: issuer.to_owned(),
            discovery_url: discovery_url.to_owned(),
            trusted_hosts: vec![trusted_host.to_owned()],
            scheme,
            allowed_ports,
            required_issuer: Some(issuer.to_owned()),
            login_lifetime_secs: login_lifetime_secs.max(1),
            callback_port: 0,
        }
    }

    /// Validate a discovered endpoint URL against this policy.
    ///
    /// The URL is parsed with [`url::Url`], never by string splitting, so the
    /// scheme, userinfo, host and port components are the parser's own: a
    /// userinfo-embedded "trusted host" (`https://huggingface.co@evil/`) or a
    /// `host:port@host` confusion cannot reach the request path. Requirements:
    ///
    /// * the configured exact scheme (`https` in production);
    /// * empty username **and** password — embedded userinfo is rejected
    ///   outright, never stripped;
    /// * an exact match of the parser-normalized host against the trusted-host
    ///   list;
    /// * an explicit port policy: the effective port (the explicit port, or
    ///   the scheme default when absent) must be nonzero and a member of
    ///   [`Self::allowed_ports`] — the HTTPS service port in production, the
    ///   fixture's own port in tests.
    pub(crate) fn validate_endpoint(&self, url: &str) -> Result<(), AuthError> {
        let parsed = Url::parse(url).map_err(|_| AuthError::ProviderMetadata)?;
        if parsed.scheme() != self.scheme {
            return Err(AuthError::ProviderMetadata);
        }
        // Userinfo bypass: an endpoint may never carry credentials.
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(AuthError::ProviderMetadata);
        }
        // Exact trusted host (parser-normalized): no untrusted host, and no
        // trailing-dot/case/port smuggling past the exact-match list.
        let Some(host) = parsed.host_str() else {
            return Err(AuthError::ProviderMetadata);
        };
        if host.is_empty() || !self.trusted_hosts.iter().any(|trusted| trusted == host) {
            return Err(AuthError::ProviderMetadata);
        }
        // Explicit port policy: `Url` normalizes the scheme's default port
        // away, so an effective default is accepted only because the policy
        // lists it. A zero or unlisted port is rejected.
        let Some(port) = parsed.port_or_known_default() else {
            return Err(AuthError::ProviderMetadata);
        };
        if port == 0 || !self.allowed_ports.contains(&port) {
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

    #[test]
    fn endpoints_reject_userinfo_host_bypass() {
        // A userinfo-embedded "trusted host" must never validate an untrusted
        // authority: `url` puts `huggingface.co` in the username, `evil` in
        // the host. Both the exact host check and the empty-userinfo rule
        // reject it.
        let settings = OidcSettings::huggingface();
        assert_eq!(
            settings.validate_endpoint("https://huggingface.co@evil.example.com/oauth/token"),
            Err(AuthError::ProviderMetadata)
        );
        assert_eq!(
            settings.validate_endpoint("https://user:pass@huggingface.co/oauth/token"),
            Err(AuthError::ProviderMetadata)
        );
        assert_eq!(
            settings.validate_endpoint("https://huggingface.co:8443@evil.example.com/x"),
            Err(AuthError::ProviderMetadata)
        );
        // The same rules hold for the production discovery/issuer URLs' own
        // shapes and for the fixture policy.
        let fixture = OidcSettings::fixture(
            "http://127.0.0.1:9417",
            "http://127.0.0.1:9417/.well-known/openid-configuration",
            "127.0.0.1",
            300,
        );
        assert_eq!(
            fixture.validate_endpoint("http://127.0.0.1:9417@evil.example.com/userinfo"),
            Err(AuthError::ProviderMetadata)
        );
    }

    #[test]
    fn endpoints_reject_untrusted_hosts_and_schemes() {
        let settings = OidcSettings::huggingface();
        // Exact host matching: no subdomain, suffix, lookalike or trailing dot.
        for url in [
            "https://evil.huggingface.co/oauth/token",
            "https://huggingface.co.evil.example.com/oauth/token",
            "https://huggingface.co./oauth/token",
            "https://huggingface.co:443.evil.example.com/x",
            "https://xn--huggingface-9xa.co/oauth/token",
        ] {
            assert_eq!(settings.validate_endpoint(url), Err(AuthError::ProviderMetadata), "{url}");
        }
        // Scheme policy: HTTPS only in production; the fixture allows exactly
        // its own scheme.
        assert_eq!(
            settings.validate_endpoint("http://huggingface.co/oauth/token"),
            Err(AuthError::ProviderMetadata)
        );
        assert_eq!(
            settings.validate_endpoint("ftp://huggingface.co/oauth/token"),
            Err(AuthError::ProviderMetadata)
        );
        assert_eq!(
            settings.validate_endpoint("file:///etc/passwd"),
            Err(AuthError::ProviderMetadata)
        );
        assert!(settings
            .validate_endpoint("https://huggingface.co/oauth/token")
            .is_ok());
    }

    #[test]
    fn endpoints_enforce_the_explicit_port_policy() {
        let settings = OidcSettings::huggingface();
        // Production: only the HTTPS service port — an absent/default port is
        // the single allowed form; any explicit or foreign port is rejected.
        assert!(settings.validate_endpoint("https://huggingface.co/oauth/token").is_ok());
        assert!(settings.validate_endpoint("https://huggingface.co:443/oauth/token").is_ok());
        for url in [
            "https://huggingface.co:444/oauth/token",
            "https://huggingface.co:8443/oauth/token",
            "https://huggingface.co:0/oauth/token",
        ] {
            assert_eq!(settings.validate_endpoint(url), Err(AuthError::ProviderMetadata), "{url}");
        }

        // Fixture: exactly the fixture's own port is allowed.
        let fixture = OidcSettings::fixture(
            "http://127.0.0.1:9417",
            "http://127.0.0.1:9417/.well-known/openid-configuration",
            "127.0.0.1",
            300,
        );
        assert!(fixture.validate_endpoint("http://127.0.0.1:9417/device").is_ok());
        for url in [
            "http://127.0.0.1/device",
            "http://127.0.0.1:9418/device",
            "http://127.0.0.1:0/device",
        ] {
            assert_eq!(fixture.validate_endpoint(url), Err(AuthError::ProviderMetadata), "{url}");
        }
    }

    #[test]
    fn issuer_validation_is_exact_and_policy_bound() {
        let settings = OidcSettings::huggingface();
        assert!(settings.validate_issuer("https://huggingface.co").is_ok());
        assert_eq!(
            settings.validate_issuer("https://huggingface.co/"),
            Err(AuthError::ProviderMetadata)
        );
        assert_eq!(
            settings.validate_issuer("https://huggingface.co:8443"),
            Err(AuthError::ProviderMetadata)
        );
        assert_eq!(
            settings.validate_issuer("https://evil.example.com"),
            Err(AuthError::ProviderMetadata)
        );
    }
}
