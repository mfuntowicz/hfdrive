//! Sanitized typed errors for the authorization boundary.
//!
//! Every variant is safe for logging, IPC error mapping and diagnostics:
//! no bearer token, authorization code, PKCE verifier, state/nonce value or
//! raw network/HTTP body ever appears in an error.

/// Authorization failure with enough structure for callers to decide between
/// "re-login required", "retry later" and "permanent configuration problem".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// No client id is configured in the current `AuthConfig`; login is refused
    /// outright (no borrowed or fake client id is ever used).
    #[error("the product OAuth client is not configured")]
    OAuthClientNotConfigured,
    /// Only one login may be outstanding at a time.
    #[error("another login is already in progress")]
    LoginAlreadyInProgress,
    /// Credential removal is still in progress; no replacement login is admitted.
    #[error("sign-out is in progress")]
    SignOutInProgress,
    /// No login session with that identifier exists (or it aged out).
    #[error("unknown login session")]
    UnknownLoginSession,
    /// The login session was cancelled (explicitly or by sign-out).
    #[error("login cancelled")]
    Cancelled,
    /// The login session ran out of time before the user completed it.
    #[error("login expired before completion")]
    Expired,
    /// The user denied the authorization request at the provider.
    #[error("authorization denied")]
    Denied,
    /// The system browser could not be opened; the login was torn down.
    #[error("the system browser could not be opened")]
    BrowserLaunch,
    /// The callback/authorization response was malformed or failed
    /// validation. Never reveals which check failed to the peer.
    #[error("the authorization response was rejected")]
    CallbackInvalid,
    /// The token endpoint rejected the grant (`invalid_grant` semantics).
    #[error("the token grant was rejected")]
    InvalidGrant,
    /// The token endpoint could not be reached or answered unacceptably.
    #[error("token request failed")]
    TokenEndpoint,
    /// The requested organization subject is not present in the verified
    /// identity; org consent was not pretended.
    #[error("the requested organization is not verified for this identity")]
    OrganizationNotVerified,
    /// The granted scopes do not cover the requested login purpose.
    #[error("the granted scopes do not cover the requested purpose")]
    ScopesNotGranted,
    /// The provider did not advertise a device authorization endpoint.
    #[error("device authorization is not available")]
    DeviceFlowUnavailable,
    /// A different identity for this account's stored credentials was
    /// observed; the existing session was preserved and never rebound.
    #[error("identity changed; the existing session was preserved and requires explicit rebinding")]
    ExistingSessionPreserved,
    /// No usable credentials for this account; interactive sign-in needed.
    #[error("sign-in is required")]
    NeedsSignIn,
    /// The protected credential record could not be read (wrong user,
    /// corruption). The record was preserved untouched.
    #[error("the credential record is unreadable")]
    CredentialRecordUnreadable,
    /// Protecting/persisting a credential record failed.
    #[error("credential persistence failed")]
    Persistence,
    /// OIDC discovery/JWKS failed strict validation or was unreachable.
    #[error("provider metadata is unavailable or invalid")]
    ProviderMetadata,
    /// ID token/userinfo identity validation failed.
    #[error("identity validation failed")]
    IdentityValidation,
    /// An internal authorization invariant was violated; the operation
    /// failed closed.
    #[error("internal authorization invariant violated")]
    Internal,
}

impl AuthError {
    /// Whether the failure means interactive sign-in is required.
    pub fn needs_sign_in(&self) -> bool {
        matches!(
            self,
            AuthError::NeedsSignIn
                | AuthError::InvalidGrant
                | AuthError::CredentialRecordUnreadable
                | AuthError::ExistingSessionPreserved
        )
    }
}

/// The [`crate::TokenSource`] error surface. Deliberately coarser than
/// [`AuthError`]: HTTP clients only need sign-in/retry/epoch semantics.
pub use crate::AuthorizationError;

/// Map a rich auth error onto the token-source surface.
pub(crate) fn to_authorization_error(error: AuthError) -> crate::AuthorizationError {
    use crate::AuthorizationError;
    match error {
        AuthError::NeedsSignIn
        | AuthError::InvalidGrant
        | AuthError::CredentialRecordUnreadable
        | AuthError::ExistingSessionPreserved
        | AuthError::IdentityValidation => AuthorizationError::NeedsSignIn,
        _ => AuthorizationError::Unavailable,
    }
}
