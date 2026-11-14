//! Login session types shared with the provider/IPC surface.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

use crate::error::AuthError;

/// Selected login flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginFlow {
    /// Authorization-code + PKCE with a `127.0.0.1` loopback callback and the
    /// system browser. The default and the only flow that can carry
    /// incremental organization re-consent.
    Pkce,
    /// RFC 8628 device authorization. **Explicitly selected only** — never an
    /// automatic browser-failure fallback — and cannot satisfy storage
    /// purposes or org consent unless the live provider grant proves it.
    Device,
}

/// Purpose of the login; selects the requested scope set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginPurpose {
    /// `openid profile read-memberships`.
    Signin,
    /// Sign-in grants plus `read-repos`.
    ReadStorage,
    /// Sign-in grants plus `read-repos write-repos`.
    WriteStorage,
    /// Sign-in grants plus `read-repos write-repos manage-repos`.
    CreateStorage,
}

/// A `start_login` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Selected flow.
    pub flow: LoginFlow,
    /// Login purpose selecting the scope set.
    pub purpose: LoginPurpose,
    /// Organization subject (`orgs[].sub`) for incremental re-consent.
    pub organization_id: Option<String>,
}

/// A login session's terminal status (mirrors `LoginState` on the wire).
pub type LoginState = crate::protocol::LoginState;

/// One login session. Contains no authorization code, PKCE verifier, state,
/// nonce or token of any kind. `Debug` is redacted: the authorization URL
/// embeds single-use `state`/`nonce`/PKCE challenge values and the device
/// user code is a live credential.
#[derive(Clone, PartialEq, Eq)]
pub struct LoginSession {
    /// Provider-issued session identifier; retained in terminal state until a
    /// new login replaces it so clients can await the real outcome.
    pub session_id: Uuid,
    /// The flow this session runs.
    pub flow: LoginFlow,
    /// The purpose this session runs for.
    pub purpose: LoginPurpose,
    /// Current state.
    pub state: LoginState,
    /// Unix seconds when the session expires.
    pub expires_at_unix: u64,
    /// Authorization URL for manual opening (PKCE).
    pub authorization_url: Option<String>,
    /// Device-flow user code.
    pub user_code: Option<String>,
    /// Device-flow verification URI.
    pub verification_uri: Option<String>,
    /// Terminal error when `state` is `Failed`/`Denied`/`Expired`.
    pub error: Option<AuthError>,
}

impl fmt::Debug for LoginSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginSession")
            .field("session_id", &self.session_id)
            .field("flow", &self.flow)
            .field("purpose", &self.purpose)
            .field("state", &self.state)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("authorization_url", &self.authorization_url.as_ref().map(|_| "[REDACTED]"))
            .field("user_code", &self.user_code.as_ref().map(|_| "[REDACTED]"))
            .field("verification_uri", &self.verification_uri.as_ref().map(|_| "[REDACTED]"))
            .field("error", &self.error)
            .finish()
    }
}

impl LoginSession {
    /// Sanitized clone for the IPC/status surface (same data; explicit for
    /// call-site clarity).
    pub fn snapshot(&self) -> LoginSession {
        self.clone()
    }
}
