//! Pure PKCE callback/authorization-response validation.
//!
//! Everything in this module is deterministic and side-effect free so the
//! adversarial rules (duplicate parameters, oversized input, wrong method or
//! path, invalid or mismatched state, missing code) can be regression-tested
//! without a network or a listener.
//!
//! The state token is checked with a constant-time comparison
//! ([`constant_time_eq`]). The valid login attempt is only consumed by the
//! caller after this module accepted the request **and** the caller decides to
//! exchange the code exactly once.

use serde::{Deserialize, Serialize};

/// Maximum accepted size of a single callback request URI plus headers
/// (16 KiB total bound from the plan).
pub const MAX_CALLBACK_REQUEST_BYTES: usize = 16 * 1024;

/// The single expected callback path (`/oauth/callback`).
pub const fn expected_callback_path() -> &'static str {
    crate::config::CALLBACK_PATH
}

/// Outcome of validating one callback request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackCheck {
    /// A valid success response with a one-time authorization code.
    Success {
        /// The authorization code (secret; never logged).
        code: String,
    },
    /// The user denied the authorization request (`error=access_denied`).
    Denied,
    /// The provider reported another terminal error (`error=...`).
    Failed {
        /// Sanitized provider error code (no free-form description).
        code: String,
    },
}

/// Validation failure. Carries no request content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CallbackError {
    /// Request line/header block exceeds the 16 KiB bound.
    #[error("callback request too large")]
    TooLarge,
    /// Method other than GET.
    #[error("unexpected method")]
    MethodNotAllowed,
    /// Path is not the exact registered callback path.
    #[error("unexpected path")]
    PathMismatch,
    /// Query string malformed (percent-encoding or structure).
    #[error("malformed query")]
    MalformedQuery,
    /// Duplicate `code`/`state`/`error` parameter.
    #[error("duplicate parameter")]
    DuplicateParameter,
    /// Missing or invalid `state`.
    #[error("missing state")]
    MissingState,
    /// `state` does not match the outstanding login (constant-time check).
    #[error("state mismatch")]
    StateMismatch,
    /// No `code` and no `error` in the response.
    #[error("missing authorization code")]
    MissingCode,
}

/// Constant-time byte comparison. Returns true when equal; runtime depends
/// only on the (equal) lengths, never on the content.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Percent-decode with `+` treated as literal plus (RFC 3986 query strings).
fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hi = *bytes.get(i + 1)?;
                let lo = *bytes.get(i + 2)?;
                let hex = |c: u8| -> Option<u8> {
                    match c {
                        b'0'..=b'9' => Some(c - b'0'),
                        b'a'..=b'f' => Some(c - b'a' + 10),
                        b'A'..=b'F' => Some(c - b'A' + 10),
                        _ => None,
                    }
                };
                out.push(hex(hi)? * 16 + hex(lo)?);
                i += 3;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Parse a raw query string into `(key, value)` pairs.
fn parse_query(query: &str) -> Option<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    if query.is_empty() {
        return Some(pairs);
    }
    for part in query.split('&') {
        if part.is_empty() {
            return None;
        }
        let (k, v) = match part.split_once('=') {
            Some((k, v)) => (k, v),
            None => (part, ""),
        };
        pairs.push((percent_decode(k)?, percent_decode(v)?));
    }
    Some(pairs)
}

/// Validate one callback request line + query against the outstanding login.
///
/// * `request_line` is the raw HTTP request line (`GET /oauth/callback?... HTTP/1.1`).
/// * `header_bytes` is the size of the parsed header block, counted against
///   the 16 KiB total bound together with the request line.
/// * `expected_state` is the outstanding login's state token (32 random
///   bytes, base64url) — compared in constant time.
pub fn validate_callback(
    request_line: &str,
    header_bytes: usize,
    expected_state: &str,
) -> Result<CallbackCheck, CallbackError> {
    if request_line.len() + header_bytes > MAX_CALLBACK_REQUEST_BYTES {
        return Err(CallbackError::TooLarge);
    }
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("");
    if method != "GET" {
        return Err(CallbackError::MethodNotAllowed);
    }
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/") || parts.next().is_some() {
        return Err(CallbackError::MalformedQuery);
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (target, None),
    };
    if path != expected_callback_path() {
        return Err(CallbackError::PathMismatch);
    }
    let query = query.unwrap_or("");
    if query.contains('#') {
        return Err(CallbackError::MalformedQuery);
    }
    let pairs = parse_query(query).ok_or(CallbackError::MalformedQuery)?;

    // Duplicate-parameter rejection for every security-relevant key.
    let mut code: Option<String> = None;
    let mut state: Option<String> = None;
    let mut error: Option<String> = None;
    for (k, v) in &pairs {
        match k.as_str() {
            "code" => {
                if code.is_some() {
                    return Err(CallbackError::DuplicateParameter);
                }
                code = Some(v.clone());
            }
            "state" => {
                if state.is_some() {
                    return Err(CallbackError::DuplicateParameter);
                }
                state = Some(v.clone());
            }
            "error" => {
                if error.is_some() {
                    return Err(CallbackError::DuplicateParameter);
                }
                error = Some(v.clone());
            }
            _ => {}
        }
    }

    let state = state.ok_or(CallbackError::MissingState)?;
    if !constant_time_eq(state.as_bytes(), expected_state.as_bytes()) {
        return Err(CallbackError::StateMismatch);
    }

    if let Some(err) = error {
        return Ok(match err.as_str() {
            "access_denied" => CallbackCheck::Denied,
            _ => CallbackCheck::Failed {
                code: sanitize_error_code(&err),
            },
        });
    }

    let code = code.ok_or(CallbackError::MissingCode)?;
    if code.is_empty() || code.len() > 4096 || !code.is_ascii() {
        return Err(CallbackError::MissingCode);
    }
    Ok(CallbackCheck::Success { code })
}

/// Keep a provider error code short, ASCII and free of free-form text.
fn sanitize_error_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .take(64)
        .collect()
}

/// Build the authorization URL query additions for organization re-consent.
///
/// Exactly one `orgIds` parameter with the verified organization subject is
/// added; nothing else is invented.
pub fn org_reconsent_param(org_subject: &str) -> (&'static str, String) {
    ("orgIds", org_subject.to_owned())
}

/// Login session terminal status, mirrored in the provider IPC surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginState {
    /// Waiting for the user to complete the flow.
    Pending,
    /// Credentials verified and stored.
    Completed,
    /// Cancelled via `cancel_login`.
    Cancelled,
    /// The five-minute login lifetime elapsed.
    Expired,
    /// The user denied the authorization request.
    Denied,
    /// The flow failed (browser launch, exchange, validation).
    Failed,
}

impl LoginState {
    /// Whether the session reached a terminal state.
    pub const fn is_terminal(self) -> bool {
        !matches!(self, LoginState::Pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATE: &str = "dGVzdC1zdGF0ZS12YWx1ZS1mb3ItdGVzdHM";

    fn line(query: &str) -> String {
        format!("GET /oauth/callback?{query} HTTP/1.1")
    }

    #[test]
    fn valid_success_is_accepted_once_payload() {
        let out = validate_callback(&line(&format!("code=abc&state={STATE}")), 100, STATE).unwrap();
        assert!(matches!(out, CallbackCheck::Success { code } if code == "abc"));
    }

    #[test]
    fn wrong_method_path_and_oversize_are_rejected() {
        assert_eq!(
            validate_callback("POST /oauth/callback?x=1", 10, STATE),
            Err(CallbackError::MethodNotAllowed)
        );
        assert_eq!(
            validate_callback("GET /other?x=1 HTTP/1.1", 10, STATE),
            Err(CallbackError::PathMismatch)
        );
        assert_eq!(
            validate_callback("GET /oauth/callback?x=1 HTTP/1.1", MAX_CALLBACK_REQUEST_BYTES, STATE),
            Err(CallbackError::TooLarge)
        );
    }

    #[test]
    fn duplicate_parameters_are_rejected() {
        assert_eq!(
            validate_callback(&line(&format!("code=a&code=b&state={STATE}")), 10, STATE),
            Err(CallbackError::DuplicateParameter)
        );
        assert_eq!(
            validate_callback(&line(&format!("error=access_denied&error=x&state={STATE}")), 10, STATE),
            Err(CallbackError::DuplicateParameter)
        );
    }

    #[test]
    fn state_is_checked_constant_time_and_mismatch_never_consumes() {
        assert_eq!(
            validate_callback(&line("code=a&state=WRONG"), 10, STATE),
            Err(CallbackError::StateMismatch)
        );
        // Prefix/suffix variations must not compare equal.
        assert!(!constant_time_eq(STATE.as_bytes(), &STATE.as_bytes()[..STATE.len() - 1]));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(constant_time_eq(b"abc", b"abc"));
    }

    #[test]
    fn denial_and_provider_errors_are_distinct() {
        assert_eq!(
            validate_callback(&line(&format!("error=access_denied&state={STATE}")), 10, STATE),
            Ok(CallbackCheck::Denied)
        );
        assert_eq!(
            validate_callback(&line(&format!("error=server_error&state={STATE}")), 10, STATE),
            Ok(CallbackCheck::Failed { code: "server_error".to_owned() })
        );
    }

    #[test]
    fn missing_code_or_state_is_rejected() {
        assert_eq!(
            validate_callback(&line(&format!("state={STATE}")), 10, STATE),
            Err(CallbackError::MissingCode)
        );
        assert_eq!(validate_callback(&line("code=a"), 10, STATE), Err(CallbackError::MissingState));
    }

    #[test]
    fn percent_encoded_duplicate_keys_still_reject() {
        // `co%64e` decodes to `code`: a second occurrence must trip the check.
        assert_eq!(
            validate_callback(&line(&format!("code=a&co%64e=b&state={STATE}")), 10, STATE),
            Err(CallbackError::DuplicateParameter)
        );
    }

    #[test]
    fn empty_and_malformed_queries_reject() {
        assert_eq!(validate_callback("GET /oauth/callback HTTP/1.1", 10, STATE), Err(CallbackError::MissingState));
        assert_eq!(
            validate_callback(&line(&format!("state={STATE}&=%zz")), 10, STATE),
            Err(CallbackError::MalformedQuery)
        );
    }
}
