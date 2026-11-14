//! Protocol error codes and codec errors.
//!
//! Error codes never carry secrets; messages are human-readable and
//! non-secret. `retry_after_ms` is an optional decimal-string `u64` hint.

use serde::{Deserialize, Serialize};

/// Machine-readable error code carried in `body.error.code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolErrorCode {
    /// Peer speaks an unsupported protocol major.
    UnsupportedProtocol,
    /// No OAuth client id is configured for this build.
    #[serde(rename = "oauth_client_not_configured")]
    OAuthClientNotConfigured,
    /// Sign-in is required before this command.
    NeedsSignIn,
    /// Supplemental storage setup is required.
    StorageSetupRequired,
    /// Authorization denied.
    PermissionDenied,
    /// Connection is read-only for this operation.
    ReadOnly,
    /// Preview inputs changed; rerun the preview.
    PreviewChanged,
    /// Remote format is newer/unknown; never initialize over it.
    UnsupportedFormat,
    /// Local root fails validation.
    LocalRootInvalid,
    /// The operation conflicts with existing state.
    Conflict,
    /// Insufficient disk space.
    DiskFull,
    /// A referenced immutable remote object is unavailable.
    RemoteContentUnavailable,
    /// The request was cancelled.
    Cancelled,
    /// A provider for this user runs in another session.
    ProviderInOtherSession,
    /// The provider is at capacity; retry later.
    Busy,
    /// The request body/fields are invalid.
    InvalidRequest,
    /// The referenced entity does not exist.
    NotFound,
    /// Internal provider failure (redacted).
    Internal,
    /// The request timed out.
    Timeout,
    /// Frame exceeds the 1 MiB bound (codec-level).
    FrameTooLarge,
    /// Frame bytes are not valid envelope JSON (codec-level).
    MalformedFrame,
    /// Stream ended mid-frame (codec-level).
    UnexpectedEof,
    /// Envelope protocol version is not 1.0 (codec-level).
    VersionMismatch,
    /// The connection is closed (codec-level).
    Closed,
}

impl ProtocolErrorCode {
    /// Returns the snake_case wire name.
    pub fn wire(self) -> &'static str {
        match self {
            ProtocolErrorCode::UnsupportedProtocol => "unsupported_protocol",
            ProtocolErrorCode::OAuthClientNotConfigured => "oauth_client_not_configured",
            ProtocolErrorCode::NeedsSignIn => "needs_sign_in",
            ProtocolErrorCode::StorageSetupRequired => "storage_setup_required",
            ProtocolErrorCode::PermissionDenied => "permission_denied",
            ProtocolErrorCode::ReadOnly => "read_only",
            ProtocolErrorCode::PreviewChanged => "preview_changed",
            ProtocolErrorCode::UnsupportedFormat => "unsupported_format",
            ProtocolErrorCode::LocalRootInvalid => "local_root_invalid",
            ProtocolErrorCode::Conflict => "conflict",
            ProtocolErrorCode::DiskFull => "disk_full",
            ProtocolErrorCode::RemoteContentUnavailable => "remote_content_unavailable",
            ProtocolErrorCode::Cancelled => "cancelled",
            ProtocolErrorCode::ProviderInOtherSession => "provider_in_other_session",
            ProtocolErrorCode::Busy => "busy",
            ProtocolErrorCode::InvalidRequest => "invalid_request",
            ProtocolErrorCode::NotFound => "not_found",
            ProtocolErrorCode::Internal => "internal",
            ProtocolErrorCode::Timeout => "timeout",
            ProtocolErrorCode::FrameTooLarge => "frame_too_large",
            ProtocolErrorCode::MalformedFrame => "malformed_frame",
            ProtocolErrorCode::UnexpectedEof => "unexpected_eof",
            ProtocolErrorCode::VersionMismatch => "version_mismatch",
            ProtocolErrorCode::Closed => "closed",
        }
    }

    /// Parses a snake_case wire name.
    pub fn from_wire(text: &str) -> Option<Self> {
        Self::try_from_wire(text).ok()
    }

    fn try_from_wire(text: &str) -> Result<Self, crate::errors::ProtocolCodecError> {
        use ProtocolErrorCode::*;
        let code = match text {
            "unsupported_protocol" => UnsupportedProtocol,
            "oauth_client_not_configured" => OAuthClientNotConfigured,
            "needs_sign_in" => NeedsSignIn,
            "storage_setup_required" => StorageSetupRequired,
            "permission_denied" => PermissionDenied,
            "read_only" => ReadOnly,
            "preview_changed" => PreviewChanged,
            "unsupported_format" => UnsupportedFormat,
            "local_root_invalid" => LocalRootInvalid,
            "conflict" => Conflict,
            "disk_full" => DiskFull,
            "remote_content_unavailable" => RemoteContentUnavailable,
            "cancelled" => Cancelled,
            "provider_in_other_session" => ProviderInOtherSession,
            "busy" => Busy,
            "invalid_request" => InvalidRequest,
            "not_found" => NotFound,
            "internal" => Internal,
            "timeout" => Timeout,
            "frame_too_large" => FrameTooLarge,
            "malformed_frame" => MalformedFrame,
            "unexpected_eof" => UnexpectedEof,
            "version_mismatch" => VersionMismatch,
            "closed" => Closed,
            _ => return Err(crate::errors::ProtocolCodecError::InvalidField("code")),
        };
        Ok(code)
    }
}

/// An error object carried inside `body.error`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ProtocolError {
    /// Machine-readable code.
    pub code: ProtocolErrorCode,
    /// Human-readable, non-secret message.
    pub message: String,
    /// Retry hint in milliseconds (decimal string), when applicable.
    #[serde(default, with = "crate::dec_u64::option", skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.code.wire(), self.message)
    }
}

/// Framing/decoding failure. `Display` never includes payload bytes.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolCodecError {
    /// Declared frame length exceeds the 1 MiB bound.
    #[error("frame length {len} exceeds the maximum")]
    FrameTooLarge {
        /// The declared length.
        len: u32,
    },
    /// Stream ended mid-frame or at an unexpected point.
    #[error("unexpected end of stream")]
    UnexpectedEof,
    /// Frame length prefix is invalid (zero-length not allowed).
    #[error("invalid frame length")]
    InvalidFrameLength,
    /// Payload is not valid JSON.
    #[error("invalid JSON payload")]
    InvalidJson,
    /// Payload contains a duplicate object member name.
    #[error("duplicate JSON member")]
    DuplicateJsonKey,
    /// Payload is not valid UTF-8.
    #[error("payload is not UTF-8")]
    Utf8,
    /// Envelope protocol version mismatch.
    #[error("protocol version {major}.{minor} is not supported")]
    VersionMismatch {
        /// Declared major.
        major: u32,
        /// Declared minor.
        minor: u32,
    },
    /// Envelope kind and body shape disagree.
    #[error("envelope kind/body mismatch")]
    WrongKind,
    /// Method name is not part of the contract.
    #[error("unknown method {0}")]
    UnknownMethod(String),
    /// A field is missing, mistyped, or non-canonical.
    #[error("invalid field {0}")]
    InvalidField(&'static str),
    /// Underlying transport I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl ProtocolCodecError {
    /// Converts to the wire error object for a protocol-level rejection.
    pub fn to_protocol_error(&self) -> ProtocolError {
        let code = match self {
            ProtocolCodecError::FrameTooLarge { .. } => ProtocolErrorCode::FrameTooLarge,
            ProtocolCodecError::UnexpectedEof => ProtocolErrorCode::UnexpectedEof,
            ProtocolCodecError::InvalidFrameLength
            | ProtocolCodecError::InvalidJson
            | ProtocolCodecError::DuplicateJsonKey
            | ProtocolCodecError::Utf8
            | ProtocolCodecError::WrongKind
            | ProtocolCodecError::InvalidField(_) => ProtocolErrorCode::MalformedFrame,
            ProtocolCodecError::VersionMismatch { .. } => ProtocolErrorCode::UnsupportedProtocol,
            ProtocolCodecError::UnknownMethod(_) => ProtocolErrorCode::InvalidRequest,
            ProtocolCodecError::Io(_) => ProtocolErrorCode::Internal,
        };
        ProtocolError {
            code,
            message: self.to_string(),
            retry_after_ms: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ProtocolErrorCode;

    #[test]
    fn oauth_client_error_has_one_canonical_wire_spelling() {
        let code = ProtocolErrorCode::OAuthClientNotConfigured;
        assert_eq!(code.wire(), "oauth_client_not_configured");
        assert_eq!(serde_json::to_string(&code).unwrap(), "\"oauth_client_not_configured\"");
        assert_eq!(serde_json::from_str::<ProtocolErrorCode>("\"oauth_client_not_configured\"").unwrap(), code);
        assert_eq!(ProtocolErrorCode::from_wire(code.wire()), Some(code));
    }
}
