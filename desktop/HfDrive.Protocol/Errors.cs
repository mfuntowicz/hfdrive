using System.Text.Json;
using System.Text.Json.Serialization;

namespace HfDrive.Protocol;

/// <summary>Machine-readable error code carried in <c>body.error.code</c>.</summary>
[JsonConverter(typeof(ProtocolErrorCodeConverter))]
public enum ProtocolErrorCode
{
    /// <summary>Peer speaks an unsupported protocol major.</summary>
    UnsupportedProtocol,
    /// <summary>No OAuth client id is configured for this build.</summary>
    OAuthClientNotConfigured,
    /// <summary>Sign-in is required before this command.</summary>
    NeedsSignIn,
    /// <summary>Supplemental storage setup is required.</summary>
    StorageSetupRequired,
    /// <summary>Authorization denied.</summary>
    PermissionDenied,
    /// <summary>Connection is read-only for this operation.</summary>
    ReadOnly,
    /// <summary>Preview inputs changed; rerun the preview.</summary>
    PreviewChanged,
    /// <summary>Remote format is newer/unknown; never initialize over it.</summary>
    UnsupportedFormat,
    /// <summary>Local root fails validation.</summary>
    LocalRootInvalid,
    /// <summary>The operation conflicts with existing state.</summary>
    Conflict,
    /// <summary>Insufficient disk space.</summary>
    DiskFull,
    /// <summary>A referenced immutable remote object is unavailable.</summary>
    RemoteContentUnavailable,
    /// <summary>The request was cancelled.</summary>
    Cancelled,
    /// <summary>A provider for this user runs in another session.</summary>
    ProviderInOtherSession,
    /// <summary>The provider is at capacity; retry later.</summary>
    Busy,
    /// <summary>The request body/fields are invalid.</summary>
    InvalidRequest,
    /// <summary>The referenced entity does not exist.</summary>
    NotFound,
    /// <summary>Internal provider failure (redacted).</summary>
    Internal,
    /// <summary>The request timed out.</summary>
    Timeout,
    /// <summary>Frame exceeds the 1 MiB bound (codec-level).</summary>
    FrameTooLarge,
    /// <summary>Frame bytes are not valid envelope JSON (codec-level).</summary>
    MalformedFrame,
    /// <summary>Stream ended mid-frame (codec-level).</summary>
    UnexpectedEof,
    /// <summary>Envelope protocol version is not 1.0 (codec-level).</summary>
    VersionMismatch,
    /// <summary>The connection is closed (codec-level).</summary>
    Closed,
}

/// <summary>An error object carried inside <c>body.error</c> and status records.</summary>
public sealed record ProtocolError
{
    /// <summary>Machine-readable code.</summary>
    public required ProtocolErrorCode Code { get; init; }

    /// <summary>Human-readable, non-secret message.</summary>
    public required string Message { get; init; }

    /// <summary>Retry hint in milliseconds (decimal string on the wire), when applicable.</summary>
    public ulong? RetryAfterMs { get; init; }

    /// <summary>Non-secret description matching the Rust <c>Display</c> form.</summary>
    public override string ToString() => $"{Code}: {Message}";
}

/// <summary>
/// Raised for wire-level protocol failures and provider-reported error
/// results. Never contains payload bytes or secrets.
/// </summary>
public sealed class ProtocolException : Exception
{
    /// <summary>The structured protocol error.</summary>
    public ProtocolError Error { get; }

    /// <summary>Creates a protocol exception carrying a structured error.</summary>
    public ProtocolException(ProtocolError error)
        : base($"{error.Code}: {error.Message}")
    {
        Error = error;
    }

    /// <summary>Creates a protocol exception with an explicit code and message.</summary>
    public ProtocolException(ProtocolErrorCode code, string message)
        : this(new ProtocolError { Code = code, Message = message })
    {
    }
}
