using System.Text.Json;
using System.Text.Json.Serialization;

namespace HfDrive.Protocol;

/// <summary>Wire-name converter for <see cref="ProtocolErrorCode"/>.</summary>
public sealed class ProtocolErrorCodeConverter : JsonConverter<ProtocolErrorCode>
{
    /// <inheritdoc />
    public override ProtocolErrorCode Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException("error code must be a string");
        }
        var text = reader.GetString() ?? throw new JsonException("error code must be a string");
        return WireToCode(text);
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, ProtocolErrorCode value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(CodeToWire(value));
    }

    /// <summary>Returns the snake_case wire name for a code.</summary>
    public static string CodeToWire(ProtocolErrorCode code) => code switch
    {
        ProtocolErrorCode.UnsupportedProtocol => "unsupported_protocol",
        ProtocolErrorCode.OAuthClientNotConfigured => "oauth_client_not_configured",
        ProtocolErrorCode.NeedsSignIn => "needs_sign_in",
        ProtocolErrorCode.StorageSetupRequired => "storage_setup_required",
        ProtocolErrorCode.PermissionDenied => "permission_denied",
        ProtocolErrorCode.ReadOnly => "read_only",
        ProtocolErrorCode.PreviewChanged => "preview_changed",
        ProtocolErrorCode.UnsupportedFormat => "unsupported_format",
        ProtocolErrorCode.LocalRootInvalid => "local_root_invalid",
        ProtocolErrorCode.Conflict => "conflict",
        ProtocolErrorCode.DiskFull => "disk_full",
        ProtocolErrorCode.RemoteContentUnavailable => "remote_content_unavailable",
        ProtocolErrorCode.Cancelled => "cancelled",
        ProtocolErrorCode.ProviderInOtherSession => "provider_in_other_session",
        ProtocolErrorCode.Busy => "busy",
        ProtocolErrorCode.InvalidRequest => "invalid_request",
        ProtocolErrorCode.NotFound => "not_found",
        ProtocolErrorCode.Internal => "internal",
        ProtocolErrorCode.Timeout => "timeout",
        ProtocolErrorCode.FrameTooLarge => "frame_too_large",
        ProtocolErrorCode.MalformedFrame => "malformed_frame",
        ProtocolErrorCode.UnexpectedEof => "unexpected_eof",
        ProtocolErrorCode.VersionMismatch => "version_mismatch",
        ProtocolErrorCode.Closed => "closed",
        _ => throw new ArgumentOutOfRangeException(nameof(code), code, "unknown error code"),
    };

    /// <summary>Parses a snake_case wire name into a code.</summary>
    public static ProtocolErrorCode WireToCode(string text) => text switch
    {
        "unsupported_protocol" => ProtocolErrorCode.UnsupportedProtocol,
        "oauth_client_not_configured" => ProtocolErrorCode.OAuthClientNotConfigured,
        "needs_sign_in" => ProtocolErrorCode.NeedsSignIn,
        "storage_setup_required" => ProtocolErrorCode.StorageSetupRequired,
        "permission_denied" => ProtocolErrorCode.PermissionDenied,
        "read_only" => ProtocolErrorCode.ReadOnly,
        "preview_changed" => ProtocolErrorCode.PreviewChanged,
        "unsupported_format" => ProtocolErrorCode.UnsupportedFormat,
        "local_root_invalid" => ProtocolErrorCode.LocalRootInvalid,
        "conflict" => ProtocolErrorCode.Conflict,
        "disk_full" => ProtocolErrorCode.DiskFull,
        "remote_content_unavailable" => ProtocolErrorCode.RemoteContentUnavailable,
        "cancelled" => ProtocolErrorCode.Cancelled,
        "provider_in_other_session" => ProtocolErrorCode.ProviderInOtherSession,
        "busy" => ProtocolErrorCode.Busy,
        "invalid_request" => ProtocolErrorCode.InvalidRequest,
        "not_found" => ProtocolErrorCode.NotFound,
        "internal" => ProtocolErrorCode.Internal,
        "timeout" => ProtocolErrorCode.Timeout,
        "frame_too_large" => ProtocolErrorCode.FrameTooLarge,
        "malformed_frame" => ProtocolErrorCode.MalformedFrame,
        "unexpected_eof" => ProtocolErrorCode.UnexpectedEof,
        "version_mismatch" => ProtocolErrorCode.VersionMismatch,
        "closed" => ProtocolErrorCode.Closed,
        _ => throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "invalid error code"),
    };
}
