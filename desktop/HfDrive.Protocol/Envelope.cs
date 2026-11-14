using System.Text;
using System.Text.Json;

namespace HfDrive.Protocol;

/// <summary>Envelope discriminant (wire: request/response/event).</summary>
public enum EnvelopeKind
{
    /// <summary>Client to provider command.</summary>
    Request,
    /// <summary>Provider to client command outcome.</summary>
    Response,
    /// <summary>Provider to client notification.</summary>
    Event,
}

/// <summary>
/// The single wire message shape. Members serialize in canonical order
/// (<c>protocol_major, protocol_minor, request_id, kind, method, body</c>);
/// canonical bytes are produced by <see cref="ProtocolJson"/>.
/// </summary>
public sealed record Envelope
{
    /// <summary>Protocol major (JSON number).</summary>
    public required int ProtocolMajor { get; init; }

    /// <summary>Protocol minor (JSON number).</summary>
    public required int ProtocolMinor { get; init; }

    /// <summary>Request correlation id; for events this is the event id.</summary>
    public required Guid RequestId { get; init; }

    /// <summary>Envelope discriminant.</summary>
    public required EnvelopeKind Kind { get; init; }

    /// <summary>Request method, echoed request method, or event name.</summary>
    public required string Method { get; init; }

    /// <summary>Typed body as JSON (see the typed request/result/event records).</summary>
    public required JsonElement Body { get; init; }

    /// <summary>Builds a request envelope at protocol 1.0.</summary>
    public static Envelope Request<TRequest, TResult>(Guid requestId, CommandSpec<TRequest, TResult> spec, TRequest body) where TRequest : notnull =>
        Request(requestId, spec.Method, body);

    /// <summary>Builds a request envelope at protocol 1.0 from a method name.</summary>
    public static Envelope Request<T>(Guid requestId, string method, T body) where T : notnull => new()
    {
        ProtocolMajor = ProtocolConstants.ProtocolMajor,
        ProtocolMinor = ProtocolConstants.ProtocolMinor,
        RequestId = requestId,
        Kind = EnvelopeKind.Request,
        Method = method,
        Body = ToElement(body),
    };

    /// <summary>Builds a response envelope carrying a typed result.</summary>
    public static Envelope Response<T>(Guid requestId, string requestMethod, T result) where T : notnull => new()
    {
        ProtocolMajor = ProtocolConstants.ProtocolMajor,
        ProtocolMinor = ProtocolConstants.ProtocolMinor,
        RequestId = requestId,
        Kind = EnvelopeKind.Response,
        Method = requestMethod,
        Body = WrapResult(ToElement(result)),
    };

    /// <summary>Builds a response envelope carrying an error.</summary>
    public static Envelope ResponseError(Guid requestId, string requestMethod, ProtocolError error) => new()
    {
        ProtocolMajor = ProtocolConstants.ProtocolMajor,
        ProtocolMinor = ProtocolConstants.ProtocolMinor,
        RequestId = requestId,
        Kind = EnvelopeKind.Response,
        Method = requestMethod,
        Body = WrapError(ToElement(error)),
    };

    /// <summary>Builds an event envelope at protocol 1.0.</summary>
    public static Envelope Event<T>(Guid eventId, string method, T body) where T : notnull => new()
    {
        ProtocolMajor = ProtocolConstants.ProtocolMajor,
        ProtocolMinor = ProtocolConstants.ProtocolMinor,
        RequestId = eventId,
        Kind = EnvelopeKind.Event,
        Method = method,
        Body = ToElement(body),
    };

    private static JsonElement ToElement<T>(T value) =>
        JsonSerializer.SerializeToElement(value, ProtocolJson.Options);

    private readonly record struct ResultBody(
        [property: System.Text.Json.Serialization.JsonPropertyName("result")] JsonElement Result);
    private readonly record struct ErrorBody(
        [property: System.Text.Json.Serialization.JsonPropertyName("error")] JsonElement Error);

    private static JsonElement WrapResult(JsonElement result) =>
        JsonSerializer.SerializeToElement(new ResultBody(result), ProtocolJson.Options);

    private static JsonElement WrapError(JsonElement error) =>
        JsonSerializer.SerializeToElement(new ErrorBody(error), ProtocolJson.Options);

    /// <summary>Serializes this envelope to canonical bytes.</summary>
    public byte[] ToCanonicalBytes()
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(this, ProtocolJson.Options);
        return ProtocolJson.Canonicalize(bytes);
    }

    /// <summary>
    /// Strict parse: protocol must be exactly 1.0. Unknown/duplicate members,
    /// non-canonical UUID spelling, kind/method/body disagreement and unknown
    /// methods are rejected before this returns.
    /// </summary>
    public static Envelope Parse(ReadOnlySpan<byte> utf8Json) => ParseCore(utf8Json, allowHandshake: false);

    /// <summary>
    /// Handshake-tolerant parse used only to inspect a <c>hello</c> request
    /// whose declared protocol version may differ; every structural rule still
    /// applies. The caller replies with supported versions and closes.
    /// </summary>
    public static Envelope ParseHandshake(ReadOnlySpan<byte> utf8Json) => ParseCore(utf8Json, allowHandshake: true);

    private static Envelope ParseCore(ReadOnlySpan<byte> utf8Json, bool allowHandshake)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(utf8Json.ToArray(), ProtocolJson.DocumentOptions);
        }
        catch (JsonException error)
        {
            throw new ProtocolException(ProtocolErrorCode.MalformedFrame, $"invalid JSON payload: {error.Message}");
        }
        using (document)
        {
            var root = document.RootElement;
            ProtocolJson.ValidateStrict(root);
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "invalid envelope");
            }

            var members = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
            {
                members[property.Name] = property.Value;
            }

            var protocolMajor = TakeInt(members, "protocol_major");
            var protocolMinor = TakeInt(members, "protocol_minor");
            var requestIdText = TakeString(members, "request_id");
            if (!Guid.TryParseExact(requestIdText, "D", out var requestId) || requestId.ToString("D") != requestIdText)
            {
                throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "invalid field request_id");
            }
            var kindText = TakeString(members, "kind");
            var kind = kindText switch
            {
                "request" => EnvelopeKind.Request,
                "response" => EnvelopeKind.Response,
                "event" => EnvelopeKind.Event,
                _ => throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "invalid field kind"),
            };
            var method = TakeString(members, "method");
            if (!members.Remove("body", out var body))
            {
                throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "missing member body");
            }
            if (members.Count != 0)
            {
                throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "unknown member");
            }

            var versionOk = protocolMajor == ProtocolConstants.ProtocolMajor
                && protocolMinor == ProtocolConstants.ProtocolMinor;
            if (!versionOk)
            {
                var handshakeHello = allowHandshake && method == ProtocolConstants.HelloMethod && kind == EnvelopeKind.Request;
                if (!handshakeHello)
                {
                    // The wire code for a version rejection is
                    // unsupported_protocol (see the Rust codec's mapping).
                    throw new ProtocolException(
                        ProtocolErrorCode.UnsupportedProtocol,
                        $"protocol version {protocolMajor}.{protocolMinor} is not supported");
                }
            }

            ValidateBody(kind, method, body);
            if (kind == EnvelopeKind.Request && method == ProtocolConstants.HelloMethod)
            {
                // A hello body must announce the version of the envelope that
                // carries it.
                var hello = Deserialize<HelloRequest>(body);
                if (hello.ProtocolMajor != protocolMajor || hello.ProtocolMinor != protocolMinor)
                {
                    throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "hello body version disagrees with the envelope");
                }
            }

            return new Envelope
            {
                ProtocolMajor = protocolMajor,
                ProtocolMinor = protocolMinor,
                RequestId = requestId,
                Kind = kind,
                Method = method,
                Body = body.Clone(),
            };
        }
    }

    private static void ValidateBody(EnvelopeKind kind, string method, JsonElement body)
    {
        switch (kind)
        {
            case EnvelopeKind.Request:
                if (body.ValueKind != JsonValueKind.Object)
                {
                    throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "invalid field body");
                }
                var (requestType, _) = CommandTypes.Lookup(method);
                DeserializeInto(body, requestType);
                break;

            case EnvelopeKind.Response:
                if (body.ValueKind != JsonValueKind.Object)
                {
                    throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "invalid field body");
                }
                var hasResult = body.TryGetProperty("result", out var result);
                var hasError = body.TryGetProperty("error", out var error);
                if (hasResult == hasError)
                {
                    throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "body must carry exactly one of result or error");
                }
                if (body.EnumerateObject().Count() != 1)
                {
                    throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "unknown member");
                }
                var (_, resultType) = CommandTypes.Lookup(method);
                if (hasResult)
                {
                    DeserializeInto(result, resultType);
                }
                else
                {
                    Deserialize<ProtocolError>(error);
                }
                break;

            case EnvelopeKind.Event:
                if (body.ValueKind != JsonValueKind.Object)
                {
                    throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "invalid field body");
                }
                switch (method)
                {
                    case "status_changed":
                        Deserialize<StatusChangedEvent>(body);
                        break;
                    case "activity_changed":
                        Deserialize<ActivityChangedEvent>(body);
                        break;
                    case "conflicts_changed":
                        Deserialize<ConflictsChangedEvent>(body);
                        break;
                    default:
                        throw new ProtocolException(ProtocolErrorCode.InvalidRequest, $"unknown method {method}");
                }
                break;
        }
    }

    private static void DeserializeInto(JsonElement element, Type type)
    {
        try
        {
            JsonSerializer.Deserialize(element, type, ProtocolJson.Options);
        }
        catch (JsonException error)
        {
            throw new ProtocolException(ProtocolErrorCode.MalformedFrame, $"invalid field body: {error.Message}");
        }
    }

    private static T Deserialize<T>(JsonElement element)
    {
        try
        {
            var value = JsonSerializer.Deserialize<T>(element, ProtocolJson.Options);
            return value ?? throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "invalid field body");
        }
        catch (JsonException error)
        {
            throw new ProtocolException(ProtocolErrorCode.MalformedFrame, $"invalid field body: {error.Message}");
        }
    }

    private static int TakeInt(Dictionary<string, JsonElement> members, string name)
    {
        if (!members.Remove(name, out var value) || value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var number))
        {
            throw new ProtocolException(ProtocolErrorCode.MalformedFrame, $"invalid field {name}");
        }
        return number;
    }

    private static string TakeString(Dictionary<string, JsonElement> members, string name)
    {
        if (!members.Remove(name, out var value) || value.ValueKind != JsonValueKind.String)
        {
            throw new ProtocolException(ProtocolErrorCode.MalformedFrame, $"invalid field {name}");
        }
        return value.GetString() ?? throw new ProtocolException(ProtocolErrorCode.MalformedFrame, $"invalid field {name}");
    }

    /// <summary>Deserializes the body as a typed request body.</summary>
    public T GetRequestBody<T>()
    {
        if (Kind != EnvelopeKind.Request)
        {
            throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "not a request envelope");
        }
        return Deserialize<T>(Body);
    }

    /// <summary>Deserializes the body as a typed result body.</summary>
    public T GetResult<T>()
    {
        if (Kind != EnvelopeKind.Response || !Body.TryGetProperty("result", out var result))
        {
            throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "not a response result envelope");
        }
        return Deserialize<T>(result);
    }

    /// <summary>Deserializes the body as a typed event payload.</summary>
    public T GetEventPayload<T>()
    {
        if (Kind != EnvelopeKind.Event)
        {
            throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "not an event envelope");
        }
        return Deserialize<T>(Body);
    }

    /// <summary>Returns the structured error of a response error envelope.</summary>
    public ProtocolError GetError()
    {
        if (Kind != EnvelopeKind.Response || !Body.TryGetProperty("error", out var error))
        {
            throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "not a response error envelope");
        }
        return Deserialize<ProtocolError>(error);
    }

    /// <summary>
    /// Returns a log-safe description: the credential command's body is
    /// redacted; everything else is identified by kind/method/id only.
    /// </summary>
    public string DescribeForLog()
    {
        var secret = Method == "set_publication_credentials";
        var body = secret
            ? "<redacted>"
            : Kind switch
            {
                EnvelopeKind.Request => "request",
                EnvelopeKind.Response when Body.TryGetProperty("error", out _) => "error",
                EnvelopeKind.Response => "result",
                EnvelopeKind.Event => "event",
                _ => "unknown",
            };
        return $"{Kind.ToString().ToLowerInvariant()} {Method} request_id={RequestId} body={body}";
    }

    /// <summary>Redacted description; safe for logs.</summary>
    public override string ToString() => DescribeForLog();
}

/// <summary>Maps wire methods to their typed request/result bodies.</summary>
internal static class CommandTypes
{
    private static readonly Dictionary<string, (Type Request, Type Result)> Map = new(StringComparer.Ordinal)
    {
        ["hello"] = (typeof(HelloRequest), typeof(HelloResult)),
        ["get_status"] = (typeof(GetStatusRequest), typeof(GetStatusResult)),
        ["subscribe_status"] = (typeof(SubscribeStatusRequest), typeof(SubscribeStatusResult)),
        ["cancel_request"] = (typeof(CancelRequestRequest), typeof(CancelRequestResult)),
        ["start_login"] = (typeof(StartLoginRequest), typeof(StartLoginResult)),
        ["cancel_login"] = (typeof(CancelLoginRequest), typeof(CancelLoginResult)),
        ["sign_out"] = (typeof(SignOutRequest), typeof(SignOutResult)),
        ["list_owners"] = (typeof(ListOwnersRequest), typeof(ListOwnersResult)),
        ["list_buckets"] = (typeof(ListBucketsRequest), typeof(ListBucketsResult)),
        ["create_bucket"] = (typeof(CreateBucketRequest), typeof(CreateBucketResult)),
        ["inspect_drive"] = (typeof(InspectDriveRequest), typeof(InspectDriveResult)),
        ["begin_setup"] = (typeof(BeginSetupRequest), typeof(BeginSetupResult)),
        ["set_publication_credentials"] = (typeof(SetPublicationCredentialsRequest), typeof(SetPublicationCredentialsResult)),
        ["probe_storage"] = (typeof(ProbeStorageRequest), typeof(ProbeStorageResult)),
        ["preview_connect"] = (typeof(PreviewConnectRequest), typeof(PreviewConnectResult)),
        ["connect"] = (typeof(ConnectRequest), typeof(ConnectResult)),
        ["pause"] = (typeof(PauseRequest), typeof(PauseResult)),
        ["resume"] = (typeof(ResumeRequest), typeof(ResumeResult)),
        ["set_pin"] = (typeof(SetPinRequest), typeof(SetPinResult)),
        ["free_space"] = (typeof(FreeSpaceRequest), typeof(FreeSpaceResult)),
        ["set_selective_sync"] = (typeof(SetSelectiveSyncRequest), typeof(SetSelectiveSyncResult)),
        ["update_settings"] = (typeof(UpdateSettingsRequest), typeof(UpdateSettingsResult)),
        ["list_history"] = (typeof(ListHistoryRequest), typeof(ListHistoryResult)),
        ["restore"] = (typeof(RestoreRequest), typeof(RestoreResult)),
        ["list_conflicts"] = (typeof(ListConflictsRequest), typeof(ListConflictsResult)),
        ["resolve_conflict"] = (typeof(ResolveConflictRequest), typeof(ResolveConflictResult)),
        ["export_diagnostics"] = (typeof(ExportDiagnosticsRequest), typeof(ExportDiagnosticsResult)),
        ["prepare_unlink"] = (typeof(PrepareUnlinkRequest), typeof(PrepareUnlinkResult)),
        ["unlink"] = (typeof(UnlinkRequest), typeof(UnlinkResult)),
        ["prepare_upgrade"] = (typeof(PrepareUpgradeRequest), typeof(PrepareUpgradeResult)),
        ["exit_provider"] = (typeof(ExitProviderRequest), typeof(ExitProviderResult)),
    };

    internal static (Type Request, Type Result) Lookup(string method) =>
        Map.TryGetValue(method, out var types)
            ? types
            : throw new ProtocolException(ProtocolErrorCode.InvalidRequest, $"unknown method {method}");

    internal static int Count => Map.Count;
}
