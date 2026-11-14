using System.Buffers;
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HfDrive.Protocol;

/// <summary>Serializes <see cref="ulong"/> as its canonical decimal string.</summary>
public sealed class DecimalStringUInt64Converter : JsonConverter<ulong>
{
    /// <inheritdoc />
    public override ulong Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException("u64 fields must be decimal strings");
        }
        var text = reader.GetString() ?? throw new JsonException("u64 fields must be decimal strings");
        return ProtocolJson.ParseDecimal64(text);
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, ulong value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.ToString(CultureInfo.InvariantCulture));
    }
}

/// <summary>Serializes optional <see cref="ulong"/> values as canonical decimal strings.</summary>
public sealed class NullableDecimalStringUInt64Converter : JsonConverter<ulong?>
{
    private static readonly DecimalStringUInt64Converter Inner = new();

    /// <inheritdoc />
    public override ulong? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null)
        {
            return null;
        }
        return Inner.Read(ref reader, typeof(ulong), options);
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, ulong? value, JsonSerializerOptions options)
    {
        if (value is null)
        {
            writer.WriteNullValue();
        }
        else
        {
            Inner.Write(writer, value.Value, options);
        }
    }
}

/// <summary>
/// Shared strict JSON configuration and the canonical writer that mirrors the
/// Rust codec byte-for-byte (see spec/ipc-v1.schema.json).
/// </summary>
public static class ProtocolJson
{
    /// <summary>
    /// Strict serializer options: snake_case members, snake_case enum names,
    /// unknown members rejected, optional members omitted, no integer-looking
    /// enums.
    /// </summary>
    public static JsonSerializerOptions Options { get; } = CreateOptions();

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            PropertyNameCaseInsensitive = false,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            NumberHandling = JsonNumberHandling.Strict,
        };
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower, allowIntegerValues: false));
        options.Converters.Add(new DecimalStringUInt64Converter());
        options.Converters.Add(new NullableDecimalStringUInt64Converter());
        return options;
    }

    /// <summary>Strict JSON parse options: no comments, no trailing commas, bounded depth.</summary>
    public static JsonDocumentOptions DocumentOptions { get; } = new()
    {
        CommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false,
        MaxDepth = ProtocolConstants.MaxJsonDepth,
    };

    /// <summary>Parses a canonical decimal u64 string, rejecting any other shape.</summary>
    public static ulong ParseDecimal64(string text)
    {
        if (text.Length == 0)
        {
            throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "expected decimal string, got empty string");
        }
        if (text.Length > 1 && text[0] == '0')
        {
            throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "decimal string has a leading zero");
        }
        foreach (var ch in text)
        {
            if (ch is < '0' or > '9')
            {
                throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "decimal string contains a non-digit character");
            }
        }
        if (!ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value))
        {
            throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "decimal string overflows u64");
        }
        return value;
    }

    /// <summary>Serializes a typed value to canonical bytes.</summary>
    public static byte[] SerializeCanonical<T>(T value)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, Options);
        return Canonicalize(bytes);
    }

    /// <summary>Deserializes canonical bytes into a typed value (strict).</summary>
    public static T Deserialize<T>(ReadOnlySpan<byte> utf8Json)
    {
        try
        {
            var value = JsonSerializer.Deserialize<T>(utf8Json, Options);
            return value is null
                ? throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "null payload")
                : value;
        }
        catch (JsonException error)
        {
            throw new ProtocolException(ProtocolErrorCode.MalformedFrame, $"invalid payload: {error.Message}");
        }
    }

    /// <summary>
    /// Re-serializes JSON text to canonical bytes: members sorted by UTF-8 key
    /// bytes, compact separators, minimal escapes, null members dropped.
    /// </summary>
    public static byte[] Canonicalize(ReadOnlySpan<byte> utf8Json)
    {
        using var document = JsonDocument.Parse(utf8Json.ToArray(), DocumentOptions);
        ValidateStrict(document.RootElement);
        var buffer = new ArrayBufferWriter<byte>(256);
        WriteCanonical(buffer, document.RootElement);
        return buffer.WrittenSpan.ToArray();
    }

    /// <summary>
    /// Rejects duplicate member names and non-integer numbers anywhere in the
    /// tree (the protocol defines no floats).
    /// </summary>
    public static void ValidateStrict(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                var seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in element.EnumerateObject())
                {
                    if (!seen.Add(property.Name))
                    {
                        throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "duplicate JSON member");
                    }
                    ValidateStrict(property.Value);
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    ValidateStrict(item);
                }
                break;
            case JsonValueKind.Number:
                if (!IsInteger(element))
                {
                    throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "floats are not allowed");
                }
                break;
            default:
                break;
        }
    }

    private static bool IsInteger(JsonElement element)
    {
        if (element.TryGetInt64(out _) || element.TryGetUInt64(out _))
        {
            return true;
        }
        return false;
    }

    /// <summary>Appends the canonical form of <paramref name="element"/> to a buffer.</summary>
    public static void WriteCanonical(IBufferWriter<byte> output, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Null:
                WriteRaw(output, "null");
                break;
            case JsonValueKind.True:
                WriteRaw(output, "true");
                break;
            case JsonValueKind.False:
                WriteRaw(output, "false");
                break;
            case JsonValueKind.Number:
                WriteRaw(output, element.GetRawText());
                break;
            case JsonValueKind.String:
                WriteCanonicalString(output, element.GetString()!);
                break;
            case JsonValueKind.Array:
                WriteByte(output, (byte)'[');
                var firstItem = true;
                foreach (var item in element.EnumerateArray())
                {
                    if (!firstItem)
                    {
                        WriteByte(output, (byte)',');
                    }
                    firstItem = false;
                    WriteCanonical(output, item);
                }
                WriteByte(output, (byte)']');
                break;
            case JsonValueKind.Object:
                WriteByte(output, (byte)'{');
                var properties = new List<JsonProperty>();
                foreach (var property in element.EnumerateObject())
                {
                    // Absent optional fields are omitted; serde encodes None as
                    // null, so drop null members here.
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    properties.Add(property);
                }
                properties.Sort(static (left, right) => CompareUtf8(left.Name, right.Name));
                var firstProperty = true;
                foreach (var property in properties)
                {
                    if (!firstProperty)
                    {
                        WriteByte(output, (byte)',');
                    }
                    firstProperty = false;
                    WriteCanonicalString(output, property.Name);
                    WriteByte(output, (byte)':');
                    WriteCanonical(output, property.Value);
                }
                WriteByte(output, (byte)'}');
                break;
            default:
                throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "unsupported JSON value");
        }
    }

    private static int CompareUtf8(string left, string right)
    {
        var leftBytes = Encoding.UTF8.GetBytes(left);
        var rightBytes = Encoding.UTF8.GetBytes(right);
        return leftBytes.AsSpan().SequenceCompareTo(rightBytes);
    }

    /// <summary>
    /// Writes a JSON string with minimal escaping matching the Rust writer:
    /// short escapes for quote/backslash/b/t/n/f/r and \u00xx (lowercase hex)
    /// for other C0 controls and DEL; all other code points pass through as
    /// raw UTF-8.
    /// </summary>
    public static void WriteCanonicalString(IBufferWriter<byte> output, string text)
    {
        WriteByte(output, (byte)'"');
        foreach (var rune in text.EnumerateRunes())
        {
            if (rune.IsBmp)
            {
                var c = (char)rune.Value;
                switch (c)
                {
                    case '"': WriteRaw(output, "\\\""); break;
                    case '\\': WriteRaw(output, "\\\\"); break;
                    case '\b': WriteRaw(output, "\\b"); break;
                    case '\t': WriteRaw(output, "\\t"); break;
                    case '\n': WriteRaw(output, "\\n"); break;
                    case '\f': WriteRaw(output, "\\f"); break;
                    case '\r': WriteRaw(output, "\\r"); break;
                    default:
                        if (c < 0x20 || c == 0x7F)
                        {
                            WriteRaw(output, "\\u00");
                            WriteByte(output, (byte)"0123456789abcdef"[(c >> 4) & 0x0F]);
                            WriteByte(output, (byte)"0123456789abcdef"[c & 0x0F]);
                        }
                        else
                        {
                            WriteRune(output, rune);
                        }
                        break;
                }
            }
            else
            {
                WriteRune(output, rune);
            }
        }
        WriteByte(output, (byte)'"');
    }

    private static void WriteRune(IBufferWriter<byte> output, Rune rune)
    {
        Span<byte> buffer = stackalloc byte[4];
        var count = rune.EncodeToUtf8(buffer);
        WriteBytes(output, buffer[..count]);
    }

    /// <summary>Appends a single byte.</summary>
    public static void WriteByte(IBufferWriter<byte> output, byte value)
    {
        var span = output.GetSpan(1);
        span[0] = value;
        output.Advance(1);
    }

    /// <summary>Appends raw ASCII text.</summary>
    public static void WriteRaw(IBufferWriter<byte> output, string asciiText)
    {
        var span = output.GetSpan(asciiText.Length);
        var count = Encoding.ASCII.GetBytes(asciiText, span);
        output.Advance(count);
    }

    /// <summary>Appends raw bytes.</summary>
    public static void WriteBytes(IBufferWriter<byte> output, ReadOnlySpan<byte> bytes)
    {
        var span = output.GetSpan(bytes.Length);
        bytes.CopyTo(span);
        output.Advance(bytes.Length);
    }
}
