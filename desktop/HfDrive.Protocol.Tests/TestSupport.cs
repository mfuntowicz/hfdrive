using System.Text;
using System.Text.Json;
using Xunit;

namespace HfDrive.Protocol.Tests;

/// <summary>Locates the repository's spec/fixtures directory.</summary>
internal static class RepoPaths
{
    internal static string SpecDirectory
    {
        get
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null)
            {
                var candidate = Path.Combine(dir.FullName, "spec", "fixtures");
                if (Directory.Exists(candidate))
                {
                    return Path.Combine(dir.FullName, "spec");
                }
                dir = dir.Parent;
            }
            throw new InvalidOperationException("spec/fixtures not found above the test output directory");
        }
    }

    internal static string FixturesDirectory => Path.Combine(SpecDirectory, "fixtures");
}

/// <summary>Hex helpers for fixture payloads.</summary>
internal static class Hex
{
    internal static byte[] Decode(string text)
    {
        Assert.Equal(0, text.Length % 2);
        var bytes = new byte[text.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(text.Substring(i * 2, 2), 16);
        }
        return bytes;
    }

    internal static string Encode(ReadOnlySpan<byte> bytes)
    {
        var builder = new StringBuilder(bytes.Length * 2);
        foreach (var value in bytes)
        {
            builder.Append(value.ToString("x2"));
        }
        return builder.ToString();
    }
}

/// <summary>One cross-language fixture file.</summary>
internal sealed record Fixture(
    string Name,
    string Description,
    string? Stage,
    string? ExpectedErrorCode,
    string? ExpectationParse,
    string? ExpectationParseHandshake,
    string? RedactionMarker,
    string FrameHex,
    string? PayloadHex);

/// <summary>Loads cross-language fixtures from spec/fixtures.</summary>
internal static class Fixtures
{
    internal static IReadOnlyList<Fixture> Load(string subdir)
    {
        var directory = Path.Combine(RepoPaths.FixturesDirectory, subdir);
        var files = Directory.GetFiles(directory, "*.json").OrderBy(f => f, StringComparer.Ordinal).ToArray();
        Assert.NotEmpty(files);
        return files.Select(LoadFile).ToArray();
    }

    internal static Fixture LoadFile(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(path), new JsonDocumentOptions
        {
            CommentHandling = JsonCommentHandling.Disallow,
            AllowTrailingCommas = false,
            MaxDepth = ProtocolConstants.MaxJsonDepth,
        });
        var root = document.RootElement;
        string? StageValue = root.TryGetProperty("stage", out var stage) ? stage.GetString() : null;
        string? ErrorCodeValue = null;
        if (root.TryGetProperty("expectation", out var expectation)
            && expectation.TryGetProperty("error_code", out var errorCode))
        {
            ErrorCodeValue = errorCode.GetString();
        }
        string? ParseValue = null;
        string? ParseHandshakeValue = null;
        string? RedactionMarkerValue = null;
        if (root.TryGetProperty("expectation", out expectation))
        {
            if (expectation.TryGetProperty("parse", out var parse))
            {
                ParseValue = parse.GetString();
            }
            if (expectation.TryGetProperty("parse_handshake", out var parseHandshake))
            {
                ParseHandshakeValue = parseHandshake.GetString();
            }
            if (expectation.TryGetProperty("describe_for_log_must_not_contain", out var marker))
            {
                RedactionMarkerValue = marker.GetString();
            }
        }

        return new Fixture(
            Name: root.GetProperty("name").GetString()!,
            Description: root.GetProperty("description").GetString()!,
            Stage: StageValue,
            ExpectedErrorCode: ErrorCodeValue,
            ExpectationParse: ParseValue,
            ExpectationParseHandshake: ParseHandshakeValue,
            RedactionMarker: RedactionMarkerValue,
            FrameHex: root.GetProperty("frame_hex").GetString()!,
            PayloadHex: root.TryGetProperty("payload_hex", out var payload) ? payload.GetString() : null);
    }
}

/// <summary>Shared async test helpers.</summary>
internal static class Async
{
    internal static T Run<T>(Func<Task<T>> body) => body().GetAwaiter().GetResult();

    internal static void Run(Func<Task> body) => body().GetAwaiter().GetResult();
}
