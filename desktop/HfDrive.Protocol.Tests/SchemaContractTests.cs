using System.Text.Json;
using Xunit;

namespace HfDrive.Protocol.Tests;

/// <summary>
/// The typed registry in this project must not drift from the normative
/// schema and the shared fixture set.
/// </summary>
public sealed class SchemaContractTests
{
    [Fact]
    public void Schema_Body_Map_Matches_The_Typed_Command_Registry()
    {
        var schemaPath = Path.Combine(RepoPaths.SpecDirectory, "ipc-v1.schema.json");
        using var document = JsonDocument.Parse(File.ReadAllBytes(schemaPath), ProtocolJson.DocumentOptions);
        var listed = document.RootElement
            .GetProperty("$defs")
            .GetProperty("body_map")
            .GetProperty("request_methods")
            .EnumerateArray()
            .Select(element => element.GetString()!)
            .ToArray();
        var registry = Commands.AllMethods.OrderBy(m => m, StringComparer.Ordinal).ToArray();
        Assert.Equal(registry, listed);
    }

    [Fact]
    public void Schema_Envelope_Members_Are_The_Wire_Contract()
    {
        var schemaPath = Path.Combine(RepoPaths.SpecDirectory, "ipc-v1.schema.json");
        using var document = JsonDocument.Parse(File.ReadAllBytes(schemaPath), ProtocolJson.DocumentOptions);
        var envelope = document.RootElement.GetProperty("$defs").GetProperty("envelope");
        var required = envelope.GetProperty("required")
            .EnumerateArray()
            .Select(element => element.GetString()!)
            .ToArray();
        Assert.Equal(
            new[] { "protocol_major", "protocol_minor", "request_id", "kind", "method", "body" },
            required);
        Assert.False(envelope.GetProperty("additionalProperties").GetBoolean());
    }

    [Fact]
    public void Fixture_Index_Covers_Every_Fixture_File()
    {
        var indexPath = Path.Combine(RepoPaths.FixturesDirectory, "index.json");
        using var document = JsonDocument.Parse(File.ReadAllBytes(indexPath), ProtocolJson.DocumentOptions);
        var listed = new HashSet<string>(StringComparer.Ordinal);
        foreach (var group in new[] { "golden", "invalid" })
        {
            foreach (var item in document.RootElement.GetProperty(group).EnumerateArray())
            {
                listed.Add(item.GetProperty("file").GetString()!);
            }
        }

        var onDisk = Directory.GetFiles(Path.Combine(RepoPaths.FixturesDirectory, "golden"), "*.json")
            .Concat(Directory.GetFiles(Path.Combine(RepoPaths.FixturesDirectory, "invalid"), "*.json"))
            .Select(path => $"{Path.GetFileName(Path.GetDirectoryName(path))}/{Path.GetFileName(path)}")
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(onDisk, listed.OrderBy(name => name, StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public void Handshake_Parse_Rejects_Foreign_Versions_For_Non_Hello_Methods()
    {
        const string raw =
            "{\"protocol_major\":2,\"protocol_minor\":0,\"request_id\":\"00000000-0000-4000-8000-000000000000\",\"kind\":\"request\",\"method\":\"get_status\",\"body\":{}}";
        var exception = Assert.Throws<ProtocolException>(
            () => Envelope.ParseHandshake(System.Text.Encoding.UTF8.GetBytes(raw)));
        Assert.Equal(ProtocolErrorCode.UnsupportedProtocol, exception.Error.Code);
    }

    [Fact]
    public void Commands_Registry_Methods_Are_All_Distinct_And_Snake_Case()
    {
        Assert.Equal(Commands.AllMethods.Count, Commands.AllMethods.Distinct(StringComparer.Ordinal).Count());
        foreach (var method in Commands.AllMethods)
        {
            Assert.Equal(method.ToLowerInvariant(), method);
            Assert.DoesNotContain(' ', method);
        }
    }
}
