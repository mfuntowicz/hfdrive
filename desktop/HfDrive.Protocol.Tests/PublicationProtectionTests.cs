using System.Text.Json;
using Xunit;

namespace HfDrive.Protocol.Tests;

public sealed class PublicationProtectionTests
{
    [Fact]
    public void ProtectionContextMatchesCrossLanguageUuidAndUnicodeVectors()
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(RepoPaths.FixturesDirectory, "publication-protection.json")));
        foreach (var vector in document.RootElement.GetProperty("vectors").EnumerateArray())
        {
            var context = vector.GetProperty("context").Deserialize<PublicationProtectionContext>(ProtocolJson.Options)!;
            var operationId = vector.GetProperty("operation_id").GetGuid();
            var expected = vector.GetProperty("entropy").EnumerateArray().Select(value => value.GetByte()).ToArray();
            Assert.Equal(expected, context.Entropy(operationId));
            Assert.Throws<ArgumentException>(() => context.Entropy(Guid.Empty));
        }
    }
}
