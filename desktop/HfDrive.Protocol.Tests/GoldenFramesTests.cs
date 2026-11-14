using System.Text;
using Xunit;

namespace HfDrive.Protocol.Tests;

/// <summary>Golden cross-language frames must decode and re-encode identically.</summary>
public sealed class GoldenFramesTests
{
    [Fact]
    public void GoldenFrames_Parse_And_Reencode_Byte_Identically()
    {
        foreach (var fixture in Fixtures.Load("golden"))
        {
            if (fixture.ExpectationParse != "accept")
            {
                // Fixtures with a non-accept expectation are covered by
                // Hello_From_Future_Version_Uses_Handshake_Parse.
                continue;
            }

            var frame = Hex.Decode(fixture.FrameHex);
            Assert.NotNull(fixture.PayloadHex);
            var payload = Hex.Decode(fixture.PayloadHex!);

            // Frame layer: header + payload delivered as stored.
            var readPayload = Async.Run(() => FrameCodec.ReadFrameAsync(new MemoryStream(frame), CancellationToken.None).AsTask());
            Assert.Equal(payload, readPayload);

            // Envelope layer: strict parse, then canonical re-encode must be
            // byte-identical to the golden payload.
            var envelope = Envelope.Parse(payload);
            Assert.Equal(payload, envelope.ToCanonicalBytes());

            if (fixture.RedactionMarker is not null)
            {
                Assert.DoesNotContain(fixture.RedactionMarker, envelope.DescribeForLog(), StringComparison.Ordinal);
                Assert.DoesNotContain(fixture.RedactionMarker, envelope.ToString(), StringComparison.Ordinal);
            }
        }
    }

    [Fact]
    public void Hello_From_Future_Version_Uses_Handshake_Parse()
    {
        var fixture = Fixtures.LoadFile(Path.Combine(RepoPaths.FixturesDirectory, "golden", "hello_request_from_v2.json"));
        Assert.Equal("reject:unsupported_protocol", fixture.ExpectationParse);
        var payload = Hex.Decode(fixture.PayloadHex!);

        var exception = Assert.Throws<ProtocolException>(() => Envelope.Parse(payload));
        Assert.Equal(ProtocolErrorCode.UnsupportedProtocol, exception.Error.Code);

        var envelope = Envelope.ParseHandshake(payload);
        Assert.Equal(EnvelopeKind.Request, envelope.Kind);
        Assert.Equal("hello", envelope.Method);
        var hello = envelope.GetRequestBody<HelloRequest>();
        Assert.Equal(2, hello.ProtocolMajor);
        Assert.Equal(3, hello.ProtocolMinor);
        Assert.Equal("accept", fixture.ExpectationParseHandshake);
    }

    [Fact]
    public void Hello_Body_Version_Must_Agree_With_Envelope()
    {
        // 1.0 envelope whose hello body announces 2.0 must be rejected even
        // though the shape is otherwise valid.
        const string raw =
            "{\"protocol_major\":1,\"protocol_minor\":0,\"request_id\":\"00000000-0000-4000-8000-000000000000\",\"kind\":\"request\",\"method\":\"hello\",\"body\":{\"protocol_major\":2,\"protocol_minor\":0,\"role\":\"cli\",\"build_version\":\"1\"}}";
        var exception = Assert.Throws<ProtocolException>(() => Envelope.Parse(Encoding.UTF8.GetBytes(raw)));
        Assert.Equal(ProtocolErrorCode.MalformedFrame, exception.Error.Code);
    }

    [Fact]
    public void All_Golden_Methods_Are_In_The_Typed_Registry()
    {
        foreach (var fixture in Fixtures.Load("golden"))
        {
            Assert.NotNull(fixture.PayloadHex);
            using var document = System.Text.Json.JsonDocument.Parse(Hex.Decode(fixture.PayloadHex!));
            var kind = document.RootElement.GetProperty("kind").GetString();
            var method = document.RootElement.GetProperty("method").GetString()!;
            if (kind == "event")
            {
                Assert.Contains(method, new[] { "status_changed", "activity_changed", "conflicts_changed" });
            }
            else
            {
                Assert.Contains(method, Commands.AllMethods);
            }
        }
    }
}
