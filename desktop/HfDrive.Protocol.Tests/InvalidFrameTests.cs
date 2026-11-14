using System.Text;
using Xunit;

namespace HfDrive.Protocol.Tests;

/// <summary>Adversarial frames must be rejected with the documented error code.</summary>
public sealed class InvalidFrameTests
{
    [Fact]
    public void InvalidFrames_Are_Rejected_With_Documented_Codes()
    {
        foreach (var fixture in Fixtures.Load("invalid"))
        {
            var frame = Hex.Decode(fixture.FrameHex);
            var expected = ProtocolErrorCodeConverter.WireToCode(fixture.ExpectedErrorCode!);

            if (fixture.Stage == "frame")
            {
                var exception = Assert.Throws<ProtocolException>(() =>
                    Async.Run(() => FrameCodec.ReadFrameAsync(new MemoryStream(frame), CancellationToken.None).AsTask()));
                Assert.Equal(expected, exception.Error.Code);
                continue;
            }

            // Envelope stage: the frame itself must be well-formed.
            var payload = Async.Run(() => FrameCodec.ReadFrameAsync(new MemoryStream(frame), CancellationToken.None).AsTask());
            Assert.NotNull(payload);
            var envelopeException = Assert.Throws<ProtocolException>(() => Envelope.Parse(payload!));
            Assert.Equal(expected, envelopeException.Error.Code);
        }
    }

    [Fact]
    public void Oversized_Declaration_Is_Rejected_Before_The_Payload_Is_Read()
    {
        // Length 0x00100001 (1 MiB + 1) with a single stray payload byte: the
        // codec must reject on the declaration, not attempt the read.
        var frame = Hex.Decode("01001000" + "00");
        var exception = Assert.Throws<ProtocolException>(() =>
            Async.Run(() => FrameCodec.ReadFrameAsync(new MemoryStream(frame), CancellationToken.None).AsTask()));
        Assert.Equal(ProtocolErrorCode.FrameTooLarge, exception.Error.Code);
    }

    [Fact]
    public void Zero_Length_Frame_Is_Invalid()
    {
        var frame = new byte[] { 0, 0, 0, 0 };
        var exception = Assert.Throws<ProtocolException>(() =>
            Async.Run(() => FrameCodec.ReadFrameAsync(new MemoryStream(frame), CancellationToken.None).AsTask()));
        Assert.Equal(ProtocolErrorCode.MalformedFrame, exception.Error.Code);
    }

    [Fact]
    public void Clean_Eof_At_Frame_Boundary_Returns_Null()
    {
        var result = Async.Run(() => FrameCodec.ReadFrameAsync(new MemoryStream(Array.Empty<byte>()), CancellationToken.None).AsTask());
        Assert.Null(result);
    }

    [Fact]
    public void Truncated_Header_Or_Payload_Is_Unexpected_Eof()
    {
        var truncatedHeader = new byte[] { 1, 0 };
        var first = Assert.Throws<ProtocolException>(() =>
            Async.Run(() => FrameCodec.ReadFrameAsync(new MemoryStream(truncatedHeader), CancellationToken.None).AsTask()));
        Assert.Equal(ProtocolErrorCode.UnexpectedEof, first.Error.Code);

        var truncatedPayload = new byte[] { 4, 0, 0, 0, (byte)'a' };
        var second = Assert.Throws<ProtocolException>(() =>
            Async.Run(() => FrameCodec.ReadFrameAsync(new MemoryStream(truncatedPayload), CancellationToken.None).AsTask()));
        Assert.Equal(ProtocolErrorCode.UnexpectedEof, second.Error.Code);
    }

    [Fact]
    public void Write_Rejects_Empty_And_Oversized_Payloads()
    {
        Assert.Throws<ProtocolException>(() =>
            Async.Run(() => FrameCodec.WriteFrameAsync(new MemoryStream(), ReadOnlyMemory<byte>.Empty, CancellationToken.None).AsTask()));
        Assert.Throws<ProtocolException>(() =>
            Async.Run(() => FrameCodec.WriteFrameAsync(new MemoryStream(), new byte[ProtocolConstants.MaxFrameBytes + 1], CancellationToken.None).AsTask()));
    }

    [Fact]
    public void Boundary_Payload_Round_Trips()
    {
        var payload = Enumerable.Repeat((byte)'q', ProtocolConstants.MaxFrameBytes).ToArray();
        var stream = new MemoryStream();
        Async.Run(() => FrameCodec.WriteFrameAsync(stream, payload, CancellationToken.None).AsTask());
        Assert.Equal(4 + payload.Length, stream.Length);
        stream.Position = 0;
        var read = Async.Run(() => FrameCodec.ReadFrameAsync(stream, CancellationToken.None).AsTask());
        Assert.Equal(payload, read);
    }

    [Fact]
    public void Envelope_Parse_Rejects_Non_Utf8_And_Trailing_Bytes()
    {
        Assert.Throws<ProtocolException>(() => Envelope.Parse(new byte[] { 0x22, 0xC3, 0x28, 0x22 }));
        var trailing = Encoding.UTF8.GetBytes("{\"protocol_major\":1}x");
        Assert.Throws<ProtocolException>(() => Envelope.Parse(trailing));
    }
}
