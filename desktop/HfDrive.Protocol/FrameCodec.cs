using System.Buffers.Binary;

namespace HfDrive.Protocol;

/// <summary>
/// Length-prefixed frame codec: 4-byte little-endian length (1..=1 MiB)
/// followed by the UTF-8 JSON payload.
/// </summary>
public static class FrameCodec
{
    /// <summary>
    /// Reads exactly one frame. Returns <c>null</c> on a clean end of stream at
    /// a frame boundary; a partial header or payload raises
    /// <see cref="ProtocolErrorCode.UnexpectedEof"/>.
    /// </summary>
    public static async ValueTask<byte[]?> ReadFrameAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[ProtocolConstants.HeaderLength];
        var filled = 0;
        while (filled < header.Length)
        {
            var read = await stream.ReadAsync(header.AsMemory(filled), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return filled == 0
                    ? null
                    : throw new ProtocolException(ProtocolErrorCode.UnexpectedEof, "unexpected end of stream");
            }
            filled += read;
        }

        var length = BinaryPrimitives.ReadUInt32LittleEndian(header);
        if (length == 0)
        {
            throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "invalid frame length");
        }
        if (length > ProtocolConstants.MaxFrameBytes)
        {
            throw new ProtocolException(ProtocolErrorCode.FrameTooLarge, $"frame length {length} exceeds the maximum");
        }

        var payload = new byte[length];
        filled = 0;
        while (filled < payload.Length)
        {
            var read = await stream.ReadAsync(payload.AsMemory(filled), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new ProtocolException(ProtocolErrorCode.UnexpectedEof, "unexpected end of stream");
            }
            filled += read;
        }
        return payload;
    }

    /// <summary>
    /// Writes exactly one frame and flushes it. Cancelling mid-frame leaves a
    /// partial frame on the wire and therefore closes the connection; callers
    /// must only cancel between frames.
    /// </summary>
    public static async ValueTask WriteFrameAsync(Stream stream, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        if (payload.Length == 0)
        {
            throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "invalid frame length");
        }
        if (payload.Length > ProtocolConstants.MaxFrameBytes)
        {
            throw new ProtocolException(ProtocolErrorCode.FrameTooLarge, $"frame length {payload.Length} exceeds the maximum");
        }

        var header = new byte[ProtocolConstants.HeaderLength];
        BinaryPrimitives.WriteUInt32LittleEndian(header, (uint)payload.Length);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}
