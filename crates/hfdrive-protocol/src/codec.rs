//! Length-prefixed frame codec.
//!
//! Frame layout: a 4-byte little-endian unsigned length `N` followed by `N`
//! bytes of UTF-8 JSON payload. `N` must be in `1..=MAX_FRAME_BYTES`
//! (1 MiB); a zero length is invalid and a larger declared length is rejected
//! **before** the payload is read.
//!
//! # Cancellation safety
//!
//! [`read_frame`] returns `Ok(None)` only on a clean end of stream at a frame
//! boundary; a partial length prefix or payload is [`ProtocolCodecError::UnexpectedEof`].
//! Dropping a read future is harmless (the caller still owns the stream
//! position decision), but dropping [`write_frame`] mid-frame leaves a partial
//! frame on the wire and therefore **cancels the connection**, not the frame:
//! callers must only cancel writes between frames and close the stream when a
//! write future is cancelled mid-frame. Every request on a connection is
//! otherwise independent: cancelling one request never disturbs other frames.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::envelope::{Envelope, MAX_FRAME_BYTES};
use crate::errors::ProtocolCodecError;

/// Reads exactly one frame.
///
/// Returns `Ok(None)` when the stream is cleanly closed at a frame boundary.
pub async fn read_frame<R>(reader: &mut R) -> Result<Option<Vec<u8>>, ProtocolCodecError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    let mut filled = 0usize;
    while filled < 4 {
        let read = reader
            .read(&mut header[filled..])
            .await
            .map_err(ProtocolCodecError::Io)?;
        if read == 0 {
            if filled == 0 {
                return Ok(None);
            }
            return Err(ProtocolCodecError::UnexpectedEof);
        }
        filled += read;
    }
    let length = u32::from_le_bytes(header);
    if length == 0 {
        return Err(ProtocolCodecError::InvalidFrameLength);
    }
    if length as usize > MAX_FRAME_BYTES {
        return Err(ProtocolCodecError::FrameTooLarge { len: length });
    }
    let mut payload = vec![0u8; length as usize];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::UnexpectedEof => ProtocolCodecError::UnexpectedEof,
            _ => ProtocolCodecError::Io(error),
        })?;
    Ok(Some(payload))
}

/// Writes exactly one frame and flushes it to the transport.
pub async fn write_frame<W>(writer: &mut W, payload: &[u8]) -> Result<(), ProtocolCodecError>
where
    W: AsyncWrite + Unpin,
{
    if payload.is_empty() {
        return Err(ProtocolCodecError::InvalidFrameLength);
    }
    if payload.len() > MAX_FRAME_BYTES {
        return Err(ProtocolCodecError::FrameTooLarge {
            len: payload.len() as u32,
        });
    }
    let header = (payload.len() as u32).to_le_bytes();
    writer
        .write_all(&header)
        .await
        .map_err(ProtocolCodecError::Io)?;
    writer
        .write_all(payload)
        .await
        .map_err(ProtocolCodecError::Io)?;
    writer.flush().await.map_err(ProtocolCodecError::Io)?;
    Ok(())
}

/// Reads and strictly decodes one envelope frame.
///
/// Returns `Ok(None)` on a clean end of stream at a frame boundary.
pub async fn read_envelope<R>(reader: &mut R) -> Result<Option<Envelope>, ProtocolCodecError>
where
    R: AsyncRead + Unpin,
{
    match read_frame(reader).await? {
        None => Ok(None),
        Some(payload) => Envelope::parse(&payload).map(Some),
    }
}

/// Reads and strictly decodes one envelope frame, tolerating a foreign
/// protocol version only for the `hello` request (handshake semantics).
///
/// The caller inspects `protocol_major`/`protocol_minor` and replies with the
/// supported versions before closing when they differ.
pub async fn read_envelope_handshake<R>(reader: &mut R) -> Result<Option<Envelope>, ProtocolCodecError>
where
    R: AsyncRead + Unpin,
{
    match read_frame(reader).await? {
        None => Ok(None),
        Some(payload) => Envelope::parse_handshake(&payload).map(Some),
    }
}

/// Encodes and writes one envelope frame.
pub async fn write_envelope<W>(writer: &mut W, envelope: &Envelope) -> Result<(), ProtocolCodecError>
where
    W: AsyncWrite + Unpin,
{
    let payload = envelope.encode_canonical()?;
    write_frame(writer, &payload).await
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWrite;

    use super::*;

    /// Minimal in-memory `AsyncWrite` sink for codec tests.
    struct Sink(Vec<u8>);

    impl AsyncWrite for Sink {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.get_mut().0.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    async fn round_trip(payload: &[u8]) {
        let mut sink = Sink(Vec::new());
        write_frame(&mut sink, payload).await.unwrap();
        let mut source: &[u8] = &sink.0;
        let read = read_frame(&mut source).await.unwrap().unwrap();
        assert_eq!(read, payload);
    }

    #[tokio::test]
    async fn round_trips_payloads() {
        round_trip(b"x").await;
        round_trip(&vec![b'a'; MAX_FRAME_BYTES]).await;
    }

    #[tokio::test]
    async fn clean_eof_is_none() {
        let mut source: &[u8] = &[];
        assert!(read_frame(&mut source).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn partial_header_is_unexpected_eof() {
        let mut source: &[u8] = &[0x01, 0x00];
        assert!(matches!(
            read_frame(&mut source).await,
            Err(ProtocolCodecError::UnexpectedEof)
        ));
    }

    #[tokio::test]
    async fn partial_payload_is_unexpected_eof() {
        let mut bytes = 4u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"ab");
        let mut source: &[u8] = &bytes;
        assert!(matches!(
            read_frame(&mut source).await,
            Err(ProtocolCodecError::UnexpectedEof)
        ));
    }

    #[tokio::test]
    async fn zero_length_is_invalid() {
        let bytes = 0u32.to_le_bytes();
        let mut source: &[u8] = &bytes;
        assert!(matches!(
            read_frame(&mut source).await,
            Err(ProtocolCodecError::InvalidFrameLength)
        ));
    }

    #[tokio::test]
    async fn oversized_declaration_is_rejected_before_payload() {
        let length = (MAX_FRAME_BYTES as u32) + 1;
        let mut bytes = length.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"payload-that-must-not-be-read");
        let mut source: &[u8] = &bytes;
        assert!(matches!(
            read_frame(&mut source).await,
            Err(ProtocolCodecError::FrameTooLarge { len }) if len == length
        ));
        // The payload was not consumed: only the 4 header bytes are gone.
        assert_eq!(source.len(), bytes.len() - 4);
    }

    #[tokio::test]
    async fn write_rejects_empty_and_oversized_payloads() {
        let mut sink = Sink(Vec::new());
        assert!(write_frame(&mut sink, b"").await.is_err());
        assert!(write_frame(&mut sink, &vec![0u8; MAX_FRAME_BYTES + 1])
            .await
            .is_err());
    }

    #[tokio::test]
    async fn streaming_reads_interleave_with_writes() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let writer = tokio::spawn(async move {
            write_frame(&mut client, b"one").await.unwrap();
            write_frame(&mut client, b"two").await.unwrap();
        });
        assert_eq!(
            read_frame(&mut server).await.unwrap().unwrap(),
            b"one".to_vec()
        );
        assert_eq!(
            read_frame(&mut server).await.unwrap().unwrap(),
            b"two".to_vec()
        );
        assert!(read_frame(&mut server).await.unwrap().is_none());
        writer.await.unwrap();
        let source: &[u8] = &[1, 0, 0, 0, b'z'];
        let mut source = source;
        let payload = read_frame(&mut source).await.unwrap().unwrap();
        assert_eq!(payload, b"z");
    }

    #[tokio::test]
    async fn envelope_round_trip_over_frames() {
        use uuid::Uuid;

        use crate::envelope::{Envelope, Request};
        use crate::types::GetStatusRequest;

        let envelope = Envelope::request(Uuid::nil(), Request::GetStatus(GetStatusRequest {}));
        let mut sink = Sink(Vec::new());
        write_envelope(&mut sink, &envelope).await.unwrap();
        let mut source: &[u8] = &sink.0;
        let decoded = read_envelope(&mut source).await.unwrap().unwrap();
        assert_eq!(decoded, envelope);
    }

    #[tokio::test]
    async fn write_all_then_flush_keeps_stream_writable() {
        let (mut write_half, mut read_half) = tokio::io::duplex(64);
        let task = tokio::spawn(async move {
            write_frame(&mut write_half, b"payload").await.unwrap();
        });
        let payload = read_frame(&mut read_half).await.unwrap().unwrap();
        assert_eq!(payload, b"payload");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn cancellation_between_frames_is_safe() {
        let mut sink = Sink(Vec::new());
        write_frame(&mut sink, b"first").await.unwrap();
        // A cancelled read/write pair at a frame boundary leaves the stream
        // parseable from the next frame onward.
        let mut source: &[u8] = &sink.0;
        assert_eq!(
            read_frame(&mut source).await.unwrap().unwrap(),
            b"first".to_vec()
        );
        assert!(read_frame(&mut source).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn read_exact_edge_accepts_boundary_payload() {
        let mut bytes = (MAX_FRAME_BYTES as u32).to_le_bytes().to_vec();
        bytes.extend(std::iter::repeat(b'q').take(MAX_FRAME_BYTES));
        let mut source: &[u8] = &bytes;
        let payload = read_frame(&mut source).await.unwrap().unwrap();
        assert_eq!(payload.len(), MAX_FRAME_BYTES);
    }

    #[tokio::test]
    async fn writer_flush_is_required_between_frames() {
        use tokio::io::AsyncReadExt;
        let (mut writer, mut reader) = tokio::io::duplex(32);
        write_frame(&mut writer, b"abc").await.unwrap();
        let mut header = [0u8; 4];
        reader.read_exact(&mut header).await.unwrap();
        assert_eq!(u32::from_le_bytes(header), 3);
    }
}
