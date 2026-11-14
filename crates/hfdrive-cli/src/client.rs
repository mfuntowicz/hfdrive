use hfdrive_protocol::{Body, Envelope, ProtocolCodecError, ProtocolError, Request, ResponseResult, read_envelope, write_envelope};
use std::fmt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Debug)]
pub enum ClientError {
    Codec(ProtocolCodecError),
    Remote(ProtocolError),
    Closed,
    UnexpectedReply,
    Cancelled,
}
impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => fmt::Display::fmt(error, f),
            Self::Remote(error) => write!(f, "{:?}: {}", error.code, error.message),
            Self::Closed => f.write_str("provider disconnected before returning a result; accepted work may still be pending"),
            Self::UnexpectedReply => f.write_str("provider returned an uncorrelated response"),
            Self::Cancelled => f.write_str("request cancelled; accepted durable work is retained"),
        }
    }
}
impl std::error::Error for ClientError {}

/// Call only after OS-level server identity verification. This client has one
/// outstanding command; an interrupted frame requires closing the connection.
pub async fn call<S>(stream: &mut S, request: Request, cancel: &CancellationToken) -> Result<ResponseResult, ClientError>
where S: AsyncRead + AsyncWrite + Unpin {
    let id = Uuid::new_v4();
    let method = request.method();
    let envelope = Envelope::request(id, request);
    tokio::select! {
        _ = cancel.cancelled() => return Err(ClientError::Cancelled),
        result = write_envelope(stream, &envelope) => result.map_err(ClientError::Codec)?,
    }
    loop {
        let reply = tokio::select! {
            _ = cancel.cancelled() => return Err(ClientError::Cancelled),
            result = read_envelope(stream) => result.map_err(ClientError::Codec)?.ok_or(ClientError::Closed)?,
        };
        match reply.body {
            Body::Event(_) => continue,
            Body::Response { outcome } if reply.request_id == id && reply.method == method => {
                return outcome.map_err(ClientError::Remote);
            }
            _ => return Err(ClientError::UnexpectedReply),
        }
    }
}
