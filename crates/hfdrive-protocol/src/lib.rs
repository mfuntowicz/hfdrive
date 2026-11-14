//! HF Drive IPC protocol 1.0: portable wire contract and codecs.
//!
//! This crate is transport- and OS-independent: it defines the typed message
//! model, the strict envelope parser, the canonical cross-language
//! serialization, and the Tokio frame codec over any
//! [`tokio::io::AsyncRead`]/[`tokio::io::AsyncWrite`] stream (the provider's
//! authenticated named pipe supplies one). It has no dependency on the core,
//! state, or provider crates.
//!
//! # Wire summary
//!
//! * Frame: 4-byte little-endian length (1..=1 MiB) + UTF-8 JSON payload.
//! * Envelope members (in canonical order): `protocol_major` (number),
//!   `protocol_minor` (number), `request_id` (lowercase UUID), `kind`
//!   (`request`|`response`|`event`), `method` (snake_case), `body` (object).
//! * Response `body` is exactly one of `{"result": ...}` or
//!   `{"error": {"code","message","retry_after_ms?"}}`.
//! * All `u64` values are canonical decimal strings; optional fields are
//!   omitted when absent; unknown members and non-canonical values are
//!   rejected.
//! * Protocol 1.0 only: [`Envelope::parse`] rejects anything else, while
//!   [`Envelope::parse_handshake`] admits a `hello` request from any version
//!   so the provider can answer with its supported versions and close.
//!
//! See `spec/ipc-v1.schema.json` (normative schema), `spec/remote-v1.md`
//! (managed remote format) and `spec/fixtures/` (cross-language golden
//! frames shared with the C# `HfDrive.Protocol` project).

mod account;
mod codec;
mod dec_u64;
mod envelope;
mod errors;
mod types;

pub use account::*;
pub use codec::{
    read_envelope, read_envelope_handshake, read_frame, write_envelope, write_frame,
};
pub use envelope::{
    Body, Envelope, EnvelopeKind, Event, Request, Response, ResponseResult, ALL_METHODS,
    MAX_FRAME_BYTES, MAX_JSON_DEPTH, MAX_PAGE_LIMIT, PROTOCOL_MAJOR, PROTOCOL_MINOR,
};
pub use errors::{ProtocolCodecError, ProtocolError, ProtocolErrorCode};
pub use types::*;
