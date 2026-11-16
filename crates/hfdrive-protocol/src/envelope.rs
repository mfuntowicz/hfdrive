//! Envelope model, strict parsing, and canonical serialization.
//!
//! # Canonical form
//!
//! Cross-language golden fixtures require byte-identical output from the Rust
//! and C# codecs. The canonical JSON writer is defined as:
//!
//! * objects emit members in **UTF-8 byte-lexicographic key order** (for the
//!   protocol's ASCII keys this equals declaration order, which the typed
//!   serializers already produce),
//! * no insignificant whitespace,
//! * strings are escaped minimally: `\"`, `\\`, `\b`, `\t`, `\n`, `\f`, `\r`,
//!   and other `C0`/`DEL` controls as `\u00xx` with **lowercase** hex digits,
//! * numbers: `u32` as decimal integers, `u64` as decimal strings, no floats
//!   appear anywhere in the protocol,
//! * UUIDs are lowercase hyphenated strings.
//!
//! Typed serialization goes through `serde_json`'s `Value` so both the member
//! order and the escaping are produced by one deterministic writer. The parser
//! rejects duplicate member names, `NaN`/infinity, numbers where strings are
//! required (and vice versa), unknown enum variants, and unknown members.
//!
//! # Version rules
//!
//! [`Envelope::parse`] accepts only protocol `1.0`. [`Envelope::parse_handshake`]
//! additionally accepts any `protocol_major`/`protocol_minor` so the provider
//! can answer a `hello` request with its supported versions and close, as the
//! wire contract requires; only the `hello` method is accepted there.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::errors::{ProtocolCodecError, ProtocolError, ProtocolErrorCode};
use crate::types::*;

/// Protocol major implemented by this crate.
pub const PROTOCOL_MAJOR: u32 = 1;
/// Protocol minor implemented by this crate.
pub const PROTOCOL_MINOR: u32 = 0;
/// Maximum frame payload in bytes (1 MiB), length prefix excluded.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
/// Maximum JSON nesting depth accepted while parsing.
pub const MAX_JSON_DEPTH: usize = 64;
/// Maximum records in one page response.
pub const MAX_PAGE_LIMIT: u32 = 200;

/// Every request method name in the wire contract, in canonical order.
///
/// Used by the host for dispatch validation and by the cross-language tests
/// to prove the Rust, C#, and schema registries do not drift.
pub const ALL_METHODS: &[&str] = &[
    "hello",
    "get_status",
    "subscribe_status",
    "cancel_request",
    "start_login",
    "cancel_login",
    "sign_out",
    "list_owners",
    "list_buckets",
    "create_bucket",
    "inspect_drive",
    "begin_setup",
    "set_publication_credentials",
    "probe_storage",
    "repair_storage",
    "preview_connect",
    "connect",
    "pause",
    "resume",
    "set_pin",
    "free_space",
    "set_selective_sync",
    "update_settings",
    "list_activity",
    "list_history",
    "restore",
    "list_conflicts",
    "resolve_conflict",
    "export_diagnostics",
    "prepare_unlink",
    "unlink",
    "prepare_upgrade",
    "exit_provider",
];

/// Envelope discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeKind {
    /// Client to provider command.
    Request,
    /// Provider to client command outcome.
    Response,
    /// Provider to client notification.
    Event,
}

impl EnvelopeKind {
    fn wire(self) -> &'static str {
        match self {
            EnvelopeKind::Request => "request",
            EnvelopeKind::Response => "response",
            EnvelopeKind::Event => "event",
        }
    }

    fn from_wire(text: &str) -> Result<Self, ProtocolCodecError> {
        match text {
            "request" => Ok(EnvelopeKind::Request),
            "response" => Ok(EnvelopeKind::Response),
            "event" => Ok(EnvelopeKind::Event),
            _ => Err(ProtocolCodecError::InvalidField("kind")),
        }
    }
}

/// Typed request body: one variant per command. There is no raw-JSON dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(missing_docs)]
#[serde(untagged)]
pub enum Request {
    Hello(HelloRequest),
    GetStatus(GetStatusRequest),
    SubscribeStatus(SubscribeStatusRequest),
    CancelRequest(CancelRequestRequest),
    StartLogin(StartLoginRequest),
    CancelLogin(CancelLoginRequest),
    SignOut(SignOutRequest),
    ListOwners(ListOwnersRequest),
    ListBuckets(ListBucketsRequest),
    CreateBucket(CreateBucketRequest),
    InspectDrive(InspectDriveRequest),
    BeginSetup(BeginSetupRequest),
    SetPublicationCredentials(SetPublicationCredentialsRequest),
    ProbeStorage(ProbeStorageRequest),
    RepairStorage(RepairStorageRequest),
    PreviewConnect(PreviewConnectRequest),
    Connect(ConnectRequest),
    Pause(PauseRequest),
    Resume(ResumeRequest),
    SetPin(SetPinRequest),
    FreeSpace(FreeSpaceRequest),
    SetSelectiveSync(SetSelectiveSyncRequest),
    UpdateSettings(UpdateSettingsRequest),
    ListActivity(ListActivityRequest),
    ListHistory(ListHistoryRequest),
    Restore(RestoreRequest),
    ListConflicts(ListConflictsRequest),
    ResolveConflict(ResolveConflictRequest),
    ExportDiagnostics(ExportDiagnosticsRequest),
    PrepareUnlink(PrepareUnlinkRequest),
    Unlink(UnlinkRequest),
    PrepareUpgrade(PrepareUpgradeRequest),
    ExitProvider(ExitProviderRequest),
}

/// Typed response result body: one variant per command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(missing_docs)]
#[serde(untagged)]
pub enum ResponseResult {
    Hello(HelloResult),
    GetStatus(GetStatusResult),
    SubscribeStatus(SubscribeStatusResult),
    CancelRequest(CancelRequestResult),
    StartLogin(StartLoginResult),
    CancelLogin(CancelLoginResult),
    SignOut(SignOutResult),
    ListOwners(ListOwnersResult),
    ListBuckets(ListBucketsResult),
    CreateBucket(CreateBucketResult),
    InspectDrive(InspectDriveResult),
    BeginSetup(BeginSetupResult),
    SetPublicationCredentials(SetPublicationCredentialsResult),
    ProbeStorage(ProbeStorageResult),
    RepairStorage(RepairStorageResult),
    PreviewConnect(PreviewConnectResult),
    Connect(ConnectResult),
    Pause(PauseResult),
    Resume(ResumeResult),
    SetPin(SetPinResult),
    FreeSpace(FreeSpaceResult),
    SetSelectiveSync(SetSelectiveSyncResult),
    UpdateSettings(UpdateSettingsResult),
    ListActivity(ListActivityResult),
    ListHistory(ListHistoryResult),
    Restore(RestoreResult),
    ListConflicts(ListConflictsResult),
    ResolveConflict(ResolveConflictResult),
    ExportDiagnostics(ExportDiagnosticsResult),
    PrepareUnlink(PrepareUnlinkResult),
    Unlink(UnlinkResult),
    PrepareUpgrade(PrepareUpgradeResult),
    ExitProvider(ExitProviderResult),
}

/// Typed event payload.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Event {
    StatusChanged(StatusChangedEvent),
    ActivityChanged(ActivityChangedEvent),
    ConflictsChanged(ConflictsChangedEvent),
}

/// Typed response outcome for a command: either the typed result or a
/// structured error (wire `body.result` | `body.error`).
pub type Response = Result<ResponseResult, ProtocolError>;

/// Envelope body, discriminated by the envelope `kind`/`method`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// Typed request payload.
    Request(Request),
    /// Typed response outcome.
    Response {
        /// `Ok` serializes as `body.result`, `Err` as `body.error`.
        outcome: Response,
    },
    /// Typed event payload.
    Event(Event),
}

/// The single wire message shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Protocol major (JSON number).
    pub protocol_major: u32,
    /// Protocol minor (JSON number).
    pub protocol_minor: u32,
    /// Request correlation id; for events this is the event id.
    pub request_id: Uuid,
    /// Envelope discriminant.
    pub kind: EnvelopeKind,
    /// Request method, echoed request method, or event name.
    pub method: String,
    /// Typed body.
    pub body: Body,
}

impl Request {
    /// Returns the wire method name of this request.
    pub fn method(&self) -> &'static str {
        match self {
            Request::Hello(_) => HelloRequest::METHOD,
            Request::GetStatus(_) => GetStatusRequest::METHOD,
            Request::SubscribeStatus(_) => SubscribeStatusRequest::METHOD,
            Request::CancelRequest(_) => CancelRequestRequest::METHOD,
            Request::StartLogin(_) => StartLoginRequest::METHOD,
            Request::CancelLogin(_) => CancelLoginRequest::METHOD,
            Request::SignOut(_) => SignOutRequest::METHOD,
            Request::ListOwners(_) => ListOwnersRequest::METHOD,
            Request::ListBuckets(_) => ListBucketsRequest::METHOD,
            Request::CreateBucket(_) => CreateBucketRequest::METHOD,
            Request::InspectDrive(_) => InspectDriveRequest::METHOD,
            Request::BeginSetup(_) => BeginSetupRequest::METHOD,
            Request::SetPublicationCredentials(_) => SetPublicationCredentialsRequest::METHOD,
            Request::ProbeStorage(_) => ProbeStorageRequest::METHOD,
            Request::RepairStorage(_) => RepairStorageRequest::METHOD,
            Request::PreviewConnect(_) => PreviewConnectRequest::METHOD,
            Request::Connect(_) => ConnectRequest::METHOD,
            Request::Pause(_) => PauseRequest::METHOD,
            Request::Resume(_) => ResumeRequest::METHOD,
            Request::SetPin(_) => SetPinRequest::METHOD,
            Request::FreeSpace(_) => FreeSpaceRequest::METHOD,
            Request::SetSelectiveSync(_) => SetSelectiveSyncRequest::METHOD,
            Request::UpdateSettings(_) => UpdateSettingsRequest::METHOD,
            Request::ListActivity(_) => ListActivityRequest::METHOD,
            Request::ListHistory(_) => ListHistoryRequest::METHOD,
            Request::Restore(_) => RestoreRequest::METHOD,
            Request::ListConflicts(_) => ListConflictsRequest::METHOD,
            Request::ResolveConflict(_) => ResolveConflictRequest::METHOD,
            Request::ExportDiagnostics(_) => ExportDiagnosticsRequest::METHOD,
            Request::PrepareUnlink(_) => PrepareUnlinkRequest::METHOD,
            Request::Unlink(_) => UnlinkRequest::METHOD,
            Request::PrepareUpgrade(_) => PrepareUpgradeRequest::METHOD,
            Request::ExitProvider(_) => ExitProviderRequest::METHOD,
        }
    }

    /// Returns the mutation operation id, when this request is a mutation.
    /// Read-only queries (including `list_activity`) never carry one. The
    /// match is exhaustive on purpose: a new request variant must be
    /// classified as read-only or as a mutation when it is added.
    pub fn operation_id(&self) -> Option<Uuid> {
        match self {
            Request::StartLogin(r) => Some(r.operation_id),
            Request::CancelLogin(r) => Some(r.operation_id),
            Request::SignOut(r) => Some(r.operation_id),
            Request::CreateBucket(r) => Some(r.operation_id),
            Request::BeginSetup(r) => Some(r.operation_id),
            Request::SetPublicationCredentials(r) => Some(r.operation_id),
            Request::ProbeStorage(r) => Some(r.operation_id),
            Request::RepairStorage(r) => Some(r.operation_id),
            Request::PreviewConnect(r) => Some(r.operation_id),
            Request::Connect(r) => Some(r.operation_id),
            Request::Pause(r) => Some(r.operation_id),
            Request::Resume(r) => Some(r.operation_id),
            Request::SetPin(r) => Some(r.operation_id),
            Request::FreeSpace(r) => Some(r.operation_id),
            Request::SetSelectiveSync(r) => Some(r.operation_id),
            Request::UpdateSettings(r) => Some(r.operation_id),
            Request::Restore(r) => Some(r.operation_id),
            Request::ResolveConflict(r) => Some(r.operation_id),
            Request::ExportDiagnostics(r) => Some(r.operation_id),
            Request::PrepareUnlink(r) => Some(r.operation_id),
            Request::Unlink(r) => Some(r.operation_id),
            Request::PrepareUpgrade(r) => Some(r.operation_id),
            Request::ExitProvider(r) => Some(r.operation_id),
            Request::Hello(_)
            | Request::GetStatus(_)
            | Request::SubscribeStatus(_)
            | Request::CancelRequest(_)
            | Request::ListOwners(_)
            | Request::ListBuckets(_)
            | Request::InspectDrive(_)
            | Request::ListActivity(_)
            | Request::ListHistory(_)
            | Request::ListConflicts(_) => None,
        }
    }
}

impl ResponseResult {
    /// Decode a persisted typed result for the same operation method. Raw JSON never dispatches work.
    pub fn from_body(method: &str, value: Value) -> Result<Self, ProtocolCodecError> {
        crate::envelope::decode_result(method, value)
    }
}

impl Event {
    /// Returns the wire event name.
    pub fn method(&self) -> &'static str {
        match self {
            Event::StatusChanged(_) => "status_changed",
            Event::ActivityChanged(_) => "activity_changed",
            Event::ConflictsChanged(_) => "conflicts_changed",
        }
    }

    /// Returns the monotonically increasing event sequence.
    pub fn sequence(&self) -> u64 {
        match self {
            Event::StatusChanged(e) => e.sequence,
            Event::ActivityChanged(e) => e.sequence,
            Event::ConflictsChanged(e) => e.sequence,
        }
    }
}

impl Envelope {
    /// Builds a request envelope at protocol 1.0.
    pub fn request(request_id: Uuid, request: Request) -> Self {
        Envelope {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            request_id,
            kind: EnvelopeKind::Request,
            method: request.method().to_string(),
            body: Body::Request(request),
        }
    }

    /// Builds a response envelope at protocol 1.0.
    pub fn response(
        request_id: Uuid,
        request_method: &str,
        outcome: Response,
    ) -> Self {
        Envelope {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            request_id,
            kind: EnvelopeKind::Response,
            method: request_method.to_string(),
            body: Body::Response { outcome },
        }
    }

    /// Builds an event envelope at protocol 1.0.
    pub fn event(event_id: Uuid, event: Event) -> Self {
        Envelope {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            request_id: event_id,
            kind: EnvelopeKind::Event,
            method: event.method().to_string(),
            body: Body::Event(event),
        }
    }

    /// Serializes this envelope to canonical bytes (see module docs).
    pub fn encode_canonical(&self) -> Result<Vec<u8>, ProtocolCodecError> {
        let body = match &self.body {
            Body::Request(request) => to_value(request)?,
            Body::Response { outcome } => match outcome {
                Ok(result) => {
                    let mut map = Map::new();
                    map.insert("result".to_string(), to_value(result)?);
                    Value::Object(map)
                }
                Err(error) => {
                    let mut map = Map::new();
                    map.insert("error".to_string(), to_value(error)?);
                    Value::Object(map)
                }
            },
            Body::Event(event) => match event {
                Event::StatusChanged(inner) => to_value(inner)?,
                Event::ActivityChanged(inner) => to_value(inner)?,
                Event::ConflictsChanged(inner) => to_value(inner)?,
            },
        };
        let mut map = Map::new();
        map.insert("protocol_major".to_string(), self.protocol_major.into());
        map.insert("protocol_minor".to_string(), self.protocol_minor.into());
        map.insert("request_id".to_string(), self.request_id.to_string().into());
        map.insert("kind".to_string(), self.kind.wire().into());
        map.insert("method".to_string(), self.method.clone().into());
        map.insert("body".to_string(), body);
        canonical::to_vec(&Value::Object(map))
    }

    /// Strict parse: protocol must be exactly 1.0.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolCodecError> {
        Self::parse_inner(bytes, false)
    }

    /// Handshake-tolerant parse used only to inspect a `hello` request whose
    /// declared protocol version may differ. Every structural rule still
    /// applies; any other method with a non-1.0 version is rejected.
    pub fn parse_handshake(bytes: &[u8]) -> Result<Self, ProtocolCodecError> {
        Self::parse_inner(bytes, true)
    }

    fn parse_inner(bytes: &[u8], handshake: bool) -> Result<Self, ProtocolCodecError> {
        let root = parse::parse_value(bytes)?;
        let mut map = match root {
            Value::Object(map) => map,
            _ => return Err(ProtocolCodecError::InvalidField("envelope")),
        };
        let protocol_major = take_u32(&mut map, "protocol_major")?;
        let protocol_minor = take_u32(&mut map, "protocol_minor")?;
        let request_id_text = take_string(&mut map, "request_id")?;
        let request_id = Uuid::parse_str(&request_id_text)
            .map_err(|_| ProtocolCodecError::InvalidField("request_id"))?;
        // Reject non-lowercase or otherwise non-canonical UUID spelling.
        if request_id.to_string() != request_id_text {
            return Err(ProtocolCodecError::InvalidField("request_id"));
        }
        let kind = EnvelopeKind::from_wire(&take_string(&mut map, "kind")?)?;
        let method = take_string(&mut map, "method")?;
        let body = take_value(&mut map, "body")?;
        reject_extra(&map)?;

        let version_ok = protocol_major == PROTOCOL_MAJOR && protocol_minor == PROTOCOL_MINOR;
        if !version_ok {
            if handshake && method == METHOD_HELLO && kind == EnvelopeKind::Request {
                // Accepted only so the host can reply with supported versions.
            } else {
                return Err(ProtocolCodecError::VersionMismatch {
                    major: protocol_major,
                    minor: protocol_minor,
                });
            }
        }

        let body = match kind {
            EnvelopeKind::Request => {
                let request = decode_request(&method, body)?;
                if let Request::Hello(hello) = &request {
                    // A hello body must announce the version of the envelope
                    // that carries it.
                    if hello.protocol_major != protocol_major
                        || hello.protocol_minor != protocol_minor
                    {
                        return Err(ProtocolCodecError::InvalidField("body"));
                    }
                }
                Body::Request(request)
            }
            EnvelopeKind::Response => {
                let mut map = match body {
                    Value::Object(map) => map,
                    _ => return Err(ProtocolCodecError::InvalidField("body")),
                };
                let has_result = map.contains_key("result");
                let has_error = map.contains_key("error");
                if has_result == has_error {
                    return Err(ProtocolCodecError::InvalidField("body"));
                }
                let outcome = if has_result {
                    let result = take_value(&mut map, "result")?;
                    reject_extra(&map)?;
                    Ok(decode_result(&method, result)?)
                } else {
                    let error = take_value(&mut map, "error")?;
                    reject_extra(&map)?;
                    Err(decode_error(error)?)
                };
                Body::Response { outcome }
            }
            EnvelopeKind::Event => Body::Event(decode_event(&method, body)?),
        };

        Ok(Envelope {
            protocol_major,
            protocol_minor,
            request_id,
            kind,
            method,
            body,
        })
    }

    /// Returns a log-safe description: the credential command's body is
    /// redacted, everything else is identified by kind/method/id only.
    pub fn describe_for_log(&self) -> String {
        let secret = self.method == SetPublicationCredentialsRequest::METHOD;
        let body = if secret {
            "<redacted>"
        } else {
            match &self.body {
                Body::Request(_) => "request",
                Body::Response { outcome } => match outcome {
                    Ok(_) => "result",
                    Err(_) => "error",
                },
                Body::Event(_) => "event",
            }
        };
        format!(
            "{} {} request_id={} body={}",
            self.kind.wire(),
            self.method,
            self.request_id,
            body
        )
    }
}

/// `Display` never includes payloads; credential bodies are redacted.
impl core::fmt::Display for Envelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.describe_for_log())
    }
}

// ---------------------------------------------------------------------------
// Method/body agreement helpers.
// ---------------------------------------------------------------------------

macro_rules! dispatch {
    ($value:expr, $method:expr, $enum:ident, $err:ident, $( $name:literal => ($v:ident, $ty:ty) ),+ $(,)? ) => {{
        match $method {
            $( $name => {
                let inner: $ty = from_value($value)
                    .map_err(|_| ProtocolCodecError::InvalidField("body"))?;
                Ok($enum::$v(inner))
            } )+
            other => Err(ProtocolCodecError::$err(other.to_string())),
        }
    }};
}

fn decode_request(method: &str, value: Value) -> Result<Request, ProtocolCodecError> {
    dispatch!(
        value,
        method,
        Request,
        UnknownMethod,
        "hello" => (Hello, HelloRequest),
        "get_status" => (GetStatus, GetStatusRequest),
        "subscribe_status" => (SubscribeStatus, SubscribeStatusRequest),
        "cancel_request" => (CancelRequest, CancelRequestRequest),
        "start_login" => (StartLogin, StartLoginRequest),
        "cancel_login" => (CancelLogin, CancelLoginRequest),
        "sign_out" => (SignOut, SignOutRequest),
        "list_owners" => (ListOwners, ListOwnersRequest),
        "list_buckets" => (ListBuckets, ListBucketsRequest),
        "create_bucket" => (CreateBucket, CreateBucketRequest),
        "inspect_drive" => (InspectDrive, InspectDriveRequest),
        "begin_setup" => (BeginSetup, BeginSetupRequest),
        "set_publication_credentials" => (SetPublicationCredentials, SetPublicationCredentialsRequest),
        "probe_storage" => (ProbeStorage, ProbeStorageRequest),
        "repair_storage" => (RepairStorage, RepairStorageRequest),
        "preview_connect" => (PreviewConnect, PreviewConnectRequest),
        "connect" => (Connect, ConnectRequest),
        "pause" => (Pause, PauseRequest),
        "resume" => (Resume, ResumeRequest),
        "set_pin" => (SetPin, SetPinRequest),
        "free_space" => (FreeSpace, FreeSpaceRequest),
        "set_selective_sync" => (SetSelectiveSync, SetSelectiveSyncRequest),
        "update_settings" => (UpdateSettings, UpdateSettingsRequest),
        "list_activity" => (ListActivity, ListActivityRequest),
        "list_history" => (ListHistory, ListHistoryRequest),
        "restore" => (Restore, RestoreRequest),
        "list_conflicts" => (ListConflicts, ListConflictsRequest),
        "resolve_conflict" => (ResolveConflict, ResolveConflictRequest),
        "export_diagnostics" => (ExportDiagnostics, ExportDiagnosticsRequest),
        "prepare_unlink" => (PrepareUnlink, PrepareUnlinkRequest),
        "unlink" => (Unlink, UnlinkRequest),
        "prepare_upgrade" => (PrepareUpgrade, PrepareUpgradeRequest),
        "exit_provider" => (ExitProvider, ExitProviderRequest)
    )
}

pub(crate) fn decode_result(method: &str, value: Value) -> Result<ResponseResult, ProtocolCodecError> {
    dispatch!(
        value,
        method,
        ResponseResult,
        UnknownMethod,
        "hello" => (Hello, HelloResult),
        "get_status" => (GetStatus, GetStatusResult),
        "subscribe_status" => (SubscribeStatus, SubscribeStatusResult),
        "cancel_request" => (CancelRequest, CancelRequestResult),
        "start_login" => (StartLogin, StartLoginResult),
        "cancel_login" => (CancelLogin, CancelLoginResult),
        "sign_out" => (SignOut, SignOutResult),
        "list_owners" => (ListOwners, ListOwnersResult),
        "list_buckets" => (ListBuckets, ListBucketsResult),
        "create_bucket" => (CreateBucket, CreateBucketResult),
        "inspect_drive" => (InspectDrive, InspectDriveResult),
        "begin_setup" => (BeginSetup, BeginSetupResult),
        "set_publication_credentials" => (SetPublicationCredentials, SetPublicationCredentialsResult),
        "probe_storage" => (ProbeStorage, ProbeStorageResult),
        "repair_storage" => (RepairStorage, RepairStorageResult),
        "preview_connect" => (PreviewConnect, PreviewConnectResult),
        "connect" => (Connect, ConnectResult),
        "pause" => (Pause, PauseResult),
        "resume" => (Resume, ResumeResult),
        "set_pin" => (SetPin, SetPinResult),
        "free_space" => (FreeSpace, FreeSpaceResult),
        "set_selective_sync" => (SetSelectiveSync, SetSelectiveSyncResult),
        "update_settings" => (UpdateSettings, UpdateSettingsResult),
        "list_activity" => (ListActivity, ListActivityResult),
        "list_history" => (ListHistory, ListHistoryResult),
        "restore" => (Restore, RestoreResult),
        "list_conflicts" => (ListConflicts, ListConflictsResult),
        "resolve_conflict" => (ResolveConflict, ResolveConflictResult),
        "export_diagnostics" => (ExportDiagnostics, ExportDiagnosticsResult),
        "prepare_unlink" => (PrepareUnlink, PrepareUnlinkResult),
        "unlink" => (Unlink, UnlinkResult),
        "prepare_upgrade" => (PrepareUpgrade, PrepareUpgradeResult),
        "exit_provider" => (ExitProvider, ExitProviderResult)
    )
}

fn decode_event(method: &str, value: Value) -> Result<Event, ProtocolCodecError> {
    dispatch!(
        value,
        method,
        Event,
        UnknownMethod,
        "status_changed" => (StatusChanged, StatusChangedEvent),
        "activity_changed" => (ActivityChanged, ActivityChangedEvent),
        "conflicts_changed" => (ConflictsChanged, ConflictsChangedEvent)
    )
}

fn decode_error(value: Value) -> Result<ProtocolError, ProtocolCodecError> {
    let map = match value {
        Value::Object(map) => map,
        _ => return Err(ProtocolCodecError::InvalidField("error")),
    };
    // Accept the typed ErrorObject shape ("code","message","retry_after_ms").
    let mut map = map;
    let code_text = take_string(&mut map, "code")?;
    let code = ProtocolErrorCode::from_wire(&code_text).ok_or(ProtocolCodecError::InvalidField("code"))?;
    let message = take_string(&mut map, "message")?;
    let retry_after_ms = match map.remove("retry_after_ms") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(
            crate::dec_u64::parse(&text)
                .map_err(|_| ProtocolCodecError::InvalidField("retry_after_ms"))?,
        ),
        Some(_) => return Err(ProtocolCodecError::InvalidField("retry_after_ms")),
    };
    reject_extra(&map)?;
    Ok(ProtocolError {
        code,
        message,
        retry_after_ms,
    })
}

// ---------------------------------------------------------------------------
// Value <-> typed helpers (serde_json::Value keeps ordering deterministic).
// ---------------------------------------------------------------------------

fn to_value<T: Serialize>(value: &T) -> Result<Value, ProtocolCodecError> {
    serde_json::to_value(value).map_err(|_| ProtocolCodecError::InvalidField("serialization"))
}

fn from_value<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, ProtocolCodecError> {
    serde_json::from_value(value).map_err(|_| ProtocolCodecError::InvalidField("body"))
}

fn take_value(map: &mut Map<String, Value>, key: &str) -> Result<Value, ProtocolCodecError> {
    map.remove(key)
        .ok_or(ProtocolCodecError::InvalidField("missing member"))
}

fn take_string(map: &mut Map<String, Value>, key: &'static str) -> Result<String, ProtocolCodecError> {
    match take_value(map, key)? {
        Value::String(text) => Ok(text),
        _ => Err(ProtocolCodecError::InvalidField(key)),
    }
}

fn take_u32(map: &mut Map<String, Value>, key: &'static str) -> Result<u32, ProtocolCodecError> {
    match take_value(map, key)? {
        Value::Number(number) => number
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(ProtocolCodecError::InvalidField(key)),
        _ => Err(ProtocolCodecError::InvalidField(key)),
    }
}

fn reject_extra(map: &Map<String, Value>) -> Result<(), ProtocolCodecError> {
    if map.is_empty() {
        Ok(())
    } else {
        Err(ProtocolCodecError::InvalidField("unknown member"))
    }
}

mod parse {
    //! Minimal strict JSON parser with duplicate-key and depth rejection.

    use serde_json::{Map, Value};

    use super::MAX_JSON_DEPTH;
    use crate::errors::ProtocolCodecError;

    pub(crate) fn parse_value(bytes: &[u8]) -> Result<Value, ProtocolCodecError> {
        let text = std::str::from_utf8(bytes).map_err(|_| ProtocolCodecError::Utf8)?;
        let mut parser = Parser {
            bytes: text.as_bytes(),
            pos: 0,
        };
        parser.skip_ws();
        let value = parser.value(0)?;
        parser.skip_ws();
        if parser.pos != parser.bytes.len() {
            return Err(ProtocolCodecError::InvalidJson);
        }
        Ok(value)
    }

    struct Parser<'a> {
        bytes: &'a [u8],
        pos: usize,
    }

    impl Parser<'_> {
        fn peek(&self) -> Option<u8> {
            self.bytes.get(self.pos).copied()
        }

        fn skip_ws(&mut self) {
            while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
                self.pos += 1;
            }
        }

        fn expect(&mut self, byte: u8) -> Result<(), ProtocolCodecError> {
            if self.peek() == Some(byte) {
                self.pos += 1;
                Ok(())
            } else {
                Err(ProtocolCodecError::InvalidJson)
            }
        }

        fn value(&mut self, depth: usize) -> Result<Value, ProtocolCodecError> {
            if depth > MAX_JSON_DEPTH {
                return Err(ProtocolCodecError::InvalidJson);
            }
            match self.peek() {
                Some(b'{') => self.object(depth),
                Some(b'[') => self.array(depth),
                Some(b'"') => Ok(Value::String(self.string()?)),
                Some(b't') => self.literal("true", Value::Bool(true)),
                Some(b'f') => self.literal("false", Value::Bool(false)),
                Some(b'n') => self.literal("null", Value::Null),
                Some(byte) if byte == b'-' || byte.is_ascii_digit() => self.number(),
                _ => Err(ProtocolCodecError::InvalidJson),
            }
        }

        fn literal(&mut self, text: &str, value: Value) -> Result<Value, ProtocolCodecError> {
            if self.bytes[self.pos..].starts_with(text.as_bytes()) {
                self.pos += text.len();
                Ok(value)
            } else {
                Err(ProtocolCodecError::InvalidJson)
            }
        }

        fn object(&mut self, depth: usize) -> Result<Value, ProtocolCodecError> {
            self.expect(b'{')?;
            let mut map = Map::new();
            self.skip_ws();
            if self.peek() == Some(b'}') {
                self.pos += 1;
                return Ok(Value::Object(map));
            }
            loop {
                self.skip_ws();
                let key = self.string()?;
                self.skip_ws();
                self.expect(b':')?;
                self.skip_ws();
                let value = self.value(depth + 1)?;
                if map.insert(key, value).is_some() {
                    return Err(ProtocolCodecError::DuplicateJsonKey);
                }
                self.skip_ws();
                match self.peek() {
                    Some(b',') => self.pos += 1,
                    Some(b'}') => {
                        self.pos += 1;
                        return Ok(Value::Object(map));
                    }
                    _ => return Err(ProtocolCodecError::InvalidJson),
                }
            }
        }

        fn array(&mut self, depth: usize) -> Result<Value, ProtocolCodecError> {
            self.expect(b'[')?;
            let mut items = Vec::new();
            self.skip_ws();
            if self.peek() == Some(b']') {
                self.pos += 1;
                return Ok(Value::Array(items));
            }
            loop {
                self.skip_ws();
                items.push(self.value(depth + 1)?);
                self.skip_ws();
                match self.peek() {
                    Some(b',') => self.pos += 1,
                    Some(b']') => {
                        self.pos += 1;
                        return Ok(Value::Array(items));
                    }
                    _ => return Err(ProtocolCodecError::InvalidJson),
                }
            }
        }

        fn string(&mut self) -> Result<String, ProtocolCodecError> {
            self.expect(b'"')?;
            let mut out = Vec::new();
            loop {
                let byte = self.peek().ok_or(ProtocolCodecError::InvalidJson)?;
                self.pos += 1;
                match byte {
                    b'"' => break,
                    b'\\' => {
                        let escape = self.peek().ok_or(ProtocolCodecError::InvalidJson)?;
                        self.pos += 1;
                        match escape {
                            b'"' => out.push(b'"'),
                            b'\\' => out.push(b'\\'),
                            b'/' => out.push(b'/'),
                            b'b' => out.push(0x08),
                            b't' => out.push(b'\t'),
                            b'n' => out.push(b'\n'),
                            b'f' => out.push(0x0c),
                            b'r' => out.push(b'\r'),
                            b'u' => {
                                let unit = self.hex4()?;
                                if (0xD800..=0xDBFF).contains(&unit) {
                                    // Surrogate pair.
                                    self.expect(b'\\')?;
                                    self.expect(b'u')?;
                                    let low = self.hex4()?;
                                    if !(0xDC00..=0xDFFF).contains(&low) {
                                        return Err(ProtocolCodecError::InvalidJson);
                                    }
                                    let code = 0x10000
                                        + ((unit - 0xD800) as u32) * 0x400
                                        + (low - 0xDC00) as u32;
                                    let ch = char::from_u32(code)
                                        .ok_or(ProtocolCodecError::InvalidJson)?;
                                    let mut buffer = [0u8; 4];
                                    out.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
                                } else if (0xDC00..=0xDFFF).contains(&unit) {
                                    return Err(ProtocolCodecError::InvalidJson);
                                } else {
                                    let ch = char::from_u32(unit as u32)
                                        .ok_or(ProtocolCodecError::InvalidJson)?;
                                    let mut buffer = [0u8; 4];
                                    out.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
                                }
                            }
                            _ => return Err(ProtocolCodecError::InvalidJson),
                        }
                    }
                    0x00..=0x1F => return Err(ProtocolCodecError::InvalidJson),
                    _ => out.push(byte),
                }
            }
            String::from_utf8(out).map_err(|_| ProtocolCodecError::Utf8)
        }

        fn hex4(&mut self) -> Result<u16, ProtocolCodecError> {
            if self.pos + 4 > self.bytes.len() {
                return Err(ProtocolCodecError::InvalidJson);
            }
            let text = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4])
                .map_err(|_| ProtocolCodecError::InvalidJson)?;
            let value = u16::from_str_radix(text, 16).map_err(|_| ProtocolCodecError::InvalidJson)?;
            self.pos += 4;
            Ok(value)
        }

        fn number(&mut self) -> Result<Value, ProtocolCodecError> {
            let start = self.pos;
            if self.peek() == Some(b'-') {
                self.pos += 1;
            }
            let mut digits = 0;
            while matches!(self.peek(), Some(byte) if byte.is_ascii_digit()) {
                self.pos += 1;
                digits += 1;
            }
            if digits == 0 {
                return Err(ProtocolCodecError::InvalidJson);
            }
            let mut is_float = false;
            if self.peek() == Some(b'.') {
                is_float = true;
                self.pos += 1;
                let mut fraction = 0;
                while matches!(self.peek(), Some(byte) if byte.is_ascii_digit()) {
                    self.pos += 1;
                    fraction += 1;
                }
                if fraction == 0 {
                    return Err(ProtocolCodecError::InvalidJson);
                }
            }
            if matches!(self.peek(), Some(b'e' | b'E')) {
                is_float = true;
                self.pos += 1;
                if matches!(self.peek(), Some(b'+' | b'-')) {
                    self.pos += 1;
                }
                let mut exponent = 0;
                while matches!(self.peek(), Some(byte) if byte.is_ascii_digit()) {
                    self.pos += 1;
                    exponent += 1;
                }
                if exponent == 0 {
                    return Err(ProtocolCodecError::InvalidJson);
                }
            }
            let text = std::str::from_utf8(&self.bytes[start..self.pos])
                .map_err(|_| ProtocolCodecError::InvalidJson)?;
            if is_float {
                serde_json::Number::from_f64(text.parse::<f64>().map_err(|_| {
                    ProtocolCodecError::InvalidJson
                })?)
                .map(Value::Number)
                .ok_or(ProtocolCodecError::InvalidJson)
            } else {
                serde_json::from_str::<Value>(text).map_err(|_| ProtocolCodecError::InvalidJson)
            }
        }
    }
}

pub(crate) fn canonical_body<T: Serialize>(body: &T) -> Result<Vec<u8>, ProtocolCodecError> {
    canonical::to_vec(&to_value(body)?)
}

mod canonical {
    //! Deterministic canonical JSON writer (see module docs at crate root).

    use serde_json::Value;

    use crate::errors::ProtocolCodecError;

    pub(crate) fn to_vec(value: &Value) -> Result<Vec<u8>, ProtocolCodecError> {
        let mut out = Vec::new();
        write_value(&mut out, value)?;
        Ok(out)
    }

    fn write_value(out: &mut Vec<u8>, value: &Value) -> Result<(), ProtocolCodecError> {
        match value {
            Value::Null => out.extend_from_slice(b"null"),
            Value::Bool(true) => out.extend_from_slice(b"true"),
            Value::Bool(false) => out.extend_from_slice(b"false"),
            Value::Number(number) => out.extend_from_slice(number.to_string().as_bytes()),
            Value::String(text) => write_string(out, text),
            Value::Array(items) => {
                out.push(b'[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    write_value(out, item)?;
                }
                out.push(b']');
            }
            Value::Object(map) => {
                out.push(b'{');
                let mut first = true;
                for (key, item) in map.iter() {
                    // The wire contract omits absent optional fields; serde
                    // encodes `None` as `null`, so drop null members here.
                    if item.is_null() {
                        continue;
                    }
                    if !first {
                        out.push(b',');
                    }
                    first = false;
                    write_string(out, key);
                    out.push(b':');
                    write_value(out, item)?;
                }
                out.push(b'}');
            }
        }
        Ok(())
    }

    fn write_string(out: &mut Vec<u8>, text: &str) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        out.push(b'"');
        for byte in text.bytes() {
            match byte {
                b'"' => out.extend_from_slice(b"\\\""),
                b'\\' => out.extend_from_slice(b"\\\\"),
                0x08 => out.extend_from_slice(b"\\b"),
                b'\t' => out.extend_from_slice(b"\\t"),
                b'\n' => out.extend_from_slice(b"\\n"),
                0x0C => out.extend_from_slice(b"\\f"),
                b'\r' => out.extend_from_slice(b"\\r"),
                0x00..=0x1F | 0x7F => {
                    out.extend_from_slice(b"\\u00");
                    out.push(HEX[(byte >> 4) as usize]);
                    out.push(HEX[(byte & 0x0F) as usize]);
                }
                _ => out.push(byte),
            }
        }
        out.push(b'"');
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::AccountStatus;

    fn sample_request() -> Envelope {
        Envelope::request(
            Uuid::from_bytes([0x11; 16]),
            Request::StartLogin(StartLoginRequest {
                operation_id: Uuid::from_bytes([0x22; 16]),
                flow: LoginFlow::Pkce,
                purpose: LoginPurpose::Signin,
                organization_id: None,
            }),
        )
    }

    #[test]
    fn canonical_round_trip_request() {
        let envelope = sample_request();
        let bytes = envelope.encode_canonical().unwrap();
        let parsed = Envelope::parse(&bytes).unwrap();
        assert_eq!(parsed, envelope);
    }

    #[test]
    fn rejects_duplicate_keys() {
        let bytes = br#"{"protocol_major":1,"protocol_minor":0,"request_id":"00000000-0000-4000-8000-000000000000","kind":"request","method":"get_status","body":{},"kind":"request"}"#;
        assert!(matches!(
            Envelope::parse(bytes),
            Err(ProtocolCodecError::DuplicateJsonKey)
        ));
    }

    #[test]
    fn rejects_version_mismatch_but_handshake_allows_hello() {
        let bytes = br#"{"protocol_major":2,"protocol_minor":7,"request_id":"00000000-0000-4000-8000-000000000000","kind":"request","method":"hello","body":{"protocol_major":2,"protocol_minor":7,"role":"cli","build_version":"x"}}"#;
        assert!(matches!(
            Envelope::parse(bytes),
            Err(ProtocolCodecError::VersionMismatch {
                major: 2,
                minor: 7
            })
        ));
        let parsed = Envelope::parse_handshake(bytes).unwrap();
        assert!(matches!(parsed.body, Body::Request(Request::Hello(_))));
    }

    #[test]
    fn handshake_rejects_non_hello_with_foreign_version() {
        let bytes = br#"{"protocol_major":2,"protocol_minor":0,"request_id":"00000000-0000-4000-8000-000000000000","kind":"request","method":"get_status","body":{}}"#;
        assert!(Envelope::parse_handshake(bytes).is_err());
    }

    #[test]
    fn rejects_unknown_members_and_methods() {
        let bytes = br#"{"protocol_major":1,"protocol_minor":0,"request_id":"00000000-0000-4000-8000-000000000000","kind":"request","method":"get_status","body":{},"extra":1}"#;
        assert!(Envelope::parse(bytes).is_err());
        let bytes = br#"{"protocol_major":1,"protocol_minor":0,"request_id":"00000000-0000-4000-8000-000000000000","kind":"request","method":"nope","body":{}}"#;
        assert!(matches!(
            Envelope::parse(bytes),
            Err(ProtocolCodecError::UnknownMethod(_))
        ));
    }

    #[test]
    fn response_result_and_error_shapes() {
        let ok = Envelope::response(
            Uuid::from_bytes([0x33; 16]),
            "get_status",
            Ok(ResponseResult::GetStatus(GetStatusResult {
                event_sequence: 7,
                account: AccountStatus::default(),
                connections: vec![],
            })),
        );
        let bytes = ok.encode_canonical().unwrap();
        assert_eq!(Envelope::parse(&bytes).unwrap(), ok);

        let err = Envelope::response(
            Uuid::from_bytes([0x33; 16]),
            "get_status",
            Err(ProtocolError {
                code: ProtocolErrorCode::Busy,
                message: "retry".to_string(),
                retry_after_ms: Some(50),
            }),
        );
        let bytes = err.encode_canonical().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.contains(r#""body":{"error":{"code":"busy","message":"retry","retry_after_ms":"50""#));
        assert_eq!(Envelope::parse(&bytes).unwrap(), err);
    }

    #[test]
    fn credential_body_is_redacted() {
        let envelope = Envelope::request(
            Uuid::from_bytes([0x44; 16]),
            Request::SetPublicationCredentials(SetPublicationCredentialsRequest {
                operation_id: Uuid::from_bytes([0x55; 16]),
                connection_id: Uuid::from_bytes([0x66; 16]),
                protected_credentials: "AAAA".to_string(),
            }),
        );
        let description = envelope.describe_for_log();
        assert!(!description.contains("AAAA"));
        let debug = format!("{:?}", envelope);
        assert!(!debug.contains("AAAA"));
    }

    #[test]
    fn rejects_wrong_kind_body_combination() {
        let bytes = br#"{"protocol_major":1,"protocol_minor":0,"request_id":"00000000-0000-4000-8000-000000000000","kind":"response","method":"get_status","body":{}}"#;
        assert!(Envelope::parse(bytes).is_err());
        let bytes = br#"{"protocol_major":1,"protocol_minor":0,"request_id":"00000000-0000-4000-8000-000000000000","kind":"event","method":"get_status","body":{}}"#;
        assert!(Envelope::parse(bytes).is_err());
    }

    #[test]
    fn operation_id_classifies_mutations_and_read_only_queries() {
        // A mutation carries a unique operation id; the provider uses
        // `operation_id()` for durable-operation reservation. This catches a
        // request variant silently losing its id classification.
        let mutation = Request::Restore(RestoreRequest {
            operation_id: Uuid::from_bytes([0x22; 16]),
            connection_id: Uuid::from_bytes([0x77; 16]),
            item_id: Uuid::from_bytes([0x33; 16]),
            version_id: Uuid::from_bytes([0x44; 16]),
        });
        assert_eq!(mutation.operation_id(), Some(Uuid::from_bytes([0x22; 16])));

        // `list_activity` is the additive optional read-only query: its request
        // has no operation id, and its name is a registered wire method.
        let read_only = Request::ListActivity(ListActivityRequest {
            connection_id: Uuid::from_bytes([0x77; 16]),
            cursor: Some("activity:1".to_string()),
            limit: 50,
        });
        assert_eq!(read_only.method(), "list_activity");
        assert_eq!(read_only.operation_id(), None);
        assert!(ALL_METHODS.contains(&read_only.method()));
    }
}
