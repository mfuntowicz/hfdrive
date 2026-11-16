//! Typed IPC 1.0 message model.
//!
//! Wire shape rules (mirrored exactly by the C# `HfDrive.Protocol` project and
//! enforced by `spec/ipc-v1.schema.json`):
//!
//! * Struct members are serialized in declaration order with
//!   `#[serde(rename_all = "snake_case")]`; envelope member order is fixed to
//!   `protocol_major`, `protocol_minor`, `request_id`, `kind`, `method`, `body`.
//! * Absent optional fields are omitted from canonical output; a JSON `null`
//!   for an optional field decodes as absent.
//! * Every `u64` field is a decimal string (see [`crate::dec_u64`]); `u32`
//!   fields are JSON numbers; UUIDs are lowercase hyphenated strings.
//! * Unknown struct members are rejected everywhere
//!   (`deny_unknown_fields`), unknown enum variants are rejected, and string
//!   enums use their `snake_case` wire names.
//! * All mutation requests carry a unique `operation_id` (operation UUID) so a
//!   reconnect/retry cannot apply a durable mutation twice.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Wire name of the `hello` request method.
pub const METHOD_HELLO: &str = "hello";

/// Returns the wire method name for every request type.
pub trait RequestMethod {
    /// The `method` string carried in the request envelope.
    const METHOD: &'static str;
}

macro_rules! request_method {
    ($ty:ty, $method:literal) => {
        impl RequestMethod for $ty {
            const METHOD: &'static str = $method;
        }
    };
}

/// Client role announced in [`HelloRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientRole {
    /// The WinUI desktop application.
    Desktop,
    /// The `hfdrive` command line tool.
    Cli,
}

/// OAuth login flow selected by the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginFlow {
    /// Authorization-code flow with PKCE through the system browser.
    Pkce,
    /// Explicitly selected device-authorization fallback.
    Device,
}

/// Why the login is being started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginPurpose {
    /// Establish the signed-in person.
    Signin,
    /// Request read access to storage.
    ReadStorage,
    /// Request write access to storage.
    WriteStorage,
    /// Request permission to create new storage.
    CreateStorage,
}

/// Owner kind for a bucket/namespace owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerKind {
    /// The signed-in person's own namespace.
    Personal,
    /// An organization namespace.
    Organization,
}

/// Bucket visibility as reported by the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    /// Private bucket.
    Private,
    /// Public bucket.
    Public,
}

/// Access mode of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    /// Committed content is browsable; local edits cannot be uploaded.
    ReadOnly,
    /// Full bidirectional synchronization.
    Writable,
}

/// Capability state of a connection (Step 2 capability gates).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    /// Committed content readable, no write authorization.
    ReadOnly,
    /// Supplemental publication authorization is missing.
    StorageSetupRequired,
    /// Writes are paused pending capability revalidation.
    WriteSyncPaused,
    /// Native and publication authorization plus capability evidence present.
    Writable,
}

/// Display/health state of a connection (exact UI state list).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    /// Committed publication and local generation agree.
    UpToDate,
    /// Local changes await upload.
    PendingUpload,
    /// Content upload in progress.
    Uploading,
    /// Publication (CAS) in progress.
    PublishingChanges,
    /// Remote content download in progress.
    Downloading,
    /// Provider cannot reach the remote services.
    Offline,
    /// Sign-in required.
    NeedsSignIn,
    /// Supplemental storage setup required.
    StorageSetupRequired,
    /// Authorization denied.
    PermissionDenied,
    /// Unresolved conflict present.
    Conflict,
    /// Insufficient local disk space.
    DiskFull,
    /// Writes paused by the user or policy.
    WriteSyncPaused,
}

/// Pin state (requested versus fully resident is tracked separately).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinState {
    /// No offline pin requested.
    Unpinned,
    /// Offline pin requested.
    Pinned,
    /// Pin partially satisfied.
    Partial,
}

/// Placeholder hydration state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HydrationState {
    /// All bytes resident.
    Full,
    /// Some bytes resident.
    Partial,
    /// Metadata only.
    OnlineOnly,
}

/// Pin request mode for `SetPin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinMode {
    /// Keep content fully available offline.
    Pin,
    /// Remove the offline pin.
    Unpin,
}

/// Free-local-space mode for `FreeSpace`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreeSpaceMode {
    /// Free everything that is safely freeable.
    All,
    /// Free everything except pinned subtrees.
    ExceptPinned,
}

/// Item kind in the managed namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    /// A file item.
    File,
    /// A directory item.
    Directory,
}

/// Direction of an activity record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityDirection {
    /// Local to remote.
    Upload,
    /// Remote to local.
    Download,
    /// Metadata only.
    Metadata,
}

/// Lifecycle phase of an activity record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityPhase {
    /// A local save was observed.
    Observed,
    /// Snapshot capture in progress.
    Snapshot,
    /// Content upload in progress.
    Uploading,
    /// Publication in progress.
    Publishing,
    /// Download in progress.
    Downloading,
    /// The operation completed.
    Completed,
    /// The operation failed; see `last_error`.
    Failed,
    /// The operation is blocked by a conflict.
    Conflict,
}

/// Class of a colliding item during connect preview.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollisionKind {
    /// Both sides have the item with identical bytes.
    IdenticalContent,
    /// Both sides differ.
    DifferentContent,
    /// Present locally only.
    LocalOnly,
    /// Present remotely only.
    RemoteOnly,
    /// Case-colliding names on Windows.
    CaseCollision,
    /// Name reserved or otherwise invalid.
    NameInvalid,
}

/// Proposed preview action for a colliding item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposedAction {
    /// Adopt the identical bytes after digest verification.
    AdoptIdentical,
    /// Keep both sides as separate items.
    KeepBoth,
    /// Queue the local file as new work.
    QueueLocal,
    /// Materialize the remote item locally.
    DownloadRemote,
    /// User must choose a resolution.
    RequiresReview,
}

/// History change kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryChangeKind {
    /// Item created.
    Create,
    /// Content changed.
    Content,
    /// Item renamed or moved.
    Location,
    /// Item deleted.
    Delete,
}

/// Conflict kind recorded during reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    /// Concurrent content edits.
    Content,
    /// Concurrent renames/moves.
    Rename,
    /// Delete versus edit.
    DeleteEdit,
    /// Case-colliding names.
    CaseCollision,
    /// Move would produce a cycle.
    MoveCycle,
}

/// Conflict resolution choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictResolution {
    /// The conflict still needs a resolution.
    Unresolved,
    /// Keep the local version as the contested path.
    KeepLocal,
    /// Keep the remote version.
    KeepRemote,
    /// Keep both versions.
    KeepBoth,
    /// Reconciliation preserved the changed side and dropped the deletion.
    Recovered,
}

/// Unlink mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnlinkMode {
    /// Hydrate/export committed content, then unregister.
    SafeRemove,
    /// Disconnect only, keeping the registration for recovery.
    DisconnectKeepRegistration,
}

/// Probe check kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeCheckKind {
    /// Native upload visible natively.
    NativeUploadVisibleNatively,
    /// Native upload visible through S3.
    NativeUploadVisibleS3,
    /// GET body and ETag coherence.
    GetBodyEtagCoherence,
    /// Guarded initial create.
    GuardedCreate,
    /// Two writers with the same ETag: exactly one winner.
    ConcurrentSameEtag,
    /// Stale ETag overwrite rejection.
    StaleOverwriteRejected,
    /// Discarded successful CAS response recovered through ancestry.
    AmbiguousCasRecovery,
    /// Random Xet ranges equal the source slices.
    XetRangeReads,
}

/// Probe check outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    /// Observed behavior matched the expectation.
    Passed,
    /// Observed behavior differed.
    Failed,
    /// The check could not be executed; see `detail`.
    NotRun,
}

/// Progress update for a long-running request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ProgressUpdate {
    /// Units completed so far.
    #[serde(with = "crate::dec_u64")]
    pub completed: u64,
    /// Total units, when known.
    #[serde(default, with = "crate::dec_u64::option", skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    /// Display-only phase label.
    pub phase: String,
}

/// Verified owner candidate populated from userinfo and capability probes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Owner {
    /// Whether the owner is the person or an organization.
    pub owner_kind: OwnerKind,
    /// Stable server-side owner identifier (retained across display renames).
    pub owner_id: String,
    /// Validated canonical namespace, absent when the provider did not supply one.
    pub namespace: Option<String>,
    /// Display-only name.
    pub display_name: String,
    /// Role hint for display; never an authorization decision.
    pub role: Option<String>,
    /// Provider-reported restrictions for display; not an authorization decision.
    pub restrictions: Vec<String>,
    /// True when storage creation was observed to be permitted.
    pub can_create: bool,
}

/// A bucket candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Bucket {
    /// Stable server-side bucket identifier.
    pub bucket_id: String,
    /// Bucket name.
    pub name: String,
    /// Owner namespace of the bucket.
    pub namespace: String,
    /// Bucket visibility.
    pub visibility: Visibility,
}

/// Bucket/prefix selector before the managed workspace identity has been discovered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteLocation {
    /// Current canonical owner namespace.
    pub owner_namespace: String,
    /// Stable verified owner identity.
    pub owner_id: String,
    /// Personal or organization owner.
    pub owner_kind: OwnerKind,
    /// Current bare bucket name.
    pub bucket: String,
    /// Stable bucket identity.
    pub bucket_id: String,
    /// Exact selected prefix.
    pub prefix: String,
}

/// The validated remote binding selected for a connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RemoteBinding {
    /// Canonical owner namespace.
    pub owner_namespace: String,
    /// Stable owner identifier.
    pub owner_id: String,
    /// Owner kind.
    pub owner_kind: OwnerKind,
    /// Bucket name.
    pub bucket: String,
    /// Stable bucket identifier.
    pub bucket_id: String,
    /// Managed prefix inside the bucket.
    pub prefix: String,
    /// Workspace identifier of the managed namespace at that prefix.
    pub workspace_id: Uuid,
}

/// A single probe expectation/observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ProbeCheck {
    /// Which check this record describes.
    pub kind: ProbeCheckKind,
    /// Expected behavior (display text).
    pub expected: String,
    /// Observed behavior (display text).
    pub observed: String,
    /// Outcome.
    pub outcome: ProbeOutcome,
    /// Optional non-secret detail.
    pub detail: Option<String>,
}

/// A connect-preview collision record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Collision {
    /// Collision class.
    pub kind: CollisionKind,
    /// Relative path under the connection root (display form).
    pub relative_path: String,
    /// Item identifier when one side is already tracked.
    pub item_id: Option<Uuid>,
    /// Proposed action requiring user review.
    pub proposed_action: ProposedAction,
}

/// A proposed namespace/file action shown during connect preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ProposedActionRecord {
    /// Item the action concerns, when known.
    pub item_id: Option<Uuid>,
    /// Action class.
    pub action: ProposedAction,
    /// Display-only description.
    pub description: String,
}

/// A committed history entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct HistoryRecord {
    /// Commit identifier.
    pub commit_id: Uuid,
    /// Parent commit, `None` only for the initial commit.
    pub parent_commit_id: Option<Uuid>,
    /// Generation recorded in `HEAD` for this commit, when retained evidence proves it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<Uuid>,
    /// Device that produced the commit (display only).
    pub device_id: Uuid,
    /// Display-only RFC 3339 creation time; never used for ordering.
    pub created_at: String,
    /// Summary of changes.
    pub changes: Vec<HistoryChange>,
}

/// One change inside a history record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct HistoryChange {
    /// Item identifier.
    pub item_id: Uuid,
    /// Change class.
    pub kind: HistoryChangeKind,
    /// Display name after the change.
    pub name: String,
    /// Parent after the change (`None` only for the root item).
    pub parent_id: Option<Uuid>,
}

/// A recorded conflict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ConflictRecord {
    /// Deterministic conflict identifier (UUIDv5).
    pub conflict_id: Uuid,
    /// Item identifier.
    pub item_id: Uuid,
    /// Conflict class.
    pub kind: ConflictKind,
    /// Competing operation UUIDs, sorted.
    pub competing_operation_ids: Vec<Uuid>,
    /// Both revisions involved.
    pub revisions: Vec<Uuid>,
    /// Original names/locations preserved for both sides.
    pub original_names: Vec<String>,
    /// Display-only RFC 3339 timestamp.
    pub detected_at: String,
    /// Current resolution state.
    pub resolution_state: ConflictResolution,
}

/// The target bucket/owner object of a raw bucket import.
///
/// The import destination is exactly the `hfdrive-imports/<import_id>` prefix (no trailing slash)
/// reported by the `import` result; nothing else in the bucket is touched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ImportTarget {
    /// Whether the target owner is the person or an organization.
    pub owner_kind: OwnerKind,
    /// Stable server-side owner identifier (retained across display renames).
    pub owner_id: String,
    /// Canonical owner namespace.
    pub owner_namespace: String,
    /// Stable server-side bucket identifier.
    pub bucket_id: String,
    /// Bucket name.
    pub bucket_name: String,
    /// Bucket visibility as reported by the service.
    pub visibility: Visibility,
}

/// One imported file in an `import` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ImportFileResult {
    /// Exact object key created under `hfdrive-imports/<import_id>`.
    pub key: String,
    /// Imported byte length (decimal string on the wire).
    #[serde(with = "crate::dec_u64")]
    pub size: u64,
    /// Lowercase hex SHA-256 of the imported bytes.
    pub sha256: String,
    /// Xet file identifier of the imported payload.
    pub xet_file_id: String,
}

/// An activity record for the Activity page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ActivityRecord {
    /// Activity identifier.
    pub activity_id: Uuid,
    /// Connection the activity belongs to.
    pub connection_id: Uuid,
    /// Item the activity concerns, when known.
    pub item_id: Option<Uuid>,
    /// Display-only item name; internal object keys are never exposed.
    pub item_name: String,
    /// Direction.
    pub direction: ActivityDirection,
    /// Lifecycle phase.
    pub phase: ActivityPhase,
    /// Logical bytes completed.
    #[serde(with = "crate::dec_u64")]
    pub bytes_completed: u64,
    /// Logical bytes total, when known.
    #[serde(default, with = "crate::dec_u64::option", skip_serializing_if = "Option::is_none")]
    pub bytes_total: Option<u64>,
    /// Display-only RFC 3339 timestamp.
    pub started_at: String,
    /// Last error, if the activity failed.
    pub last_error: Option<ErrorObject>,
}

/// Per-connection status snapshot record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ConnectionStatus {
    /// Connection identifier.
    pub connection_id: Uuid,
    /// Managed workspace identifier.
    pub workspace_id: Uuid,
    /// Verified owner.
    pub owner: Owner,
    /// Selected bucket.
    pub bucket: Bucket,
    /// Managed prefix.
    pub prefix: String,
    /// Absolute local root path.
    pub root_path: String,
    /// Access mode.
    pub mode: ConnectionMode,
    /// Capability gate state.
    pub capability: CapabilityState,
    /// Display/health state.
    pub state: ConnectionState,
    /// Pin state (requested).
    pub pin: PinState,
    /// Placeholder hydration state.
    pub hydration: HydrationState,
    /// Last remote commit observed.
    pub observed_commit: Option<Uuid>,
    /// Last commit published by this device.
    pub published_commit: Option<Uuid>,
    /// Last commit applied locally.
    pub applied_commit: Option<Uuid>,
    /// Persisted observed generation counter, when known.
    #[serde(default, with = "crate::dec_u64::option", skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<u64>,
    /// Files waiting to be uploaded.
    pub pending_files: u32,
    /// Files with local unsynchronized changes.
    pub dirty_files: u32,
    /// Files with unresolved conflicts.
    pub conflict_files: u32,
    /// Files available online only.
    pub online_only_files: u32,
    /// Files with a satisfied offline pin.
    pub pinned_files: u32,
    /// Bytes pending upload.
    #[serde(with = "crate::dec_u64")]
    pub pending_upload_bytes: u64,
    /// Local bytes occupied under the root.
    #[serde(with = "crate::dec_u64")]
    pub local_bytes: u64,
    /// Staging bytes currently admitted.
    #[serde(with = "crate::dec_u64")]
    pub staging_used_bytes: u64,
    /// Range-cache bytes currently retained.
    #[serde(with = "crate::dec_u64")]
    pub range_cache_used_bytes: u64,
    /// Transfer-memory bytes currently used.
    #[serde(with = "crate::dec_u64")]
    pub transfer_memory_used_bytes: u64,
    /// Last non-secret error for this connection.
    pub last_error: Option<ErrorObject>,
    /// Display-only RFC 3339 update time.
    pub updated_at: String,
}

/// An error object carried inside responses and inside status/activity data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ErrorObject {
    /// Machine-readable error code.
    pub code: crate::errors::ProtocolErrorCode,
    /// Human-readable, non-secret message.
    pub message: String,
    /// Retry hint in milliseconds (decimal string), when applicable.
    #[serde(default, with = "crate::dec_u64::option", skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

// ---------------------------------------------------------------------------
// Requests and results, one pair per command.
// ---------------------------------------------------------------------------

/// `hello` request; MUST be the first command on a connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct HelloRequest {
    /// Highest protocol major the client implements (1).
    pub protocol_major: u32,
    /// Highest protocol minor the client implements (0).
    pub protocol_minor: u32,
    /// Client role.
    pub role: ClientRole,
    /// Client build version (display/provenance only).
    pub build_version: String,
}
request_method!(HelloRequest, "hello");

/// `hello` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct HelloResult {
    /// Protocol major implemented by the provider (1).
    pub protocol_major: u32,
    /// Protocol minor implemented by the provider (0).
    pub protocol_minor: u32,
    /// Provider build version.
    pub provider_version: String,
    /// Feature names understood by the provider.
    pub supported_features: Vec<String>,
    /// Lowerest protocol minor the provider will still accept (0).
    pub supported_min_protocol_minor: u32,
}

/// `get_status` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct GetStatusRequest {}
request_method!(GetStatusRequest, "get_status");

/// `get_status` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct GetStatusResult {
    /// Current monotonically increasing event sequence.
    #[serde(with = "crate::dec_u64")]
    pub event_sequence: u64,
    /// Full account and interactive-login snapshot, without credentials.
    pub account: crate::AccountStatus,
    /// Status of every configured connection.
    pub connections: Vec<ConnectionStatus>,
}

/// `subscribe_status` request.
///
/// Subscription lifetime: a new `subscribe_status` replaces any existing
/// subscription for this connection, and client disconnect removes it; there
/// is no separate stop command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SubscribeStatusRequest {
    /// Last event sequence the client observed; resubscribe after a gap
    /// delivers a full snapshot instead of deltas.
    #[serde(default, with = "crate::dec_u64::option", skip_serializing_if = "Option::is_none")]
    pub last_sequence: Option<u64>,
}
request_method!(SubscribeStatusRequest, "subscribe_status");

/// `subscribe_status` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SubscribeStatusResult {
    /// True when the subscription is active.
    pub subscribed: bool,
    /// Full status snapshot delivered at subscription time.
    pub snapshot: StatusSnapshot,
}

/// A full status snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct StatusSnapshot {
    /// Event sequence this snapshot reflects.
    #[serde(with = "crate::dec_u64")]
    pub sequence: u64,
    /// Full account and interactive-login snapshot.
    pub account: crate::AccountStatus,
    /// Status of every configured connection.
    pub connections: Vec<ConnectionStatus>,
}

/// `cancel_request` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CancelRequestRequest {
    /// The `request_id` whose work should stop.
    pub target_request_id: Uuid,
}
request_method!(CancelRequestRequest, "cancel_request");

/// `cancel_request` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CancelRequestResult {
    /// True when cancellation was delivered to a known in-flight request.
    pub accepted: bool,
}

/// `start_login` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct StartLoginRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Selected flow.
    pub flow: LoginFlow,
    /// Login purpose selecting the scope set.
    pub purpose: LoginPurpose,
    /// Organization identifier for re-consent, when requested.
    pub organization_id: Option<String>,
}
request_method!(StartLoginRequest, "start_login");

/// `start_login` result.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct StartLoginResult {
    /// Provider-issued login session identifier.
    pub session_id: Uuid,
    /// URL the user should open when a browser did not launch automatically.
    pub authorization_url: Option<String>,
    /// Device user code, for the device flow only.
    pub user_code: Option<String>,
    /// Device verification URI, for the device flow only.
    pub verification_uri: Option<String>,
    /// Display-only RFC 3339 expiry of the login session.
    pub expires_at: String,
}

impl std::fmt::Debug for StartLoginResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartLoginResult")
            .field("session_id", &self.session_id)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// `cancel_login` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CancelLoginRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Login session to cancel.
    pub session_id: Uuid,
}
request_method!(CancelLoginRequest, "cancel_login");

/// `cancel_login` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CancelLoginResult {
    /// True when a known session was cancelled.
    pub cancelled: bool,
}

/// `sign_out` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SignOutRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
}
request_method!(SignOutRequest, "sign_out");

/// `sign_out` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SignOutResult {
    /// True when credentials were disabled and local work preserved.
    pub signed_out: bool,
}

/// `list_owners` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ListOwnersRequest {
    /// Optional continuation cursor from a previous page.
    pub cursor: Option<String>,
    /// Maximum records to return (<= 200).
    pub limit: u32,
}
request_method!(ListOwnersRequest, "list_owners");

/// `list_owners` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ListOwnersResult {
    /// One page of owners.
    pub items: Vec<Owner>,
    /// Continuation cursor, `None` on the last page.
    pub next_cursor: Option<String>,
}

/// `list_buckets` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ListBucketsRequest {
    /// Owner namespace to list.
    pub owner_namespace: String,
    /// Optional continuation cursor from a previous page.
    pub cursor: Option<String>,
    /// Maximum records to return (<= 200).
    pub limit: u32,
}
request_method!(ListBucketsRequest, "list_buckets");

/// `list_buckets` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ListBucketsResult {
    /// One page of buckets.
    pub items: Vec<Bucket>,
    /// Continuation cursor, `None` on the last page.
    pub next_cursor: Option<String>,
}

/// `create_bucket` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CreateBucketRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Stable verified owner identity; names alone cannot select a mutation target.
    pub owner_id: String,
    /// Personal or organization owner associated with that stable identity.
    pub owner_kind: OwnerKind,
    /// Owner namespace that will own the bucket.
    pub owner_namespace: String,
    /// Requested bucket name (validated against service rules).
    pub bucket_name: String,
    /// Explicit region selection; `None` uses the service default.
    pub region: Option<String>,
}
request_method!(CreateBucketRequest, "create_bucket");

/// `create_bucket` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CreateBucketResult {
    /// The created bucket.
    pub bucket: Bucket,
    /// True when the operation completed fully; on partial failure the
    /// created resources remain recorded in the setup intent.
    pub completed: bool,
}

/// `inspect_drive` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct InspectDriveRequest {
    /// Connection to inspect; `None` inspects a not-yet-connected binding.
    pub connection_id: Option<Uuid>,
    /// Location to discover when `connection_id` is absent; no invented workspace ID.
    pub location: Option<RemoteLocation>,
    /// Optional continuation cursor from a previous page.
    pub cursor: Option<String>,
    /// Maximum records to return (<= 200).
    pub limit: u32,
}
request_method!(InspectDriveRequest, "inspect_drive");

/// `inspect_drive` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct InspectDriveResult {
    /// Validated managed identity, absent when no managed HEAD exists.
    pub binding: Option<RemoteBinding>,
    /// Remote HEAD generation, when a managed namespace exists.
    pub head_generation: Option<Uuid>,
    /// True when the prefix is a compatible managed drive.
    pub is_managed_drive: bool,
    /// True only after a complete native listing confirms the prefix is empty.
    pub prefix_empty: bool,
    /// One page of item records.
    pub items: Vec<InspectItem>,
    /// Continuation cursor, `None` on the last page.
    pub next_cursor: Option<String>,
}

/// One browsable item returned by `inspect_drive`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct InspectItem {
    /// Item identifier.
    pub item_id: Uuid,
    /// Parent identifier (`None` only for the root).
    pub parent_id: Option<Uuid>,
    /// Exact item name (`""` only for the root).
    pub name: String,
    /// Item kind.
    pub kind: ItemKind,
    /// Current item revision (operation UUID).
    pub item_revision: Uuid,
    /// Content version identifier for files.
    pub content_version_id: Option<Uuid>,
}

/// Reserve a durable setup binding before supplemental credentials or a local folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginSetupRequest {
    /// Idempotent local setup operation.
    pub operation_id: Uuid,
    /// Explicit verified account identity.
    pub account_key: String,
    /// Existing validated workspace or explicit new-workspace intent.
    pub binding: RemoteBinding,
    /// Explicit permission to initialize this new empty prefix at final Connect.
    pub initialize: bool,
    /// Acknowledged bucket-creation operation whose provenance this draft adopts.
    pub bucket_creation_operation_id: Option<Uuid>,
}
request_method!(BeginSetupRequest, "begin_setup");

/// A draft is not a registered connection or an initialized remote workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginSetupResult {
    /// Durable setup journal identity.
    pub setup_id: Uuid,
    /// Reserved identity used by credentials, probe and final preview.
    pub connection_id: Uuid,
    /// Exact validated binding, never silently reassigned.
    pub binding: RemoteBinding,
    /// Expected context inside the encrypted credential envelope and its entropy.
    pub protection_context: crate::PublicationProtectionContext,
}

/// `set_publication_credentials` request.
///
/// `protected_credentials` is a base64 DPAPI ciphertext of both S3 key fields
/// and their binding, produced for the current user; no raw credentials travel on the pipe.
/// This type's `Debug` output is redacted; its command envelope is never logged
/// or published as an event.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SetPublicationCredentialsRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Connection the publication credentials are bound to.
    pub connection_id: Uuid,
    /// Base64 DPAPI ciphertext containing the complete credential pair and binding.
    pub protected_credentials: String,
}
request_method!(SetPublicationCredentialsRequest, "set_publication_credentials");

impl core::fmt::Debug for SetPublicationCredentialsRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SetPublicationCredentialsRequest")
            .field("operation_id", &self.operation_id)
            .field("connection_id", &self.connection_id)
            .field("protected_credentials", &"<redacted>")
            .finish()
    }
}

/// `set_publication_credentials` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SetPublicationCredentialsResult {
    /// True when the protected record was stored.
    pub stored: bool,
    /// Capability state after storing.
    pub capability: CapabilityState,
}

/// `probe_storage` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ProbeStorageRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Connection to probe.
    pub connection_id: Uuid,
    /// Probe run identifier; created probe keys are tracked under it.
    pub run_id: Uuid,
}
request_method!(ProbeStorageRequest, "probe_storage");

/// `probe_storage` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ProbeStorageResult {
    /// Run identifier echoed back.
    pub run_id: Uuid,
    /// Capability state after the probe.
    pub capability: CapabilityState,
    /// Per-check expectations and observations.
    pub checks: Vec<ProbeCheck>,
    /// Non-secret artifact path for the capability report.
    pub report_path: Option<String>,
}

/// `repair_storage` request.
///
/// Repairs one existing connected drive's supplemental publication access by
/// rebinding the verified publication credentials recorded for a source setup
/// reservation to the target's existing protection context. No secret travels
/// on the pipe: the provider loads, re-protects and stores the pair internally,
/// and the source setup reservation is never modified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RepairStorageRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Existing connected connection whose storage access is repaired.
    pub connection_id: Uuid,
    /// Source setup reservation whose verified protected credentials are reused.
    pub credentials_from_connection_id: Uuid,
}
request_method!(RepairStorageRequest, "repair_storage");

/// `repair_storage` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RepairStorageResult {
    /// The repaired target connection identifier.
    pub connection_id: Uuid,
    /// True only when the repaired credentials are committed and the live
    /// binding is active with the fresh proof recorded below. A committed
    /// repair whose runtime refresh failed is reported honestly as false.
    pub repaired: bool,
    /// Fresh probe run identity of the required storage check.
    pub run_id: Uuid,
    /// Non-secret capability report artifact identity.
    pub report_path: Option<String>,
    /// Current status of the repaired connection.
    pub status: ConnectionStatus,
}

/// `preview_connect` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PreviewConnectRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Previously reserved draft; the client cannot rebind its protected credentials.
    pub connection_id: Uuid,
    /// Absolute local root path.
    pub root_path: String,
    /// Access mode to preview.
    pub mode: ConnectionMode,
}
request_method!(PreviewConnectRequest, "preview_connect");

/// `preview_connect` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PreviewConnectResult {
    /// Persisted preview identifier consumed by `connect`.
    pub preview_id: Uuid,
    /// Reserved connection identity this preview will connect.
    pub connection_id: Uuid,
    /// The validated binding the preview inspected.
    pub binding: RemoteBinding,
    /// Visibility freshly observed for this preview, not an old picker hint.
    pub visibility: Visibility,
    /// Actual HEAD generation, absent only for explicit empty-prefix initialization.
    pub head_generation: Option<Uuid>,
    /// Local scan generation observed during the preview.
    #[serde(with = "crate::dec_u64")]
    pub local_scan_generation: u64,
    /// Complete per-category counts; representative paths below are bounded to 200.
    pub collision_summary: Vec<crate::CollisionCategorySummary>,
    /// Representative collisions requiring review, not an unbounded scan manifest.
    pub collisions: Vec<Collision>,
    /// Total proposed actions in the persisted plan.
    #[serde(with = "crate::dec_u64")]
    pub proposed_action_count: u64,
    /// At most 200 representative actions from the persisted plan.
    pub proposed_actions: Vec<ProposedActionRecord>,
    /// True when the preview requires review of every collision category.
    pub requires_review: bool,
}

/// `connect` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ConnectRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Preview identifier from `preview_connect`.
    pub preview_id: Uuid,
}
request_method!(ConnectRequest, "connect");

/// `connect` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ConnectResult {
    /// The connected connection identifier.
    pub connection_id: Uuid,
    /// Final status of the new connection.
    pub status: ConnectionStatus,
}

/// `pause` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PauseRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Connection to pause; `None` pauses every connection.
    pub connection_id: Option<Uuid>,
}
request_method!(PauseRequest, "pause");

/// `pause` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PauseResult {
    /// Connections that entered the paused state.
    pub paused_connection_ids: Vec<Uuid>,
}

/// `resume` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ResumeRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Connection to resume; `None` resumes every paused connection.
    pub connection_id: Option<Uuid>,
}
request_method!(ResumeRequest, "resume");

/// `resume` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ResumeResult {
    /// Connections that left the paused state.
    pub resumed_connection_ids: Vec<Uuid>,
}

/// `set_pin` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SetPinRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Connection to modify.
    pub connection_id: Uuid,
    /// Optional subtree item; `None` targets the whole connection.
    pub item_id: Option<Uuid>,
    /// Pin or unpin.
    pub mode: PinMode,
}
request_method!(SetPinRequest, "set_pin");

/// `set_pin` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SetPinResult {
    /// Pin state after the request.
    pub pin_state: PinState,
    /// Files fully hydrated for the pin right now.
    pub pinned_files: u32,
}

/// `free_space` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FreeSpaceRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Connection to shrink.
    pub connection_id: Uuid,
    /// Optional subtree item; `None` targets the whole connection.
    pub item_id: Option<Uuid>,
    /// Free-all or free-except-pinned.
    pub mode: FreeSpaceMode,
}
request_method!(FreeSpaceRequest, "free_space");

/// `free_space` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FreeSpaceResult {
    /// Logical bytes released from local storage.
    #[serde(with = "crate::dec_u64")]
    pub freed_bytes: u64,
    /// Files dehydrated.
    pub dehydrated_files: u32,
}

/// `set_selective_sync` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SetSelectiveSyncRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Connection to modify.
    pub connection_id: Uuid,
    /// Item identifiers whose subtrees are excluded from sync.
    pub exclude_item_ids: Vec<Uuid>,
}
request_method!(SetSelectiveSyncRequest, "set_selective_sync");

/// `set_selective_sync` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SetSelectiveSyncResult {
    /// Effective exclusions after the request.
    pub excluded_item_ids: Vec<Uuid>,
    /// Items that retain unsynchronized work locally.
    pub retained_dirty_item_ids: Vec<Uuid>,
}

/// `update_settings` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct UpdateSettingsRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Scope identifier (`global` or a connection UUID string).
    pub scope_id: String,
    /// Settings revision expected by the client (optimistic concurrency).
    #[serde(with = "crate::dec_u64")]
    pub expected_revision: u64,
    /// Patched settings values; `None` removes a key.
    pub settings: Vec<SettingsPatch>,
}
request_method!(UpdateSettingsRequest, "update_settings");

/// One settings patch entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SettingsPatch {
    /// Settings key (see the settings key registry in the IPC contract).
    pub key: String,
    /// New value; `None` removes the key.
    pub value_json: Option<String>,
}

/// `update_settings` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct UpdateSettingsResult {
    /// New settings revision after applying the patch.
    #[serde(with = "crate::dec_u64")]
    pub revision: u64,
    /// Fully resolved settings after applying the patch.
    pub settings: Vec<SettingsEntry>,
}

/// A resolved settings entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SettingsEntry {
    /// Settings key.
    pub key: String,
    /// JSON-encoded value.
    pub value_json: String,
}

/// `list_activity` request.
///
/// Read-only listing of the connection's real current synchronization work
/// (durable outbox/local actions/transfers and live in-flight hydration),
/// one bounded page at a time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ListActivityRequest {
    /// Connection whose activity is listed.
    pub connection_id: Uuid,
    /// Optional continuation cursor from a previous page. The cursor is bound
    /// to the connection that produced it.
    pub cursor: Option<String>,
    /// Maximum records to return (<= 200).
    pub limit: u32,
}
request_method!(ListActivityRequest, "list_activity");

/// `list_activity` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ListActivityResult {
    /// One page of activity records.
    pub items: Vec<ActivityRecord>,
    /// Continuation cursor, `None` on the last page.
    pub next_cursor: Option<String>,
}

/// `list_history` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ListHistoryRequest {
    /// Connection whose history is listed.
    pub connection_id: Uuid,
    /// Optional subtree item filter.
    pub item_id: Option<Uuid>,
    /// Optional continuation cursor from a previous page.
    pub cursor: Option<String>,
    /// Maximum records to return (<= 200).
    pub limit: u32,
}
request_method!(ListHistoryRequest, "list_history");

/// `list_history` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ListHistoryResult {
    /// One page of history records.
    pub items: Vec<HistoryRecord>,
    /// Continuation cursor, `None` on the last page.
    pub next_cursor: Option<String>,
}

/// `restore` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RestoreRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Connection to restore into.
    pub connection_id: Uuid,
    /// Item to restore.
    pub item_id: Uuid,
    /// Version to restore.
    pub version_id: Uuid,
}
request_method!(RestoreRequest, "restore");

/// `restore` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RestoreResult {
    /// Operation identifier echoed back.
    pub operation_id: Uuid,
    /// Status of the connection after the restore was queued.
    pub status: ConnectionStatus,
}

/// `list_conflicts` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ListConflictsRequest {
    /// Connection whose conflicts are listed.
    pub connection_id: Uuid,
    /// Optional continuation cursor from a previous page.
    pub cursor: Option<String>,
    /// Maximum records to return (<= 200).
    pub limit: u32,
}
request_method!(ListConflictsRequest, "list_conflicts");

/// `list_conflicts` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ListConflictsResult {
    /// One page of conflict records.
    pub items: Vec<ConflictRecord>,
    /// Continuation cursor, `None` on the last page.
    pub next_cursor: Option<String>,
}

/// `resolve_conflict` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ResolveConflictRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Connection the conflict belongs to.
    pub connection_id: Uuid,
    /// Conflict identifier.
    pub conflict_id: Uuid,
    /// Resolution choice.
    pub resolution: ConflictResolution,
}
request_method!(ResolveConflictRequest, "resolve_conflict");

/// `resolve_conflict` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ResolveConflictResult {
    /// Conflict identifier echoed back.
    pub conflict_id: Uuid,
    /// Resolution state after the request.
    pub resolution_state: ConflictResolution,
}

/// `export_diagnostics` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExportDiagnosticsRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Optional connection filter; `None` exports everything.
    pub connection_id: Option<Uuid>,
    /// Absolute destination path for the redacted diagnostics ZIP.
    pub destination_path: String,
}
request_method!(ExportDiagnosticsRequest, "export_diagnostics");

/// `export_diagnostics` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExportDiagnosticsResult {
    /// Absolute path of the produced archive.
    pub archive_path: String,
    /// Stable per-export aliases applied to user paths/names.
    pub redacted: bool,
}

/// `prepare_unlink` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PrepareUnlinkRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Connection to unlink.
    pub connection_id: Uuid,
    /// Planned unlink mode.
    pub mode: UnlinkMode,
}
request_method!(PrepareUnlinkRequest, "prepare_unlink");

/// `prepare_unlink` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PrepareUnlinkResult {
    /// True when the unlink can proceed under the selected mode.
    pub safe_to_unlink: bool,
    /// Online-only files needing hydration/export first.
    pub online_only_files: u32,
    /// Partially hydrated files blocking a safe remove.
    pub partial_files: u32,
    /// Files with unsynchronized local changes.
    pub dirty_files: u32,
    /// Files with unresolved conflicts.
    pub conflict_files: u32,
    /// Logical bytes required to export/hydrate.
    #[serde(with = "crate::dec_u64")]
    pub required_export_bytes: u64,
    /// Blocking reasons (non-secret display text), empty when safe.
    pub blocking_reasons: Vec<String>,
}

/// `unlink` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct UnlinkRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Connection to unlink.
    pub connection_id: Uuid,
    /// Unlink mode actually selected.
    pub mode: UnlinkMode,
}
request_method!(UnlinkRequest, "unlink");

/// `unlink` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct UnlinkResult {
    /// Connection echoed back.
    pub connection_id: Uuid,
    /// True when the root was fully unregistered.
    pub unregistered: bool,
    /// True when the binding/registration was retained for recovery.
    pub retained_for_recovery: bool,
}

/// `prepare_upgrade` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PrepareUpgradeRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
}
request_method!(PrepareUpgradeRequest, "prepare_upgrade");

/// `prepare_upgrade` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PrepareUpgradeResult {
    /// True when scheduling stopped and state checkpointed.
    pub checkpointed: bool,
    /// Uncertain remote operations that remain durably recorded.
    pub pending_operations: u32,
}

/// `exit_provider` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExitProviderRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
}
request_method!(ExitProviderRequest, "exit_provider");

/// `exit_provider` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExitProviderResult {
    /// True when the provider accepted the exit request.
    pub accepted: bool,
}

/// `import` request (raw bucket import initiated by Explorer).
///
/// A durable mutation: `operation_id` identifies the import operation and a
/// reconnect/retry reusing it must not duplicate the import. `import_id`
/// determines the exact destination prefix `hfdrive-imports/<import_id>` (no trailing slash).
///
/// Per-file result records are paged: the first call carries no `files_cursor`
/// and runs the import; a request carrying `files_cursor` is a continuation of
/// the same operation's persisted result (never a second mutation — it must
/// not be admitted as a new operation). See [`ImportResult`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ImportRequest {
    /// Unique durable operation identifier for this mutation.
    pub operation_id: Uuid,
    /// Import identifier; fixes the destination prefix.
    pub import_id: Uuid,
    /// Exact target bucket/owner object.
    pub target: ImportTarget,
    /// Absolute local source paths to import.
    pub sources: Vec<String>,
    /// Continuation cursor from a previous `import` result page. Present only
    /// for page continuations of the same operation; absent on the first call.
    pub files_cursor: Option<String>,
}
request_method!(ImportRequest, "import");

/// `import` result.
///
/// `files` is **one page** of per-file result records (at most the protocol
/// page bound of 200 records); `next_cursor` is present exactly when more
/// records remain and is passed back as [`ImportRequest::files_cursor`] on the
/// same operation. Every page repeats the complete `import_id`, `prefix`,
/// `file_count`, `total_bytes` and `empty_directory_count`, so each page is self-describing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ImportResult {
    /// Import identifier echoed back.
    pub import_id: Uuid,
    /// Exact destination prefix: `hfdrive-imports/<import_id>` (no trailing slash).
    pub prefix: String,
    /// One page of per-file result records.
    pub files: Vec<ImportFileResult>,
    /// Continuation cursor for the next page, `None` on the last page.
    pub next_cursor: Option<String>,
    /// Total number of imported files (all pages).
    pub file_count: u32,
    /// Total imported bytes across all files (decimal string on the wire).
    #[serde(with = "crate::dec_u64")]
    pub total_bytes: u64,
    /// Directories that produced no files. Native buckets have no standalone
    /// directory objects; per-directory evidence remains in the local journal.
    pub empty_directory_count: u32,
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// `status_changed` event payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct StatusChangedEvent {
    /// Monotonically increasing event sequence.
    #[serde(with = "crate::dec_u64")]
    pub sequence: u64,
    /// True when this is a full snapshot (subscription start or gap recovery).
    pub snapshot: bool,
    /// Complete account state, including when connection records are deltas.
    pub account: crate::AccountStatus,
    /// Changed connection records.
    pub changes: Vec<ConnectionStatus>,
    /// Connections removed since the previous event.
    pub removed_connection_ids: Vec<Uuid>,
}

/// `activity_changed` event payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ActivityChangedEvent {
    /// Monotonically increasing event sequence.
    #[serde(with = "crate::dec_u64")]
    pub sequence: u64,
    /// Changed activity records (batched).
    pub changes: Vec<ActivityRecord>,
}

/// `conflicts_changed` event payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ConflictsChangedEvent {
    /// Monotonically increasing event sequence.
    #[serde(with = "crate::dec_u64")]
    pub sequence: u64,
    /// Changed conflict records.
    pub changes: Vec<ConflictRecord>,
    /// Conflicts resolved/removed since the previous event.
    pub removed_conflict_ids: Vec<Uuid>,
}
