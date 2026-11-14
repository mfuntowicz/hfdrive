//! Typed persisted state. Every record round-trips through serde JSON columns
//! and strict typed columns; no SDK or credential material lives here.

use hfdrive_core::ids::{
    AccountKey, ActionId, CommitId, ConnectionId, GenerationId, OperationId, SetupId,
    SnapshotId, TransferId, VersionId,
};
use hfdrive_core::storage::{ObjectRef, Sha256Digest};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// How an operation's effects may outlive it. `External` effects must be
/// reconciled after an interruption instead of being replayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    None,
    Local,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Pending,
    ExternalPending,
    Committed,
    Failed,
    Abandoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxState {
    Observed,
    SnapshotReady,
    PayloadReady,
    MetadataReady,
    PublishUnknown,
    Published,
    LocalApplyPending,
    Complete,
}

impl OutboxState {
    /// The only durable forward edges. `PublishUnknown` is the parked state for
    /// an uncertain conditional publication; it is resolved by reconciliation
    /// (`Published` or back to `MetadataReady`), never by blind replay.
    /// Metadata-only intents go straight `Observed -> MetadataReady`.
    pub fn can_transition_to(self, to: Self) -> bool {
        use OutboxState::*;
        matches!(
            (self, to),
            (Observed, SnapshotReady)
                | (Observed, MetadataReady) // metadata-only intent
                | (SnapshotReady, PayloadReady)
                | (SnapshotReady, Observed) // recapture after a failed capture
                | (PayloadReady, MetadataReady)
                | (MetadataReady, PublishUnknown)
                | (MetadataReady, Published) // precondition-succeeded CAS
                | (MetadataReady, Observed) // re-reconciled onto a new base
                | (PublishUnknown, Published) // reconciliation found our commit
                | (PublishUnknown, MetadataReady) // reconciliation proved absent
                | (Published, LocalApplyPending)
                | (LocalApplyPending, Complete)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupPhase {
    Reserved,
    CredentialsRecorded,
    Probed,
    PreviewReady,
    Registering,
    Connected,
}

impl SetupPhase {
    /// Forward-only. The chain deliberately does not categorically require
    /// `CredentialsRecorded`/`Probed`: a read-only setup advances straight to
    /// `PreviewReady`, while the writable coordinator enforces credential and
    /// evidence requirements itself.
    pub fn can_advance_to(self, to: Self) -> bool {
        to > self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupStatus {
    Active,
    Failed,
    Connected,
    Abandoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    Active,
    NeedsSignIn,
    SignedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    ReadOnly,
    Writable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryClass {
    None,
    Backoff,
    NeedsUser,
    NeedsAuth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    Capturing,
    Ready,
    Consumed,
    Released,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferDirection {
    Upload,
    Download,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferState {
    Pending,
    InProgress,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitStatus {
    Candidate,
    Committed,
    Applied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictResolution {
    Unresolved,
    KeepLocal,
    KeepRemote,
    KeepBoth,
    Recovered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalActionKind {
    CreatePlaceholder,
    UpdatePlaceholder,
    Rename,
    DeletePlaceholder,
    Hydrate,
    Dehydrate,
    SetPin,
    ConvertToNormal,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalActionState {
    Pending,
    InProgress,
    Applied,
    Failed,
    Requeued,
    Recovered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKeyState {
    Reserved,
    CreateInFlight,
    Created,
    NotCreated,
    Deleted,
}

/// A record whose credential name references a DPAPI-protected file owned by
/// `hfdrive-windows`; the database never contains credential bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialRef(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRecord {
    pub account_key: AccountKey,
    pub issuer: String,
    pub subject: String,
    pub namespace: String,
    pub credential_ref: CredentialRef,
    pub auth_epoch: u64,
    pub status: AccountStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionRecord {
    pub connection_id: ConnectionId,
    pub account_key: AccountKey,
    pub binding: DriveBinding,
    pub root_path: PathBuf,
    pub mode: ConnectionMode,
    pub volume_guid: Option<String>,
    pub volume_serial: Option<u64>,
    pub sync_root_id: Option<String>,
    pub oauth_ref: Option<CredentialRef>,
    pub s3_ref: Option<CredentialRef>,
    pub schema_version: u32,
    pub config_json: serde_json::Value,
    pub registered: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationBaseline {
    pub observed_commit: Option<CommitId>,
    pub published_commit: Option<CommitId>,
    pub applied_commit: Option<CommitId>,
}

impl Default for PublicationBaseline {
    fn default() -> Self {
        Self {
            observed_commit: None,
            published_commit: None,
            applied_commit: None,
        }
    }
}

/// A durable local intent waiting for publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboxEntry {
    pub connection_id: ConnectionId,
    pub operation_id: OperationId,
    pub item_id: Option<hfdrive_core::ids::ItemId>,
    pub base_commit: Option<CommitId>,
    /// The base item record as canonical format bytes
    /// (`hfdrive_core::format::to_item_record_bytes`), stored verbatim so byte
    /// identity survives restart. Never re-serialized by the state layer.
    pub base_json: Option<String>,
    pub observed_generation: u64,
    pub intent_json: serde_json::Value,
    pub state: OutboxState,
    pub snapshot_id: Option<SnapshotId>,
    pub object_ref: Option<ObjectRef>,
    pub candidate_commit: Option<CommitId>,
    pub candidate_head_json: Option<serde_json::Value>,
    pub expected_etag: Option<String>,
    pub retry_class: RetryClass,
    pub next_attempt_at_ms: Option<u64>,
}

/// One remembered common base item record, keyed by (connection, item, commit).
/// `item_json` is canonical format bytes (`format::to_item_record_bytes`),
/// stored verbatim; the state layer validates it is JSON but never
/// re-serializes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonBaseRecord {
    pub connection_id: ConnectionId,
    pub item_id: hfdrive_core::ids::ItemId,
    pub commit_id: CommitId,
    pub item_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRecord {
    pub connection_id: ConnectionId,
    pub snapshot_id: SnapshotId,
    pub path: PathBuf,
    /// `None` while a capture is in flight; always set for `Ready` rows.
    pub size: Option<u64>,
    /// `None` while a capture is in flight; always set for `Ready` rows.
    pub sha256: Option<Sha256Digest>,
    pub status: SnapshotStatus,
}

/// A draft setup reservation request: account + exact binding + explicit,
/// immutable initialization intent, before any credential/probe/local work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupDraft {
    pub operation_id: OperationId,
    pub account_key: AccountKey,
    pub binding: DriveBinding,
    pub initialize: bool,
}

/// Idempotency request for an IPC mutation. `request` is the canonical request
/// body whose digest binds the operation id to one exact request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginOperationRequest {
    pub operation_id: OperationId,
    pub kind: String,
    pub request: serde_json::Value,
    pub effect_class: EffectClass,
    pub account_key: Option<AccountKey>,
    pub connection_id: Option<ConnectionId>,
    /// Creation feeding a later begin_setup; lets a resumed draft record an
    /// existing external effect rather than repeat it.
    pub bucket_creation_operation_id: Option<OperationId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineKind {
    Observed,
    Published,
    Applied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferRecord {
    pub connection_id: ConnectionId,
    pub transfer_id: TransferId,
    pub operation_id: Option<OperationId>,
    pub direction: TransferDirection,
    pub version_id: Option<VersionId>,
    pub range_start: Option<u64>,
    pub range_end: Option<u64>,
    pub state: TransferState,
    /// Byte-exact SDK resume state when the SDK proved it; `None` otherwise.
    pub sdk_resume_json: Option<serde_json::Value>,
    pub logical_bytes: u64,
    pub wire_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitRecord {
    pub connection_id: ConnectionId,
    pub commit_id: CommitId,
    pub parent_id: Option<CommitId>,
    pub catalog_root: Option<Sha256Digest>,
    pub operation_ids: Vec<OperationId>,
    pub status: CommitStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalAction {
    pub connection_id: ConnectionId,
    pub action_id: ActionId,
    pub item_id: Option<hfdrive_core::ids::ItemId>,
    pub kind: LocalActionKind,
    pub expected_file_id: Option<String>,
    pub expected_generation: Option<u64>,
    pub expected_usn: Option<u64>,
    pub old_version: Option<VersionId>,
    pub new_version: Option<VersionId>,
    pub source_path: Option<PathBuf>,
    pub target_path: Option<PathBuf>,
    pub recovery_path: Option<PathBuf>,
    pub state: LocalActionState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictRecord {
    pub connection_id: ConnectionId,
    pub conflict_id: hfdrive_core::ids::ConflictId,
    pub item_id: hfdrive_core::ids::ItemId,
    pub competing_ops: Vec<OperationId>,
    pub revisions_json: serde_json::Value,
    pub original_names: Vec<String>,
    pub resolution_state: ConflictResolution,
    pub detected_at_ms: Option<u64>,
}

/// Local observation: the durable per-item generation and dirty/pin/exclusion
/// flags. Generations are persisted signed integers, checked on conversion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalObservation {
    pub connection_id: ConnectionId,
    pub item_id: hfdrive_core::ids::ItemId,
    pub generation: u64,
    pub observed_usn: Option<u64>,
    pub dirty: bool,
    pub pin_requested: bool,
    pub pin_complete: bool,
    pub excluded: bool,
    pub scan_epoch: u64,
}

/// Evidence of a completed metadata scan. Deletion may only be inferred while
/// `scan_complete` and not `scan_invalidated`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanState {
    pub connection_id: ConnectionId,
    pub cursor: Option<String>,
    pub pending_head_refresh: bool,
    pub volume_id: String,
    pub journal_id: String,
    pub usn_cursor: Option<u64>,
    pub scan_epoch: u64,
    pub scan_complete: bool,
    pub scan_invalidated: bool,
}

impl ScanState {
    /// A disappearance is deletion evidence only after a fully completed,
    /// still-valid scan; overflow, reset, denial, or an incomplete enumeration
    /// all invalidate it.
    pub fn may_infer_deletion(&self) -> bool {
        self.scan_complete && !self.scan_invalidated
    }
}

/// SQL-projected file health counts; no unbounded outbox or registry materialization.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionWorkCounts {
    pub pending_files: u32,
    pub dirty_files: u32,
    pub conflict_files: u32,
}

/// Upload-byte and pin evidence for connection status projection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionStorageCounts {
    pub pending_upload_bytes: u64,
    pub pinned_files: u32,
    pub pin_requests: u32,
}

/// A durable setup reservation. Drafts bind an account and exact
/// `DriveBinding` before any credential/probe/local-folder work; they are not
/// registered connections and never appear as connected Explorer roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupRecord {
    pub setup_id: SetupId,
    pub connection_id: ConnectionId,
    pub operation_id: OperationId,
    pub account_key: AccountKey,
    pub binding: DriveBinding,
    /// Explicit, immutable new-workspace initialization intent. Absence can
    /// never silently authorize initialization.
    pub initialize: bool,
    /// External bucket creation feeding this draft; independent from the local reservation.
    pub bucket_creation_operation_id: Option<OperationId>,
    pub request_fingerprint: Sha256Digest,
    pub phase: SetupPhase,
    pub status: SetupStatus,
    pub created_resources: Vec<CreatedResource>,
    pub preview_json: Option<serde_json::Value>,
    /// Local-root proof attached at preview time; absent until then.
    pub root_path: Option<PathBuf>,
    /// Access mode selected at preview time.
    pub mode: Option<ConnectionMode>,
    pub credential_ref: Option<CredentialRef>,
    pub probe_evidence_json: Option<serde_json::Value>,
    pub failure_reason: Option<String>,
    /// Bumped whenever credential/evidence inputs change so stale probe/preview
    /// evidence can be detected and invalidated.
    pub evidence_generation: u64,
    pub account_committed: bool,
    pub control_committed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatedResource {
    pub kind: String,
    pub identity: String,
    /// Kept visible on partial failure so cleanup/inspection never loses it.
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRecord {
    pub operation_id: OperationId,
    pub kind: String,
    pub request_digest: Sha256Digest,
    pub effect_class: EffectClass,
    pub state: OperationState,
    pub account_key: Option<AccountKey>,
    pub connection_id: Option<ConnectionId>,
    pub bucket_creation_operation_id: Option<OperationId>,
    pub result_json: Option<serde_json::Value>,
    pub error_code: Option<String>,
}

/// Outcome of reserving an operation id in the idempotency ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeginOutcome {
    /// The operation was newly recorded and may run.
    Fresh(OperationRecord),
    /// The identical operation was already recorded; `record` carries the
    /// persisted result/state so the caller can answer from it or reconcile an
    /// uncertain external effect. Nothing was re-executed.
    Replayed(OperationRecord),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsRow {
    pub scope_id: String,
    pub revision: u64,
    pub value_json: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupReservation {
    pub setup_id: SetupId,
    pub connection_id: ConnectionId,
    pub operation_id: OperationId,
    pub account_key: AccountKey,
    pub binding: DriveBinding,
    pub initialize: bool,
    pub request_fingerprint: Sha256Digest,
    pub phase: SetupPhase,
}

impl From<&SetupRecord> for SetupReservation {
    fn from(value: &SetupRecord) -> Self {
        Self {
            setup_id: value.setup_id,
            connection_id: value.connection_id,
            operation_id: value.operation_id,
            account_key: value.account_key,
            binding: value.binding.clone(),
            initialize: value.initialize,
            request_fingerprint: value.request_fingerprint,
            phase: value.phase,
        }
    }
}

/// Retained reference accounting for diagnostics; no deletion method exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionSnapshot {
    pub epoch: u64,
    pub retained_commits: u64,
    pub pending_upload_reservations: u64,
}

/// A single probe-created storage key. The journal is reserved before any
/// external create effect and cleanup enumerates only confirmed keys of the
/// run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeKeyRecord {
    pub run_id: GenerationId,
    pub connection_id: ConnectionId,
    pub setup_id: Option<SetupId>,
    pub key: String,
    pub state: ProbeKeyState,
}

/// Uniqueness/parent/case-folding components are computed by the core catalog;
/// state persists only what the durable boundary needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemRecord {
    pub connection_id: ConnectionId,
    pub item_id: hfdrive_core::ids::ItemId,
    pub parent_id: Option<hfdrive_core::ids::ItemId>,
    pub name: String,
    /// `hfdrive_core::names::collision_key(name)` output (NFC + full default
    /// casefold); the state layer never computes it.
    pub name_key: String,
    pub kind: ItemKind,
    pub revision: OperationId,
    pub content_version_id: Option<VersionId>,
    pub deleted: bool,
    /// Display-only metadata (original name, modification time); never part of
    /// catalog identity.
    pub metadata_json: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    File,
    Directory,
}

/// Re-exported for callers constructing bindings from persisted JSON.
pub use hfdrive_core::storage::{BucketBinding, DriveBinding, OwnerKind};
