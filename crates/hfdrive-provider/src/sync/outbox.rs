//! Durable local intents and the eight-phase outbox state machine.
//!
//! Every external effect is preceded by a durable record:
//!
//! * a local observation persists a new generation and the outbox intent
//!   (`Observed`) before anything is captured or sent anywhere;
//! * capture materializes and stages a coherent immutable snapshot before the
//!   payload upload starts (`SnapshotReady`);
//! * the native Xet checkpoints (`IngestionCheckpoint`,
//!   `CasCommitCheckpoint`) are persisted in the connection's transfer
//!   journal before the next external boundary (`PayloadReady` after exact
//!   key binding);
//! * the publication candidate's immutable identifiers (fresh commit and
//!   generation UUIDs, version records) are persisted as transition evidence
//!   before the guarded `HEAD` write (`MetadataReady`);
//! * an uncertain conditional write parks the entry (`PublishUnknown`) until
//!   committed-ancestry reconciliation proves `Published` or absent;
//! * remote-to-local application is journaled (`LocalApplyPending`) before
//!   any placeholder mutation and completion is generation-guarded
//!   (`Complete`).
//!
//! The step planner ([`next_step`]) is pure: it reads only the persisted
//! entry and tells the worker what the next durable boundary is. Recovery
//! ([`recover_entry`]) is equally explicit — an interrupted entry is never
//! replayed blindly and never discarded.

use hfdrive_core::format::{ItemKind, is_canonical_timestamp};
use hfdrive_core::ids::{
    ActionId, CommitId, ItemId, OperationId, SnapshotId, TransferId, UploadId, VersionId,
};
use hfdrive_core::reconcile::{
    LocalChange, LocalIntent, LocalOrigin, NewContent,
};
use hfdrive_core::storage::{ObjectRef, StableSnapshot};
use hfdrive_hf::{CasCommitCheckpoint, IngestionCheckpoint};
use hfdrive_state::{
    OutboxEntry, OutboxState, OutboxTransition, RetryClass, SnapshotRecord, SnapshotStatus,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Intent schema (the durable `intent_json` body)
// ---------------------------------------------------------------------------

/// Wire spelling of the managed item kind inside intent JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    File,
    Directory,
}

impl From<IntentKind> for ItemKind {
    fn from(value: IntentKind) -> Self {
        match value {
            IntentKind::File => ItemKind::File,
            IntentKind::Directory => ItemKind::Directory,
        }
    }
}

/// The immutable content identity a local intent will publish. Generated with
/// the OS CSPRNG at observation time and persisted **before** any effect, so
/// a crash cannot orphan or duplicate the payload key or the version record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingContent {
    /// Future payload key `objects/<upload-uuid>`.
    pub upload_id: Uuid,
    /// Version record identifier this content will publish as.
    pub version_id: Uuid,
    /// Display-only RFC 3339 modification time (whole seconds).
    pub modified_at: String,
}

/// The durable body of an outbox intent. One intent mutates exactly one item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "intent", rename_all = "snake_case", deny_unknown_fields)]
pub enum SyncIntent {
    /// A new local item. Files require content.
    Create {
        item_id: Uuid,
        parent_id: Uuid,
        name: String,
        kind: IntentKind,
        content: Option<PendingContent>,
    },
    /// New content at the item's current location.
    Content {
        item_id: Uuid,
        content: PendingContent,
    },
    /// New location or name; content unchanged.
    Move {
        item_id: Uuid,
        parent_id: Uuid,
        name: String,
    },
    /// New content and location.
    MoveAndContent {
        item_id: Uuid,
        parent_id: Uuid,
        name: String,
        content: PendingContent,
    },
    /// The item (and, for a directory, its locally known subtree) was
    /// removed on this device.
    Delete { item_id: Uuid },
    /// Restore a historical content version as a new committed operation.
    ///
    /// The historical payload is reused (payload reference reuse, never a
    /// re-upload and never a rewrite of the historical immutable version
    /// record): `restored_version_id` is the provenance, `version_id` is the
    /// fresh version record this operation publishes, and `object` is the
    /// binding validated against the immutable version record before the
    /// intent was persisted.
    Restore {
        item_id: Uuid,
        restored_version_id: Uuid,
        version_id: Uuid,
        object: ObjectRef,
        modified_at: String,
    },
    /// Resolve one conflict side as a new committed content and location
    /// change, reusing that side's validated historical payload.
    Resolve {
        item_id: Uuid,
        parent_id: Uuid,
        name: String,
        restored_version_id: Uuid,
        version_id: Uuid,
        object: ObjectRef,
        modified_at: String,
    },
}

impl SyncIntent {
    pub fn item_id(&self) -> ItemId {
        let raw = match self {
            SyncIntent::Create { item_id, .. }
            | SyncIntent::Content { item_id, .. }
            | SyncIntent::Move { item_id, .. }
            | SyncIntent::MoveAndContent { item_id, .. }
            | SyncIntent::Delete { item_id }
            | SyncIntent::Restore { item_id, .. }
            | SyncIntent::Resolve { item_id, .. } => *item_id,
        };
        ItemId::from_uuid(raw).expect("a stored intent always carries a valid item id")
    }

    /// Content publication is required for this intent.
    pub fn has_content(&self) -> bool {
        matches!(
            self,
            SyncIntent::Create { content: Some(_), .. }
                | SyncIntent::Content { .. }
                | SyncIntent::MoveAndContent { .. }
        )
    }

    /// A restore reuses an already-bound payload reference: no capture and no
    /// upload, only a new version record and item revision.
    pub fn is_restore(&self) -> bool {
        matches!(self, SyncIntent::Restore { .. } | SyncIntent::Resolve { .. })
    }

    pub fn pending_content(&self) -> Option<&PendingContent> {
        match self {
            SyncIntent::Create { content, .. } => content.as_ref(),
            SyncIntent::Content { content, .. } | SyncIntent::MoveAndContent { content, .. } => {
                Some(content)
            }
            SyncIntent::Move { .. }
            | SyncIntent::Delete { .. }
            | SyncIntent::Restore { .. }
            | SyncIntent::Resolve { .. } => None,
        }
    }

    /// Renders the intent as the pure reconciliation input. `object` is the
    /// bound payload reference; it must exist before content intents plan.
    pub fn to_local_intent(
        &self,
        operation_id: OperationId,
        origin: LocalOrigin,
        observed_generation: u64,
        current_name: &str,
        object: Option<&ObjectRef>,
    ) -> Option<LocalIntent> {
        let content = |pending: &PendingContent, name: &str| -> Option<NewContent> {
            let object = object?.clone();
            Some(NewContent {
                version_id: VersionId::from_uuid(pending.version_id)
                    .expect("a stored intent always carries a valid version id"),
                object,
                display: hfdrive_core::format::DisplayMetadata {
                    name: name.to_owned(),
                    modified_at: pending.modified_at.clone(),
                },
            })
        };
        let change = match self {
            SyncIntent::Create {
                parent_id,
                name,
                kind,
                content: pending,
                ..
            } => LocalChange::Create {
                parent_id: ItemId::from_uuid(*parent_id).ok()?,
                name: name.clone(),
                kind: (*kind).into(),
                content: pending.as_ref().and_then(|pending| content(pending, name)),
            },
            SyncIntent::Content { content: pending, .. } => LocalChange::Content {
                content: content(pending, current_name)?,
            },
            SyncIntent::Move {
                parent_id,
                name,
                ..
            } => LocalChange::Move {
                parent_id: ItemId::from_uuid(*parent_id).ok()?,
                name: name.clone(),
            },
            SyncIntent::MoveAndContent {
                parent_id,
                name,
                content: pending,
                ..
            } => LocalChange::MoveAndContent {
                parent_id: ItemId::from_uuid(*parent_id).ok()?,
                name: name.clone(),
                content: content(pending, name)?,
            },
            SyncIntent::Delete { .. } => LocalChange::Delete,
            SyncIntent::Restore {
                version_id,
                object,
                modified_at,
                ..
            } => LocalChange::Content {
                content: NewContent {
                    version_id: VersionId::from_uuid(*version_id).ok()?,
                    // The validated historical binding, persisted inside the
                    // intent at restore time; the passed object is for
                    // captured uploads only.
                    object: object.clone(),
                    display: hfdrive_core::format::DisplayMetadata {
                        name: current_name.to_owned(),
                        modified_at: modified_at.clone(),
                    },
                },
            },
            SyncIntent::Resolve {
                parent_id,
                name,
                version_id,
                object,
                modified_at,
                ..
            } => LocalChange::MoveAndContent {
                parent_id: ItemId::from_uuid(*parent_id).ok()?,
                name: name.clone(),
                content: NewContent {
                    version_id: VersionId::from_uuid(*version_id).ok()?,
                    object: object.clone(),
                    display: hfdrive_core::format::DisplayMetadata {
                        name: name.to_owned(),
                        modified_at: modified_at.clone(),
                    },
                },
            },
        };
        Some(LocalIntent {
            operation_id,
            item_id: self.item_id(),
            origin,
            observed_generation,
            change,
        })
    }
}

/// RFC 3339 UTC, whole seconds — the canonical display timestamp
/// (`YYYY-MM-DDTHH:MM:SSZ`, validated by the core format rules).
pub fn display_timestamp(last_write_time_100ns: i64) -> String {
    const EPOCH_OFFSET_100NS: i64 = 116_444_736_000_000_000; // 1601 -> 1970
    let seconds = last_write_time_100ns
        .saturating_sub(EPOCH_OFFSET_100NS)
        .div_euclid(10_000_000);
    match time::OffsetDateTime::from_unix_timestamp(seconds) {
        Ok(at) => {
            let formatted = format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                at.year(),
                u8::from(at.month()),
                at.day(),
                at.hour(),
                at.minute(),
                at.second()
            );
            if is_canonical_timestamp(&formatted) {
                formatted
            } else {
                "1970-01-01T00:00:00Z".to_owned()
            }
        }
        Err(_) => "1970-01-01T00:00:00Z".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Intent creation (persist before effects)
// ---------------------------------------------------------------------------

/// Builds the durable outbox entry for one local intent. The caller persists
/// it (`record_outbox`) **before** capture or any network effect. The base
/// commit and base record are captured at observation time so reconciliation
/// after a crash has its common base.
pub fn intent_entry(
    connection_id: hfdrive_core::ids::ConnectionId,
    operation_id: OperationId,
    item_id: Option<ItemId>,
    base_commit: Option<CommitId>,
    base_json: Option<String>,
    observed_generation: u64,
    intent: &SyncIntent,
) -> Result<OutboxEntry, serde_json::Error> {
    let intent_json = serde_json::to_value(intent)?;
    Ok(OutboxEntry {
        connection_id,
        operation_id,
        item_id,
        base_commit,
        base_json,
        observed_generation,
        intent_json,
        state: OutboxState::Observed,
        snapshot_id: None,
        object_ref: None,
        candidate_commit: None,
        candidate_head_json: None,
        expected_etag: None,
        retry_class: RetryClass::None,
        next_attempt_at_ms: None,
    })
}

/// Parses an entry's intent body, including the pre-`intent` discriminator
/// used by the first durable schema. Legacy create records had two `kind`
/// fields; JSON object deserialization retained the item kind (`file` or
/// `directory`), which together with parent/name identifies the create shape.
pub fn parse_intent(entry: &OutboxEntry) -> Result<SyncIntent, serde_json::Error> {
    let mut value = entry.intent_json.clone();
    if let Some(object) = value.as_object_mut() {
        if !object.contains_key("intent") {
            let legacy_create = object.contains_key("item_id")
                && object.contains_key("parent_id")
                && object.contains_key("name")
                && object.get("kind").and_then(serde_json::Value::as_str)
                    .is_some_and(|kind| matches!(kind, "file" | "directory"));
            if legacy_create {
                object.insert("intent".to_owned(), serde_json::Value::String("create".to_owned()));
            } else if let Some(tag) = object.remove("kind") {
                object.insert("intent".to_owned(), tag);
            }
        }
    }
    serde_json::from_value(value)
}

// ---------------------------------------------------------------------------
// The pure phase planner
// ---------------------------------------------------------------------------

/// The next durable boundary one outbox entry is waiting for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhaseStep {
    /// Materialize (if needed) and capture a coherent staged snapshot.
    Capture,
    /// Upload the staged snapshot through the three native Xet checkpoints.
    Upload,
    /// Build/rebuild the publication candidate and reconcile.
    Plan,
    /// The candidate evidence is persisted; perform the guarded `HEAD` write.
    Publish,
    /// The conditional write is uncertain; resolve through committed ancestry.
    Resolve,
    /// The publication is committed; apply the remote change locally.
    Apply,
    /// Local application finished; close the entry (generation-guarded).
    Complete,
    /// Parked for a durable retry at `next_attempt_at_ms` (or user action).
    Wait,
}

/// Pure step classification from the persisted entry. Evidence columns are
/// authoritative:
///
/// * an `Observed` content entry with a bound `object_ref` was rebased after
///   a conditional-write failure *without* losing its payload binding and
///   never re-uploads;
/// * an `Observed` content entry with a Ready snapshot but no payload binding
///   re-uploads from that staged capture (a `Rebased`/`Recaptured` transition
///   restarts from a coherent capture and clears earlier payload/commit
///   evidence by design);
/// * metadata-only intents skip content states entirely.
pub fn next_step(entry: &OutboxEntry, now_ms: u64) -> PhaseStep {
    if let Some(at) = entry.next_attempt_at_ms {
        if entry.retry_class != RetryClass::None && at > now_ms {
            return PhaseStep::Wait;
        }
    }
    match entry.state {
        OutboxState::Observed => {
            let intent = parse_intent(entry).ok();
            match intent {
                // A restore reuses an already-bound payload: it plans
                // directly, never capturing or uploading anything.
                Some(intent) if intent.is_restore() => PhaseStep::Plan,
                Some(intent) if intent.has_content() => {
                    if entry.object_ref.is_some() {
                        PhaseStep::Plan
                    } else if entry.snapshot_id.is_some() {
                        PhaseStep::Upload
                    } else {
                        PhaseStep::Capture
                    }
                }
                _ => PhaseStep::Plan,
            }
        }
        OutboxState::SnapshotReady => PhaseStep::Upload,
        OutboxState::PayloadReady => PhaseStep::Plan,
        OutboxState::MetadataReady => PhaseStep::Publish,
        OutboxState::PublishUnknown => PhaseStep::Resolve,
        OutboxState::Published => PhaseStep::Apply,
        OutboxState::LocalApplyPending => PhaseStep::Complete,
        OutboxState::Complete => PhaseStep::Complete,
    }
}

// ---------------------------------------------------------------------------
// Recovery classification
// ---------------------------------------------------------------------------

/// What restart must do with one interrupted entry. Nothing here replays an
/// external effect blindly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovery {
    /// Resume ordinary phase processing at this step.
    Resume(PhaseStep),
    /// The capture was interrupted before it was durable; recapture.
    Recapture,
    /// The publication outcome is unknown; resolve through ancestry before
    /// any further remote write.
    ResolveUncertain,
    /// Local application was in flight; classify the journal action against
    /// the real filesystem before deciding.
    ClassifyLocalAction(ActionId),
}

/// Classifies one persisted entry after a crash/restart.
///
/// `actions` are the entry's still-open local action journal rows.
pub fn recover_entry(entry: &OutboxEntry, open_actions: &[ActionId]) -> Recovery {
    match entry.state {
        OutboxState::Observed => {
            let intent = parse_intent(entry).ok();
            match intent {
                Some(intent) if intent.has_content() && entry.object_ref.is_none() => {
                    // A capture that completed is evidenced by a Ready snapshot.
                    match entry.snapshot_id {
                        Some(_) => Recovery::Resume(PhaseStep::Upload),
                        None => Recovery::Recapture,
                    }
                }
                _ => Recovery::Resume(PhaseStep::Plan),
            }
        }
        OutboxState::SnapshotReady => match entry.snapshot_id {
            Some(_) => Recovery::Resume(PhaseStep::Upload),
            None => Recovery::Recapture,
        },
        OutboxState::PayloadReady => Recovery::Resume(PhaseStep::Plan),
        OutboxState::MetadataReady => Recovery::Resume(PhaseStep::Publish),
        OutboxState::PublishUnknown => Recovery::ResolveUncertain,
        OutboxState::Published | OutboxState::LocalApplyPending => match open_actions.first() {
            Some(action) => Recovery::ClassifyLocalAction(*action),
            None => Recovery::Resume(PhaseStep::Apply),
        },
        OutboxState::Complete => Recovery::Resume(PhaseStep::Complete),
    }
}

/// True when the entry may still perform remote mutation. Read-only
/// connections and parked retries never dispatch.
pub fn allows_remote_dispatch(entry: &OutboxEntry, writable: bool, now_ms: u64) -> bool {
    writable
        && entry.retry_class != RetryClass::NeedsUser
        && entry.retry_class != RetryClass::NeedsAuth
        && next_step(entry, now_ms) != PhaseStep::Wait
}

// ---------------------------------------------------------------------------
// Native Xet checkpoint journal (durable, per payload upload)
// ---------------------------------------------------------------------------

/// The durable checkpoints of one staged payload upload. Serialized into the
/// connection's transfer journal row (`transfers.sdk_resume_json`) under the
/// entry's operation identifier; `None` fields are boundaries not yet
/// reached. These are genuine SDK checkpoints (task id, target key, digest),
/// not invented resume state; the capture evidence binds the upload to the
/// exact local file identity/generation that was read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadCheckpoints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<CaptureEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingested: Option<IngestionCheckpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cas_committed: Option<CasCommitCheckpoint>,
}

/// Exactly what the coherent capture read: stable file identity, size,
/// modification time and USN. The guarded local finalization compares this
/// against the live file before marking anything in sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureEvidence {
    pub volume_serial_number: u64,
    pub file_id: [u8; 16],
    pub size: u64,
    pub last_write_time_100ns: i64,
    /// `None` when the volume has no usable USN journal — never a wildcard.
    pub usn: Option<i64>,
}

impl CaptureEvidence {
    /// The guard state for `CfSetInSyncState`/`CfUpdatePlaceholder`.
    pub fn to_file_state(&self) -> hfdrive_windows::filesystem::volume::FileState {
        hfdrive_windows::filesystem::volume::FileState {
            identity: hfdrive_windows::filesystem::volume::FileIdentity {
                volume_serial_number: self.volume_serial_number,
                file_id: self.file_id,
                link_count: 1,
                attributes: 0x20,
                reparse_tag: 0,
            },
            size: self.size,
            last_write_time_100ns: self.last_write_time_100ns,
            usn: self.usn,
        }
    }
}

impl PayloadCheckpoints {
    pub fn is_bound(&self) -> bool {
        self.cas_committed.is_some()
    }
}

/// Deterministic transfer identity for one outbox operation's payload
/// upload: the operation UUID doubles as the transfer UUID so recovery can
/// always find the journal row without extra lookup tables.
pub fn transfer_id_for(operation_id: OperationId) -> TransferId {
    TransferId::from_uuid(*operation_id.as_uuid()).expect("a UUID is never nil")
}

// ---------------------------------------------------------------------------
// Snapshot staging records
// ---------------------------------------------------------------------------

/// The staged snapshot identity ready for upload.
#[derive(Debug, Clone)]
pub struct StagedPayload {
    pub snapshot_id: SnapshotId,
    pub upload_id: UploadId,
    pub staged_path: PathBuf,
    pub size: u64,
    pub sha256: hfdrive_core::storage::Sha256Digest,
}

impl StagedPayload {
    /// The immutable upload descriptor consumed by the remote boundary.
    pub fn stable_snapshot(&self) -> StableSnapshot {
        StableSnapshot {
            snapshot_id: self.snapshot_id,
            upload_id: self.upload_id,
            path: self.staged_path.clone(),
            size: self.size,
            sha256: self.sha256,
        }
    }
}

/// Loads a ready staged payload from its durable snapshot record plus the
/// entry's persisted upload identity. A missing or still-capturing snapshot
/// is never treated as uploadable.
pub fn staged_payload(
    entry: &OutboxEntry,
    snapshot: &SnapshotRecord,
) -> Result<StagedPayload, Recovery> {
    if snapshot.status != SnapshotStatus::Ready {
        return Err(Recovery::Recapture);
    }
    let (Some(size), Some(sha256)) = (snapshot.size, snapshot.sha256) else {
        return Err(Recovery::Recapture);
    };
    let intent = parse_intent(entry).map_err(|_| Recovery::Recapture)?;
    let upload_id = intent
        .pending_content()
        .map(|pending| UploadId::from_uuid(pending.upload_id))
        .transpose()
        .map_err(|_| Recovery::Recapture)?
        .ok_or(Recovery::Recapture)?;
    Ok(StagedPayload {
        snapshot_id: snapshot.snapshot_id,
        upload_id,
        staged_path: snapshot.path.clone(),
        size,
        sha256,
    })
}

/// Applies a durable phase transition on the shared state worker.
pub async fn transition(
    state: &hfdrive_state::AccountStore,
    entry: &OutboxEntry,
    change: OutboxTransition,
) -> Result<OutboxEntry, hfdrive_state::StateError> {
    state
        .transition_outbox(entry.connection_id, entry.operation_id, change)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use hfdrive_core::ids::ConnectionId;

    fn entry(state: OutboxState, intent: SyncIntent, generation: u64) -> OutboxEntry {
        let operation = OperationId::new();
        let mut record = intent_entry(
            ConnectionId::new(),
            operation,
            Some(intent.item_id()),
            None,
            None,
            generation,
            &intent,
        )
        .unwrap();
        record.state = state;
        record
    }

    fn pending() -> PendingContent {
        PendingContent {
            upload_id: Uuid::new_v4(),
            version_id: Uuid::new_v4(),
            modified_at: "2026-11-13T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn content_intents_capture_before_upload_and_metadata_only_intents_plan() {
        let content = entry(
            OutboxState::Observed,
            SyncIntent::Content { item_id: Uuid::new_v4(), content: pending() },
            1,
        );
        assert_eq!(next_step(&content, 0), PhaseStep::Capture);
        let move_only = entry(
            OutboxState::Observed,
            SyncIntent::Move {
                item_id: Uuid::new_v4(),
                parent_id: Uuid::new_v4(),
                name: "renamed.txt".to_owned(),
            },
            1,
        );
        assert_eq!(next_step(&move_only, 0), PhaseStep::Plan);
    }

    #[test]
    fn rebased_entries_with_bound_payload_never_reupload() {
        let mut content = entry(
            OutboxState::Observed,
            SyncIntent::Content { item_id: Uuid::new_v4(), content: pending() },
            1,
        );
        content.object_ref = Some(ObjectRef {
            key: hfdrive_core::storage::PayloadKey::new(UploadId::new()),
            sha256: hfdrive_core::storage::Sha256Digest::of(b"bytes"),
            size: 5,
            xet_file_id: hfdrive_core::storage::XetFileId::new(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            )
            .unwrap(),
        });
        assert_eq!(next_step(&content, 0), PhaseStep::Plan);
    }

    #[test]
    fn pending_retries_wait_until_their_time_and_never_dispatch() {
        let mut content = entry(
            OutboxState::SnapshotReady,
            SyncIntent::Content { item_id: Uuid::new_v4(), content: pending() },
            1,
        );
        content.retry_class = RetryClass::Backoff;
        content.next_attempt_at_ms = Some(500);
        assert_eq!(next_step(&content, 400), PhaseStep::Wait);
        assert!(!allows_remote_dispatch(&content, true, 400));
        assert_eq!(next_step(&content, 500), PhaseStep::Upload);
        assert!(allows_remote_dispatch(&content, true, 500));
        assert!(!allows_remote_dispatch(&content, false, 500), "read-only never dispatches");
    }

    #[test]
    fn interrupted_publications_resolve_uncertainty_and_interrupted_applies_classify() {
        let uncertain = entry(
            OutboxState::PublishUnknown,
            SyncIntent::Content { item_id: Uuid::new_v4(), content: pending() },
            1,
        );
        assert_eq!(recover_entry(&uncertain, &[]), Recovery::ResolveUncertain);

        let applying = entry(
            OutboxState::LocalApplyPending,
            SyncIntent::Content { item_id: Uuid::new_v4(), content: pending() },
            1,
        );
        let action = ActionId::new();
        assert_eq!(recover_entry(&applying, &[action]), Recovery::ClassifyLocalAction(action));

        let published = entry(
            OutboxState::Published,
            SyncIntent::Delete { item_id: Uuid::new_v4() },
            1,
        );
        assert_eq!(recover_entry(&published, &[]), Recovery::Resume(PhaseStep::Apply));
    }

    #[test]
    fn interrupted_capture_recaptures_but_durable_snapshots_resume_upload() {
        let content = SyncIntent::Content { item_id: Uuid::new_v4(), content: pending() };
        let never_captured = entry(OutboxState::Observed, content.clone(), 1);
        assert_eq!(recover_entry(&never_captured, &[]), Recovery::Recapture);

        let mut captured = entry(OutboxState::Observed, content, 1);
        captured.snapshot_id = Some(SnapshotId::new());
        assert_eq!(recover_entry(&captured, &[]), Recovery::Resume(PhaseStep::Upload));
    }

    #[test]
    fn intent_json_round_trips_every_shape() {
        for intent in [
            SyncIntent::Create {
                item_id: Uuid::new_v4(),
                parent_id: Uuid::new_v4(),
                name: "neu.txt".to_owned(),
                kind: IntentKind::File,
                content: Some(pending()),
            },
            SyncIntent::MoveAndContent {
                item_id: Uuid::new_v4(),
                parent_id: Uuid::new_v4(),
                name: "moved.txt".to_owned(),
                content: pending(),
            },
            SyncIntent::Resolve {
                item_id: Uuid::new_v4(),
                parent_id: Uuid::new_v4(),
                name: "chosen.txt".to_owned(),
                restored_version_id: Uuid::new_v4(),
                version_id: Uuid::new_v4(),
                object: ObjectRef {
                    key: hfdrive_core::storage::PayloadKey::new(UploadId::new()),
                    sha256: hfdrive_core::storage::Sha256Digest::of(b"chosen"),
                    size: 6,
                    xet_file_id: hfdrive_core::storage::XetFileId::new(
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
                    ).unwrap(),
                },
                modified_at: "2026-01-01T00:00:00Z".to_owned(),
            },
            SyncIntent::Delete { item_id: Uuid::new_v4() },
        ] {
            let entry = entry(OutboxState::Observed, intent.clone(), 3);
            assert_eq!(parse_intent(&entry).unwrap(), intent);
            let round_trip = serde_json::to_value(&intent).unwrap();
            assert_eq!(serde_json::from_value::<SyncIntent>(round_trip).unwrap(), intent);
        }
    }

    #[test]
    fn legacy_intent_discriminators_remain_recoverable() {
        let item = Uuid::new_v4();
        let parent = Uuid::new_v4();
        let create = SyncIntent::Create {
            item_id: item,
            parent_id: parent,
            name: "legacy.txt".to_owned(),
            kind: IntentKind::File,
            content: None,
        };
        let mut entry = intent_entry(
            hfdrive_core::ids::ConnectionId::new(),
            OperationId::new(),
            Some(create.item_id()),
            None,
            None,
            1,
            &create,
        ).unwrap();
        entry.intent_json = serde_json::json!({
            "item_id": item,
            "parent_id": parent,
            "name": "legacy.txt",
            "kind": "file",
            "content": null
        });
        assert_eq!(parse_intent(&entry).unwrap(), create);

        let delete = SyncIntent::Delete { item_id: item };
        entry.intent_json = serde_json::json!({"kind": "delete", "item_id": item});
        assert_eq!(parse_intent(&entry).unwrap(), delete);
    }
}
