//! Real activity projection for the read-only `list_activity` endpoint.
//!
//! One record here is one piece of *actual unfinished work* of one
//! connection: a durable outbox intent, a journaled local action, a transfer
//! journal row, or a live in-flight CFAPI request from the engine's live-work
//! registry. Nothing is synthesized at projection time:
//!
//! * `started_at` is the row's persisted `created_at_ms` (or the live request's
//!   real dispatch time) rendered as RFC 3339. A missing/zero start time is an
//!   explicit error, never a fabricated epoch timestamp and never
//!   projection-time "now".
//! * `item_name` is real name evidence: the intent's own name, the item
//!   registry's relative path, a journaled action path, a live request path
//!   hint, or the persisted base item record. Internal object keys are never
//!   names. A record whose name evidence is missing produces an explicit
//!   unavailable error — it is never silently dropped.
//! * `bytes_total` is a real known total (staged capture size, bound payload
//!   size, range span, live span length, or exactly `0` for metadata-only work
//!   that moves no bytes). It is `None` when the total is genuinely unknown.
//!   `bytes_completed` counts only real completed logical bytes: today that is
//!   the live fetch counter; durable work has no logical progress counter and
//!   reports `0` rather than an invented one.
//! * `last_error` is the persisted [`WorkErrorRow`] of the row: the classified
//!   code captured at the failure site plus its safe detail. A `Failed` record
//!   without one is an explicit error.
//!
//! # Stage contract
//!
//! Stages are the fixed wire vocabulary ([`wire::ActivityPhase`]); the wire
//! carries no separate "metadata" phase, so metadata-only work uses direction
//! [`wire::ActivityDirection::Metadata`] with the publication or local-
//! application phase:
//!
//! | work | direction | phase |
//! |------|-----------|-------|
//! | content intent, observed, no capture yet | `upload` | `observed` |
//! | metadata-only intent (directory/empty-file create, move), observed | `metadata` | `observed` |
//! | bound snapshot still capturing | `upload` | `snapshot` |
//! | staged capture / payload round (`SnapshotReady`, `PayloadReady`) | `upload` | `uploading` |
//! | candidate persisted / uncertain write (`MetadataReady`, `PublishUnknown`) | `upload` (content) or `metadata` | `publishing` |
//! | local application of a create/update/hydrate/restore | `download` | `downloading` |
//! | local application of a rename/delete | `metadata` | `downloading` |
//! | any row with a recorded work failure | unchanged | `failed` |
//!
//! Local application is the remote-to-local half of the sync cycle; the
//! direction field distinguishes content application (`download`) from
//! metadata-only application (`metadata`), which is what "rename/delete ->
//! metadata" fixes in this vocabulary. Metadata-only intents skip the content
//! states entirely (they go `Observed -> MetadataReady`), so they never
//! project `snapshot` or `uploading`.
//!
//! # Paging
//!
//! Sources are merged in the stable global key order
//! `(unix milliseconds, source rank, work UUID)` with ranks `0` outbox,
//! `1` action, `2` transfer, `3` live. The continuation cursor is
//! `activity-v1:<connection>:<ms>:<rank>:<uuid>`, bound to the connection that
//! produced it; a foreign or malformed cursor is rejected. Each source is
//! asked for `limit + 1` rows strictly after its rank-adjusted position
//! (a rank below the cursor rank starts after the `max` UUID at the cursor
//! timestamp, a rank above after the `nil` UUID, the same rank after the exact
//! UUID), so no source ever materializes an offset prefix. Pages stop at the
//! request limit or at the frame budget, whichever comes first; a record that
//! cannot fit even alone is an explicit error rather than an infinite cursor
//! loop. A terminal empty first page (no cursor) is the proof of idle: every
//! source was queried from its beginning.

use std::collections::HashMap;
use std::path::Path;

use hfdrive_core::format::{self, is_canonical_timestamp};
use hfdrive_core::ids::{ConnectionId, ItemId};
use hfdrive_protocol as wire;
use hfdrive_state::{
    AccountStore, ActionWorkRow, LocalAction, LocalActionKind, LocalActionState, OutboxEntry,
    OutboxState, OutboxWorkRow, RetryClass, SnapshotStatus, TransferDirection, TransferRecord,
    TransferState, TransferWorkRow, WorkErrorKind, WorkErrorRow, WorkPageCursor,
};
use uuid::Uuid;

use crate::sync::activity::{LiveWorkKind, LiveWorkView};
use crate::sync::outbox::{SyncIntent, parse_intent};
use crate::{Provider, operations::error, operations::internal, operations::state_error, storage::invalid};

/// Merged-source ranks in the global `(ms, rank, uuid)` order.
const RANK_OUTBOX: u8 = 0;
const RANK_ACTION: u8 = 1;
const RANK_TRANSFER: u8 = 2;
const RANK_LIVE: u8 = 3;

/// The maximum UUID: the position after every equal-time record of a lower
/// source rank.
const MAX_UUID: Uuid = Uuid::from_bytes([0xFF; 16]);

/// Cursor grammar version prefix.
const CURSOR_PREFIX: &str = "activity-v1";

/// Room reserved inside the 1 MiB frame for the envelope, result wrapper and
/// continuation cursor; records are truncated to the remainder.
const FRAME_MARGIN_BYTES: usize = 8 * 1024;
const ITEMS_BUDGET_BYTES: usize = wire::MAX_FRAME_BYTES - FRAME_MARGIN_BYTES;

/// Bound on the item-registry parent walk; beyond this the persisted
/// namespace is corrupt and projection fails closed instead of looping.
const MAX_PATH_DEPTH: usize = 512;

// ---------------------------------------------------------------------------
// Keyset positions
// ---------------------------------------------------------------------------

/// One position in the merged `(unix ms, source rank, work UUID)` order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActivityPosition {
    created_at_ms: u64,
    rank: u8,
    work_id: Uuid,
}

/// The rank-adjusted position each durable source resumes from. The same rank
/// resumes after the exact UUID; a lower rank excludes the cursor timestamp
/// entirely (`max` UUID at that time); a higher rank includes every record at
/// the cursor timestamp (`nil` UUID at that time). `None` starts at the
/// beginning of the stream — the only start that can prove idle. Positions are
/// pure ordered positions, not row anchors: a deleted row's cursor keeps
/// working, and the `nil`/`max` sentinels are ordinary positions.
fn source_after(cursor: Option<&ActivityPosition>, rank: u8) -> Option<(u64, Uuid)> {
    let cursor = cursor?;
    Some(match rank.cmp(&cursor.rank) {
        std::cmp::Ordering::Equal => (cursor.created_at_ms, cursor.work_id),
        std::cmp::Ordering::Less => (cursor.created_at_ms, MAX_UUID),
        std::cmp::Ordering::Greater => (cursor.created_at_ms, Uuid::nil()),
    })
}

/// The same position in the state layer's keyset shape.
fn state_after(cursor: Option<&ActivityPosition>, rank: u8) -> Option<WorkPageCursor> {
    source_after(cursor, rank).map(|(created_at_ms, work_id)| WorkPageCursor { created_at_ms, work_id })
}

fn encode_cursor(connection: ConnectionId, position: &ActivityPosition) -> String {
    format!(
        "{CURSOR_PREFIX}:{connection}:{}:{}:{}",
        position.created_at_ms, position.rank, position.work_id
    )
}

fn decode_cursor(
    text: &str,
    connection: ConnectionId,
) -> Result<ActivityPosition, wire::ProtocolError> {
    let mut parts = text.split(':');
    if parts.next() != Some(CURSOR_PREFIX) {
        return Err(invalid("Invalid activity continuation cursor"));
    }
    if parts.next() != Some(connection.to_string().as_str()) {
        return Err(invalid("Activity cursor belongs to a different connection"));
    }
    let created_at_ms = parts
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| invalid("Invalid activity continuation cursor"))?;
    let rank = parts
        .next()
        .and_then(|value| value.parse::<u8>().ok())
        .filter(|rank| *rank <= RANK_LIVE)
        .ok_or_else(|| invalid("Invalid activity continuation cursor"))?;
    // Canonical lowercase hyphenated spelling only: the cursor is opaque and
    // the endpoint only ever emits that form.
    let work_id = parts
        .next()
        .and_then(|value| {
            let id = Uuid::parse_str(value).ok()?;
            (id.hyphenated().to_string() == value).then_some(id)
        })
        .ok_or_else(|| invalid("Invalid activity continuation cursor"))?;
    if parts.next().is_some() {
        return Err(invalid("Invalid activity continuation cursor"));
    }
    Ok(ActivityPosition { created_at_ms, rank, work_id })
}

// ---------------------------------------------------------------------------
// Identity, time and error projection
// ---------------------------------------------------------------------------

/// The durable identity of one activity record: UUIDv5 under the connection
/// over `<kind>/<work id>`. Deriving it keeps upload journal rows (whose
/// transfer id equals their operation id) distinct from their outbox rows.
fn durable_activity_id(connection: ConnectionId, kind: &str, work_id: Uuid) -> Uuid {
    Uuid::new_v5(connection.as_uuid(), format!("{kind}/{work_id}").as_bytes())
}

/// RFC 3339 UTC, whole seconds, from real persisted/dispatch unix
/// milliseconds. Zero means the start evidence is unavailable and is an
/// explicit error — never a fabricated epoch timestamp.
fn activity_timestamp(milliseconds: u64) -> Result<String, wire::ProtocolError> {
    if milliseconds == 0 {
        return Err(unavailable_evidence("activity record has no real start time evidence"));
    }
    let seconds = i64::try_from(milliseconds / 1_000)
        .map_err(|_| unavailable_evidence("activity start time is out of range"))?;
    let at = time::OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|_| unavailable_evidence("activity start time is out of range"))?;
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
        Ok(formatted)
    } else {
        Err(unavailable_evidence("activity start time is out of range"))
    }
}

/// Projects one persisted work failure. The classified code is preserved
/// exactly: when it is a protocol code it fills the code field; otherwise the
/// code field is `internal` and the classified code leads the message
/// (`"<classified code>: <safe detail>"`), so consumers can always classify on
/// the stable `codes::*` spelling without widening the wire shape.
fn work_error_object(row: &WorkErrorRow) -> wire::ErrorObject {
    let detail = row.error_detail.trim();
    let message = if detail.is_empty() {
        row.error_code.clone()
    } else {
        detail.to_owned()
    };
    match wire::ProtocolErrorCode::from_wire(&row.error_code) {
        Some(code) => wire::ErrorObject { code, message, retry_after_ms: None },
        None => wire::ErrorObject {
            code: wire::ProtocolErrorCode::Internal,
            message: if detail.is_empty() {
                row.error_code.clone()
            } else {
                format!("{}: {message}", row.error_code)
            },
            retry_after_ms: None,
        },
    }
}

/// Missing name/start/failure evidence is always explicit: the same
/// fail-closed class conflicts use for missing kind/revision evidence.
fn unavailable_evidence(detail: &'static str) -> wire::ProtocolError {
    error(wire::ProtocolErrorCode::UnsupportedFormat, detail)
}

// ---------------------------------------------------------------------------
// Stage classification
// ---------------------------------------------------------------------------

/// What kind of change one outbox intent describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChangeClass {
    /// Content publication (create with content, content edit, move + content).
    ContentUpload,
    /// Version rebinding with payload reuse (restore, conflict resolve).
    Rebind,
    /// New item without content records (directory or empty file).
    Create,
    /// Location change only.
    Move,
    /// Deletion.
    Delete,
}

fn change_class(intent: &SyncIntent) -> ChangeClass {
    match intent {
        SyncIntent::Create { content: Some(_), .. }
        | SyncIntent::Content { .. }
        | SyncIntent::MoveAndContent { .. } => ChangeClass::ContentUpload,
        SyncIntent::Create { content: None, .. } => ChangeClass::Create,
        SyncIntent::Move { .. } => ChangeClass::Move,
        SyncIntent::Delete { .. } => ChangeClass::Delete,
        SyncIntent::Restore { .. } | SyncIntent::Resolve { .. } => ChangeClass::Rebind,
    }
}

/// The stage of one outbox record from its durable evidence alone.
fn outbox_stage(
    class: ChangeClass,
    state: OutboxState,
    capture: Option<SnapshotStatus>,
    has_object: bool,
) -> Result<(wire::ActivityDirection, wire::ActivityPhase), wire::ProtocolError> {
    use wire::ActivityDirection as Direction;
    use wire::ActivityPhase as Phase;
    let content = matches!(class, ChangeClass::ContentUpload | ChangeClass::Rebind);
    let pre_apply = if content { Direction::Upload } else { Direction::Metadata };
    Ok(match state {
        OutboxState::Complete => {
            return Err(unavailable_evidence(
                "a finished record reached the unfinished activity listing",
            ));
        }
        OutboxState::Observed => {
            if matches!(capture, Some(SnapshotStatus::Capturing)) {
                // A capture is bound and still running.
                (Direction::Upload, Phase::Snapshot)
            } else if has_object {
                // Payload already bound (rebased): publication is what remains.
                (Direction::Upload, Phase::Publishing)
            } else if matches!(
                capture,
                Some(SnapshotStatus::Ready | SnapshotStatus::Consumed | SnapshotStatus::Released)
            ) {
                // Staged capture: the payload upload round is what remains.
                (Direction::Upload, Phase::Uploading)
            } else {
                (pre_apply, Phase::Observed)
            }
        }
        OutboxState::SnapshotReady | OutboxState::PayloadReady => {
            (Direction::Upload, Phase::Uploading)
        }
        OutboxState::MetadataReady | OutboxState::PublishUnknown => (pre_apply, Phase::Publishing),
        OutboxState::Published | OutboxState::LocalApplyPending => match class {
            // Local application: create/update/hydrate/restore bring content
            // availability down, rename/delete are metadata-only.
            ChangeClass::Move | ChangeClass::Delete => (Direction::Metadata, Phase::Downloading),
            _ => (Direction::Download, Phase::Downloading),
        },
    })
}

/// The stage of one journaled local action (always a local application).
fn action_stage(kind: LocalActionKind) -> (wire::ActivityDirection, wire::ActivityPhase) {
    use wire::ActivityDirection as Direction;
    use wire::ActivityPhase as Phase;
    match kind {
        LocalActionKind::CreatePlaceholder
        | LocalActionKind::UpdatePlaceholder
        | LocalActionKind::Hydrate
        | LocalActionKind::SetPin => (Direction::Download, Phase::Downloading),
        LocalActionKind::Rename
        | LocalActionKind::DeletePlaceholder
        | LocalActionKind::Dehydrate
        | LocalActionKind::ConvertToNormal
        | LocalActionKind::Other => (Direction::Metadata, Phase::Downloading),
    }
}

/// The stage of one transfer journal row: the upload payload round or a
/// download range.
fn transfer_stage(direction: TransferDirection) -> (wire::ActivityDirection, wire::ActivityPhase) {
    use wire::ActivityDirection as Direction;
    use wire::ActivityPhase as Phase;
    match direction {
        TransferDirection::Upload => (Direction::Upload, Phase::Uploading),
        TransferDirection::Download => (Direction::Download, Phase::Downloading),
    }
}

/// The stage of one live in-flight request.
fn live_stage(kind: LiveWorkKind) -> (wire::ActivityDirection, wire::ActivityPhase) {
    use wire::ActivityDirection as Direction;
    use wire::ActivityPhase as Phase;
    match kind {
        LiveWorkKind::Fetch => (Direction::Download, Phase::Downloading),
        // Directory population creates metadata only: entries are not bytes.
        LiveWorkKind::DirectoryPopulation => (Direction::Metadata, Phase::Downloading),
    }
}

// ---------------------------------------------------------------------------
// Name evidence
// ---------------------------------------------------------------------------

/// Bounded name-evidence resolution over the item registry of one page.
struct Evidence<'a> {
    account: &'a AccountStore,
    connection: ConnectionId,
    paths: HashMap<ItemId, Option<String>>,
}

impl<'a> Evidence<'a> {
    fn new(account: &'a AccountStore, connection: ConnectionId) -> Self {
        Self { account, connection, paths: HashMap::new() }
    }

    /// The registry relative path of one item (the root's is `""`), `None`
    /// when the registry cannot resolve it. Ancestors are memoized per page
    /// and the walk is depth-bounded; a cyclic/corrupt namespace is an
    /// explicit error.
    async fn display_path(&mut self, item_id: ItemId) -> Result<Option<String>, wire::ProtocolError> {
        if let Some(cached) = self.paths.get(&item_id) {
            return Ok(cached.clone());
        }
        // Walk ancestors until a cached/known path or the root is reached.
        let mut chain: Vec<(ItemId, String)> = Vec::new();
        let mut current = item_id;
        // Every loop exit initializes `base` before the post-loop build; the
        // `return Err` paths never reach it, so no initial value is needed.
        let base: Option<String>;
        loop {
            if let Some(cached) = self.paths.get(&current) {
                base = cached.clone();
                break;
            }
            if chain.len() >= MAX_PATH_DEPTH {
                return Err(unavailable_evidence("persisted item ancestry is unresolvable"));
            }
            let Some(record) = self.account.item(self.connection, current).await.map_err(state_error)?
            else {
                base = None;
                break;
            };
            let name = record.name;
            let parent = record.parent_id;
            chain.push((current, name));
            match parent {
                None => {
                    base = Some(String::new());
                    break;
                }
                Some(parent) => current = parent,
            }
        }
        // Build each path once, deepest ancestor first.
        let mut path = base;
        for (id, name) in chain.iter().rev() {
            path = path.map(|prefix| {
                if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}/{name}")
                }
            });
            self.paths.insert(*id, path.clone());
        }
        Ok(path)
    }

    /// The display name of one outbox record: the intent's own name with its
    /// parent's registry path, else the registry path of the item, else the
    /// persisted base item record's name. Missing evidence is an error.
    async fn outbox_name(
        &mut self,
        entry: &OutboxEntry,
        intent: &SyncIntent,
    ) -> Result<(Option<ItemId>, String), wire::ProtocolError> {
        let item_id = entry.item_id.or_else(|| intent_item_id(intent));
        match intent {
            SyncIntent::Create { parent_id, name, .. }
            | SyncIntent::Move { parent_id, name, .. }
            | SyncIntent::MoveAndContent { parent_id, name, .. }
            | SyncIntent::Resolve { parent_id, name, .. } => {
                if name.is_empty() {
                    return Err(unavailable_evidence("persisted intent has no item name"));
                }
                let parent_prefix = match ItemId::from_uuid(*parent_id).ok() {
                    Some(parent) => self.display_path(parent).await?,
                    None => None,
                };
                let full = match parent_prefix {
                    Some(prefix) if !prefix.is_empty() => format!("{prefix}/{name}"),
                    _ => name.clone(),
                };
                Ok((item_id, full))
            }
            SyncIntent::Content { .. }
            | SyncIntent::Delete { .. }
            | SyncIntent::Restore { .. } => {
                if let Some(item_id) = item_id {
                    if let Some(path) = self.display_path(item_id).await? {
                        return Ok((Some(item_id), path));
                    }
                }
                if let Some(base) = base_item_name(entry) {
                    return Ok((item_id, base));
                }
                Err(unavailable_evidence("a persisted outbox record lacks item name evidence"))
            }
        }
    }

    /// The display name of one journaled action: its real target/source path,
    /// else the item registry path. Missing evidence is an error.
    async fn action_name(&mut self, action: &LocalAction) -> Result<String, wire::ProtocolError> {
        for path in [action.target_path.as_deref(), action.source_path.as_deref()] {
            if let Some(text) = relative_path_text(path) {
                return Ok(text);
            }
        }
        if let Some(item_id) = action.item_id {
            if let Some(path) = self.display_path(item_id).await? {
                return Ok(path);
            }
        }
        Err(unavailable_evidence("a journaled local action lacks item name evidence"))
    }

    /// The item id and display name of one transfer row: its operation's
    /// intent, else the item bound to its version. Missing evidence is an
    /// error.
    async fn transfer_evidence(
        &mut self,
        transfer: &TransferRecord,
    ) -> Result<(Option<ItemId>, String), wire::ProtocolError> {
        if let Some(operation) = transfer.operation_id {
            if let Some(entry) = self
                .account
                .outbox_entry(self.connection, operation)
                .await
                .map_err(state_error)?
            {
                if let Ok(intent) = parse_intent(&entry) {
                    return self.outbox_name(&entry, &intent).await;
                }
            }
        }
        if let Some(version) = transfer.version_id {
            if let Some(item) = self
                .account
                .item_for_version(self.connection, version)
                .await
                .map_err(state_error)?
            {
                if let Some(path) = self.display_path(item.item_id).await? {
                    return Ok((Some(item.item_id), path));
                }
            }
        }
        Err(unavailable_evidence("a transfer journal row lacks item name evidence"))
    }

    /// The display name of one live request: its request path hint, else the
    /// item registry path. Missing evidence is an error.
    async fn live_name(&mut self, view: &LiveWorkView) -> Result<String, wire::ProtocolError> {
        if let Some(hint) = view.path_hint.as_deref() {
            if !hint.is_empty() {
                return Ok(hint.replace('\\', "/"));
            }
        }
        if let Some(item_id) = view.item_id {
            if let Some(path) = self.display_path(item_id).await? {
                return Ok(path);
            }
        }
        Err(unavailable_evidence("a live request lacks item name evidence"))
    }
}

/// The item id of a stored intent, without the panicking convenience accessor.
fn intent_item_id(intent: &SyncIntent) -> Option<ItemId> {
    let raw = match intent {
        SyncIntent::Create { item_id, .. }
        | SyncIntent::Content { item_id, .. }
        | SyncIntent::Move { item_id, .. }
        | SyncIntent::MoveAndContent { item_id, .. }
        | SyncIntent::Delete { item_id }
        | SyncIntent::Restore { item_id, .. }
        | SyncIntent::Resolve { item_id, .. } => *item_id,
    };
    ItemId::from_uuid(raw).ok()
}

/// The persisted base item record's own name, when the row carried one.
fn base_item_name(entry: &OutboxEntry) -> Option<String> {
    let bytes = entry.base_json.as_ref()?.as_bytes();
    let record = format::from_item_record_bytes(bytes).ok()?;
    (!record.name.is_empty()).then_some(record.name)
}

/// A journaled relative path as a portable display path (always `/`
/// separators); non-UTF-8 or empty paths are unusable evidence.
fn relative_path_text(path: Option<&Path>) -> Option<String> {
    let text = path?.to_str()?;
    let text = text.replace('\\', "/");
    (!text.is_empty()).then_some(text)
}

// ---------------------------------------------------------------------------
// Per-source projection
// ---------------------------------------------------------------------------

/// One fetched work row with its merged-order key.
struct Keyed {
    key: (u64, u8, Uuid),
    work: Work,
}

enum Work {
    Outbox(OutboxWorkRow),
    Action(ActionWorkRow),
    Transfer(TransferWorkRow),
    Live(LiveWorkView),
}

fn outbox_bytes_total(
    entry: &OutboxEntry,
    intent: &SyncIntent,
    snapshot_size: Option<u64>,
) -> Option<u64> {
    if let Some(object) = &entry.object_ref {
        return Some(object.size);
    }
    if let SyncIntent::Restore { object, .. } | SyncIntent::Resolve { object, .. } = intent {
        return Some(object.size);
    }
    if let Some(size) = snapshot_size {
        return Some(size);
    }
    match change_class(intent) {
        // Metadata-only work moves no content: zero is a known total.
        ChangeClass::Create | ChangeClass::Move | ChangeClass::Delete => Some(0),
        // A content change before capture has no known size yet.
        _ => None,
    }
}

async fn project_outbox(
    evidence: &mut Evidence<'_>,
    row: &OutboxWorkRow,
) -> Result<wire::ActivityRecord, wire::ProtocolError> {
    let entry = &row.entry;
    let intent = parse_intent(entry).map_err(|_| {
        unavailable_evidence("a persisted outbox intent is not valid intent JSON")
    })?;
    let class = change_class(&intent);
    let snapshot = match entry.snapshot_id {
        Some(snapshot_id) => evidence
            .account
            .snapshot(evidence.connection, snapshot_id)
            .await
            .map_err(state_error)?,
        None => None,
    };
    let (item_id, item_name) = evidence.outbox_name(entry, &intent).await?;
    let mut stage = outbox_stage(
        class,
        entry.state,
        snapshot.as_ref().map(|record| record.status),
        entry.object_ref.is_some(),
    )?;
    let failure = evidence
        .account
        .work_error(evidence.connection, WorkErrorKind::Outbox, *entry.operation_id.as_uuid())
        .await
        .map_err(state_error)?;
    let last_error = match failure {
        Some(row) => {
            stage = (stage.0, wire::ActivityPhase::Failed);
            Some(work_error_object(&row))
        }
        None => {
            // A row parked on a real user/auth action must carry its failure
            // classification; without one the projection cannot describe why
            // the work is stuck and fails closed instead of inventing one.
            if matches!(entry.retry_class, RetryClass::NeedsUser | RetryClass::NeedsAuth) {
                return Err(unavailable_evidence(
                    "a parked outbox record has no recorded failure classification",
                ));
            }
            None
        }
    };
    Ok(wire::ActivityRecord {
        activity_id: durable_activity_id(
            evidence.connection,
            "outbox",
            *entry.operation_id.as_uuid(),
        ),
        connection_id: *evidence.connection.as_uuid(),
        item_id: item_id.map(|id| *id.as_uuid()),
        item_name,
        direction: stage.0,
        phase: stage.1,
        // No durable logical progress counter exists; never present a planned
        // size as completed progress.
        bytes_completed: 0,
        bytes_total: outbox_bytes_total(entry, &intent, snapshot.and_then(|record| record.size)),
        started_at: activity_timestamp(row.created_at_ms)?,
        last_error,
    })
}

async fn project_action(
    evidence: &mut Evidence<'_>,
    row: &ActionWorkRow,
) -> Result<wire::ActivityRecord, wire::ProtocolError> {
    let action = &row.action;
    let item_name = evidence.action_name(action).await?;
    let mut stage = action_stage(action.kind);
    let failure = evidence
        .account
        .work_error(evidence.connection, WorkErrorKind::Action, *action.action_id.as_uuid())
        .await
        .map_err(state_error)?;
    if matches!(action.state, LocalActionState::Failed) && failure.is_none() {
        return Err(unavailable_evidence(
            "a failed local action has no recorded failure classification",
        ));
    }
    let last_error = failure.map(|row| {
        stage = (stage.0, wire::ActivityPhase::Failed);
        work_error_object(&row)
    });
    let bytes_total = match action.kind {
        // Content application has no size evidence in the action row.
        LocalActionKind::CreatePlaceholder
        | LocalActionKind::UpdatePlaceholder
        | LocalActionKind::Hydrate
        | LocalActionKind::SetPin => None,
        // Metadata-only application moves no content.
        _ => Some(0),
    };
    Ok(wire::ActivityRecord {
        activity_id: durable_activity_id(
            evidence.connection,
            "action",
            *action.action_id.as_uuid(),
        ),
        connection_id: *evidence.connection.as_uuid(),
        item_id: action.item_id.map(|id| *id.as_uuid()),
        item_name,
        direction: stage.0,
        phase: stage.1,
        bytes_completed: 0,
        bytes_total,
        started_at: activity_timestamp(row.created_at_ms)?,
        last_error,
    })
}

async fn project_transfer(
    evidence: &mut Evidence<'_>,
    row: &TransferWorkRow,
) -> Result<wire::ActivityRecord, wire::ProtocolError> {
    let transfer = &row.transfer;
    let (item_id, item_name) = evidence.transfer_evidence(transfer).await?;
    let mut stage = transfer_stage(transfer.direction);
    let failure = evidence
        .account
        .work_error(
            evidence.connection,
            WorkErrorKind::Transfer,
            *transfer.transfer_id.as_uuid(),
        )
        .await
        .map_err(state_error)?;
    if matches!(transfer.state, TransferState::Failed) && failure.is_none() {
        return Err(unavailable_evidence(
            "a failed transfer journal row has no recorded failure classification",
        ));
    }
    let last_error = failure.map(|row| {
        stage = (stage.0, wire::ActivityPhase::Failed);
        work_error_object(&row)
    });
    // A range transfer has an exact span (`range_end` is exclusive); the
    // payload upload journal carries its planned logical size. Completed
    // logical bytes have no durable counter (`wire_bytes` counts wire bytes,
    // not logical bytes) and stay 0 rather than being invented.
    let bytes_total = match (transfer.range_start, transfer.range_end) {
        (Some(start), Some(end)) => Some(end.saturating_sub(start)),
        _ if transfer.logical_bytes > 0 => Some(transfer.logical_bytes),
        _ => None,
    };
    Ok(wire::ActivityRecord {
        activity_id: durable_activity_id(
            evidence.connection,
            "transfer",
            *transfer.transfer_id.as_uuid(),
        ),
        connection_id: *evidence.connection.as_uuid(),
        item_id: item_id.map(|id| *id.as_uuid()),
        item_name,
        direction: stage.0,
        phase: stage.1,
        bytes_completed: 0,
        bytes_total,
        started_at: activity_timestamp(row.created_at_ms)?,
        last_error,
    })
}

async fn project_live(
    evidence: &mut Evidence<'_>,
    view: &LiveWorkView,
) -> Result<wire::ActivityRecord, wire::ProtocolError> {
    let item_name = evidence.live_name(view).await?;
    let stage = live_stage(view.kind);
    let (bytes_total, bytes_completed) = match view.kind {
        // Real delivered-bytes counter, real planned span length.
        LiveWorkKind::Fetch => (view.total_bytes, view.completed_bytes),
        // Directory entries are not bytes.
        LiveWorkKind::DirectoryPopulation => (None, 0),
    };
    Ok(wire::ActivityRecord {
        activity_id: view.activity_id,
        connection_id: *evidence.connection.as_uuid(),
        item_id: view.item_id.map(|id| *id.as_uuid()),
        item_name,
        direction: stage.0,
        phase: stage.1,
        bytes_completed,
        bytes_total,
        started_at: activity_timestamp(view.started_unix_ms)?,
        last_error: None,
    })
}

async fn project_work(
    evidence: &mut Evidence<'_>,
    work: &Work,
) -> Result<wire::ActivityRecord, wire::ProtocolError> {
    match work {
        Work::Outbox(row) => project_outbox(evidence, row).await,
        Work::Action(row) => project_action(evidence, row).await,
        Work::Transfer(row) => project_transfer(evidence, row).await,
        Work::Live(view) => project_live(evidence, view).await,
    }
}

// ---------------------------------------------------------------------------
// The endpoint
// ---------------------------------------------------------------------------

impl Provider {
    /// One bounded page of the connection's real unfinished work, in stable
    /// `(unix ms, source rank, work UUID)` order. Read-only: no durable work,
    /// no live span and no remote state is touched or mutated.
    pub(crate) async fn list_activity(
        &self,
        request: wire::ListActivityRequest,
    ) -> Result<wire::ListActivityResult, wire::ProtocolError> {
        if !(1..=wire::MAX_PAGE_LIMIT).contains(&request.limit) {
            return Err(invalid("Activity page size must be between 1 and 200"));
        }
        let profile = self.current_account()?;
        let connection = ConnectionId::from_uuid(request.connection_id)
            .map_err(|_| invalid("A nonzero connection identifier is required"))?;
        // The same authorization boundary as `list_conflicts`: the connection
        // must be registered for the signed-in account.
        self.state
            .reconcile_connections()
            .await
            .map_err(state_error)?
            .into_iter()
            .find(|record| {
                record.connection_id == connection && record.account_key == profile.account_key
            })
            .ok_or_else(|| {
                error(
                    wire::ProtocolErrorCode::NotFound,
                    "The connection does not exist for this account",
                )
            })?;
        // A cursor is bound to the connection that produced it; foreign and
        // malformed cursors are rejected before any listing happens.
        let position = request
            .cursor
            .as_deref()
            .map(|text| decode_cursor(text, connection))
            .transpose()?;
        let account = self
            .state
            .open_account(profile.account_key)
            .await
            .map_err(state_error)?;

        // Each source answers at most `limit + 1` rows strictly after its
        // rank-adjusted position; nothing is ever scanned from an offset.
        let mut pool: Vec<Keyed> = Vec::new();
        let rows = account
            .list_outbox_rows(connection, state_after(position.as_ref(), RANK_OUTBOX), request.limit)
            .await
            .map_err(state_error)?;
        for row in rows {
            pool.push(Keyed {
                key: (row.created_at_ms, RANK_OUTBOX, *row.entry.operation_id.as_uuid()),
                work: Work::Outbox(row),
            });
        }
        let rows = account
            .list_action_rows(connection, state_after(position.as_ref(), RANK_ACTION), request.limit)
            .await
            .map_err(state_error)?;
        for row in rows {
            pool.push(Keyed {
                key: (row.created_at_ms, RANK_ACTION, *row.action.action_id.as_uuid()),
                work: Work::Action(row),
            });
        }
        let rows = account
            .list_transfer_rows(
                connection,
                state_after(position.as_ref(), RANK_TRANSFER),
                request.limit,
            )
            .await
            .map_err(state_error)?;
        for row in rows {
            pool.push(Keyed {
                key: (row.created_at_ms, RANK_TRANSFER, *row.transfer.transfer_id.as_uuid()),
                work: Work::Transfer(row),
            });
        }
        if let Some(engine) = &self.engine {
            // No engine means no live spans — never a claim of durable idle.
            for view in engine.activity_registry().snapshot(
                connection,
                source_after(position.as_ref(), RANK_LIVE),
                request.limit,
            ) {
                pool.push(Keyed {
                    key: (view.started_unix_ms, RANK_LIVE, view.activity_id),
                    work: Work::Live(view),
                });
            }
        }
        pool.sort_unstable_by(|left, right| left.key.cmp(&right.key));

        // Project only the page: name and error lookups are bounded to the
        // records actually returned. Frame size stops the page before the
        // response could exceed the codec bound.
        let mut evidence = Evidence::new(&account, connection);
        let mut items = Vec::new();
        let mut used = 0usize;
        let mut last: Option<(u64, u8, Uuid)> = None;
        for (index, row) in pool.iter().enumerate() {
            let record = project_work(&mut evidence, &row.work).await?;
            let size = serde_json::to_vec(&record).map_err(|_| internal())?.len() + 1;
            if used + size > ITEMS_BUDGET_BYTES {
                if index == 0 {
                    return Err(error(
                        wire::ProtocolErrorCode::FrameTooLarge,
                        "One activity record cannot fit in a bounded response frame",
                    ));
                }
                break;
            }
            used += size;
            last = Some(row.key);
            items.push(record);
            if items.len() as u32 >= request.limit {
                break;
            }
        }
        // The pool held up to `limit + 1` rows per source: any unprojected row
        // proves another page exists, and a source that answered with fewer
        // rows answered completely. An empty first page is therefore the proof
        // of idle, not an early return.
        let more = items.len() < pool.len();
        let next_cursor = match (more, last) {
            (true, Some((created_at_ms, rank, work_id))) => Some(encode_cursor(
                connection,
                &ActivityPosition { created_at_ms, rank, work_id },
            )),
            _ => None,
        };
        Ok(wire::ListActivityResult { items, next_cursor })
    }
}

// ---------------------------------------------------------------------------
// Regression tests: cursor, stages, missing evidence and error projection.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hfdrive_core::ids::{
        ActionId, DeviceId, OperationId, TransferId, VersionId, WorkspaceId,
    };
    use hfdrive_core::storage::{
        BucketBinding, BucketId, BucketName, DriveBinding, Namespace, OwnerId, OwnerKind,
        RemotePrefix,
    };
    use hfdrive_state::{
        AccountRecord, AccountStatus, ConnectionMode, CredentialRef, ItemRecord,
    };
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    // ---- cursor contract ------------------------------------------

    #[test]
    fn cursor_round_trips_and_binds_to_the_connection() {
        let connection = ConnectionId::new();
        let position = ActivityPosition {
            created_at_ms: 1_700_000_000_123,
            rank: RANK_TRANSFER,
            work_id: Uuid::new_v4(),
        };
        let encoded = encode_cursor(connection, &position);
        assert_eq!(decode_cursor(&encoded, connection).unwrap(), position);

        // Positions are pure ordered positions: the sentinel UUIDs survive a
        // round trip, and a cursor keeps working after its row is deleted.
        for work_id in [Uuid::nil(), MAX_UUID] {
            let sentinel = ActivityPosition { work_id, ..position };
            let encoded = encode_cursor(connection, &sentinel);
            assert_eq!(decode_cursor(&encoded, connection).unwrap(), sentinel);
        }

        // Foreign and malformed cursors are rejected, never reinterpreted.
        let other = ConnectionId::new();
        assert_eq!(
            decode_cursor(&encoded, other).unwrap_err().code,
            wire::ProtocolErrorCode::InvalidRequest
        );
        let simple = Uuid::new_v4();
        for bad in [
            String::new(),
            "conflicts-v1:x:0".to_owned(),
            format!("{CURSOR_PREFIX}:{connection}"),
            format!("{CURSOR_PREFIX}:{connection}:not-a-number:0:{}", position.work_id),
            format!("{CURSOR_PREFIX}:{connection}:1:4:{}", position.work_id),
            format!("{CURSOR_PREFIX}:{connection}:1:{}:not-a-uuid", RANK_LIVE),
            format!("{CURSOR_PREFIX}:{connection}:1:{}:{}", RANK_LIVE, simple.simple()),
            format!(
                "{CURSOR_PREFIX}:{connection}:1:{}:{}:extra",
                RANK_LIVE, position.work_id
            ),
            format!(
                "{CURSOR_PREFIX}:{connection}:99999999999999999999:{}:{}",
                RANK_LIVE, position.work_id
            ),
        ] {
            assert!(
                decode_cursor(&bad, connection).is_err(),
                "cursor must be rejected: {bad}"
            );
        }
    }

    #[test]
    fn derived_positions_use_nil_and_max_sentinels_per_rank() {
        let position = ActivityPosition {
            created_at_ms: 42,
            rank: RANK_TRANSFER,
            work_id: Uuid::new_v4(),
        };
        // Same rank: strictly after the exact UUID.
        assert_eq!(source_after(Some(&position), RANK_TRANSFER), Some((42, position.work_id)));
        // Lower rank: exclude the whole equal timestamp.
        assert_eq!(source_after(Some(&position), RANK_OUTBOX), Some((42, MAX_UUID)));
        assert_eq!(source_after(Some(&position), RANK_ACTION), Some((42, MAX_UUID)));
        // Higher rank: include every nonzero equal-time record.
        assert_eq!(source_after(Some(&position), RANK_LIVE), Some((42, Uuid::nil())));
        // No cursor: the beginning of the stream (the only idle proof).
        assert_eq!(source_after(None, RANK_OUTBOX), None);
        assert_eq!(
            state_after(Some(&position), RANK_OUTBOX),
            Some(WorkPageCursor { created_at_ms: 42, work_id: MAX_UUID })
        );
    }

    #[test]
    fn durable_activity_ids_are_distinct_across_sources() {
        let connection = ConnectionId::new();
        let work = Uuid::new_v4();
        let outbox = durable_activity_id(connection, "outbox", work);
        let transfer = durable_activity_id(connection, "transfer", work);
        assert_ne!(outbox, transfer, "an upload journal shares its work id with its operation");
        assert_eq!(outbox, durable_activity_id(connection, "outbox", work), "stable across calls");
    }

    // ---- start-time provenance ------------------------------------

    #[test]
    fn started_at_requires_real_time_and_formats_canonically() {
        assert!(activity_timestamp(0).is_err(), "0 is unavailable evidence, never an epoch placeholder");
        assert_eq!(activity_timestamp(1_000).unwrap(), "1970-01-01T00:00:01Z");
        assert_eq!(activity_timestamp(86_400_000).unwrap(), "1970-01-02T00:00:00Z");
        assert!(is_canonical_timestamp(&activity_timestamp(1_700_000_000_000).unwrap()));
    }

    // ---- error projection -----------------------------------------

    #[test]
    fn work_error_projection_preserves_classified_codes() {
        let connection = ConnectionId::new();
        let classified = WorkErrorRow {
            connection_id: connection,
            kind: WorkErrorKind::Outbox,
            work_id: Uuid::new_v4(),
            error_code: "needs_sign_in".to_owned(),
            error_detail: "the access token was rejected".to_owned(),
            updated_at_ms: 5_000,
        };
        let projected = work_error_object(&classified);
        assert_eq!(projected.code, wire::ProtocolErrorCode::NeedsSignIn);
        assert_eq!(projected.message, "the access token was rejected");

        let mechanical = WorkErrorRow {
            error_code: "capture_failed".to_owned(),
            error_detail: "the source could not be opened".to_owned(),
            ..classified
        };
        let projected = work_error_object(&mechanical);
        assert_eq!(projected.code, wire::ProtocolErrorCode::Internal);
        assert_eq!(projected.message, "capture_failed: the source could not be opened");

        let empty = WorkErrorRow { error_detail: String::new(), ..mechanical };
        assert_eq!(work_error_object(&empty).message, "capture_failed");
    }

    // ---- stage tables ---------------------------------------------

    #[test]
    fn outbox_stage_matches_the_lifecycle_contract() {
        use wire::ActivityDirection as Direction;
        use wire::ActivityPhase as Phase;
        let content = ChangeClass::ContentUpload;
        // Observed content without capture -> observed.
        assert_eq!(
            outbox_stage(content, OutboxState::Observed, None, false).unwrap(),
            (Direction::Upload, Phase::Observed)
        );
        // Bound capturing snapshot -> snapshot.
        assert_eq!(
            outbox_stage(content, OutboxState::Observed, Some(SnapshotStatus::Capturing), false)
                .unwrap(),
            (Direction::Upload, Phase::Snapshot)
        );
        // Staged capture / payload round -> uploading.
        assert_eq!(
            outbox_stage(content, OutboxState::Observed, Some(SnapshotStatus::Ready), false).unwrap(),
            (Direction::Upload, Phase::Uploading)
        );
        assert_eq!(
            outbox_stage(content, OutboxState::SnapshotReady, Some(SnapshotStatus::Ready), false)
                .unwrap(),
            (Direction::Upload, Phase::Uploading)
        );
        assert_eq!(
            outbox_stage(content, OutboxState::PayloadReady, None, true).unwrap(),
            (Direction::Upload, Phase::Uploading)
        );
        // Rebased payload binding: publication is what remains.
        assert_eq!(
            outbox_stage(content, OutboxState::Observed, Some(SnapshotStatus::Released), true)
                .unwrap(),
            (Direction::Upload, Phase::Publishing)
        );
        // Candidate persisted / uncertain write -> publishing.
        assert_eq!(
            outbox_stage(content, OutboxState::MetadataReady, None, true).unwrap(),
            (Direction::Upload, Phase::Publishing)
        );
        assert_eq!(
            outbox_stage(content, OutboxState::PublishUnknown, None, true).unwrap(),
            (Direction::Upload, Phase::Publishing)
        );
        // Local application: create/update/hydrate -> downloading with a
        // download direction, rename/delete -> metadata direction.
        assert_eq!(
            outbox_stage(content, OutboxState::Published, None, true).unwrap(),
            (Direction::Download, Phase::Downloading)
        );
        assert_eq!(
            outbox_stage(ChangeClass::Create, OutboxState::LocalApplyPending, None, false).unwrap(),
            (Direction::Download, Phase::Downloading)
        );
        assert_eq!(
            outbox_stage(ChangeClass::Move, OutboxState::LocalApplyPending, None, false).unwrap(),
            (Direction::Metadata, Phase::Downloading)
        );
        assert_eq!(
            outbox_stage(ChangeClass::Delete, OutboxState::Published, None, false).unwrap(),
            (Direction::Metadata, Phase::Downloading)
        );
        // Metadata-only publication keeps its metadata direction.
        assert_eq!(
            outbox_stage(ChangeClass::Move, OutboxState::MetadataReady, None, false).unwrap(),
            (Direction::Metadata, Phase::Publishing)
        );
        assert_eq!(
            outbox_stage(ChangeClass::Move, OutboxState::Observed, None, false).unwrap(),
            (Direction::Metadata, Phase::Observed)
        );
        // A finished record never reaches the unfinished listing.
        assert!(outbox_stage(content, OutboxState::Complete, None, true).is_err());
    }

    #[test]
    fn action_transfer_and_live_stage_tables() {
        use wire::ActivityDirection as Direction;
        use wire::ActivityPhase as Phase;
        assert_eq!(action_stage(LocalActionKind::Hydrate), (Direction::Download, Phase::Downloading));
        assert_eq!(
            action_stage(LocalActionKind::CreatePlaceholder),
            (Direction::Download, Phase::Downloading)
        );
        assert_eq!(action_stage(LocalActionKind::Rename), (Direction::Metadata, Phase::Downloading));
        assert_eq!(
            action_stage(LocalActionKind::DeletePlaceholder),
            (Direction::Metadata, Phase::Downloading)
        );
        assert_eq!(transfer_stage(TransferDirection::Upload), (Direction::Upload, Phase::Uploading));
        assert_eq!(
            transfer_stage(TransferDirection::Download),
            (Direction::Download, Phase::Downloading)
        );
        assert_eq!(live_stage(LiveWorkKind::Fetch), (Direction::Download, Phase::Downloading));
        assert_eq!(
            live_stage(LiveWorkKind::DirectoryPopulation),
            (Direction::Metadata, Phase::Downloading)
        );
    }

    // ---- endpoint regressions -------------------------------------

    fn fixture_account_key() -> hfdrive_core::ids::AccountKey {
        hfdrive_core::ids::AccountKey::from_subject(
            "https://huggingface.co",
            "activity-fixture-subject",
        )
    }

    fn drive_binding(account_key: hfdrive_core::ids::AccountKey) -> DriveBinding {
        DriveBinding {
            account_key,
            bucket: BucketBinding {
                bucket_id: BucketId::new("bucket-01".to_owned()).unwrap(),
                bucket_name: BucketName::new("activity-fixture".to_owned()).unwrap(),
                owner_id: OwnerId::new("owner-01".to_owned()).unwrap(),
                owner_kind: OwnerKind::Personal,
                owner_namespace: Namespace::new("fixture-person".to_owned()).unwrap(),
            },
            prefix: RemotePrefix::new(format!("hfdrive/{}", WorkspaceId::new())).unwrap(),
            workspace_id: WorkspaceId::new(),
        }
    }

    async fn record_account(
        provider: &Provider,
        account_key: hfdrive_core::ids::AccountKey,
        subject: &str,
    ) {
        provider
            .state
            .record_account(AccountRecord {
                account_key,
                issuer: "https://huggingface.co".to_owned(),
                subject: subject.to_owned(),
                namespace: "fixture-person".to_owned(),
                credential_ref: CredentialRef("oauth.hfdcred".to_owned()),
                auth_epoch: 1,
                status: AccountStatus::Active,
            })
            .await
            .unwrap();
    }

    /// Signs a fixture identity in through the real protected credential
    /// record and registers one real connection through the setup journal.
    async fn signed_in_provider() -> (Provider, ConnectionId, hfdrive_core::ids::AccountKey) {
        let provider = Provider::new(hfdrive_protocol::StatusSnapshot {
            sequence: 0,
            account: Default::default(),
            connections: Vec::new(),
        });
        let account_key = fixture_account_key();
        let store = hfdrive_auth::AccountCredentialStore::open(
            provider.paths.account(account_key).credentials(),
            account_key,
        )
        .unwrap();
        store
            .save(&hfdrive_auth::CredentialEnvelope {
                schema: hfdrive_auth::store::ENVELOPE_SCHEMA,
                issuer: "https://huggingface.co".to_owned(),
                subject: "activity-fixture-subject".to_owned(),
                namespace: "fixture-person".to_owned(),
                avatar_url: None,
                orgs: Vec::new(),
                granted_scopes: Some(vec!["openid".to_owned(), "profile".to_owned()]),
                covered_purpose: hfdrive_auth::LoginPurpose::WriteStorage,
                login_flow: hfdrive_auth::LoginFlow::Pkce,
                generation: 1,
                authorization_epoch: 1,
                lifetime_secs: 3_600,
                expires_at: 4_000_000_000,
                access_token: "HFDRIVE-MARKER-SECRET-do-not-render".to_owned(),
                refresh_token: Some("HFDRIVE-MARKER-REFRESH-do-not-render".to_owned()),
            })
            .unwrap();
        provider.auth.restore_account(account_key).unwrap();
        record_account(&provider, account_key, "activity-fixture-subject").await;
        let connection = register_connection(&provider, account_key).await;
        (provider, connection, account_key)
    }

    async fn register_connection(
        provider: &Provider,
        account_key: hfdrive_core::ids::AccountKey,
    ) -> ConnectionId {
        // Setup journal methods live on the control-level store; work rows
        // and items live on the account-level store.
        let setup = provider
            .state
            .reserve_setup(hfdrive_state::SetupDraft {
                operation_id: OperationId::new(),
                account_key,
                binding: drive_binding(account_key),
                initialize: false,
            })
            .await
            .unwrap();
        provider
            .state
            .attach_setup_preview(
                setup.setup_id,
                serde_json::json!({"fixture": true}),
                std::env::temp_dir().join(format!("hfdrive-activity-fixture-{}", setup.connection_id)),
                ConnectionMode::ReadOnly,
            )
            .await
            .unwrap();
        provider.state.finalize_setup(setup.setup_id).await.unwrap();
        setup.connection_id
    }

    fn intent_create(item_id: ItemId, parent_id: ItemId, name: &str) -> SyncIntent {
        SyncIntent::Create {
            item_id: *item_id.as_uuid(),
            parent_id: *parent_id.as_uuid(),
            name: name.to_owned(),
            kind: crate::sync::outbox::IntentKind::File,
            content: Some(crate::sync::outbox::PendingContent {
                upload_id: Uuid::new_v4(),
                version_id: Uuid::new_v4(),
                modified_at: "2026-01-01T00:00:00Z".to_owned(),
            }),
        }
    }

    fn registry_item(
        connection: ConnectionId,
        item_id: ItemId,
        parent_id: Option<ItemId>,
        name: &str,
    ) -> ItemRecord {
        ItemRecord {
            connection_id: connection,
            item_id,
            parent_id,
            name: name.to_owned(),
            name_key: name.to_owned(),
            kind: hfdrive_state::ItemKind::Directory,
            revision: OperationId::new(),
            content_version_id: None,
            deleted: false,
            metadata_json: serde_json::json!({}),
        }
    }

    fn request(
        connection: ConnectionId,
        cursor: Option<String>,
        limit: u32,
    ) -> wire::ListActivityRequest {
        wire::ListActivityRequest {
            connection_id: *connection.as_uuid(),
            cursor,
            limit,
        }
    }

    #[tokio::test]
    async fn endpoint_lists_real_work_from_every_durable_source_and_proves_idle_first_page() {
        let (provider, connection, account_key) = signed_in_provider().await;
        let account = provider.state.open_account(account_key).await.unwrap();
        let root = ItemId::new();
        let docs = ItemId::new();
        account.upsert_item(registry_item(connection, root, None, "")).await.unwrap();
        account
            .upsert_item(registry_item(connection, docs, Some(root), "docs"))
            .await
            .unwrap();

        // One real outbox intent with a real relative name path.
        let operation = OperationId::new();
        let entry = crate::sync::outbox::intent_entry(
            connection,
            operation,
            Some(docs),
            None,
            None,
            1,
            &intent_create(ItemId::new(), docs, "hello.txt"),
        )
        .unwrap();
        account.record_outbox(entry).await.unwrap();

        // One real journaled local action.
        account
            .record_local_action(LocalAction {
                connection_id: connection,
                action_id: ActionId::new(),
                item_id: Some(docs),
                kind: LocalActionKind::Rename,
                expected_file_id: None,
                expected_generation: None,
                expected_usn: None,
                old_version: None,
                new_version: None,
                source_path: Some(Path::new("docs/old.txt").to_owned()),
                target_path: Some(Path::new("docs/new.txt").to_owned()),
                recovery_path: None,
                state: LocalActionState::Pending,
            })
            .await
            .unwrap();

        // One real transfer journal row, named through its bound version.
        let version = VersionId::new();
        let data = ItemId::new();
        let mut data_item = registry_item(connection, data, Some(docs), "data.bin");
        data_item.kind = hfdrive_state::ItemKind::File;
        data_item.content_version_id = Some(version);
        account.upsert_item(data_item).await.unwrap();
        account
            .record_transfer(TransferRecord {
                connection_id: connection,
                transfer_id: TransferId::new(),
                operation_id: None,
                direction: TransferDirection::Download,
                version_id: Some(version),
                range_start: Some(4_096),
                range_end: Some(8_192),
                state: TransferState::InProgress,
                sdk_resume_json: None,
                logical_bytes: 0,
                wire_bytes: 0,
            })
            .await
            .unwrap();

        let page = provider.list_activity(request(connection, None, 200)).await.unwrap();
        assert!(page.next_cursor.is_none());
        assert_eq!(page.items.len(), 3, "no source may be silently skipped");
        let names = page
            .items
            .iter()
            .map(|record| record.item_name.as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"docs/hello.txt"), "real relative path, got {names:?}");
        assert!(names.contains(&"docs/new.txt"), "real action path, got {names:?}");
        assert!(names.contains(&"docs/data.bin"), "real version-bound name, got {names:?}");
        // The range transfer reports its exact span, not an invented total.
        let transfer = page
            .items
            .iter()
            .find(|record| record.item_name == "docs/data.bin")
            .unwrap();
        assert_eq!(transfer.bytes_total, Some(4_096));
        assert_eq!(transfer.bytes_completed, 0);
        // No internal object keys and no credential material may leak.
        let rendered = serde_json::to_string(&page.items).unwrap();
        assert!(!rendered.contains("objects/"));
        assert!(!rendered.contains("HFDRIVE-MARKER"));
        for record in &page.items {
            assert!(is_canonical_timestamp(&record.started_at), "{}", record.started_at);
            assert_ne!(
                record.started_at, "1970-01-01T00:00:00Z",
                "never an epoch placeholder"
            );
        }

        // A terminal empty first page (no cursor) is the proof of idle.
        let idle_connection = register_connection(&provider, account_key).await;
        let idle = provider.list_activity(request(idle_connection, None, 200)).await.unwrap();
        assert!(idle.items.is_empty());
        assert!(idle.next_cursor.is_none());
    }

    #[tokio::test]
    async fn endpoint_rejects_foreign_malformed_and_cross_account_requests() {
        let (provider, connection, account_key) = signed_in_provider().await;
        let foreign = register_connection(&provider, account_key).await;
        let cursor = format!(
            "{CURSOR_PREFIX}:{connection}:1:{}:{}",
            RANK_OUTBOX,
            Uuid::new_v4()
        );
        let error = provider
            .list_activity(request(foreign, Some(cursor.clone()), 200))
            .await
            .unwrap_err();
        assert_eq!(error.code, wire::ProtocolErrorCode::InvalidRequest);
        assert!(error.message.contains("different connection"), "{}", error.message);
        let error = provider
            .list_activity(request(connection, Some("activity-v1:broken".to_owned()), 200))
            .await
            .unwrap_err();
        assert_eq!(error.code, wire::ProtocolErrorCode::InvalidRequest);
        // Page bounds are enforced exactly.
        for limit in [0, 201] {
            let error = provider
                .list_activity(request(connection, None, limit))
                .await
                .unwrap_err();
            assert_eq!(error.code, wire::ProtocolErrorCode::InvalidRequest);
        }
        // A connection owned by another account is not visible here.
        let other_account =
            hfdrive_core::ids::AccountKey::from_subject("https://huggingface.co", "activity-other-subject");
        record_account(&provider, other_account, "activity-other-subject").await;
        let other = register_connection(&provider, other_account).await;
        let error = provider.list_activity(request(other, None, 200)).await.unwrap_err();
        assert_eq!(error.code, wire::ProtocolErrorCode::NotFound);
    }

    #[tokio::test]
    async fn endpoint_pages_without_omission_or_duplication() {
        let (provider, connection, account_key) = signed_in_provider().await;
        let account = provider.state.open_account(account_key).await.unwrap();
        let root = ItemId::new();
        account.upsert_item(registry_item(connection, root, None, "")).await.unwrap();
        let mut expected_names = Vec::new();
        for index in 0..5 {
            let name = format!("file-{index}.txt");
            let entry = crate::sync::outbox::intent_entry(
                connection,
                OperationId::new(),
                Some(root),
                None,
                None,
                1,
                &intent_create(ItemId::new(), root, &name),
            )
            .unwrap();
            account.record_outbox(entry).await.unwrap();
            expected_names.push(name);
        }

        // Walk every page with a small limit: every record exactly once.
        let mut seen = Vec::new();
        let mut cursor = None;
        let mut pages = 0;
        loop {
            let page = provider
                .list_activity(request(connection, cursor.clone(), 2))
                .await
                .unwrap();
            pages += 1;
            for record in &page.items {
                seen.push(record.item_name.clone());
            }
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
            assert!(pages <= 8, "paging must terminate");
        }
        seen.sort();
        expected_names.sort();
        assert_eq!(seen, expected_names);
        assert!(pages >= 3, "limit 2 over 5 records needs several pages");

        // started_at is the persisted creation time of the row, not now.
        let rows = account.list_outbox_rows(connection, None, 200).await.unwrap();
        let mut timestamps: Vec<String> = rows
            .iter()
            .map(|row| activity_timestamp(row.created_at_ms).unwrap())
            .collect();
        timestamps.sort();
        let page = provider.list_activity(request(connection, None, 200)).await.unwrap();
        let mut projected: Vec<String> =
            page.items.iter().map(|record| record.started_at.clone()).collect();
        projected.sort();
        assert_eq!(projected, timestamps);
    }

    #[tokio::test]
    async fn endpoint_fails_closed_on_missing_name_evidence() {
        let (provider, connection, account_key) = signed_in_provider().await;
        let account = provider.state.open_account(account_key).await.unwrap();
        // A content intent whose item exists in neither the intent name, the
        // registry nor a base record: name evidence is missing.
        let missing_item = ItemId::new();
        let entry = crate::sync::outbox::intent_entry(
            connection,
            OperationId::new(),
            Some(missing_item),
            None,
            None,
            1,
            &SyncIntent::Content {
                item_id: *missing_item.as_uuid(),
                content: crate::sync::outbox::PendingContent {
                    upload_id: Uuid::new_v4(),
                    version_id: Uuid::new_v4(),
                    modified_at: "2026-01-01T00:00:00Z".to_owned(),
                },
            },
        )
        .unwrap();
        account.record_outbox(entry).await.unwrap();
        let error = provider
            .list_activity(request(connection, None, 200))
            .await
            .unwrap_err();
        assert_eq!(error.code, wire::ProtocolErrorCode::UnsupportedFormat);
        assert!(error.message.contains("name"), "{}", error.message);

        // The same change with its persisted base item record names itself.
        // (A fresh connection: the missing-evidence row above must keep
        // failing its own page closed rather than being silently skipped.)
        let connection = register_connection(&provider, account_key).await;
        let named_item = ItemId::new();
        // A valid base item record: only the empty root directory may be
        // parentless, so a named item carries its real parent id.
        let base = hfdrive_core::format::to_item_record_bytes(&hfdrive_core::format::ItemRecord {
            item_id: named_item,
            parent_id: Some(ItemId::new()),
            name: "based.txt".to_owned(),
            kind: hfdrive_core::format::ItemKind::File,
            item_revision: OperationId::new(),
            content_version_id: Some(VersionId::new()),
            deleted: false,
            content_operation: OperationId::new(),
            location_operation: OperationId::new(),
            deletion_operation: None,
        })
        .unwrap();
        let entry = crate::sync::outbox::intent_entry(
            connection,
            OperationId::new(),
            Some(named_item),
            None,
            Some(String::from_utf8(base).unwrap()),
            1,
            &SyncIntent::Delete { item_id: *named_item.as_uuid() },
        )
        .unwrap();
        account.record_outbox(entry).await.unwrap();
        let page = provider.list_activity(request(connection, None, 200)).await.unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].item_name, "based.txt");
    }

    #[tokio::test]
    async fn endpoint_projects_persisted_work_error_as_failed() {
        let (provider, connection, account_key) = signed_in_provider().await;
        let account = provider.state.open_account(account_key).await.unwrap();
        let root = ItemId::new();
        account.upsert_item(registry_item(connection, root, None, "")).await.unwrap();
        let operation = OperationId::new();
        let entry = crate::sync::outbox::intent_entry(
            connection,
            operation,
            Some(root),
            None,
            None,
            1,
            &intent_create(ItemId::new(), root, "stuck.txt"),
        )
        .unwrap();
        account.record_outbox(entry).await.unwrap();
        account
            .record_work_error(
                connection,
                WorkErrorKind::Outbox,
                *operation.as_uuid(),
                "permission_denied".to_owned(),
                "the bucket rejected the write".to_owned(),
            )
            .await
            .unwrap();

        let page = provider.list_activity(request(connection, None, 200)).await.unwrap();
        assert_eq!(page.items.len(), 1);
        let record = &page.items[0];
        assert_eq!(record.phase, wire::ActivityPhase::Failed);
        assert_eq!(record.direction, wire::ActivityDirection::Upload);
        let last_error = record.last_error.as_ref().expect("failed work carries its error");
        assert_eq!(last_error.code, wire::ProtocolErrorCode::PermissionDenied);
        assert_eq!(last_error.message, "the bucket rejected the write");

        // A row parked on a user/auth action without failure evidence is an
        // explicit error, never a silent omission and never a guessed reason.
        account
            .clear_work_error(connection, WorkErrorKind::Outbox, *operation.as_uuid())
            .await
            .unwrap();
        let mut entry = account
            .outbox_entry(connection, operation)
            .await
            .unwrap()
            .expect("outbox row");
        entry.retry_class = RetryClass::NeedsAuth;
        entry.next_attempt_at_ms = Some(1);
        let evidence_row = OutboxWorkRow { entry: entry.clone(), created_at_ms: 1 };
        let mut evidence = Evidence::new(&account, connection);
        assert!(project_outbox(&mut evidence, &evidence_row).await.is_err());
    }

    #[tokio::test]
    async fn endpoint_stops_pages_at_the_frame_bound_and_covers_every_record() {
        let (provider, connection, account_key) = signed_in_provider().await;
        let account = provider.state.open_account(account_key).await.unwrap();
        let root = ItemId::new();
        account.upsert_item(registry_item(connection, root, None, "")).await.unwrap();
        let mut names = Vec::new();
        for index in 0..3 {
            // Each name alone fits a frame; two of them do not.
            let name = format!("big-{index}-{}", "x".repeat(600_000));
            let entry = crate::sync::outbox::intent_entry(
                connection,
                OperationId::new(),
                Some(root),
                None,
                None,
                1,
                &intent_create(ItemId::new(), root, &name),
            )
            .unwrap();
            account.record_outbox(entry).await.unwrap();
            names.push(name);
        }
        // The page stops at the frame bound, not the request limit, and the
        // walk still covers every record exactly once.
        let mut seen = Vec::new();
        let mut cursor = None;
        loop {
            let page = provider
                .list_activity(request(connection, cursor.clone(), 200))
                .await
                .unwrap();
            assert_eq!(page.items.len(), 1, "one oversized record per bounded frame");
            seen.push(page.items[0].item_name.clone());
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        seen.sort();
        names.sort();
        assert_eq!(seen, names);
    }

    #[tokio::test]
    async fn endpoint_rejects_a_record_that_cannot_fit_a_frame() {
        let (provider, connection, account_key) = signed_in_provider().await;
        let account = provider.state.open_account(account_key).await.unwrap();
        let root = ItemId::new();
        account.upsert_item(registry_item(connection, root, None, "")).await.unwrap();
        // A record that cannot fit even alone must be an explicit error, not
        // an endless empty-page cursor loop.
        let huge = format!("huge-{}", "y".repeat(2_000_000));
        let entry = crate::sync::outbox::intent_entry(
            connection,
            OperationId::new(),
            Some(root),
            None,
            None,
            1,
            &intent_create(ItemId::new(), root, &huge),
        )
        .unwrap();
        account.record_outbox(entry).await.unwrap();
        let error = provider
            .list_activity(request(connection, None, 200))
            .await
            .unwrap_err();
        assert_eq!(error.code, wire::ProtocolErrorCode::FrameTooLarge);
    }

    #[tokio::test]
    async fn endpoint_live_spans_project_real_dispatch_progress() {
        let (provider, connection, account_key) = signed_in_provider().await;
        let account = provider.state.open_account(account_key).await.unwrap();
        let root = ItemId::new();
        account.upsert_item(registry_item(connection, root, None, "")).await.unwrap();
        let engine = Arc::new(crate::sync::SyncEngine::new(
            crate::sync::EngineConfig {
                state_dir: provider.paths.base().to_path_buf(),
                user_sid: "test-user".to_owned(),
                device_id: DeviceId::new(),
                version: "test".to_owned(),
            },
            provider.state.clone(),
            Arc::new(provider.scheduler.clone()),
            provider.shutdown.child_token(),
        ));
        let mut provider = provider;
        provider.engine = Some(engine.clone());
        let completed = Arc::new(AtomicU64::new(128));
        let handle = engine.activity_registry().begin(crate::sync::activity::LiveWork {
            connection_id: connection,
            activity_id: Uuid::new_v4(),
            kind: LiveWorkKind::Fetch,
            item_id: Some(root),
            path_hint: None,
            started_unix_ms: 1_000,
            total_bytes: Some(4_096),
            completed_bytes: completed.clone(),
        });

        let page = provider.list_activity(request(connection, None, 200)).await.unwrap();
        assert_eq!(page.items.len(), 1);
        let record = &page.items[0];
        assert_eq!(record.direction, wire::ActivityDirection::Download);
        assert_eq!(record.phase, wire::ActivityPhase::Downloading);
        assert_eq!(record.bytes_completed, 128, "only real delivered bytes are counted");
        assert_eq!(record.bytes_total, Some(4_096));
        assert_eq!(record.started_at, "1970-01-01T00:00:01Z", "real dispatch time, not now");
        assert_eq!(record.item_name, "", "the placeholder item resolves through the registry");
        drop(handle);
        let page = provider.list_activity(request(connection, None, 200)).await.unwrap();
        assert!(page.items.is_empty(), "finished spans are not in-flight activity");
    }
}
