//! Pure three-way reconciliation for one managed drive.
//!
//! [`reconcile`] merges the common base catalog, this device's pending local
//! intents, and the committed remote catalog into one deterministic plan:
//! ordered CAS-ready item mutations, version records to publish, guarded local
//! actions, conflict/recovery records and per-intent outcomes. The module is
//! pure: no I/O, no wall clock, no network, no Windows calls, and no random
//! identifier generation. Every ordinary identifier (operations, versions,
//! actions) is supplied through the inputs or the caller's [`IdSource`]; the
//! only generated identities are deterministic UUIDv5 conflict identities
//! (see [`conflict_identity`]).
//!
//! Component provenance is explicit: content, location (parent and name) and
//! deletion are compared and merged independently, and every emitted record
//! carries the operation responsible for each component. Dirty local content
//! always survives a racing remote rename or delete: it is published,
//! preserved as a deterministic conflict copy, kept locally (read-only
//! connections), or preserved to recovery before local replacement. Remote
//! materialization is never captured as a local write: intents with
//! [`LocalOrigin::RemoteMaterialization`] can never produce remote mutations.
//!
//! The canonical conflict tuple and name policy is specified in
//! `spec/reconciliation.md` and frozen by the integration tests.

use crate::format::{self, ChangeKind, DisplayMetadata, ItemChange, ItemKind, ItemRecord};
use crate::ids::{ActionId, ConflictId, ItemId, OperationId, VersionId, WorkspaceId};
use crate::names;
use crate::storage::{ObjectRef, Sha256Digest};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A piece of context the caller failed to supply. Reconciliation never
/// guesses missing ancestors or descendants; it reports exactly what is
/// required.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissingRef {
    /// `item_id` requires `missing` as an ancestor, which is in no view.
    Ancestor { item_id: ItemId, missing: ItemId },
    /// An item or intent references `item_id`, which is not in the view that
    /// must contain it.
    Item { item_id: ItemId },
    /// `item_id` needs parent `missing`, which is not in the local view.
    Parent { item_id: ItemId, missing: ItemId },
}

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("incomplete reconciliation context: {0:?}")]
    MissingContext(Vec<MissingRef>),
    #[error("local intent is inconsistent with the supplied context: {0}")]
    InconsistentIntent(&'static str),
    #[error("remote materialization state is not traceable to a known content binding")]
    MaterializationEchoMismatch,
    #[error("supplied catalog view is not a valid namespace: {0}")]
    InvalidView(&'static str),
    #[error("merged item record violates the remote format invariants: {0}")]
    InvalidRecord(&'static str),
    #[error("name violates the portable name rules: {0}")]
    InvalidName(#[from] names::NameError),
    #[error("batch bounds must be nonzero and cannot be satisfied by one operation")]
    InvalidBatchBound,
    #[error("reconciliation did not converge")]
    NotConverged,
}

// ---------------------------------------------------------------------------
// Item state
// ---------------------------------------------------------------------------

/// One item's reconcilable state on one side of the merge. Mirrors the remote
/// `ItemRecord` and adds the payload identity (digest and size) the merge
/// needs to compare content without touching storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemState {
    pub item_id: ItemId,
    pub parent_id: Option<ItemId>,
    pub name: String,
    pub kind: ItemKind,
    pub deleted: bool,
    pub item_revision: OperationId,
    pub content_version_id: Option<VersionId>,
    pub content_operation: OperationId,
    pub location_operation: OperationId,
    pub deletion_operation: Option<OperationId>,
    /// SHA-256 of the file payload; `None` for directories.
    pub content_sha256: Option<Sha256Digest>,
    /// Payload length in bytes; `None` for directories.
    pub content_size: Option<u64>,
}

impl ItemState {
    /// Builds a state from a remote item record plus the payload identity of
    /// its bound version. Files must carry a digest and size; directories
    /// must not.
    pub fn from_record(
        record: &ItemRecord,
        content_sha256: Option<Sha256Digest>,
        content_size: Option<u64>,
    ) -> Result<Self, ReconcileError> {
        let state = Self {
            item_id: record.item_id,
            parent_id: record.parent_id,
            name: record.name.clone(),
            kind: record.kind,
            deleted: record.deleted,
            item_revision: record.item_revision,
            content_version_id: record.content_version_id,
            content_operation: record.content_operation,
            location_operation: record.location_operation,
            deletion_operation: record.deletion_operation,
            content_sha256,
            content_size,
        };
        state.validate_shape()?;
        Ok(state)
    }

    fn validate_shape(&self) -> Result<(), ReconcileError> {
        match self.kind {
            ItemKind::Directory => {
                if self.content_version_id.is_some()
                    || self.content_sha256.is_some()
                    || self.content_size.is_some()
                {
                    return Err(ReconcileError::InvalidView("directory carries content"));
                }
            }
            ItemKind::File => {
                if self.content_version_id.is_none()
                    || self.content_sha256.is_some() == false
                    || self.content_size.is_none()
                {
                    return Err(ReconcileError::InvalidView("file without content binding"));
                }
            }
        }
        if self.deleted != self.deletion_operation.is_some() {
            return Err(ReconcileError::InvalidView(
                "deleted flag and deletion operation disagree",
            ));
        }
        if self.parent_id == Some(self.item_id) {
            return Err(ReconcileError::InvalidView("item is its own parent"));
        }
        Ok(())
    }

    /// The remote item record for this state.
    pub fn to_record(&self) -> ItemRecord {
        ItemRecord {
            item_id: self.item_id,
            parent_id: self.parent_id,
            name: self.name.clone(),
            kind: self.kind,
            item_revision: self.item_revision,
            content_version_id: self.content_version_id,
            deleted: self.deleted,
            content_operation: self.content_operation,
            location_operation: self.location_operation,
            deletion_operation: self.deletion_operation,
        }
    }

    /// Content identity comparison: equal payloads converge even when they
    /// carry different version identifiers.
    pub fn content_equal(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.content_sha256 == other.content_sha256
            && self.content_size == other.content_size
    }

    /// Location comparison: parent and exact name spelling.
    pub fn location_equal(&self, other: &Self) -> bool {
        self.parent_id == other.parent_id && self.name == other.name
    }

    /// True when every meaningful component (content, location, deletion)
    /// matches. Provenance fields are ignored.
    pub fn meaningful_equal(&self, other: &Self) -> bool {
        self.content_equal(other) && self.location_equal(other) && self.deleted == other.deleted
    }
}

// ---------------------------------------------------------------------------
// Local intents
// ---------------------------------------------------------------------------

/// Where a local observation came from. Only [`LocalEdit`] can publish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalOrigin {
    /// A user or application edit observed on this device.
    LocalEdit,
    /// Application-produced materialization of remote or planned work
    /// (placeholder create/update/rename/delete apply). Never publishes
    /// anything and never becomes a local write.
    RemoteMaterialization,
}

/// A captured local payload ready to bind to a version record. The payload
/// must already be uploaded (or staged for upload) before the plan is
/// consumed; the merge only records its identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewContent {
    /// Caller-supplied identifier of the version record to publish.
    pub version_id: VersionId,
    /// Uploaded payload binding.
    pub object: ObjectRef,
    /// Display metadata for the version record.
    pub display: DisplayMetadata,
}

/// One observed local change. Intents are applied in order to build the local
/// side of the merge; one intent mutates exactly one item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalChange {
    /// A new item at `parent_id`/`name`. Files require `content`.
    Create {
        parent_id: ItemId,
        name: String,
        kind: ItemKind,
        content: Option<NewContent>,
    },
    /// New content at the current location.
    Content { content: NewContent },
    /// New location or name; content unchanged.
    Move { parent_id: ItemId, name: String },
    /// New content and location.
    MoveAndContent {
        parent_id: ItemId,
        name: String,
        content: NewContent,
    },
    /// The item (and, for a directory, every item in its locally known
    /// subtree) was removed on this device.
    Delete,
    /// The local filesystem now matches `state`; bookkeeping only.
    Materialized { state: ItemState },
}

/// One pending local intent with its durable operation identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalIntent {
    /// Caller-supplied durable operation identifier for this intent.
    pub operation_id: OperationId,
    pub item_id: ItemId,
    pub origin: LocalOrigin,
    /// Local generation at capture time. Reconciliation records it but never
    /// compares it; the provider guards clean-marking with it.
    pub observed_generation: u64,
    pub change: LocalChange,
}

// ---------------------------------------------------------------------------
// Catalog views
// ---------------------------------------------------------------------------

/// A complete, verified namespace view of one catalog state. The constructor
/// refuses incomplete or inconsistent input: reconciliation never guesses
/// missing ancestors or descendants.
#[derive(Clone, Debug, Default)]
pub struct CatalogView {
    items: BTreeMap<ItemId, ItemState>,
}

impl CatalogView {
    /// Builds a view, validating root shape, parent closure, portable names
    /// and sibling-name uniqueness.
    pub fn new(items: Vec<ItemState>) -> Result<Self, ReconcileError> {
        let mut map: BTreeMap<ItemId, ItemState> = BTreeMap::new();
        for state in items {
            state.validate_shape()?;
            if map.insert(state.item_id, state).is_some() {
                return Err(ReconcileError::InvalidView("duplicate item id"));
            }
        }
        let mut missing: Vec<MissingRef> = Vec::new();
        let mut root: Option<ItemId> = None;
        for id in map.keys().copied().collect::<Vec<_>>() {
            let mut seen: BTreeSet<ItemId> = BTreeSet::new();
            let mut cur = id;
            loop {
                let Some(state) = map.get(&cur) else {
                    missing.push(MissingRef::Ancestor { item_id: id, missing: cur });
                    break;
                };
                if !seen.insert(cur) {
                    return Err(ReconcileError::InvalidView("parent cycle"));
                }
                match state.parent_id {
                    None => {
                        if root.is_none() {
                            root = Some(cur);
                        } else if root != Some(cur) {
                            return Err(ReconcileError::InvalidView("more than one root"));
                        }
                        break;
                    }
                    Some(parent) => cur = parent,
                }
            }
        }
        if !missing.is_empty() {
            missing.sort_by_key(|m| format!("{m:?}"));
            missing.dedup();
            return Err(ReconcileError::MissingContext(missing));
        }
        let root = root.ok_or(ReconcileError::InvalidView("no root"))?;
        let root_state = &map[&root];
        if root_state.kind != ItemKind::Directory
            || root_state.deleted
            || !root_state.name.is_empty()
            || root_state.content_version_id.is_some()
        {
            return Err(ReconcileError::InvalidView("root is not a live empty directory"));
        }
        let mut slots: BTreeSet<(ItemId, Vec<u8>)> = BTreeSet::new();
        for state in map.values() {
            if state.deleted {
                continue;
            }
            if let Some(parent) = state.parent_id {
                names::validate_name(&state.name)?;
                let parent_state = map
                    .get(&parent)
                    .ok_or(ReconcileError::InvalidView("live item under an absent parent"))?;
                if parent_state.deleted || parent_state.kind != ItemKind::Directory {
                    return Err(ReconcileError::InvalidView(
                        "live item under a parent that is not a live directory",
                    ));
                }
                if !slots.insert((parent, names::collision_key(&state.name))) {
                    return Err(ReconcileError::InvalidView(
                        "two live siblings share one portable name slot",
                    ));
                }
            }
        }
        Ok(Self { items: map })
    }

    pub fn get(&self, item_id: ItemId) -> Option<&ItemState> {
        self.items.get(&item_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ItemState> {
        self.items.values()
    }

    pub fn contains(&self, item_id: ItemId) -> bool {
        self.items.contains_key(&item_id)
    }

    /// The single live root item.
    pub fn root_id(&self) -> Option<ItemId> {
        self.items
            .values()
            .find(|s| s.parent_id.is_none())
            .map(|s| s.item_id)
    }

    /// The live children of `parent_id`.
    pub fn children(&self, parent_id: ItemId) -> Vec<ItemId> {
        self.items
            .values()
            .filter(|s| !s.deleted && s.parent_id == Some(parent_id))
            .map(|s| s.item_id)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// NTFS collision comparison
// ---------------------------------------------------------------------------

/// Case-insensitive name comparison used only to plan deterministic local
/// aliases for names that are portable-distinct but collide on NTFS. The
/// Windows layer passes a `CompareStringOrdinal(..., TRUE)`-backed
/// implementation; [`OrdinalIgnoreCase`] is the pure plan-time approximation.
pub trait NtfsNameCompare {
    fn equal(&self, a: &str, b: &str) -> bool;
}

/// Pure approximation of NTFS ordinal case-insensitive comparison: equality
/// after simple (one-to-one) uppercase folding. The provider replaces it with
/// the exact Windows comparator before applying names locally and resolves
/// any additional collisions it finds with the same deterministic alias
/// policy.
pub struct OrdinalIgnoreCase;

impl NtfsNameCompare for OrdinalIgnoreCase {
    fn equal(&self, a: &str, b: &str) -> bool {
        a.chars()
            .flat_map(char::to_uppercase)
            .eq(b.chars().flat_map(char::to_uppercase))
    }
}

// ---------------------------------------------------------------------------
// Caller-owned identifiers
// ---------------------------------------------------------------------------

/// Source of caller-owned non-conflict identifiers. Reconciliation generates
/// only deterministic conflict identities; every ordinary identifier is
/// minted here so the provider can persist it before any effect.
pub trait IdSource {
    fn action_id(&mut self) -> ActionId;
}

/// Deterministic [`IdSource`] for tests and replay: identifiers are UUIDv5
/// values under a fixed namespace.
pub struct DeterministicIds {
    namespace: Uuid,
    next: u32,
}

impl DeterministicIds {
    pub fn new(namespace: Uuid) -> Self {
        Self { namespace, next: 0 }
    }
}

impl IdSource for DeterministicIds {
    fn action_id(&mut self) -> ActionId {
        let name = self.next.to_le_bytes();
        self.next += 1;
        ActionId::from_uuid(Uuid::new_v5(&self.namespace, &name))
            .expect("a UUIDv5 result is never nil")
    }
}

// ---------------------------------------------------------------------------
// Deterministic conflict identity
// ---------------------------------------------------------------------------

/// The conflict families reconciliation can produce. The tag is part of the
/// frozen UUIDv5 tuple and must never change without a format migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ConflictKind {
    /// Both sides changed one item's content to different payloads.
    ContentDivergence,
    /// Both sides changed one item's content and location and the same side
    /// lost both components; one copy preserves its complete claim.
    ContentAndLocation,
    /// Both sides moved or renamed one item to incompatible locations.
    RenameRace,
    /// Two distinct items contested one portable name slot.
    NameCollision,
    /// One side deleted the item while the other changed it; the change
    /// survived and the deletion was dropped.
    DeleteVsChange,
    /// A directory deletion raced with created, edited or moved descendants;
    /// the survivors were re-homed under a deterministic recovered directory.
    DirectoryDeleteRecovery,
    /// A directory move would have produced a parent cycle and was redirected
    /// to a root-level recovered directory.
    CycleMove,
    /// Two names are portable-distinct but collide under NTFS comparison; one
    /// gets a deterministic local alias.
    NtfsAlias,
}

impl ConflictKind {
    /// Frozen ASCII tag inside the UUIDv5 tuple.
    pub fn tag(self) -> &'static str {
        match self {
            Self::ContentDivergence => "content_divergence",
            Self::ContentAndLocation => "content_and_location",
            Self::RenameRace => "rename_race",
            Self::NameCollision => "name_collision",
            Self::DeleteVsChange => "delete_vs_change",
            Self::DirectoryDeleteRecovery => "directory_delete_recovery",
            Self::CycleMove => "cycle_move",
            Self::NtfsAlias => "ntfs_alias",
        }
    }
}

/// Deterministic identities derived from one conflict tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConflictIdentity {
    /// Identifier of the conflict record itself.
    pub conflict_id: ConflictId,
    /// Identifier of the keep-both copy preserving the losing claim.
    pub copy_item_id: ItemId,
    /// Identifier of the recovered directory re-homing survivors.
    pub recovered_dir_id: ItemId,
}

/// Derives the deterministic identities of one conflict.
///
/// The exact tuple (frozen in `spec/reconciliation.md`): the UUIDv5 namespace
/// is the workspace UUID; the name bytes are
/// `items || operations || kind_tag || 0x00 || purpose`, where `items` is the
/// concatenation of the involved item UUIDs (16 bytes each) in ascending
/// order with duplicates removed, `operations` is likewise the ascending
/// de-duplicated operation UUIDs, `kind_tag` is [`ConflictKind::tag`], and
/// `purpose` is `conflict`, `conflict-item` or `recovered-dir`. No wall-clock
/// value, randomness, or input ordering leaks into the tuple, so retries
/// recompute identical identities.
pub fn conflict_identity(
    workspace_id: WorkspaceId,
    kind: ConflictKind,
    items: &[ItemId],
    operations: &[OperationId],
) -> ConflictIdentity {
    let item_set: BTreeSet<ItemId> = items.iter().copied().collect();
    let op_set: BTreeSet<OperationId> = operations.iter().copied().collect();
    let mut tuple: Vec<u8> = Vec::new();
    for item in &item_set {
        tuple.extend_from_slice(item.as_bytes());
    }
    for op in &op_set {
        tuple.extend_from_slice(op.as_bytes());
    }
    tuple.extend_from_slice(kind.tag().as_bytes());
    let namespace = *workspace_id.as_uuid();
    let derive = |purpose: &str| -> Uuid {
        let mut name = tuple.clone();
        name.push(0);
        name.extend_from_slice(purpose.as_bytes());
        Uuid::new_v5(&namespace, &name)
    };
    ConflictIdentity {
        conflict_id: ConflictId::from_uuid(derive("conflict")).expect("a UUIDv5 result is never nil"),
        copy_item_id: ItemId::from_uuid(derive("conflict-item"))
            .expect("a UUIDv5 result is never nil"),
        recovered_dir_id: ItemId::from_uuid(derive("recovered-dir"))
            .expect("a UUIDv5 result is never nil"),
    }
}

/// Splits a name into stem and extension at the last dot, treating a leading
/// dot as part of the stem (`.gitignore` has no extension).
fn split_stem_ext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(dot) if dot > 0 => name.split_at(dot),
        _ => (name, ""),
    }
}

fn utf16_len(value: &str) -> usize {
    value.encode_utf16().count()
}

/// Builds one conflict-name candidate: `<stem> (conflict <hex>)<ext>`,
/// truncated so the whole component fits the 255 UTF-16 unit limit while the
/// `(conflict <hex>)` marker is preserved.
fn conflict_name_with_hex(base_name: &str, hex: &str) -> String {
    let (stem, ext) = split_stem_ext(base_name);
    let tail = format!(" (conflict {hex}){ext}");
    let limit = names::MAX_NAME_UTF16_UNITS.saturating_sub(utf16_len(&tail));
    let mut kept = String::new();
    let mut used = 0usize;
    for ch in stem.chars() {
        let units = utf16_len(&ch.to_string());
        if used + units > limit {
            break;
        }
        kept.push(ch);
        used += units;
    }
    if kept.is_empty() {
        // The stem would vanish or the marker cannot fit before the
        // extension: trim the extension from its start and keep the marker.
        let budget =
            names::MAX_NAME_UTF16_UNITS.saturating_sub(utf16_len(&format!(" (conflict {hex})")));
        let mut ext_kept = String::new();
        let mut used = 0usize;
        for ch in ext.chars() {
            let units = utf16_len(&ch.to_string());
            if used + units > budget {
                break;
            }
            ext_kept.push(ch);
            used += units;
        }
        return format!(" (conflict {hex}){ext_kept}");
    }
    format!("{kept}{tail}")
}

/// The canonical deterministic conflict name for `base_name`, derived from
/// the first 12 lowercase hex characters of `conflict_id`. Use
/// [`ConflictNames`] when the target slot may be occupied.
pub fn conflict_name(base_name: &str, conflict_id: ConflictId) -> String {
    let hex = hex::encode(conflict_id.as_bytes());
    conflict_name_with_hex(base_name, &hex[..12])
}

/// Deterministic candidate names for one conflict identity: the canonical
/// 12-hex spelling first, then progressively longer hex prefixes of the same
/// conflict id (12..=32), then the full hex with numeric suffixes up to 999.
/// The first candidate whose slot is free is chosen, so collisions never
/// overwrite an occupant and retries converge on the same spelling.
pub struct ConflictNames {
    base_name: String,
    hex: String,
    index: usize,
}

impl ConflictNames {
    pub fn new(base_name: &str, conflict_id: ConflictId) -> Self {
        Self {
            base_name: base_name.to_owned(),
            hex: hex::encode(conflict_id.as_bytes()),
            index: 0,
        }
    }
}

impl Iterator for ConflictNames {
    type Item = String;
    fn next(&mut self) -> Option<String> {
        let candidate = if self.index < 21 {
            let len = 12 + self.index;
            conflict_name_with_hex(&self.base_name, &self.hex[..len])
        } else {
            let n = self.index - 20;
            if n > 999 {
                return None;
            }
            conflict_name_with_hex(&self.base_name, &format!("{}-{n}", self.hex))
        };
        self.index += 1;
        Some(candidate)
    }
}

// ---------------------------------------------------------------------------
// Plan outputs
// ---------------------------------------------------------------------------

/// One CAS-ready item mutation. The provider applies these to the catalog in
/// order inside one or more commits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteOp {
    /// The final item record to write (live record or tombstone).
    pub record: ItemRecord,
    /// The change kind versus the record this op replaces.
    pub change: ChangeKind,
    /// The item revision this op replaces; `None` exactly for creates.
    pub old_revision: Option<OperationId>,
}

impl RemoteOp {
    pub fn item_id(&self) -> ItemId {
        self.record.item_id
    }
    pub fn is_tombstone(&self) -> bool {
        self.record.deleted
    }
}

/// One version record the provider must publish (as immutable metadata)
/// before the commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedVersion {
    pub version_id: VersionId,
    pub object: ObjectRef,
    pub display: DisplayMetadata,
}

/// The kind of a guarded local action. Maps onto the provider's durable
/// local-action registry; [`PreserveDirty`] is the recovery step the provider
/// stores before its destructive replacement action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum LocalActionKind {
    /// Preserve dirty local bytes into the recovery area before a destructive
    /// local replacement or removal.
    PreserveDirty,
    /// Materialize a remote item as a placeholder or file.
    CreatePlaceholder,
    /// Apply a location or name change locally.
    Rename,
    /// Update an existing local file/placeholder to a new content version.
    UpdatePlaceholder,
    /// Remove the local file/placeholder after a remote tombstone.
    DeletePlaceholder,
}

/// One durable, guarded local action. `expected` is the local state the
/// provider must verify (file identity, generation and USN are bound at
/// persist time; a missing expectation is never faked as a match).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalAction {
    pub action_id: ActionId,
    pub item_id: ItemId,
    pub action: LocalActionKind,
    /// The local item state expected before the action; `None` when no local
    /// file is expected.
    pub expected: Option<ItemState>,
    /// The item state to materialize; `None` for removals.
    pub target: Option<ItemState>,
    /// When set, materialize under this local name instead of `target`'s
    /// name and retain the alias in state (NTFS-only collision).
    pub local_alias: Option<String>,
}

/// One side of a conflict as it claimed the item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConflictSide {
    pub operation_id: OperationId,
    pub parent_id: Option<ItemId>,
    pub name: String,
    pub content_version_id: Option<VersionId>,
}

/// How a conflict was resolved. Nothing is ever silently discarded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConflictOutcome {
    /// Both complete versions are preserved: the winner keeps the contested
    /// path and the loser is preserved as the deterministic conflict copy.
    KeepBoth,
    /// The changed side survived a racing deletion; the deletion was dropped
    /// and is recorded here.
    Recovered,
    /// The losing move was redirected to a deterministic recovered directory.
    RecoveredDirectory,
    /// The loser keeps its remote name and receives a deterministic local
    /// alias at materialization time.
    LocalAlias,
}

/// One conflict or recovery record. Retries recompute the same
/// `conflict_id`, the same preserved item identity and the same name from the
/// same tuple.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConflictRecord {
    pub conflict_id: ConflictId,
    pub kind: ConflictKind,
    /// The contested item (or the deleted directory for recoveries).
    pub item_id: ItemId,
    /// Competing operations, strictly ascending by UUID bytes.
    pub competing_operations: Vec<OperationId>,
    /// Each side's claimed location and content binding, ascending by
    /// operation id.
    pub sides: Vec<ConflictSide>,
    pub outcome: ConflictOutcome,
    /// Deterministic item preserving the losing claim, when one exists.
    pub preserved_item_id: Option<ItemId>,
    pub preserved_version_id: Option<VersionId>,
    /// Final name and parent of the preserved item or recovered location.
    pub preserved_name: Option<String>,
    pub preserved_parent_id: Option<ItemId>,
}

/// A deterministic local alias for two names that are portable-distinct but
/// collide under NTFS case-insensitive comparison. The remote namespace is
/// unchanged; the alias exists only in local apply and state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AliasPlan {
    pub collision_id: ConflictId,
    pub parent_id: ItemId,
    /// The item forced under a local alias (the deterministic loser).
    pub item_id: ItemId,
    /// The remote name, preserved remotely.
    pub remote_name: String,
    /// The deterministic local alias used at materialization.
    pub local_alias: String,
}

/// What happened to one local intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentOutcomeKind {
    /// Realized by records in this publication; the intent's operation is in
    /// [`ReconcilePlan::operation_ids`].
    Published,
    /// The desired effect already exists remotely.
    Converged,
    /// Superseded by a later local intent on the same item.
    Superseded,
    /// Carried by a conflict record instead of a direct mutation.
    Conflicted,
    /// Cannot be published on this connection; stays local and recoverable.
    Deferred,
}

/// The outcome of one local intent, keyed by its durable operation id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntentOutcome {
    pub operation_id: OperationId,
    pub item_id: ItemId,
    pub outcome: IntentOutcomeKind,
    /// Present when the outcome is carried by a conflict record.
    pub conflict_id: Option<ConflictId>,
}

/// One commit-sized batch of a plan. Batches are contiguous prefixes of
/// [`ReconcilePlan::remote_ops`], so every batch is sequentially applicable
/// and batch `k + 1` applies only after batch `k` committed. A partially
/// published plan is never a completed operation: the provider keeps the
/// intent open until every batch is committed and every local action applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitBatch {
    pub index: usize,
    pub remote_ops: Vec<RemoteOp>,
    /// This batch's commit changes, strictly ascending by item id.
    pub changes: Vec<ItemChange>,
    /// Distinct operation ids referenced by this batch's records, ascending.
    pub operation_ids: Vec<OperationId>,
}

/// Whether this connection may publish remote mutations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileMode {
    Writable,
    ReadOnly,
}

/// The complete deterministic reconciliation result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconcilePlan {
    pub workspace_id: WorkspaceId,
    pub mode: ReconcileMode,
    /// Ordered, sequentially applicable item mutations. Empty in read-only
    /// mode.
    pub remote_ops: Vec<RemoteOp>,
    /// Version records to publish with the commit, ascending by version id.
    pub versions: Vec<PlannedVersion>,
    /// Commit change summaries, strictly ascending by item id.
    pub changes: Vec<ItemChange>,
    /// Distinct operation ids realized by the emitted records, ascending.
    pub operation_ids: Vec<OperationId>,
    /// Guarded local actions in apply order.
    pub local_actions: Vec<LocalAction>,
    /// Conflict and recovery records.
    pub conflicts: Vec<ConflictRecord>,
    /// NTFS-only name collision aliases for local apply.
    pub aliases: Vec<AliasPlan>,
    /// Outcome of every supplied local intent, in intent order.
    pub intents: Vec<IntentOutcome>,
}

impl ReconcilePlan {
    pub fn is_empty(&self) -> bool {
        self.remote_ops.is_empty() && self.local_actions.is_empty()
    }

    /// Splits the ordered mutations into commit-sized batches without
    /// truncating anything. Each batch holds at most `max_changes` changes
    /// and references at most `max_operations` distinct operation ids (the
    /// v1 commit bounds are 1000 and 1000). Every op lands in exactly one
    /// batch, in the original order, so partial publication is resumable but
    /// never counts as a completed operation.
    pub fn commit_batches(
        &self,
        max_changes: usize,
        max_operations: usize,
    ) -> Result<Vec<CommitBatch>, ReconcileError> {
        if max_changes == 0 || max_operations == 0 {
            return Err(ReconcileError::InvalidBatchBound);
        }
        let mut batches: Vec<CommitBatch> = Vec::new();
        let mut current: Vec<RemoteOp> = Vec::new();
        let mut current_ops: BTreeSet<OperationId> = BTreeSet::new();
        for op in &self.remote_ops {
            let mut next_ops = current_ops.clone();
            record_ops(&op.record, &mut next_ops);
            if !current.is_empty()
                && (current.len() + 1 > max_changes || next_ops.len() > max_operations)
            {
                batches.push(make_batch(batches.len(), &mut current, &mut current_ops));
            }
            current_ops = next_ops;
            if current_ops.len() > max_operations {
                // One operation referencing more ids than the bound cannot be
                // truncated; refuse instead of splitting it.
                return Err(ReconcileError::InvalidBatchBound);
            }
            current.push(op.clone());
        }
        if !current.is_empty() {
            batches.push(make_batch(batches.len(), &mut current, &mut current_ops));
        }
        Ok(batches)
    }
}

fn make_batch(
    index: usize,
    current: &mut Vec<RemoteOp>,
    current_ops: &mut BTreeSet<OperationId>,
) -> CommitBatch {
    let mut changes: Vec<ItemChange> = current
        .iter()
        .map(|op| ItemChange {
            item_id: op.record.item_id,
            change: op.change,
            old_revision: op.old_revision,
            new_revision: op.record.item_revision,
        })
        .collect();
    changes.sort_by_key(|c| c.item_id);
    CommitBatch {
        index,
        remote_ops: std::mem::take(current),
        changes,
        operation_ids: current_ops.iter().copied().collect(),
    }
}

fn record_ops(record: &ItemRecord, out: &mut BTreeSet<OperationId>) {
    out.insert(record.item_revision);
    out.insert(record.content_operation);
    out.insert(record.location_operation);
    if let Some(op) = record.deletion_operation {
        out.insert(op);
    }
}

// ---------------------------------------------------------------------------
// Inputs and entry point
// ---------------------------------------------------------------------------

/// Everything [`reconcile`] needs. Views must be complete namespace
/// snapshots; incomplete input is refused, never guessed.
pub struct ReconcileInput<'a> {
    pub workspace_id: WorkspaceId,
    pub mode: ReconcileMode,
    pub base: &'a CatalogView,
    pub local: &'a [LocalIntent],
    pub remote: &'a CatalogView,
    /// NTFS collision comparator; [`OrdinalIgnoreCase`] is the pure default.
    pub ntfs: &'a dyn NtfsNameCompare,
}

/// Computes the deterministic reconciliation plan. Running it twice on the
/// same inputs produces identical output, including conflict identities and
/// conflict names.
pub fn reconcile(
    input: &ReconcileInput<'_>,
    ids: &mut dyn IdSource,
) -> Result<ReconcilePlan, ReconcileError> {
    let local_map = apply_intents(input.base, input.remote, input.local)?;
    let mut builder = Builder::new(
        input.workspace_id,
        input.mode,
        input.base,
        input.remote,
        input.ntfs,
        input.local,
        ids,
        local_map,
    );
    builder.merge_all()?;
    builder.resolve_parents()?;
    builder.resolve_names()?;
    builder.plan_aliases();
    builder.finish()
}

// ---------------------------------------------------------------------------
// Applying local intents
// ---------------------------------------------------------------------------

fn apply_intents(
    base: &CatalogView,
    remote: &CatalogView,
    intents: &[LocalIntent],
) -> Result<BTreeMap<ItemId, ItemState>, ReconcileError> {
    let mut map: BTreeMap<ItemId, ItemState> = BTreeMap::new();
    for state in base.iter() {
        map.insert(state.item_id, state.clone());
    }
    let root = base.root_id().ok_or(ReconcileError::InvalidView("no root"))?;
    // Digests traceable to a known binding, for echo validation: every
    // committed binding on either side plus every payload captured in this
    // batch, regardless of intent order.
    let mut known_digests: BTreeSet<Sha256Digest> = BTreeSet::new();
    for state in base.iter().chain(remote.iter()) {
        if let Some(digest) = state.content_sha256 {
            known_digests.insert(digest);
        }
    }
    for intent in intents {
        let content = match &intent.change {
            LocalChange::Create { content: Some(c), .. }
            | LocalChange::Content { content: c }
            | LocalChange::MoveAndContent { content: c, .. } => Some(c),
            _ => None,
        };
        if let Some(content) = content {
            known_digests.insert(content.object.sha256);
        }
    }
    for intent in intents {
        if intent.item_id == root {
            return Err(ReconcileError::InconsistentIntent("the root item cannot change"));
        }
        match &intent.change {
            LocalChange::Materialized { state } => {
                if intent.origin != LocalOrigin::RemoteMaterialization {
                    return Err(ReconcileError::InconsistentIntent(
                        "materialized state requires the remote-materialization origin",
                    ));
                }
                if state.item_id != intent.item_id {
                    return Err(ReconcileError::InconsistentIntent(
                        "materialized state has a different item id",
                    ));
                }
                state.validate_shape()?;
                if let Some(digest) = state.content_sha256 {
                    if !known_digests.contains(&digest) {
                        return Err(ReconcileError::MaterializationEchoMismatch);
                    }
                }
                map.insert(state.item_id, state.clone());
            }
            LocalChange::Create { parent_id, name, kind, content } => {
                if intent.origin != LocalOrigin::LocalEdit {
                    return Err(ReconcileError::InconsistentIntent(
                        "creation must come from a local edit",
                    ));
                }
                if map.contains_key(&intent.item_id) {
                    return Err(ReconcileError::InconsistentIntent("duplicate create"));
                }
                names::validate_name(name)?;
                let parent = map.get(parent_id).ok_or(ReconcileError::MissingContext(vec![
                    MissingRef::Parent { item_id: intent.item_id, missing: *parent_id },
                ]))?;
                if parent.deleted || parent.kind != ItemKind::Directory {
                    return Err(ReconcileError::InconsistentIntent(
                        "creation parent is not a live directory",
                    ));
                }
                let (content_version_id, content_sha256, content_size) = match (kind, content) {
                    (ItemKind::File, Some(content)) => {
                        known_digests.insert(content.object.sha256);
                        (
                            Some(content.version_id),
                            Some(content.object.sha256),
                            Some(content.object.size),
                        )
                    }
                    (ItemKind::Directory, None) => (None, None, None),
                    _ => {
                        return Err(ReconcileError::InconsistentIntent(
                            "file creation needs content and directory creation forbids it",
                        ))
                    }
                };
                map.insert(
                    intent.item_id,
                    ItemState {
                        item_id: intent.item_id,
                        parent_id: Some(*parent_id),
                        name: name.clone(),
                        kind: *kind,
                        deleted: false,
                        item_revision: intent.operation_id,
                        content_version_id,
                        content_operation: intent.operation_id,
                        location_operation: intent.operation_id,
                        deletion_operation: None,
                        content_sha256,
                        content_size,
                    },
                );
            }
            LocalChange::Content { content } | LocalChange::MoveAndContent { content, .. } => {
                if intent.origin != LocalOrigin::LocalEdit {
                    return Err(ReconcileError::InconsistentIntent(
                        "content change must come from a local edit",
                    ));
                }
                known_digests.insert(content.object.sha256);
            }
            LocalChange::Move { .. } | LocalChange::Delete => {
                if intent.origin != LocalOrigin::LocalEdit {
                    return Err(ReconcileError::InconsistentIntent(
                        "local change must come from a local edit",
                    ));
                }
            }
        }
        // Non-create mutations are applied in a second step so the borrow of
        // `map` above ends first.
        match &intent.change {
            LocalChange::Content { content } => {
                let state = map.get_mut(&intent.item_id).ok_or(ReconcileError::MissingContext(
                    vec![MissingRef::Item { item_id: intent.item_id }],
                ))?;
                if state.deleted || state.kind != ItemKind::File {
                    return Err(ReconcileError::InconsistentIntent(
                        "content change needs a live file",
                    ));
                }
                state.content_version_id = Some(content.version_id);
                state.content_sha256 = Some(content.object.sha256);
                state.content_size = Some(content.object.size);
                state.content_operation = intent.operation_id;
                state.item_revision = intent.operation_id;
            }
            LocalChange::Move { parent_id, name } => {
                names::validate_name(name)?;
                let parent = map.get(parent_id).ok_or(ReconcileError::MissingContext(vec![
                    MissingRef::Parent { item_id: intent.item_id, missing: *parent_id },
                ]))?;
                if parent.deleted || parent.kind != ItemKind::Directory {
                    return Err(ReconcileError::InconsistentIntent(
                        "move target is not a live directory",
                    ));
                }
                let state = map.get_mut(&intent.item_id).ok_or(ReconcileError::MissingContext(
                    vec![MissingRef::Item { item_id: intent.item_id }],
                ))?;
                if state.deleted {
                    return Err(ReconcileError::InconsistentIntent("move of a deleted item"));
                }
                state.parent_id = Some(*parent_id);
                state.name = name.clone();
                state.location_operation = intent.operation_id;
                state.item_revision = intent.operation_id;
            }
            LocalChange::MoveAndContent { parent_id, name, content } => {
                names::validate_name(name)?;
                let parent = map.get(parent_id).ok_or(ReconcileError::MissingContext(vec![
                    MissingRef::Parent { item_id: intent.item_id, missing: *parent_id },
                ]))?;
                if parent.deleted || parent.kind != ItemKind::Directory {
                    return Err(ReconcileError::InconsistentIntent(
                        "move target is not a live directory",
                    ));
                }
                let state = map.get_mut(&intent.item_id).ok_or(ReconcileError::MissingContext(
                    vec![MissingRef::Item { item_id: intent.item_id }],
                ))?;
                if state.deleted || state.kind != ItemKind::File {
                    return Err(ReconcileError::InconsistentIntent(
                        "content change needs a live file",
                    ));
                }
                state.parent_id = Some(*parent_id);
                state.name = name.clone();
                state.location_operation = intent.operation_id;
                state.content_version_id = Some(content.version_id);
                state.content_sha256 = Some(content.object.sha256);
                state.content_size = Some(content.object.size);
                state.content_operation = intent.operation_id;
                state.item_revision = intent.operation_id;
            }
            LocalChange::Delete => {
                let state = map.get(&intent.item_id).ok_or(ReconcileError::MissingContext(vec![
                    MissingRef::Item { item_id: intent.item_id },
                ]))?;
                if state.deleted {
                    return Err(ReconcileError::InconsistentIntent("double delete"));
                }
                let is_directory = state.kind == ItemKind::Directory;
                let mut subtree: Vec<ItemId> = vec![intent.item_id];
                if is_directory {
                    collect_subtree(&map, intent.item_id, &mut subtree);
                }
                for id in subtree {
                    if let Some(state) = map.get_mut(&id) {
                        if !state.deleted {
                            state.deleted = true;
                            state.deletion_operation = Some(intent.operation_id);
                            state.item_revision = intent.operation_id;
                        }
                    }
                }
            }
            LocalChange::Create { .. } | LocalChange::Materialized { .. } => {}
        }
    }
    Ok(map)
}

fn collect_subtree(
    map: &BTreeMap<ItemId, ItemState>,
    root: ItemId,
    out: &mut Vec<ItemId>,
) {
    let mut stack = vec![root];
    let mut seen: BTreeSet<ItemId> = BTreeSet::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        out.push(id);
        for (other, state) in map {
            if state.parent_id == Some(id) {
                stack.push(*other);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Builder internals
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Side {
    Local,
    Remote,
}

struct Draft {
    state: ItemState,
    /// True for deterministic conflict copies and recovered directories.
    generated: bool,
    /// True once the item's name came from the conflict-name generator.
    derived: bool,
    /// The conflict identity the name derives from, when `derived`.
    conflict_id: Option<ConflictId>,
}

impl Draft {
    fn plain(state: ItemState) -> Self {
        Self { state, generated: false, derived: false, conflict_id: None }
    }
    fn generated(state: ItemState, conflict_id: ConflictId) -> Self {
        Self { state, generated: true, derived: true, conflict_id: Some(conflict_id) }
    }
}

struct ConflictBuild {
    identity: ConflictIdentity,
    kind: ConflictKind,
    item_id: ItemId,
    ops: Vec<OperationId>,
    sides: Vec<ConflictSide>,
    outcome: ConflictOutcome,
    preserved_item_id: Option<ItemId>,
    preserved_version_id: Option<VersionId>,
}

struct Builder<'s> {
    workspace_id: WorkspaceId,
    mode: ReconcileMode,
    base: &'s CatalogView,
    remote: &'s CatalogView,
    ntfs: &'s dyn NtfsNameCompare,
    ids: &'s mut dyn IdSource,
    intent_list: &'s [LocalIntent],
    local_map: BTreeMap<ItemId, ItemState>,
    /// Items whose last observed state came from a remote materialization;
    /// they can never publish and never produce local actions.
    materialized_ids: BTreeSet<ItemId>,
    /// Items touched by at least one [`LocalEdit`] intent.
    local_edit_touched: BTreeSet<ItemId>,
    drafts: BTreeMap<ItemId, Draft>,
    conflicts: Vec<ConflictBuild>,
    alias_plans: Vec<AliasPlan>,
    aliases: BTreeMap<ItemId, String>,
    intent_versions: BTreeMap<VersionId, PlannedVersion>,
    recovery_seen: BTreeSet<ConflictId>,
}

impl<'s> Builder<'s> {
    fn new(
        workspace_id: WorkspaceId,
        mode: ReconcileMode,
        base: &'s CatalogView,
        remote: &'s CatalogView,
        ntfs: &'s dyn NtfsNameCompare,
        intent_list: &'s [LocalIntent],
        ids: &'s mut dyn IdSource,
        local_map: BTreeMap<ItemId, ItemState>,
    ) -> Self {
        let mut intent_versions: BTreeMap<VersionId, PlannedVersion> = BTreeMap::new();
        let mut materialized_ids: BTreeSet<ItemId> = BTreeSet::new();
        let mut local_edit_touched: BTreeSet<ItemId> = BTreeSet::new();
        for intent in intent_list {
            match (&intent.change, intent.origin) {
                (LocalChange::Materialized { .. }, LocalOrigin::RemoteMaterialization) => {
                    materialized_ids.insert(intent.item_id);
                }
                (_, LocalOrigin::LocalEdit) => {
                    local_edit_touched.insert(intent.item_id);
                    materialized_ids.remove(&intent.item_id);
                }
                _ => {}
            }
            let content = match &intent.change {
                LocalChange::Create { content: Some(c), .. }
                | LocalChange::Content { content: c }
                | LocalChange::MoveAndContent { content: c, .. } => Some(c),
                _ => None,
            };
            if let Some(content) = content {
                intent_versions.insert(
                    content.version_id,
                    PlannedVersion {
                        version_id: content.version_id,
                        object: content.object.clone(),
                        display: content.display.clone(),
                    },
                );
            }
        }
        Self {
            workspace_id,
            mode,
            base,
            remote,
            ntfs,
            ids,
            intent_list,
            local_map,
            materialized_ids,
            local_edit_touched,
            drafts: BTreeMap::new(),
            conflicts: Vec::new(),
            alias_plans: Vec::new(),
            aliases: BTreeMap::new(),
            intent_versions,
            recovery_seen: BTreeSet::new(),
        }
    }

    // -- phase 1: per-item three-way merge ---------------------------------

    fn merge_all(&mut self) -> Result<(), ReconcileError> {
        let mut all: BTreeSet<ItemId> = BTreeSet::new();
        all.extend(self.base.iter().map(|s| s.item_id));
        all.extend(self.local_map.keys().copied());
        all.extend(self.remote.iter().map(|s| s.item_id));
        for id in all {
            let b = self.base.get(id).cloned();
            let l = self.local_map.get(&id).cloned();
            let r = self.remote.get(id).cloned();
            self.merge_item(b, l, r)?;
        }
        Ok(())
    }

    fn merge_item(
        &mut self,
        b: Option<ItemState>,
        l: Option<ItemState>,
        r: Option<ItemState>,
    ) -> Result<(), ReconcileError> {
        let id = l
            .as_ref()
            .or(r.as_ref())
            .or(b.as_ref())
            .map(|s| s.item_id)
            .expect("merge_item is called with at least one state");
        match (&b, &l, &r) {
            (Some(_), None, _) | (Some(_), _, None) => {
                return Err(ReconcileError::MissingContext(vec![MissingRef::Item {
                    item_id: id,
                }]));
            }
            _ => {}
        }
        if let (Some(a), Some(c)) = (&b, &l) {
            if a.kind != c.kind {
                return Err(ReconcileError::InconsistentIntent("item kind changed locally"));
            }
        }
        if let (Some(a), Some(c)) = (&b, &r) {
            if a.kind != c.kind {
                return Err(ReconcileError::InvalidView("item kind changed remotely"));
            }
        }
        // A state produced by remote materialization never publishes and
        // never produces local actions: adopt the committed record (if any)
        // and leave any local residue to the provider's recovery engine.
        if self.materialized_ids.contains(&id) && !self.local_edit_touched.contains(&id) {
            match (&l, &r) {
                (Some(_), Some(r)) => {
                    self.drafts.insert(id, Draft::plain(r.clone()));
                    return Ok(());
                }
                (Some(_), None) => return Ok(()),
                _ => {}
            }
        }
        match (b, l, r) {
            (None, None, None) => Ok(()),
            (None, Some(l), None) => {
                self.drafts.insert(id, Draft::plain(l));
                Ok(())
            }
            (None, None, Some(r)) => {
                self.drafts.insert(id, Draft::plain(r));
                Ok(())
            }
            (None, Some(l), Some(r)) => {
                if l.meaningful_equal(&r) {
                    // The same deterministic identity already exists
                    // remotely with the same claim (a conflict-copy retry):
                    // converge instead of racing itself.
                    self.drafts.insert(id, Draft::plain(r));
                } else {
                    self.merge_both(None, l, r)?;
                }
                Ok(())
            }
            (Some(b), Some(l), Some(r)) => {
                let l_changed = !l.meaningful_equal(&b);
                let r_changed = !r.meaningful_equal(&b);
                if !l_changed && !r_changed {
                    self.drafts.insert(id, Draft::plain(r));
                } else if l_changed && !r_changed {
                    self.drafts.insert(id, Draft::plain(l));
                } else if !l_changed && r_changed {
                    self.drafts.insert(id, Draft::plain(r));
                } else {
                    self.merge_both(Some(b), l, r)?;
                }
                Ok(())
            }
            (Some(_), _, None) | (Some(_), None, _) => {
                Err(ReconcileError::MissingContext(vec![MissingRef::Item { item_id: id }]))
            }
        }
    }

    fn merge_both(
        &mut self,
        b: Option<ItemState>,
        l: ItemState,
        r: ItemState,
    ) -> Result<(), ReconcileError> {
        let id = l.item_id;
        // Deletion component first: a deletion either converges or loses to a
        // change; a deletion never silently drops changed data.
        if l.deleted && r.deleted {
            self.drafts.insert(id, Draft::plain(r));
            return Ok(());
        }
        if l.deleted && !r.deleted {
            // Local delete versus a committed remote change: the change
            // survives, the deletion is recorded and dropped.
            self.drafts.insert(id, Draft::plain(r.clone()));
            let del_op = l
                .deletion_operation
                .ok_or(ReconcileError::InvalidView("deleted without deletion operation"))?;
            self.push_delete_vs_change(id, del_op, &l, &r)?;
            return Ok(());
        }
        if !l.deleted && r.deleted {
            // Committed remote delete versus a local change: the change
            // survives and the item is revived in place.
            let mut merged = l.clone();
            merged.deleted = false;
            merged.deletion_operation = None;
            self.drafts.insert(id, Draft::plain(merged));
            let del_op = r
                .deletion_operation
                .ok_or(ReconcileError::InvalidView("deleted without deletion operation"))?;
            self.push_delete_vs_change(id, del_op, &r, &l)?;
            return Ok(());
        }

        // Both sides live: content and location merge independently.
        let (lc, ll) = match &b {
            Some(b) => (!l.content_equal(b), !l.location_equal(b)),
            None => (true, true),
        };
        let (rc, rl) = match &b {
            Some(b) => (!r.content_equal(b), !r.location_equal(b)),
            None => (true, true),
        };
        let content_race = lc && rc && !l.content_equal(&r);
        let location_race = ll && rl && !l.location_equal(&r);

        let content_side = if content_race {
            race_winner(l.content_operation, r.content_operation)
        } else if lc && !rc {
            // Only the local side changed content: publish it. When both
            // sides changed to equal payloads the component converges to the
            // committed binding (no upload, no conflict).
            Side::Local
        } else {
            Side::Remote
        };
        let location_side = if location_race {
            race_winner(l.location_operation, r.location_operation)
        } else if ll && !rl {
            Side::Local
        } else {
            Side::Remote
        };

        let cw = if content_side == Side::Local { &l } else { &r };
        let lw = if location_side == Side::Local { &l } else { &r };
        let merged = ItemState {
            item_id: id,
            parent_id: lw.parent_id,
            name: lw.name.clone(),
            kind: l.kind,
            deleted: false,
            item_revision: cw.item_revision,
            content_version_id: cw.content_version_id,
            content_operation: cw.content_operation,
            location_operation: lw.location_operation,
            deletion_operation: None,
            content_sha256: cw.content_sha256,
            content_size: cw.content_size,
        };

        if content_race && location_race && content_side == location_side {
            // One side lost both components: one copy preserves its complete
            // claim under one conflict identity.
            let loser = if content_side == Side::Local { &r } else { &l };
            let ops = [
                l.content_operation,
                r.content_operation,
                l.location_operation,
                r.location_operation,
            ];
            let ident = conflict_identity(self.workspace_id, ConflictKind::ContentAndLocation, &[id], &ops);
            self.push_keep_both(id, ident, ConflictKind::ContentAndLocation, loser, &merged, &ops)?;
        } else {
            if content_race {
                let loser = if content_side == Side::Local { &r } else { &l };
                let ops = [l.content_operation, r.content_operation];
                let ident =
                    conflict_identity(self.workspace_id, ConflictKind::ContentDivergence, &[id], &ops);
                self.push_keep_both(id, ident, ConflictKind::ContentDivergence, loser, &merged, &ops)?;
            }
            if location_race {
                let loser = if location_side == Side::Local { &r } else { &l };
                let ops = [l.location_operation, r.location_operation];
                let ident =
                    conflict_identity(self.workspace_id, ConflictKind::RenameRace, &[id], &ops);
                self.push_keep_both(id, ident, ConflictKind::RenameRace, loser, &merged, &ops)?;
            }
        }
        self.drafts.insert(id, Draft::plain(merged));
        Ok(())
    }

    /// Places the loser's complete claim as a deterministic conflict copy.
    #[allow(clippy::too_many_arguments)]
    fn push_keep_both(
        &mut self,
        item_id: ItemId,
        ident: ConflictIdentity,
        kind: ConflictKind,
        loser: &ItemState,
        winner: &ItemState,
        tuple_ops: &[OperationId],
    ) -> Result<(), ReconcileError> {
        let copy_state = ItemState {
            item_id: ident.copy_item_id,
            parent_id: loser.parent_id,
            name: conflict_name(&loser.name, ident.conflict_id),
            kind: loser.kind,
            deleted: false,
            item_revision: loser.item_revision,
            content_version_id: loser.content_version_id,
            content_operation: loser.content_operation,
            location_operation: loser.location_operation,
            deletion_operation: None,
            content_sha256: loser.content_sha256,
            content_size: loser.content_size,
        };
        self.place_generated(copy_state, ident.conflict_id)?;
        self.conflicts.push(ConflictBuild {
            identity: ident,
            kind,
            item_id,
            ops: sorted_ops(tuple_ops),
            sides: sorted_sides(vec![side_of(loser), side_of(winner)]),
            outcome: ConflictOutcome::KeepBoth,
            preserved_item_id: Some(ident.copy_item_id),
            preserved_version_id: loser.content_version_id,
        });
        Ok(())
    }

    fn push_delete_vs_change(
        &mut self,
        item_id: ItemId,
        del_op: OperationId,
        deleter: &ItemState,
        survivor: &ItemState,
    ) -> Result<(), ReconcileError> {
        let ops = [del_op, survivor.item_revision];
        let ident = conflict_identity(self.workspace_id, ConflictKind::DeleteVsChange, &[item_id], &ops);
        self.conflicts.push(ConflictBuild {
            identity: ident,
            kind: ConflictKind::DeleteVsChange,
            item_id,
            ops: sorted_ops(&ops),
            sides: sorted_sides(vec![
                ConflictSide {
                    operation_id: del_op,
                    parent_id: deleter.parent_id,
                    name: deleter.name.clone(),
                    content_version_id: deleter.content_version_id,
                },
                side_of(survivor),
            ]),
            outcome: ConflictOutcome::Recovered,
            preserved_item_id: None,
            preserved_version_id: survivor.content_version_id,
        });
        Ok(())
    }

    /// Inserts a deterministic generated item (conflict copy or recovered
    /// directory), adopting an identical existing item on retry so the plan
    /// converges on the same identity instead of creating a second copy.
    fn place_generated(
        &mut self,
        generated: ItemState,
        conflict_id: ConflictId,
    ) -> Result<ItemId, ReconcileError> {
        let id = generated.item_id;
        if let Some(existing) = self
            .remote
            .get(id)
            .or_else(|| self.base.get(id))
            .cloned()
        {
            let same_claim = existing.kind == generated.kind
                && !existing.deleted
                && existing.content_equal(&generated);
            if !same_claim {
                return Err(ReconcileError::InconsistentIntent(
                    "deterministic conflict identity is already bound to a different state",
                ));
            }
            // Adopt the committed placement so retries converge.
            self.drafts.insert(id, Draft::generated(existing, conflict_id));
            return Ok(id);
        }
        self.drafts.insert(id, Draft::generated(generated, conflict_id));
        Ok(id)
    }

    // -- phase 2: parent liveness, recovery directories, cycles ------------

    fn resolve_parents(&mut self) -> Result<(), ReconcileError> {
        let root = self
            .remote
            .root_id()
            .or_else(|| self.base.root_id())
            .ok_or(ReconcileError::InvalidView("no root"))?;
        for _ in 0..(self.drafts.len() + 8) {
            let mut violations: Vec<ItemId> = Vec::new();
            let mut cycles: Vec<Vec<ItemId>> = Vec::new();
            let live: Vec<ItemId> = self
                .drafts
                .iter()
                .filter(|(_, d)| !d.state.deleted)
                .map(|(id, _)| *id)
                .collect();
            for &id in &live {
                match self.drafts[&id].state.parent_id {
                    None => {}
                    Some(pid) => match self.drafts.get(&pid) {
                        Some(p) if !p.state.deleted && p.state.kind == ItemKind::Directory => {}
                        Some(p) if p.state.deleted => violations.push(id),
                        Some(_) => {
                            return Err(ReconcileError::InvalidView(
                                "live item under a parent that is not a directory",
                            ))
                        }
                        None => violations.push(id),
                    },
                }
            }
            detect_cycles(&self.drafts, &live, &mut cycles);
            if violations.is_empty() && cycles.is_empty() {
                return Ok(());
            }
            violations.sort();
            violations.dedup();
            for id in violations {
                let pid = self.drafts[&id]
                    .state
                    .parent_id
                    .expect("violation implies a parent");
                // The parent is tombstoned or absent: re-home under the
                // deterministic recovered directory of that deletion.
                let del_state = self
                    .drafts
                    .get(&pid)
                    .map(|d| d.state.clone())
                    .or_else(|| self.remote.get(pid).cloned())
                    .or_else(|| self.base.get(pid).cloned())
                    .ok_or(ReconcileError::MissingContext(vec![MissingRef::Ancestor {
                        item_id: id,
                        missing: pid,
                    }]))?;
                let del_ops: Vec<OperationId> = del_state.deletion_operation.into_iter().collect();
                if !del_state.deleted || del_ops.is_empty() {
                    return Err(ReconcileError::InvalidView(
                        "re-home target is neither live nor a tombstone",
                    ));
                }
                let ident = conflict_identity(
                    self.workspace_id,
                    ConflictKind::DirectoryDeleteRecovery,
                    &[pid],
                    &del_ops,
                );
                let place_near = pid;
                let dir = self.ensure_recovered_dir(ident, place_near, del_ops[0], root)?;
                self.drafts
                    .get_mut(&id)
                    .expect("violation item has a draft")
                    .state
                    .parent_id = Some(dir);
                if self.recovery_seen.insert(ident.conflict_id) {
                    self.conflicts.push(ConflictBuild {
                        identity: ident,
                        kind: ConflictKind::DirectoryDeleteRecovery,
                        item_id: pid,
                        ops: del_ops.clone(),
                        sides: sorted_sides(vec![ConflictSide {
                            operation_id: del_ops[0],
                            parent_id: del_state.parent_id,
                            name: del_state.name.clone(),
                            content_version_id: del_state.content_version_id,
                        }]),
                        outcome: ConflictOutcome::RecoveredDirectory,
                        preserved_item_id: Some(dir),
                        preserved_version_id: None,
                    });
                }
                // Record the survivor's claim on the recovery record.
                if let Some(build) = self
                    .conflicts
                    .iter_mut()
                    .find(|c| c.identity.conflict_id == ident.conflict_id)
                {
                    let side = side_of(&self.drafts[&id].state);
                    if !build.sides.iter().any(|s| s.operation_id == side.operation_id) {
                        build.sides.push(side);
                        build.sides = sorted_sides(std::mem::take(&mut build.sides));
                    }
                }
            }
            for cycle in cycles {
                let mut members = cycle;
                members.sort();
                let ops: Vec<OperationId> = members
                    .iter()
                    .map(|id| self.drafts[id].state.location_operation)
                    .collect();
                let ident = conflict_identity(
                    self.workspace_id,
                    ConflictKind::CycleMove,
                    &members,
                    &ops,
                );
                // The cycle-producing move (greatest location operation) is
                // not applied; its subtree is preserved under a root-level
                // recovered directory.
                let loser = *members
                    .iter()
                    .max_by_key(|id| (self.drafts[id].state.location_operation, **id))
                    .expect("cycle has members");
                let loser_op = self.drafts[&loser].state.location_operation;
                let dir = self.ensure_recovered_dir(ident, root, loser_op, root)?;
                self.drafts
                    .get_mut(&loser)
                    .expect("cycle member has a draft")
                    .state
                    .parent_id = Some(dir);
                self.conflicts.push(ConflictBuild {
                    identity: ident,
                    kind: ConflictKind::CycleMove,
                    item_id: loser,
                    ops: sorted_ops(&ops),
                    sides: sorted_sides(
                        members
                            .iter()
                            .map(|id| side_of(&self.drafts[id].state))
                            .collect(),
                    ),
                    outcome: ConflictOutcome::RecoveredDirectory,
                    preserved_item_id: Some(loser),
                    preserved_version_id: None,
                });
            }
        }
        Err(ReconcileError::NotConverged)
    }

    /// Ensures the deterministic recovered directory exists as a draft and
    /// returns its id. `place_near` selects the nearest live parent for the
    /// directory (the root for cycle recovery).
    fn ensure_recovered_dir(
        &mut self,
        ident: ConflictIdentity,
        place_near: ItemId,
        responsible_op: OperationId,
        root: ItemId,
    ) -> Result<ItemId, ReconcileError> {
        let id = ident.recovered_dir_id;
        if self.drafts.contains_key(&id) {
            return Ok(id);
        }
        if let Some(existing) = self.remote.get(id).or_else(|| self.base.get(id)).cloned() {
            if existing.kind == ItemKind::Directory && !existing.deleted {
                self.drafts.insert(id, Draft::generated(existing, ident.conflict_id));
                return Ok(id);
            }
            return Err(ReconcileError::InconsistentIntent(
                "deterministic recovered directory is bound to a different state",
            ));
        }
        let parent = if place_near == root {
            root
        } else {
            self.nearest_live_directory(place_near, root)?
        };
        let state = ItemState {
            item_id: id,
            parent_id: Some(parent),
            name: conflict_name("Recovered", ident.conflict_id),
            kind: ItemKind::Directory,
            deleted: false,
            item_revision: responsible_op,
            content_version_id: None,
            content_operation: responsible_op,
            location_operation: responsible_op,
            deletion_operation: None,
            content_sha256: None,
            content_size: None,
        };
        self.place_generated(state, ident.conflict_id)?;
        Ok(id)
    }

    /// The nearest live directory at or above `start` in the draft namespace,
    /// falling back to the root.
    fn nearest_live_directory(
        &self,
        start: ItemId,
        root: ItemId,
    ) -> Result<ItemId, ReconcileError> {
        let mut seen: BTreeSet<ItemId> = BTreeSet::new();
        let mut cur = start;
        loop {
            if !seen.insert(cur) {
                return Ok(root);
            }
            match self.drafts.get(&cur) {
                Some(d) if !d.state.deleted && d.state.kind == ItemKind::Directory => {
                    return Ok(cur)
                }
                Some(d) => match d.state.parent_id {
                    Some(parent) => cur = parent,
                    None => return Ok(root),
                },
                None => return Ok(root),
            }
        }
    }

    // -- phase 3: portable name slots --------------------------------------

    fn resolve_names(&mut self) -> Result<(), ReconcileError> {
        let mut groups: BTreeMap<(Option<ItemId>, Vec<u8>), Vec<ItemId>> = BTreeMap::new();
        for (id, d) in &self.drafts {
            if d.state.deleted || d.state.parent_id.is_none() {
                continue;
            }
            groups
                .entry((d.state.parent_id, names::collision_key(&d.state.name)))
                .or_default()
                .push(*id);
        }
        // Deterministic loser order across all groups.
        let mut renames: Vec<(ItemId, ItemId, ConflictIdentity)> = Vec::new();
        for ((_, _), mut members) in groups.into_iter().filter(|(_, v)| v.len() > 1) {
            members.sort_by_key(|id| {
                (
                    self.drafts[id].derived,
                    self.drafts[id].state.location_operation,
                    *id,
                )
            });
            let winner = members[0];
            for &loser in &members[1..] {
                if self.drafts[&loser].derived {
                    // Already a conflict-derived name: extend its own hex and
                    // do not create a second conflict record.
                    let ident = conflict_identity(
                        self.workspace_id,
                        ConflictKind::NameCollision,
                        &[loser],
                        &[self.drafts[&loser].state.location_operation],
                    );
                    renames.push((loser, winner, ident));
                } else {
                    let ops = [
                        self.drafts[&winner].state.location_operation,
                        self.drafts[&loser].state.location_operation,
                    ];
                    let ident = conflict_identity(
                        self.workspace_id,
                        ConflictKind::NameCollision,
                        &[winner, loser],
                        &ops,
                    );
                    renames.push((loser, winner, ident));
                }
            }
        }
        if renames.is_empty() {
            return Ok(());
        }
        renames.sort_by_key(|(loser, _, _)| *loser);
        // Occupancy of all kept names plus already-placed renames.
        let mut taken: BTreeSet<(Option<ItemId>, Vec<u8>)> = BTreeSet::new();
        let losers: BTreeSet<ItemId> = renames.iter().map(|(l, _, _)| *l).collect();
        for (id, d) in &self.drafts {
            if d.state.deleted || d.state.parent_id.is_none() || losers.contains(id) {
                continue;
            }
            taken.insert((d.state.parent_id, names::collision_key(&d.state.name)));
        }
        for (loser, winner, ident) in &renames {
            let (parent, base_name) = {
                let d = &self.drafts[&loser];
                (d.state.parent_id, d.state.name.clone())
            };
            let mut chosen: Option<String> = None;
            for candidate in ConflictNames::new(&base_name, ident.conflict_id) {
                if names::validate_name(&candidate).is_err() {
                    continue;
                }
                let key = (parent, names::collision_key(&candidate));
                if !taken.contains(&key) {
                    taken.insert(key);
                    chosen = Some(candidate);
                    break;
                }
            }
            let name = chosen.ok_or(ReconcileError::NotConverged)?;
            let draft = self.drafts.get_mut(loser).expect("loser has a draft");
            draft.state.name = name;
            draft.derived = true;
            draft.conflict_id = Some(ident.conflict_id);
            if !self.drafts[&loser].generated {
                self.conflicts.push(ConflictBuild {
                    identity: *ident,
                    kind: ConflictKind::NameCollision,
                    item_id: *winner,
                    ops: sorted_ops(&[
                        self.drafts[&winner].state.location_operation,
                        self.drafts[&loser].state.location_operation,
                    ]),
                    sides: sorted_sides(vec![
                        side_of(&self.drafts[&winner].state),
                        side_of(&self.drafts[&loser].state),
                    ]),
                    outcome: ConflictOutcome::KeepBoth,
                    preserved_item_id: Some(*loser),
                    preserved_version_id: self.drafts[&loser].state.content_version_id,
                });
            }
        }
        Ok(())
    }

    // -- phase 3.5: NTFS-only collisions -----------------------------------

    fn plan_aliases(&mut self) {
        // Group live sibling names by simple uppercase fold, then confirm
        // each pair with the injected comparator.
        let mut by_parent: BTreeMap<Option<ItemId>, Vec<ItemId>> = BTreeMap::new();
        for (id, d) in &self.drafts {
            if d.state.deleted {
                continue;
            }
            by_parent.entry(d.state.parent_id).or_default().push(*id);
        }
        for (parent, members) in by_parent {
            let Some(parent) = parent else { continue };
            let mut classes: BTreeMap<String, Vec<ItemId>> = BTreeMap::new();
            for id in &members {
                let name = &self.drafts[id].state.name;
                let fold: String = name.chars().flat_map(char::to_uppercase).collect();
                classes.entry(fold).or_default().push(*id);
            }
            for (_, mut class) in classes.into_iter().filter(|(_, v)| v.len() > 1) {
                class.sort_by_key(|id| (self.drafts[id].derived, self.drafts[id].state.location_operation, *id));
                for window in class.windows(2) {
                    let (a, b) = (window[0], window[1]);
                    let name_a = self.drafts[&a].state.name.clone();
                    let name_b = self.drafts[&b].state.name.clone();
                    if name_a == name_b || !self.ntfs.equal(&name_a, &name_b) {
                        continue;
                    }
                    // The later member of the sorted pair is the loser.
                    let loser = b;
                    let ident = conflict_identity(
                        self.workspace_id,
                        ConflictKind::NtfsAlias,
                        &[a, loser],
                        &[
                            self.drafts[&a].state.location_operation,
                            self.drafts[&loser].state.location_operation,
                        ],
                    );
                    let remote_name = self.drafts[&loser].state.name.clone();
                    let mut alias: Option<String> = None;
                    let mut taken: BTreeSet<Vec<u8>> = self
                        .drafts
                        .values()
                        .filter(|d| !d.state.deleted && d.state.parent_id == Some(parent))
                        .map(|d| names::collision_key(&d.state.name))
                        .collect();
                    taken.extend(self.aliases.values().map(|n| names::collision_key(n)));
                    for candidate in ConflictNames::new(&remote_name, ident.conflict_id) {
                        if names::validate_name(&candidate).is_err() {
                            continue;
                        }
                        let key = names::collision_key(&candidate);
                        if !taken.contains(&key) {
                            taken.insert(key);
                            alias = Some(candidate);
                            break;
                        }
                    }
                    if let Some(local_alias) = alias {
                        self.aliases.insert(loser, local_alias.clone());
                        self.alias_plans.push(AliasPlan {
                            collision_id: ident.conflict_id,
                            parent_id: parent,
                            item_id: loser,
                            remote_name,
                            local_alias,
                        });
                    }
                }
            }
        }
    }

    // -- phase 4/5: emission ----------------------------------------------

    fn finish(mut self) -> Result<ReconcilePlan, ReconcileError> {
        // Normalize: a draft that is meaningfully equal to committed remote
        // state adopts the committed record exactly, so converged retries emit
        // no mutation and keep committed provenance.
        let draft_ids: Vec<ItemId> = self.drafts.keys().copied().collect();
        for id in draft_ids {
            if let Some(r) = self.remote.get(id).cloned() {
                let draft = self.drafts.get(&id).expect("present");
                if draft.state.meaningful_equal(&r) {
                    self.drafts.get_mut(&id).expect("present").state = r;
                }
            }
        }

        let order = self.order_ops()?;

        // Build the emitted records with final revisions.
        let mut remote_ops: Vec<RemoteOp> = Vec::with_capacity(order.len());
        let mut changes: Vec<ItemChange> = Vec::with_capacity(order.len());
        let mut realized: BTreeSet<OperationId> = BTreeSet::new();
        let mut used_versions: BTreeSet<VersionId> = BTreeSet::new();
        for id in &order {
            let state = self.drafts[id].state.clone();
            let old = self.remote.get(*id).cloned();
            let change = change_kind(old.as_ref(), &state);
            let new_revision = finalize_revision(change, &state, old.as_ref());
            let mut record = state.to_record();
            record.item_revision = new_revision;
            format::validate_item_record(&record)
                .map_err(|_| ReconcileError::InvalidRecord("emitted record is not canonical"))?;
            record_ops(&record, &mut realized);
            if let Some(version) = record.content_version_id {
                used_versions.insert(version);
            }
            changes.push(ItemChange {
                item_id: record.item_id,
                change,
                old_revision: old.as_ref().map(|r| r.item_revision),
                new_revision,
            });
            remote_ops.push(RemoteOp {
                record,
                change,
                old_revision: old.as_ref().map(|r| r.item_revision),
            });
        }
        changes.sort_by_key(|c| c.item_id);

        // Versions required by emitted records that came from local intents.
        let mut versions: Vec<PlannedVersion> = Vec::new();
        for (version_id, planned) in &self.intent_versions {
            if used_versions.contains(version_id) {
                versions.push(planned.clone());
            }
        }

        let local_actions = self.plan_local_actions()?;

        // Finalize conflict records with the settled names and parents.
        let mut conflicts: Vec<ConflictRecord> = Vec::new();
        for build in &self.conflicts {
            let (preserved_name, preserved_parent_id) = match build.preserved_item_id {
                Some(id) => match self.drafts.get(&id) {
                    Some(d) => (Some(d.state.name.clone()), d.state.parent_id),
                    None => (None, None),
                },
                None => (None, None),
            };
            conflicts.push(ConflictRecord {
                conflict_id: build.identity.conflict_id,
                kind: build.kind,
                item_id: build.item_id,
                competing_operations: build.ops.clone(),
                sides: build.sides.clone(),
                outcome: build.outcome,
                preserved_item_id: build.preserved_item_id,
                preserved_version_id: build.preserved_version_id,
                preserved_name,
                preserved_parent_id,
            });
        }

        let intents = self.plan_intent_outcomes(&realized, &conflicts);

        Ok(ReconcilePlan {
            workspace_id: self.workspace_id,
            mode: self.mode,
            remote_ops,
            versions,
            changes,
            operation_ids: realized.iter().copied().collect(),
            local_actions,
            conflicts,
            aliases: self.alias_plans,
            intents,
        })
    }

    /// Deterministic mutation order: tombstones first (deepest first), then
    /// upserts in a sequentially applicable order that frees name slots and
    /// creates parents before children.
    fn order_ops(&mut self) -> Result<Vec<ItemId>, ReconcileError> {
        if self.mode == ReconcileMode::ReadOnly {
            return Ok(Vec::new());
        }
        let mut needs: Vec<ItemId> = Vec::new();
        for (id, d) in &self.drafts {
            let required = match self.remote.get(*id) {
                None => true,
                Some(r) => !d.state.meaningful_equal(r),
            };
            if required {
                needs.push(*id);
            }
        }
        let mut tombstones: Vec<ItemId> = Vec::new();
        let mut upserts: Vec<ItemId> = Vec::new();
        for id in needs {
            if self.drafts[&id].state.deleted {
                tombstones.push(id);
            } else {
                upserts.push(id);
            }
        }
        tombstones.sort_by_key(|id| (std::cmp::Reverse(self.namespace_depth(*id)), *id));
        upserts.sort_by_key(|id| (self.namespace_depth(*id), *id));

        let mut order: Vec<ItemId> = tombstones.clone();
        let mut placed: BTreeSet<ItemId> = tombstones.iter().copied().collect();
        let upsert_set: BTreeSet<ItemId> = upserts.iter().copied().collect();

        // Name-slot occupancy as ops apply, starting from committed remote
        // live names.
        let mut occ: BTreeMap<(Option<ItemId>, Vec<u8>), ItemId> = BTreeMap::new();
        for state in self.remote.iter() {
            if state.deleted || state.parent_id.is_none() {
                continue;
            }
            occ.insert(
                (state.parent_id, names::collision_key(&state.name)),
                state.item_id,
            );
        }
        for id in &tombstones {
            if let Some(r) = self.remote.get(*id) {
                if !r.deleted {
                    occ.remove(&(r.parent_id, names::collision_key(&r.name)));
                }
            }
        }

        for _restart in 0..8 {
            let result = self.schedule_upserts(
                &upserts,
                &upsert_set,
                &mut placed,
                &mut occ,
                &mut order,
            );
            match result {
                Ok(()) => return Ok(order),
                Err(demote) => {
                    // A transient name swap that cannot be ordered: demote
                    // one participant to its deterministic conflict name and
                    // retry. Unreachable for legal single-device renames; kept
                    // as a safety net so emission is always sequentially
                    // applicable.
                    self.apply_transient_demotion(demote)?;
                    let mut fresh = Vec::new();
                    for (id, d) in &self.drafts {
                        let required = match self.remote.get(*id) {
                            None => true,
                            Some(r) => !d.state.meaningful_equal(r),
                        };
                        if required {
                            fresh.push(*id);
                        }
                    }
                    let mut new_tombstones: Vec<ItemId> = Vec::new();
                    let mut new_upserts: Vec<ItemId> = Vec::new();
                    for id in fresh {
                        if self.drafts[&id].state.deleted {
                            new_tombstones.push(id);
                        } else {
                            new_upserts.push(id);
                        }
                    }
                    new_tombstones
                        .sort_by_key(|id| (std::cmp::Reverse(self.namespace_depth(*id)), *id));
                    new_upserts.sort_by_key(|id| (self.namespace_depth(*id), *id));
                    order = new_tombstones.clone();
                    placed = new_tombstones.iter().copied().collect();
                    upserts = new_upserts.clone();
                    occ.clear();
                    for state in self.remote.iter() {
                        if state.deleted || state.parent_id.is_none() {
                            continue;
                        }
                        occ.insert(
                            (state.parent_id, names::collision_key(&state.name)),
                            state.item_id,
                        );
                    }
                    for id in &new_tombstones {
                        if let Some(r) = self.remote.get(*id) {
                            if !r.deleted {
                                occ.remove(&(r.parent_id, names::collision_key(&r.name)));
                            }
                        }
                    }
                }
            }
        }
        Err(ReconcileError::NotConverged)
    }

    fn schedule_upserts(
        &self,
        upserts: &[ItemId],
        upsert_set: &BTreeSet<ItemId>,
        placed: &mut BTreeSet<ItemId>,
        occ: &mut BTreeMap<(Option<ItemId>, Vec<u8>), ItemId>,
        order: &mut Vec<ItemId>,
    ) -> Result<(), ItemId> {
        let mut in_progress: BTreeSet<ItemId> = BTreeSet::new();
        for id in upserts {
            if placed.contains(id) {
                continue;
            }
            if place_one(
                self,
                *id,
                upsert_set,
                placed,
                occ,
                order,
                &mut in_progress,
            )
            .is_err()
            {
                return Err(*id);
            }
        }
        Ok(())
    }

    fn apply_transient_demotion(&mut self, demote: ItemId) -> Result<(), ReconcileError> {
        let state = &self.drafts[&demote].state;
        let base_name = state.name.clone();
        let parent = state.parent_id;
        let op = state.location_operation;
        let ident = conflict_identity(
            self.workspace_id,
            ConflictKind::NameCollision,
            &[demote],
            &[op],
        );
        let mut taken: BTreeSet<(Option<ItemId>, Vec<u8>)> = self
            .drafts
            .iter()
            .filter(|(id, d)| !d.state.deleted && **id != demote)
            .map(|(_, d)| (d.state.parent_id, names::collision_key(&d.state.name)))
            .collect();
        let mut chosen: Option<String> = None;
        for candidate in ConflictNames::new(&base_name, ident.conflict_id) {
            if names::validate_name(&candidate).is_err() {
                continue;
            }
            let key = (parent, names::collision_key(&candidate));
            if !taken.contains(&key) {
                taken.insert(key);
                chosen = Some(candidate);
                break;
            }
        }
        let name = chosen.ok_or(ReconcileError::NotConverged)?;
        let draft = self.drafts.get_mut(&demote).expect("demote has a draft");
        draft.state.name = name;
        draft.derived = true;
        draft.conflict_id = Some(ident.conflict_id);
        self.conflicts.push(ConflictBuild {
            identity: ident,
            kind: ConflictKind::NameCollision,
            item_id: demote,
            ops: sorted_ops(&[op]),
            sides: sorted_sides(vec![side_of(&self.drafts[&demote].state)]),
            outcome: ConflictOutcome::KeepBoth,
            preserved_item_id: Some(demote),
            preserved_version_id: self.drafts[&demote].state.content_version_id,
        });
        Ok(())
    }

    /// Depth of `id` in the draft namespace (root depth 0), cycle-safe.
    fn namespace_depth(&self, id: ItemId) -> usize {
        let mut depth = 0usize;
        let mut seen: BTreeSet<ItemId> = BTreeSet::new();
        let mut cur = id;
        while let Some(parent) = self.drafts.get(&cur).and_then(|d| d.state.parent_id) {
            if !seen.insert(cur) {
                break;
            }
            depth += 1;
            cur = parent;
        }
        depth
    }

    // -- local actions ------------------------------------------------------

    fn plan_local_actions(&mut self) -> Result<Vec<LocalAction>, ReconcileError> {
        let mut ids: BTreeSet<ItemId> = BTreeSet::new();
        ids.extend(self.local_map.keys().copied());
        ids.extend(self.drafts.keys().copied());
        let mut actions: Vec<LocalAction> = Vec::new();
        for id in ids {
            // Materialized items are already applied locally; touching them
            // again would echo remote work or undo a deliberate local alias.
            if self.materialized_ids.contains(&id) && !self.local_edit_touched.contains(&id) {
                continue;
            }
            let local = self.local_map.get(&id).cloned();
            let draft = self.drafts.get(&id).map(|d| d.state.clone());
            let remote = self.remote.get(id).cloned();
            let base = self.base.get(id).cloned();
            let alias = self.aliases.get(&id).cloned();
            match (local, draft) {
                (None, None) => {}
                (Some(l), Some(d)) => {
                    if l.meaningful_equal(&d) {
                        continue;
                    }
                    let dirty = match &base {
                        Some(b) => !l.content_equal(b),
                        None => true,
                    };
                    if self.mode == ReconcileMode::ReadOnly {
                        // Read-only: local divergence (dirty content or any
                        // unuploadable change) stays local and recoverable,
                        // and only committed remote state is materialized.
                        let local_dirty = match &base {
                            Some(b) => !l.meaningful_equal(b),
                            None => true,
                        };
                        let committed = match &remote {
                            Some(r) => d.meaningful_equal(r),
                            None => false,
                        };
                        if local_dirty || !committed {
                            continue;
                        }
                    }
                    if d.deleted {
                        if dirty {
                            actions.push(self.make_action(
                                id,
                                LocalActionKind::PreserveDirty,
                                Some(l.clone()),
                                Some(l.clone()),
                                None,
                            )?);
                        }
                        actions.push(self.make_action(
                            id,
                            LocalActionKind::DeletePlaceholder,
                            Some(l),
                            None,
                            None,
                        )?);
                    } else if l.deleted {
                        // The local file was removed but the merged item
                        // survives (a delete lost to a change): recreate.
                        actions.push(self.make_action(
                            id,
                            LocalActionKind::CreatePlaceholder,
                            Some(l),
                            Some(d),
                            alias,
                        )?);
                    } else if !d.content_equal(&l) {
                        if dirty {
                            actions.push(self.make_action(
                                id,
                                LocalActionKind::PreserveDirty,
                                Some(l.clone()),
                                Some(l.clone()),
                                None,
                            )?);
                        }
                        actions.push(self.make_action(
                            id,
                            LocalActionKind::UpdatePlaceholder,
                            Some(l),
                            Some(d),
                            alias,
                        )?);
                    } else {
                        actions.push(self.make_action(
                            id,
                            LocalActionKind::Rename,
                            Some(l),
                            Some(d),
                            alias,
                        )?);
                    }
                }
                (None, Some(d)) => {
                    if d.deleted {
                        continue;
                    }
                    if self.mode == ReconcileMode::ReadOnly {
                        // Only materialize committed remote state locally.
                        let committed = match &remote {
                            Some(r) => d.meaningful_equal(r),
                            None => false,
                        };
                        if !committed {
                            continue;
                        }
                    }
                    actions.push(self.make_action(
                        id,
                        LocalActionKind::CreatePlaceholder,
                        None,
                        Some(d),
                        alias,
                    )?);
                }
                (Some(_), None) => {
                    // A local file exists for an item that no side knows:
                    // with complete views this cannot happen, so the context
                    // is incomplete rather than the item gone.
                    return Err(ReconcileError::MissingContext(vec![MissingRef::Item {
                        item_id: id,
                    }]));
                }
            }
        }
        actions.sort_by_key(|a| (a.action, a.item_id));
        Ok(actions)
    }

    fn make_action(
        &mut self,
        item_id: ItemId,
        action: LocalActionKind,
        expected: Option<ItemState>,
        target: Option<ItemState>,
        local_alias: Option<String>,
    ) -> Result<LocalAction, ReconcileError> {
        Ok(LocalAction {
            action_id: self.ids.action_id(),
            item_id,
            action,
            expected,
            target,
            local_alias,
        })
    }

    // -- intent outcomes ----------------------------------------------------

    fn plan_intent_outcomes(
        &self,
        realized: &BTreeSet<OperationId>,
        conflicts: &[ConflictRecord],
    ) -> Vec<IntentOutcome> {
        let mut outcomes = Vec::new();
        for intent in self.intent_list {
            if intent.origin == LocalOrigin::RemoteMaterialization {
                outcomes.push(IntentOutcome {
                    operation_id: intent.operation_id,
                    item_id: intent.item_id,
                    outcome: IntentOutcomeKind::Converged,
                    conflict_id: None,
                });
                continue;
            }
            let local = self.local_map.get(&intent.item_id);
            let remote = self.remote.get(intent.item_id);
            let satisfied = match (local, remote) {
                (Some(l), Some(r)) => l.meaningful_equal(r),
                _ => false,
            };
            let conflict = conflicts
                .iter()
                .find(|c| c.competing_operations.contains(&intent.operation_id));
            let (outcome, conflict_id) = if realized.contains(&intent.operation_id) {
                (
                    IntentOutcomeKind::Published,
                    conflict.map(|c| c.conflict_id),
                )
            } else if satisfied {
                (IntentOutcomeKind::Converged, None)
            } else if let Some(c) = conflict {
                (IntentOutcomeKind::Conflicted, Some(c.conflict_id))
            } else if self.mode == ReconcileMode::ReadOnly {
                (IntentOutcomeKind::Deferred, None)
            } else {
                (IntentOutcomeKind::Superseded, None)
            };
            outcomes.push(IntentOutcome {
                operation_id: intent.operation_id,
                item_id: intent.item_id,
                outcome,
                conflict_id,
            });
        }
        outcomes
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

fn race_winner(local_op: OperationId, remote_op: OperationId) -> Side {
    // The lower lexical operation UUID (UUID byte order equals the lexical
    // order of the canonical spelling) wins the contested component.
    if local_op <= remote_op {
        Side::Local
    } else {
        Side::Remote
    }
}

fn side_of(state: &ItemState) -> ConflictSide {
    ConflictSide {
        operation_id: state.item_revision,
        parent_id: state.parent_id,
        name: state.name.clone(),
        content_version_id: state.content_version_id,
    }
}

fn sorted_ops(ops: &[OperationId]) -> Vec<OperationId> {
    let set: BTreeSet<OperationId> = ops.iter().copied().collect();
    set.into_iter().collect()
}

fn sorted_sides(mut sides: Vec<ConflictSide>) -> Vec<ConflictSide> {
    sides.sort_by_key(|s| s.operation_id);
    sides.dedup_by_key(|s| s.operation_id);
    sides
}

fn change_kind(old: Option<&ItemState>, new: &ItemState) -> ChangeKind {
    match old {
        None => ChangeKind::Create,
        Some(old) => {
            if new.deleted && !old.deleted {
                ChangeKind::Deletion
            } else if !new.deleted && old.deleted {
                ChangeKind::Undelete
            } else if !new.content_equal(old) {
                ChangeKind::Content
            } else {
                ChangeKind::Location
            }
        }
    }
}

fn finalize_revision(change: ChangeKind, new: &ItemState, old: Option<&ItemState>) -> OperationId {
    match change {
        ChangeKind::Create => {
            if new.kind == ItemKind::File {
                new.content_operation
            } else {
                new.location_operation
            }
        }
        ChangeKind::Deletion => new
            .deletion_operation
            .expect("a tombstone carries a deletion operation"),
        ChangeKind::Undelete => match old {
            Some(old) if new.content_equal(old) => new.location_operation,
            _ => new.content_operation,
        },
        ChangeKind::Content => new.content_operation,
        ChangeKind::Location => new.location_operation,
    }
}

fn detect_cycles(
    drafts: &BTreeMap<ItemId, Draft>,
    live: &[ItemId],
    cycles: &mut Vec<Vec<ItemId>>,
) {
    let mut status: BTreeMap<ItemId, u8> = BTreeMap::new();
    for &start in live {
        if status.get(&start).copied().unwrap_or(0) == 2 {
            continue;
        }
        let mut path: Vec<ItemId> = Vec::new();
        let mut cur = start;
        loop {
            match status.get(&cur).copied().unwrap_or(0) {
                2 => break,
                1 => {
                    if let Some(pos) = path.iter().position(|x| *x == cur) {
                        let mut cycle = path[pos..].to_vec();
                        cycle.sort();
                        cycle.dedup();
                        cycles.push(cycle);
                    }
                    break;
                }
                _ => {}
            }
            status.insert(cur, 1);
            path.push(cur);
            let Some(parent) = drafts.get(&cur).and_then(|d| d.state.parent_id) else {
                break;
            };
            match drafts.get(&parent) {
                Some(d) if !d.state.deleted && d.state.kind == ItemKind::Directory => cur = parent,
                _ => break,
            }
        }
        for id in &path {
            status.insert(*id, 2);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn place_one(
    builder: &Builder<'_>,
    id: ItemId,
    upsert_set: &BTreeSet<ItemId>,
    placed: &mut BTreeSet<ItemId>,
    occ: &mut BTreeMap<(Option<ItemId>, Vec<u8>), ItemId>,
    order: &mut Vec<ItemId>,
    in_progress: &mut BTreeSet<ItemId>,
) -> Result<(), ()> {
    if placed.contains(&id) {
        return Ok(());
    }
    if in_progress.contains(&id) {
        return Err(());
    }
    in_progress.insert(id);
    let state = &builder.drafts[&id].state;
    // Parents that are themselves being upserted must be placed first.
    if let Some(parent) = state.parent_id {
        if upsert_set.contains(&parent) && !placed.contains(&parent) {
            place_one(builder, parent, upsert_set, placed, occ, order, in_progress)?;
        }
    }
    let target = (state.parent_id, names::collision_key(&state.name));
    if let Some(&other) = occ.get(&target) {
        if other != id {
            if upsert_set.contains(&other) && !placed.contains(&other) {
                place_one(builder, other, upsert_set, placed, occ, order, in_progress)?;
            } else {
                in_progress.remove(&id);
                return Err(());
            }
        }
    }
    if let Some(old) = builder.remote.get(id) {
        let old_key = (old.parent_id, names::collision_key(&old.name));
        if occ.get(&old_key) == Some(&id) {
            occ.remove(&old_key);
        }
    }
    occ.insert(target, id);
    in_progress.remove(&id);
    placed.insert(id);
    order.push(id);
    Ok(())
}
