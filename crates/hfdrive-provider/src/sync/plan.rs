//! Reconciliation integration: durable state -> pure core plan -> durable
//! plan records.
//!
//! The pure merge lives in `hfdrive_core::reconcile`; this module prepares its
//! complete inputs and persists its outputs before anything executes:
//!
//! * **base** — the remembered common-base namespace (`common_bases` rows),
//!   sealed at the base commit when the base advances;
//! * **remote** — the committed catalog walked from the current `HEAD`
//!   (authoritative; the bucket tree is never the namespace);
//! * **local** — the durable outbox intents (only content-complete ones join
//!   a planning round).
//!
//! Non-conflict identifiers are supplied by this side ([`RandomIds`]) and the
//! produced local actions/conflicts are persisted **before** any effect runs.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hfdrive_core::catalog::{CatalogReader, CatalogRoot, PageSource};
use hfdrive_core::format::{self, ItemRecord};
use hfdrive_core::ids::{ActionId, CommitId, ConnectionId, ItemId, OperationId, WorkspaceId};
use hfdrive_core::reconcile::{
    CatalogView, ConflictRecord as CoreConflict, IdSource, ItemState, LocalIntent, LocalOrigin,
    OrdinalIgnoreCase, PlannedVersion, ReconcileError, ReconcileInput, ReconcileMode, ReconcilePlan,
};
use hfdrive_core::storage::Sha256Digest;
use hfdrive_state::{
    AccountStore, CommonBaseRecord, ConflictResolution, LocalAction, LocalActionState, OutboxEntry,
    OutboxState,
};
use hfdrive_state::ItemKind as StateItemKind;
use tokio_util::sync::CancellationToken;

use crate::sync::outbox::{SyncIntent, parse_intent};
use crate::sync::remote::{RemoteError, RemoteOps};

/// Random UUIDv4 action identifiers, persisted before their effects.
pub struct RandomIds;

impl IdSource for RandomIds {
    fn action_id(&mut self) -> ActionId {
        ActionId::new()
    }
}

/// Failure while preparing or persisting a plan. `MissingContext` names what
/// the views lack; plans are never guessed from partial input.
#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    #[error("reconciliation input is incomplete: {0}")]
    MissingContext(String),
    #[error("reconciliation refused the input: {0}")]
    Rejected(String),
    #[error("remote read failed: {0}")]
    Remote(#[from] RemoteError),
    #[error("durable state failed: {0}")]
    State(#[from] hfdrive_state::StateError),
    #[error("remote record violated the managed format")]
    UnsupportedFormat,
}

impl From<ReconcileError> for PlanError {
    fn from(error: ReconcileError) -> Self {
        match error {
            ReconcileError::MissingContext(refs) => {
                PlanError::MissingContext(format!("{refs:?}"))
            }
            other => PlanError::Rejected(format!("{other:?}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Catalog sources
// ---------------------------------------------------------------------------
/// One immutable remote namespace. The commit and its verified catalog root
/// both participate, so neither another connection nor another workspace can
/// reuse a view merely because it names the same commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RemoteViewKey {
    pub connection: ConnectionId,
    pub workspace: WorkspaceId,
    pub commit: CommitId,
    pub catalog_root: CatalogRoot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BaseViewKey {
    connection: ConnectionId,
    workspace: WorkspaceId,
    applied_commit: CommitId,
}

#[derive(Default)]
struct CachedViews {
    base: Option<(BaseViewKey, Arc<CatalogView>)>,
    remote: Option<(RemoteViewKey, Arc<CatalogView>)>,
}

/// Runtime-owned, two-slot cache: one full sealed base and one remote view.
/// Replacement evicts the previous slot; no commit history accumulates here.
/// The async lock covers misses as well as hits, so concurrent callers cannot
/// duplicate a load. Only successful complete views enter the cache.
///
/// HEAD/commit verification, local intent loading, materialization evidence
/// and reconciliation remain per-round work. In particular, the K16 planning
/// overlay must never replace the full base retained here.
#[derive(Default)]
pub struct PlanCache {
    views: tokio::sync::Mutex<CachedViews>,
}

impl PlanCache {
    pub(crate) async fn load<R: RemoteOps>(
        &self,
        state: &AccountStore,
        remote: &R,
        key: RemoteViewKey,
        applied_commit: Option<CommitId>,
        cancel: &CancellationToken,
    ) -> Result<(Arc<CatalogView>, Arc<CatalogView>), PlanError> {
        let applied_commit = applied_commit
            .ok_or_else(|| PlanError::MissingContext("applied common-base commit".to_owned()))?;
        let base_key = BaseViewKey {
            connection: key.connection, workspace: key.workspace, applied_commit,
        };
        let mut views = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(RemoteError::Cancelled.into()),
            views = self.views.lock() => views,
        };
        let source = RemoteDigests::new(remote, key.workspace);
        let mut digests = DigestResolver::new(&source, cancel);
        let base = match &views.base {
            Some((cached_key, view)) if *cached_key == base_key => Arc::clone(view),
            _ => {
                views.base = None;
                let view = Arc::new(build_base_view(
                    state, key.connection, Some(applied_commit), &mut digests,
                ).await?);
                views.base = Some((base_key, Arc::clone(&view)));
                view
            }
        };
        let remote = match &views.remote {
            Some((cached_key, view)) if *cached_key == key => Arc::clone(view),
            _ => {
                views.remote = None;
                let view = Arc::new(build_remote_view(
                    remote, key.catalog_root, &mut digests, cancel,
                ).await?);
                views.remote = Some((key, Arc::clone(&view)));
                view
            }
        };
        Ok((base, remote))
    }
}


/// Page source backed by bounded remote metadata reads with a per-cycle
/// content-hash cache. A page whose bytes do not hash to their address is
/// storage corruption and is never returned as valid.
pub struct RemotePages<'a, R: RemoteOps> {
    remote: &'a R,
    cache: HashMap<Sha256Digest, Option<hfdrive_core::format::CatalogPage>>,
    cancel: &'a CancellationToken,
}

impl<'a, R: RemoteOps> RemotePages<'a, R> {
    pub fn new(remote: &'a R, cancel: &'a CancellationToken) -> Self {
        Self { remote, cache: HashMap::new(), cancel }
    }
}

impl<R: RemoteOps> PageSource for RemotePages<'_, R> {
    type Error = RemoteError;

    fn load(
        &mut self,
        page_id: Sha256Digest,
    ) -> impl Future<Output = Result<Option<hfdrive_core::format::CatalogPage>, Self::Error>> + Send
    {
        async move {
            if let Some(cached) = self.cache.get(&page_id) {
                return Ok(cached.clone());
            }
            let record = hfdrive_publication::MetadataRecord::Catalog(page_id);
            let body = match self.remote.read_metadata(record, self.cancel).await {
                Ok(body) => body,
                Err(RemoteError::RemoteContentUnavailable) => {
                    self.cache.insert(page_id, None);
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
            let page = format::from_page_bytes(&body)
                .map_err(|_| RemoteError::InvalidResponse)?;
            let (hash, _) = hfdrive_core::catalog::encode_and_hash(&page)
                .map_err(|_| RemoteError::InvalidResponse)?;
            if hash != page_id {
                return Err(RemoteError::InvalidResponse);
            }
            self.cache.insert(page_id, Some(page.clone()));
            Ok(Some(page))
        }
    }
}

/// The prepared merge inputs.
pub struct PlanSources {
    pub base: Arc<CatalogView>,
    pub remote: Arc<CatalogView>,
    pub intents: Vec<LocalIntent>,
}

/// A planning round's result, already persisted where durability matters.
pub struct PlannedRound {
    pub plan: ReconcilePlan,
    /// Per-outbox-operation planning outcome.
    pub outcomes: Vec<(OperationId, IntentOutcomeKind)>,
}

/// Where each intent landed. Mirrors the core kinds with a local alias so the
/// controller does not import the whole core surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentOutcomeKind {
    Published,
    Converged,
    Superseded,
    Conflicted,
    Deferred,
}

impl From<hfdrive_core::reconcile::IntentOutcomeKind> for IntentOutcomeKind {
    fn from(value: hfdrive_core::reconcile::IntentOutcomeKind) -> Self {
        match value {
            hfdrive_core::reconcile::IntentOutcomeKind::Published => Self::Published,
            hfdrive_core::reconcile::IntentOutcomeKind::Converged => Self::Converged,
            hfdrive_core::reconcile::IntentOutcomeKind::Superseded => Self::Superseded,
            hfdrive_core::reconcile::IntentOutcomeKind::Conflicted => Self::Conflicted,
            hfdrive_core::reconcile::IntentOutcomeKind::Deferred => Self::Deferred,
        }
    }
}

/// Builds the local intents of one planning round from durable outbox entries.
/// Content intents join only when their payload is bound (`object_ref`);
/// metadata-only intents always join. Origin is always `LocalEdit`: intents
/// created from provider-applied materialization never exist (echo
/// suppression), and `Materialized` bookkeeping never publishes.
pub fn build_local_intents(
    entries: &[OutboxEntry],
    base: &CatalogView,
    remote: &CatalogView,
) -> Vec<LocalIntent> {
    let mut intents = Vec::new();
    for entry in entries {
        if entry.state == OutboxState::Complete {
            continue;
        }
        let Ok(intent) = parse_intent(entry) else { continue; };
        let needs_content = intent.has_content();
        if needs_content && entry.object_ref.is_none() {
            // Payload not bound yet; this entry joins a later round.
            continue;
        }
        let name = remote.get(intent.item_id())
            .or_else(|| base.get(intent.item_id()))
            .map(|item| item.name.as_str())
            .unwrap_or_default();
        if let Some(local) = intent.to_local_intent(
            entry.operation_id,
            LocalOrigin::LocalEdit,
            entry.observed_generation,
            name,
            entry.object_ref.as_ref(),
        ) {
            intents.push(local);
        }
    }
    intents
}

/// Assembles only the sealed namespace of the applied base commit.
pub async fn build_base_view<D: DigestSource>(
    state: &AccountStore,
    connection: ConnectionId,
    commit: Option<CommitId>,
    digests: &mut DigestResolver<'_, D>,
) -> Result<CatalogView, PlanError> {
    let commit = commit.ok_or_else(|| PlanError::MissingContext("applied common-base commit".to_owned()))?;
    let rows = state.list_common_bases(connection, commit).await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        let record = format::from_item_record_bytes(row.item_json.as_bytes())
            .map_err(|_| PlanError::UnsupportedFormat)?;
        let (sha256, size) = digests.resolve(&record).await?;
        items.push(ItemState::from_record(&record, sha256, size)?);
    }
    Ok(CatalogView::new(items)?)
}

/// Included generation-zero items are materialization candidates only if
/// their registry path is actually missing. Present items retain their
/// base until local discovery can observe them; unreadable paths fail closed.
pub(crate) async fn missing_materializations(
    state: &AccountStore,
    connection: ConnectionId,
    root: &Path,
) -> Result<HashSet<ItemId>, PlanError> {
    let mut missing = HashSet::new();
    for item in state.unmaterialized_items(connection).await? {
        if item.parent_id.is_none()
            || crate::sync::observe::excluded_here(state, connection, item.item_id).await
        {
            continue;
        }
        let path = crate::sync::controller::registry_path(state, connection, item.item_id)
            .await.ok_or_else(|| PlanError::MissingContext("materialization item path".to_owned()))?;
        match std::fs::symlink_metadata(root.join(path)) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.insert(item.item_id);
            }
            Err(_) => return Err(PlanError::MissingContext("materialization path is unreadable".to_owned())),
        }
    }
    Ok(missing)
}

/// Builds a planning-only base that treats missing selected items as not yet
/// materialized. Removing their descendants preserves parent closure, even if
/// a descendant still has older observation evidence. The sealed common-base
/// rows are untouched; the unchanged remote view then plans guarded creates.
pub(crate) fn materialization_base(
    base: Arc<CatalogView>,
    mut missing: HashSet<ItemId>,
) -> Result<Arc<CatalogView>, PlanError> {
    if missing.is_empty() {
        return Ok(base);
    }
    if let Some(root) = base.root_id() {
        missing.remove(&root);
    }
    missing.retain(|item| base.contains(*item));
    if missing.is_empty() {
        return Ok(base);
    }
    let mut children: HashMap<ItemId, Vec<ItemId>> = HashMap::new();
    for item in base.iter() {
        if let Some(parent) = item.parent_id {
            children.entry(parent).or_default().push(item.item_id);
        }
    }
    let mut pending: Vec<_> = missing.iter().copied().collect();
    while let Some(parent) = pending.pop() {
        if let Some(descendants) = children.get(&parent) {
            for &child in descendants {
                if missing.insert(child) {
                    pending.push(child);
                }
            }
        }
    }
    Ok(Arc::new(CatalogView::new(base.iter().filter(|item| !missing.contains(&item.item_id)).cloned().collect())?))
}

/// Walks the committed remote catalog into a complete namespace view.
pub async fn build_remote_view<R: RemoteOps>(
    remote: &R,
    root: CatalogRoot,
    digests: &mut DigestResolver<'_, RemoteDigests<'_, R>>,
    cancel: &CancellationToken,
) -> Result<CatalogView, PlanError> {
    let mut pages = RemotePages::new(remote, cancel);
    let mut reader = CatalogReader::new(&mut pages, root);
    let mut records: Vec<ItemRecord> = Vec::new();
    {
        let mut collect = |key: String, value: format::IndexValue| {
            match format::parse_index_key(&key).map_err(hfdrive_core::catalog::CatalogError::Format)? {
                format::IndexKey::Item { item_id } => match value {
                    format::IndexValue::Item(item) if item.item_id == item_id => {
                        records.push(item);
                        Ok(())
                    }
                    _ => Err(hfdrive_core::catalog::CatalogError::Invariant(
                        "item key/value mismatch",
                    )),
                },
                _ => Ok(()),
            }
        };
        reader
            .scan_prefix("i/", &mut collect)
            .await
            .map_err(|_| PlanError::UnsupportedFormat)?;
    }
    let mut items = Vec::with_capacity(records.len());
    for record in &records {
        let (sha256, size) = digests.resolve(record).await?;
        items.push(ItemState::from_record(record, sha256, size)?);
    }
    Ok(CatalogView::new(items)?)
}

/// Resolves a file record's content digest/size from the remote version
/// records (bounded reads; cached by immutable version for the planning cycle).
/// Tombstones retain their binding; content-less records resolve to `None`.
pub struct DigestResolver<'a, D: DigestSource> {
    remote: &'a D,
    cancel: &'a CancellationToken,
    cache: HashMap<hfdrive_core::ids::VersionId, (Sha256Digest, u64)>,
}

/// Narrow read seam so the resolver works against any remote boundary.
pub trait DigestSource: Send + Sync {
    fn version_digest(
        &self,
        version: hfdrive_core::ids::VersionId,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<(Sha256Digest, u64), RemoteError>> + Send;
}

impl<'a, D: DigestSource> DigestResolver<'a, D> {
    pub fn new(remote: &'a D, cancel: &'a CancellationToken) -> Self {
        Self { remote, cancel, cache: HashMap::new() }
    }

    pub async fn resolve(
        &mut self,
        record: &ItemRecord,
    ) -> Result<(Option<Sha256Digest>, Option<u64>), PlanError> {
        let Some(version) = record.content_version_id else { return Ok((None, None)); };
        let (sha256, size) = match self.cache.get(&version) {
            Some(cached) => *cached,
            None => {
                let binding = self.remote.version_digest(version, self.cancel).await?;
                self.cache.insert(version, binding);
                binding
            }
        };
        Ok((Some(sha256), Some(size)))
    }
}

// ---------------------------------------------------------------------------
// Planning round
// ---------------------------------------------------------------------------

/// Runs one pure reconciliation round. Plan records are persisted separately
/// ([`persist_plan_records`]) once the caller has bound the local file
/// identity/generation/USN expectations.
pub async fn plan_round(
    state: &AccountStore,
    connection: ConnectionId,
    workspace: hfdrive_core::ids::WorkspaceId,
    mode: ReconcileMode,
    sources: &PlanSources,
) -> Result<PlannedRound, PlanError> {
    let _ = (state, connection);
    let input = ReconcileInput {
        workspace_id: workspace,
        mode,
        base: &sources.base,
        local: &sources.intents,
        remote: &sources.remote,
        ntfs: &OrdinalIgnoreCase,
    };
    let mut ids = RandomIds;
    let plan = hfdrive_core::reconcile::reconcile(&input, &mut ids)?;
    let outcomes = plan
        .intents
        .iter()
        .map(|outcome| (outcome.operation_id, outcome.outcome.into()))
        .collect();
    Ok(PlannedRound { plan, outcomes })
}

/// One local action's expected local file facts, resolved against the live
/// filesystem at persist time. `None` expectations are never faked as
/// matches.
pub struct ActionFacts {
    pub source_path: Option<PathBuf>,
    pub target_path: Option<PathBuf>,
    pub expected_file_id: Option<String>,
    pub expected_generation: Option<u64>,
    pub expected_usn: Option<u64>,
}

/// Persists every local action and conflict record of a plan **before** any
/// effect runs. `facts` binds each action to the caller-observed local file
/// identity/generation/USN.
pub async fn persist_plan_records(
    state: &AccountStore,
    connection: ConnectionId,
    plan: &ReconcilePlan,
    facts: &HashMap<ActionId, ActionFacts>,
) -> Result<(), PlanError> {
    let pending = state.pending_local_actions(connection).await?;
    for action in &plan.local_actions {
        let bound = facts.get(&action.action_id);
        let kind = map_action_kind(action.action);
        let old_version = action.expected.as_ref().and_then(|item| item.content_version_id);
        let new_version = action.target.as_ref().and_then(|item| item.content_version_id);
        // A retry must retain the original guard, not bless newly observed drift.
        if pending.iter().any(|row| row.item_id == Some(action.item_id)
            && row.kind == kind && row.old_version == old_version && row.new_version == new_version
            && row.source_path.as_ref() == bound.and_then(|facts| facts.source_path.as_ref())
            && row.target_path.as_ref() == bound.and_then(|facts| facts.target_path.as_ref()))
        {
            continue;
        }
        let row = LocalAction {
            connection_id: connection,
            action_id: action.action_id,
            item_id: Some(action.item_id),
            kind,
            expected_file_id: bound.and_then(|f| f.expected_file_id.clone()),
            expected_generation: bound.and_then(|f| f.expected_generation),
            expected_usn: bound.and_then(|f| f.expected_usn),
            old_version,
            new_version,
            source_path: bound.and_then(|f| f.source_path.clone()),
            target_path: bound.and_then(|f| f.target_path.clone()),
            recovery_path: None,
            state: LocalActionState::Pending,
        };
        state.record_local_action(row).await?;
    }
    // G04: every create action's target item metadata is durable **before**
    // any effect runs. A `CreatePlaceholder` resolves its registry item (kind
    // and the bound version's size) at execution time, so the verified target
    // view/plan must already carry it — never a lookup that only succeeds
    // after `advance_base` runs later in the round. Rename/update targets are
    // not persisted here: their registry rows must keep the pre-move facts
    // until the guarded local action actually applied.
    persist_target_records(state, connection, plan).await?;
    for conflict in &plan.conflicts {
        state.record_conflict(to_state_conflict(connection, conflict)).await?;
    }
    Ok(())
}

/// Persists the registry records of every planned `CreatePlaceholder`
/// action's **target** state from the verified plan, before any effect runs.
/// The target states are exactly the reconciled records the plan
/// materializes; the registry row shape is the same one [`registry_item`]
/// builds for a committed record, so a later `advance_base` write of the same
/// record is an identical-row skip in the state layer rather than a second
/// rewrite.
pub async fn persist_target_records(
    state: &AccountStore,
    connection: ConnectionId,
    plan: &ReconcilePlan,
) -> Result<(), PlanError> {
    let mut rows = Vec::new();
    for action in &plan.local_actions {
        if action.action != hfdrive_core::reconcile::LocalActionKind::CreatePlaceholder {
            continue;
        }
        let Some(target) = action.target.as_ref() else { continue; };
        if rows.iter().any(|row: &hfdrive_state::ItemRecord| row.item_id == target.item_id) {
            continue;
        }
        rows.push(target_registry_item(connection, target, &plan.versions));
    }
    // One worker command and one transaction; identical rows are not
    // rewritten by the state layer.
    state.upsert_items(rows).await?;
    Ok(())
}

/// The durable registry entry for one planned target state, with the payload
/// identity of its bound version (`modified_at` is display-only and never
/// part of identity).
pub fn target_registry_item(
    connection: ConnectionId,
    target: &ItemState,
    versions: &[PlannedVersion],
) -> hfdrive_state::ItemRecord {
    let record = target.to_record();
    let modified_at = record
        .content_version_id
        .and_then(|version| {
            versions
                .iter()
                .find(|planned| planned.version_id == version)
        })
        .map(|planned| planned.display.modified_at.clone());
    registry_item(
        connection,
        &record,
        target.content_sha256,
        target.content_size,
        modified_at,
    )
}

fn map_action_kind(kind: hfdrive_core::reconcile::LocalActionKind) -> hfdrive_state::LocalActionKind {
    match kind {
        hfdrive_core::reconcile::LocalActionKind::PreserveDirty => hfdrive_state::LocalActionKind::Other,
        hfdrive_core::reconcile::LocalActionKind::CreatePlaceholder => {
            hfdrive_state::LocalActionKind::CreatePlaceholder
        }
        hfdrive_core::reconcile::LocalActionKind::Rename => hfdrive_state::LocalActionKind::Rename,
        hfdrive_core::reconcile::LocalActionKind::UpdatePlaceholder => {
            hfdrive_state::LocalActionKind::UpdatePlaceholder
        }
        hfdrive_core::reconcile::LocalActionKind::DeletePlaceholder => {
            hfdrive_state::LocalActionKind::DeletePlaceholder
        }
    }
}

fn to_state_conflict(connection: ConnectionId, conflict: &CoreConflict) -> hfdrive_state::ConflictRecord {
    hfdrive_state::ConflictRecord {
        connection_id: connection,
        conflict_id: conflict.conflict_id,
        item_id: conflict.item_id,
        competing_ops: conflict.competing_operations.clone(),
        revisions_json: serde_json::json!({
            "kind": conflict.kind.tag(),
            "sides": conflict.sides.iter().map(|side| serde_json::json!({
                "operation_id": side.operation_id.to_string(),
                "parent_id": side.parent_id.map(|id| id.to_string()),
                "name": side.name,
                "content_version_id": side.content_version_id.map(|id| id.to_string()),
            })).collect::<Vec<_>>(),
            "preserved_item_id": conflict.preserved_item_id.map(|id| id.to_string()),
            "preserved_version_id": conflict.preserved_version_id.map(|id| id.to_string()),
        }),
        original_names: conflict
            .sides
            .iter()
            .map(|side| side.name.clone())
            .collect(),
        resolution_state: ConflictResolution::Unresolved,
        detected_at_ms: None,
    }
}

/// Maps the item registry entry to the state model kind.
pub fn state_kind(kind: hfdrive_core::format::ItemKind) -> StateItemKind {
    match kind {
        hfdrive_core::format::ItemKind::File => StateItemKind::File,
        hfdrive_core::format::ItemKind::Directory => StateItemKind::Directory,
    }
}

/// Seeds or advances the remembered common-base namespace with one commit's
/// item records. One worker command and one transaction: every record lands
/// or none does.
pub async fn record_common_bases(
    state: &AccountStore,
    connection: ConnectionId,
    commit: CommitId,
    records: &[ItemRecord],
) -> Result<(), PlanError> {
    let mut rows = Vec::with_capacity(records.len());
    for record in records {
        let item_json = String::from_utf8(format::to_item_record_bytes(record).map_err(|_| PlanError::UnsupportedFormat)?)
            .map_err(|_| PlanError::UnsupportedFormat)?;
        rows.push(CommonBaseRecord {
            connection_id: connection,
            item_id: record.item_id,
            commit_id: commit,
            item_json,
        });
    }
    // One worker command and one transaction for the whole sealed namespace;
    // the per-row write flags are a diagnostic only — success is the completed
    // batch command, never a per-row flag.
    let written = state.put_common_bases(rows).await?;
    debug_assert_eq!(written.len(), records.len(), "one flag is reported per requested record");
    Ok(())
}

/// The durable item registry entry for one applied/pending item. `modified_at`
/// is display-only metadata from the bound version record (RFC 3339 UTC, whole
/// seconds); it never participates in identity.
pub fn registry_item(
    connection: ConnectionId,
    record: &ItemRecord,
    digest: Option<Sha256Digest>,
    size: Option<u64>,
    modified_at: Option<String>,
) -> hfdrive_state::ItemRecord {
    hfdrive_state::ItemRecord {
        connection_id: connection,
        item_id: record.item_id,
        parent_id: record.parent_id,
        name: record.name.clone(),
        name_key: String::from_utf8(hfdrive_core::names::collision_key(&record.name)).expect("collision keys are UTF-8"),
        kind: state_kind(record.kind),
        revision: record.item_revision,
        content_version_id: record.content_version_id,
        deleted: record.deleted,
        metadata_json: serde_json::json!({
            "sha256": digest.map(|d| d.to_string()),
            "size": size,
            "modified_at": modified_at,
            "content_operation": record.content_operation.to_string(),
            "location_operation": record.location_operation.to_string(),
            "deletion_operation": record.deletion_operation.map(|d| d.to_string()),
        }),
    }
}

/// Parses a registry row back into the canonical item record shape. The
/// revision/operation provenance is reconstructed from `metadata_json`.
pub fn registry_record(item: &hfdrive_state::ItemRecord) -> Option<ItemRecord> {
    let content_operation = item
        .metadata_json
        .get("content_operation")
        .and_then(|v| v.as_str())
        .and_then(|v| v.parse().ok())?;
    let location_operation = item
        .metadata_json
        .get("location_operation")
        .and_then(|v| v.as_str())
        .and_then(|v| v.parse().ok())?;
    let deletion_operation = item
        .metadata_json
        .get("deletion_operation")
        .and_then(|v| v.as_str())
        .and_then(|v| v.parse().ok());
    Some(ItemRecord {
        item_id: item.item_id,
        parent_id: item.parent_id,
        name: item.name.clone(),
        kind: match item.kind {
            StateItemKind::File => hfdrive_core::format::ItemKind::File,
            StateItemKind::Directory => hfdrive_core::format::ItemKind::Directory,
        },
        item_revision: item.revision,
        content_version_id: item.content_version_id,
        deleted: item.deleted,
        content_operation,
        location_operation,
        deletion_operation,
    })
}

/// Parses the cached digest/size of a registry row.
pub fn registry_digest(item: &hfdrive_state::ItemRecord) -> (Option<Sha256Digest>, Option<u64>) {
    let sha256 = item
        .metadata_json
        .get("sha256")
        .and_then(|v| v.as_str())
        .and_then(|v| v.parse().ok());
    let size = item.metadata_json.get("size").and_then(|v| v.as_u64());
    (sha256, size)
}

/// The intent family of one outbox entry, for the controller's dispatch.
pub fn intent_of(entry: &OutboxEntry) -> Option<SyncIntent> {
    parse_intent(entry).ok()
}

/// Every pending entry's item, used to bind planning outcomes back to
/// outbox rows.
pub fn entry_item(entry: &OutboxEntry) -> Option<ItemId> {
    entry.item_id.or_else(|| intent_of(entry).map(|intent| intent.item_id()))
}

/// Whether an outbox entry is content-complete and eligible for planning.
pub fn ready_to_plan(entry: &OutboxEntry) -> bool {
    if entry.state == OutboxState::Complete {
        return false;
    }
    match intent_of(entry) {
        Some(intent) => !intent.has_content() || entry.object_ref.is_some(),
        None => false,
    }
}

/// A `DigestSource` implementation over the remote boundary, bound to one
/// connection's workspace. The returned record must prove the requested
/// identity itself: a body naming another version or another workspace is a
/// different payload binding (or foreign storage) and never resolves this
/// request.
pub struct RemoteDigests<'a, R: RemoteOps> {
    remote: &'a R,
    workspace: WorkspaceId,
}

impl<'a, R: RemoteOps> RemoteDigests<'a, R> {
    pub fn new(remote: &'a R, workspace: WorkspaceId) -> Self {
        Self { remote, workspace }
    }
}

impl<R: RemoteOps> DigestSource for RemoteDigests<'_, R> {
    async fn version_digest(
        &self,
        version: hfdrive_core::ids::VersionId,
        cancel: &CancellationToken,
    ) -> Result<(Sha256Digest, u64), RemoteError> {
        let record = hfdrive_publication::MetadataRecord::Version(version);
        let body = self.remote.read_metadata(record, cancel).await?;
        let version_record = format::from_version_bytes(&body)
            .map_err(|_| RemoteError::InvalidResponse)?;
        if version_record.workspace_id != self.workspace || version_record.version_id != version {
            return Err(RemoteError::InvalidResponse);
        }
        Ok((version_record.sha256, version_record.size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache_records(root_item: ItemId) -> [ItemRecord; 2] {
        let revision = OperationId::new();
        let root = ItemRecord {
            item_id: root_item, parent_id: None, name: String::new(),
            kind: format::ItemKind::Directory, item_revision: revision,
            content_version_id: None, deleted: false, content_operation: revision,
            location_operation: revision, deletion_operation: None,
        };
        let file = ItemRecord {
            item_id: ItemId::new(), parent_id: Some(root_item), name: "file.bin".to_owned(),
            kind: format::ItemKind::File, content_version_id: Some(hfdrive_core::ids::VersionId::new()),
            ..root.clone()
        };
        [root, file]
    }

    #[tokio::test]
    async fn plan_cache_coalesces_loads_and_shares_complete_views() {
        use crate::sync::test_support::{HeadOnlyRemote, connection_fixture, version_metadata};
        use hfdrive_publication::MetadataRecord;
        let fixture = connection_fixture().await;
        let base_records = cache_records(fixture.root_item);
        let applied = CommitId::new();
        record_common_bases(&fixture.account, fixture.connection, applied, &base_records).await.unwrap();
        let mut current = base_records.clone();
        current[1].content_version_id = Some(hfdrive_core::ids::VersionId::new());
        current[1].content_operation = OperationId::new();
        current[1].item_revision = current[1].content_operation;
        let commit = CommitId::new();
        let (mut remote, catalog_root) = HeadOnlyRemote::catalog(fixture.workspace, commit, &current).await;
        let base_version = base_records[1].content_version_id.unwrap();
        let remote_version = current[1].content_version_id.unwrap();
        remote.records.push((MetadataRecord::Version(base_version), version_metadata(fixture.workspace, base_version)));
        let key = RemoteViewKey {
            connection: fixture.connection, workspace: fixture.workspace, commit, catalog_root,
        };
        let cancel = CancellationToken::new();
        let cache = &fixture.plan_cache;
        let (first, second) = tokio::join!(
            cache.load(&fixture.account, &remote, key, Some(applied), &cancel),
            cache.load(&fixture.account, &remote, key, Some(applied), &cancel),
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert!(Arc::ptr_eq(&first.0, &second.0));
        assert!(Arc::ptr_eq(&first.1, &second.1));
        assert_eq!(first.0.get(base_records[1].item_id).unwrap().content_version_id, Some(base_version));
        assert_eq!(first.1.get(base_records[1].item_id).unwrap().content_version_id, Some(remote_version));
        assert_eq!(remote.metadata_read_count(MetadataRecord::Version(base_version)), 1, "one base load");
        assert_eq!(remote.metadata_read_count(MetadataRecord::Version(remote_version)), 1, "one remote load");
        assert_eq!(remote.metadata_read_count(MetadataRecord::Catalog(catalog_root.digest())), 1);

        // A hit needs neither a SQL namespace read nor any immutable metadata:
        // closing the real worker makes an accidental base reload fail.
        fixture.state.close().await.unwrap();
        let hit = cache.load(&fixture.account, &remote, key, Some(applied), &cancel).await.unwrap();
        assert!(Arc::ptr_eq(&hit.0, &first.0));
        assert!(Arc::ptr_eq(&hit.1, &first.1));
        assert_eq!(remote.metadata_reads.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn plan_cache_rebuilds_changed_keys_and_evicts_previous_views() {
        use crate::sync::test_support::{HeadOnlyRemote, connection_fixture};
        use hfdrive_publication::MetadataRecord;
        let fixture = connection_fixture().await;
        let records = cache_records(fixture.root_item);
        let applied = CommitId::new();
        record_common_bases(&fixture.account, fixture.connection, applied, &records).await.unwrap();
        let (remote, catalog_root) = HeadOnlyRemote::catalog(fixture.workspace, applied, &records).await;
        let key = RemoteViewKey {
            connection: fixture.connection, workspace: fixture.workspace, commit: applied, catalog_root,
        };
        let cache = PlanCache::default();
        let cancel = CancellationToken::new();
        let first = cache.load(&fixture.account, &remote, key, Some(applied), &cancel).await.unwrap();
        let old_base = Arc::downgrade(&first.0);
        let old_remote = Arc::downgrade(&first.1);

        // A new HEAD commit misses even if its tree is byte-identical.
        let new_commit = CommitId::new();
        let (same_tree, same_root) = HeadOnlyRemote::catalog(fixture.workspace, new_commit, &records).await;
        assert_eq!(catalog_root, same_root);
        let changed_head = RemoteViewKey { commit: new_commit, ..key };
        let second = cache.load(&fixture.account, &same_tree, changed_head, Some(applied), &cancel).await.unwrap();
        assert!(Arc::ptr_eq(&first.0, &second.0));
        assert!(!Arc::ptr_eq(&first.1, &second.1));
        assert_eq!(same_tree.metadata_read_count(MetadataRecord::Catalog(catalog_root.digest())), 1);

        // The root is independently load-bearing in the key.
        let mut renamed = records.clone();
        renamed[1].name = "remote-name.bin".to_owned();
        let (changed_tree, new_root) = HeadOnlyRemote::catalog(fixture.workspace, new_commit, &renamed).await;
        assert_ne!(catalog_root, new_root);
        let changed_root = RemoteViewKey { catalog_root: new_root, ..changed_head };
        let third = cache.load(&fixture.account, &changed_tree, changed_root, Some(applied), &cancel).await.unwrap();
        assert!(Arc::ptr_eq(&second.0, &third.0));
        assert!(!Arc::ptr_eq(&second.1, &third.1));
        assert_eq!(third.1.get(records[1].item_id).unwrap().name, "remote-name.bin");
        assert_eq!(changed_tree.metadata_read_count(MetadataRecord::Catalog(new_root.digest())), 1);

        let next_applied = CommitId::new();
        let mut next_base = records.clone();
        next_base[1].name = "applied-name.bin".to_owned();
        record_common_bases(&fixture.account, fixture.connection, next_applied, &next_base).await.unwrap();
        fixture.account.set_baseline(fixture.connection, hfdrive_state::BaselineKind::Applied, Some(next_applied)).await.unwrap();
        let baseline = fixture.account.baseline(fixture.connection).await.unwrap();
        let fourth = cache.load(&fixture.account, &changed_tree, changed_root, baseline.applied_commit, &cancel).await.unwrap();
        assert!(!Arc::ptr_eq(&third.0, &fourth.0));
        assert!(Arc::ptr_eq(&third.1, &fourth.1));
        assert_eq!(fourth.0.get(records[1].item_id).unwrap().name, "applied-name.bin");
        assert_eq!(changed_tree.metadata_read_count(MetadataRecord::Version(records[1].content_version_id.unwrap())), 2);
        assert_eq!(changed_tree.metadata_read_count(MetadataRecord::Catalog(new_root.digest())), 1);

        drop((first, second, third));
        assert!(old_base.upgrade().is_none(), "only the current base is retained");
        assert!(old_remote.upgrade().is_none(), "only the current remote is retained");
        let current_base = Arc::downgrade(&fourth.0);
        let current_remote = Arc::downgrade(&fourth.1);
        drop(fourth);
        drop(cache);
        assert!(current_base.upgrade().is_none());
        assert!(current_remote.upgrade().is_none(), "runtime cache disposal retains no namespace");
        fixture.state.close().await.unwrap();
    }

    #[tokio::test]
    async fn plan_cache_never_shares_across_connection_or_workspace() {
        use crate::sync::test_support::{HeadOnlyRemote, connection_fixture};
        use hfdrive_publication::MetadataRecord;
        let first_fixture = connection_fixture().await;
        let second_fixture = connection_fixture().await;
        let records = cache_records(first_fixture.root_item);
        let applied = CommitId::new();
        for fixture in [&first_fixture, &second_fixture] {
            record_common_bases(&fixture.account, fixture.connection, applied, &records).await.unwrap();
        }
        let (remote, catalog_root) = HeadOnlyRemote::catalog(first_fixture.workspace, applied, &records).await;
        let key = RemoteViewKey {
            connection: first_fixture.connection, workspace: first_fixture.workspace,
            commit: applied, catalog_root,
        };
        let cache = PlanCache::default();
        let cancel = CancellationToken::new();
        let first = cache.load(&first_fixture.account, &remote, key, Some(applied), &cancel).await.unwrap();
        let other_connection = RemoteViewKey { connection: second_fixture.connection, ..key };
        let second = cache.load(&second_fixture.account, &remote, other_connection, Some(applied), &cancel).await.unwrap();
        assert!(!Arc::ptr_eq(&first.0, &second.0));
        assert!(!Arc::ptr_eq(&first.1, &second.1));
        assert_eq!(remote.metadata_read_count(MetadataRecord::Catalog(catalog_root.digest())), 2);
        assert_eq!(remote.metadata_read_count(MetadataRecord::Version(records[1].content_version_id.unwrap())), 2);

        let (foreign_remote, foreign_root) = HeadOnlyRemote::catalog(second_fixture.workspace, applied, &records).await;
        assert_eq!(catalog_root, foreign_root, "catalog bytes deliberately coincide");
        let other_workspace = RemoteViewKey { workspace: second_fixture.workspace, ..other_connection };
        let third = cache.load(&second_fixture.account, &foreign_remote, other_workspace, Some(applied), &cancel).await.unwrap();
        assert!(!Arc::ptr_eq(&second.0, &third.0));
        assert!(!Arc::ptr_eq(&second.1, &third.1));
        assert_eq!(foreign_remote.metadata_read_count(MetadataRecord::Catalog(catalog_root.digest())), 1);
        assert_eq!(foreign_remote.metadata_read_count(MetadataRecord::Version(records[1].content_version_id.unwrap())), 1);
        first_fixture.state.close().await.unwrap();
        second_fixture.state.close().await.unwrap();
    }

    #[tokio::test]
    async fn cached_base_rechecks_generation_zero_materialization() {
        use crate::sync::test_support::{HeadOnlyRemote, connection_fixture};
        use hfdrive_publication::MetadataRecord;
        let fixture = connection_fixture().await;
        let records = cache_records(fixture.root_item);
        let child = &records[1];
        let version = child.content_version_id.unwrap();
        let applied = CommitId::new();
        record_common_bases(&fixture.account, fixture.connection, applied, &records).await.unwrap();
        fixture.account.upsert_item(registry_item(
            fixture.connection, child, Some(Sha256Digest::of(version.as_bytes())), Some(4), None,
        )).await.unwrap();
        fixture.account.set_subtree_excluded(fixture.connection, child.item_id, true).await.unwrap();
        fixture.account.set_subtree_excluded(fixture.connection, child.item_id, false).await.unwrap();
        assert_eq!(fixture.account.observation(fixture.connection, child.item_id).await.unwrap().unwrap().generation, 0);
        let (remote, catalog_root) = HeadOnlyRemote::catalog(fixture.workspace, applied, &records).await;
        let key = RemoteViewKey {
            connection: fixture.connection, workspace: fixture.workspace, commit: applied, catalog_root,
        };
        let cancel = CancellationToken::new();
        let path = fixture.root.join(&child.name);
        std::fs::write(&path, b"data").unwrap();
        let (full_base, remote_view) = fixture.plan_cache.load(
            &fixture.account, &remote, key, Some(applied), &cancel,
        ).await.unwrap();
        let missing = missing_materializations(&fixture.account, fixture.connection, &fixture.root).await.unwrap();
        assert!(missing.is_empty());
        assert!(Arc::ptr_eq(&materialization_base(Arc::clone(&full_base), missing).unwrap(), &full_base));

        std::fs::remove_file(&path).unwrap();
        let (hit, hit_remote) = fixture.plan_cache.load(
            &fixture.account, &remote, key, Some(applied), &cancel,
        ).await.unwrap();
        assert!(Arc::ptr_eq(&hit, &full_base));
        assert!(Arc::ptr_eq(&hit_remote, &remote_view));
        let missing = missing_materializations(&fixture.account, fixture.connection, &fixture.root).await.unwrap();
        assert_eq!(missing, HashSet::from([child.item_id]));
        let sources = PlanSources {
            base: materialization_base(hit, missing).unwrap(), remote: hit_remote, intents: Vec::new(),
        };
        assert!(!sources.base.contains(child.item_id));
        assert!(full_base.contains(child.item_id), "the cached base must remain complete");
        let planned = plan_round(&fixture.account, fixture.connection, fixture.workspace, ReconcileMode::Writable, &sources).await.unwrap();
        assert!(planned.plan.remote_ops.is_empty());
        assert_eq!(planned.plan.local_actions.len(), 1);
        assert_eq!(planned.plan.local_actions[0].action, hfdrive_core::reconcile::LocalActionKind::CreatePlaceholder);
        assert!(planned.plan.local_actions[0].expected.is_none());
        assert_eq!(planned.plan.local_actions[0].target.as_ref().unwrap().content_version_id, Some(version));

        // Presence changes again with no HEAD or base change. An overlay
        // accidentally stored in the cache would keep proposing a create.
        std::fs::write(&path, b"data").unwrap();
        let (base, remote_view) = fixture.plan_cache.load(
            &fixture.account, &remote, key, Some(applied), &cancel,
        ).await.unwrap();
        let missing = missing_materializations(&fixture.account, fixture.connection, &fixture.root).await.unwrap();
        let base = materialization_base(base, missing).unwrap();
        assert!(Arc::ptr_eq(&base, &full_base));
        let sources = PlanSources { base, remote: remote_view, intents: Vec::new() };
        let planned = plan_round(&fixture.account, fixture.connection, fixture.workspace, ReconcileMode::Writable, &sources).await.unwrap();
        assert!(planned.plan.local_actions.is_empty());
        assert!(planned.plan.remote_ops.is_empty());
        assert_eq!(fixture.account.list_common_bases(fixture.connection, applied).await.unwrap().len(), records.len());
        assert_eq!(remote.metadata_read_count(MetadataRecord::Catalog(catalog_root.digest())), 1);
        assert_eq!(remote.metadata_read_count(MetadataRecord::Version(version)), 1);
        fixture.state.close().await.unwrap();
    }

    #[tokio::test]
    async fn materialization_base_keeps_present_items_and_removes_missing_parent_descendants() {
        let fixture = crate::sync::test_support::connection_fixture().await;
        let missing_parent = ItemId::new();
        let descendant = ItemId::new();
        let present = ItemId::new();
        let revision = OperationId::new();
        let root = ItemRecord {
            item_id: fixture.root_item, parent_id: None, name: String::new(),
            kind: format::ItemKind::Directory, item_revision: revision,
            content_version_id: None, deleted: false, content_operation: revision,
            location_operation: revision, deletion_operation: None,
        };
        let records = vec![
            root.clone(),
            ItemRecord { item_id: missing_parent, parent_id: Some(fixture.root_item), name: "missing".to_owned(), ..root.clone() },
            ItemRecord { item_id: descendant, parent_id: Some(missing_parent), name: "child".to_owned(), ..root.clone() },
            ItemRecord { item_id: present, parent_id: Some(fixture.root_item), name: "present".to_owned(), ..root },
        ];
        for record in &records {
            fixture.account.upsert_item(registry_item(fixture.connection, record, None, None, None)).await.unwrap();
        }
        let commit = CommitId::new();
        record_common_bases(&fixture.account, fixture.connection, commit, &records).await.unwrap();
        let sealed = fixture.account.list_common_bases(fixture.connection, commit).await.unwrap();
        fixture.account.set_subtree_excluded(fixture.connection, fixture.root_item, true).await.unwrap();
        fixture.account.set_subtree_excluded(fixture.connection, fixture.root_item, false).await.unwrap();
        fixture.account.bump_observation(fixture.connection, descendant, Some(13)).await.unwrap();
        fixture.account.set_observation_flags(fixture.connection, descendant, hfdrive_state::ObservationFlags {
            dirty: Some(false), ..Default::default()
        }).await.unwrap();
        std::fs::create_dir(fixture.root.join("present")).unwrap();

        let missing = missing_materializations(&fixture.account, fixture.connection, &fixture.root).await.unwrap();
        assert_eq!(missing, HashSet::from([missing_parent]));
        let remote = Arc::new(CatalogView::new(records.iter().map(|record| ItemState::from_record(record, None, None).unwrap()).collect()).unwrap());
        let base = materialization_base(Arc::clone(&remote), missing).unwrap();
        assert!(base.contains(present), "a present generation-zero item must retain its base");
        assert!(!base.contains(missing_parent));
        assert!(!base.contains(descendant), "omission must preserve parent closure");
        let sources = PlanSources { base, remote, intents: Vec::new() };
        let planned = plan_round(&fixture.account, fixture.connection, fixture.workspace, ReconcileMode::Writable, &sources).await.unwrap();
        assert!(planned.plan.remote_ops.is_empty());
        assert_eq!(planned.plan.local_actions.len(), 2);
        assert!(planned.plan.local_actions.iter().all(|action| {
            action.action == hfdrive_core::reconcile::LocalActionKind::CreatePlaceholder
                && action.expected.is_none()
        }));
        assert_eq!(fixture.account.list_common_bases(fixture.connection, commit).await.unwrap(), sealed);
        fixture.state.close().await.unwrap();
    }

    #[tokio::test]
    async fn common_base_view_selects_only_the_applied_commit() {
        let fixture = crate::sync::test_support::connection_fixture().await;
        let child_id = ItemId::new();
        let revision = OperationId::new();
        let root = ItemRecord {
            item_id: fixture.root_item, parent_id: None, name: String::new(),
            kind: format::ItemKind::Directory, item_revision: revision,
            content_version_id: None, deleted: false, content_operation: revision,
            location_operation: revision, deletion_operation: None,
        };
        let child = ItemRecord {
            item_id: child_id, parent_id: Some(fixture.root_item), name: "old-name".to_owned(),
            ..root.clone()
        };
        let old = CommitId::new();
        let applied = CommitId::new();
        let observed = CommitId::new();
        record_common_bases(&fixture.account, fixture.connection, old, &[root.clone(), child.clone()]).await.unwrap();
        let current_child = ItemRecord { name: "applied-name".to_owned(), ..child.clone() };
        record_common_bases(&fixture.account, fixture.connection, applied, &[root.clone(), current_child]).await.unwrap();
        let future_child = ItemRecord { name: "not-applied-name".to_owned(), ..child };
        record_common_bases(&fixture.account, fixture.connection, observed, &[root.clone(), future_child]).await.unwrap();
        fixture.account.set_baseline(fixture.connection, hfdrive_state::BaselineKind::Applied, Some(applied)).await.unwrap();
        fixture.account.set_baseline(fixture.connection, hfdrive_state::BaselineKind::Observed, Some(observed)).await.unwrap();
        let remote = crate::sync::test_support::HeadOnlyRemote::default();
        let source = RemoteDigests::new(&remote, fixture.workspace);
        let cancel = CancellationToken::new();
        let mut digests = DigestResolver::new(&source, &cancel);
        let baseline = fixture.account.baseline(fixture.connection).await.unwrap();
        let view = build_base_view(&fixture.account, fixture.connection, baseline.applied_commit, &mut digests).await.unwrap();
        let names: HashMap<_, _> = view.iter().map(|item| (item.item_id, item.name.as_str())).collect();
        assert_eq!(names, HashMap::from([(fixture.root_item, ""), (child_id, "applied-name")]));
        let older = build_base_view(&fixture.account, fixture.connection, Some(old), &mut digests).await.unwrap();
        assert_eq!(older.iter().find(|item| item.item_id == child_id).unwrap().name, "old-name");
        let absent = build_base_view(&fixture.account, fixture.connection, None, &mut digests).await;
        assert!(matches!(absent, Err(PlanError::MissingContext(_))));
        fixture.state.close().await.unwrap();
    }

    // -- K07/G13: one batch command seals the whole namespace --------------

    /// One record per requested item, verbatim, in one transaction: a failure
    /// at the third row leaves no partial namespace behind, and an identical
    /// replay rewrites nothing.
    #[tokio::test]
    async fn common_base_batch_is_complete_and_skips_identical_rows() {
        use hfdrive_core::ids::VersionId;
        let fixture = crate::sync::test_support::connection_fixture().await;
        let revision = OperationId::new();
        let root = ItemRecord {
            item_id: fixture.root_item, parent_id: None, name: String::new(),
            kind: format::ItemKind::Directory, item_revision: revision,
            content_version_id: None, deleted: false, content_operation: revision,
            location_operation: revision, deletion_operation: None,
        };
        let children: Vec<ItemRecord> = (0..4)
            .map(|index| ItemRecord {
                item_id: ItemId::new(), parent_id: Some(fixture.root_item),
                name: format!("file-{index}.bin"), kind: format::ItemKind::File,
                content_version_id: Some(VersionId::new()), ..root.clone()
            })
            .collect();
        let mut records = vec![root.clone()];
        records.extend(children.iter().cloned());
        let commit = CommitId::new();
        let database = hfdrive_state::StatePaths::new(fixture.directory.path().join("state"))
            .account(fixture.account.account_key())
            .database();

        // A failure at the third row of the batch rolls the whole batch back:
        // one transaction, one durable step. Per-row writes would leave the
        // first two rows behind, so a partial namespace is impossible.
        {
            let raw = rusqlite::Connection::open(&database).unwrap();
            raw.execute_batch(&format!(
                "CREATE TRIGGER abort_third_base BEFORE INSERT ON common_bases
                   WHEN NEW.item_id = X'{:032x}'
                   BEGIN SELECT RAISE(ABORT, 'injected batch failure'); END;",
                records[2].item_id.as_uuid().as_u128()
            ))
            .unwrap();
        }
        assert!(matches!(
            record_common_bases(&fixture.account, fixture.connection, commit, &records).await,
            Err(PlanError::State(_))
        ));
        assert!(
            fixture.account.list_common_bases(fixture.connection, commit).await.unwrap().is_empty(),
            "an aborted batch leaves no partial namespace behind"
        );
        {
            let raw = rusqlite::Connection::open(&database).unwrap();
            raw.execute_batch("DROP TRIGGER abort_third_base").unwrap();
        }

        // The retry lands the complete namespace: every requested item has a
        // row, stored verbatim.
        record_common_bases(&fixture.account, fixture.connection, commit, &records).await.unwrap();
        let stored = fixture.account.list_common_bases(fixture.connection, commit).await.unwrap();
        assert_eq!(stored.len(), records.len(), "every requested record lands");
        let sealed: HashMap<ItemId, ItemRecord> = stored
            .iter()
            .map(|row| {
                let record = format::from_item_record_bytes(row.item_json.as_bytes()).unwrap();
                (record.item_id, record)
            })
            .collect();
        for expected in &records {
            assert_eq!(sealed.get(&expected.item_id), Some(expected), "the record is stored verbatim");
        }

        // An identical replay rewrites nothing: a trigger aborting any UPDATE
        // of the table stays silent only if the batch truly writes no row.
        {
            let raw = rusqlite::Connection::open(&database).unwrap();
            raw.execute_batch(
                "CREATE TRIGGER refuse_base_rewrite BEFORE UPDATE ON common_bases
                 BEGIN SELECT RAISE(ABORT, 'identical row rewritten'); END;",
            )
            .unwrap();
        }
        record_common_bases(&fixture.account, fixture.connection, commit, &records).await.unwrap();
        {
            let raw = rusqlite::Connection::open(&database).unwrap();
            raw.execute_batch("DROP TRIGGER refuse_base_rewrite").unwrap();
        }

        // A later commit's namespace is added, never replacing an earlier one,
        // and a subset batch removes nothing.
        let later = CommitId::new();
        let mut renamed = children[0].clone();
        renamed.name = "renamed.bin".to_owned();
        record_common_bases(&fixture.account, fixture.connection, later, &[root.clone(), renamed])
            .await
            .unwrap();
        assert_eq!(
            fixture.account.list_common_bases(fixture.connection, later).await.unwrap().len(),
            2,
            "the later namespace is complete"
        );
        assert_eq!(
            fixture.account.list_common_bases(fixture.connection, commit).await.unwrap().len(),
            records.len(),
            "the earlier sealed namespace is untouched"
        );
        record_common_bases(&fixture.account, fixture.connection, commit, &records[..1]).await.unwrap();
        assert_eq!(
            fixture.account.list_common_bases(fixture.connection, commit).await.unwrap().len(),
            records.len(),
            "a subset batch never removes remembered rows"
        );
        fixture.state.close().await.unwrap();
    }

    #[tokio::test]
    async fn digest_resolution_preserves_tombstones_and_distinct_content_versions() {
        use hfdrive_core::ids::VersionId;
        struct Versions(HashMap<VersionId, (Sha256Digest, u64)>);
        impl DigestSource for Versions {
            async fn version_digest(
                &self, version: VersionId, _: &CancellationToken,
            ) -> Result<(Sha256Digest, u64), RemoteError> {
                self.0.get(&version).copied().ok_or(RemoteError::RemoteContentUnavailable)
            }
        }
        let first = VersionId::new();
        let second = VersionId::new();
        let first_digest = Sha256Digest::of(b"first");
        let second_digest = Sha256Digest::of(b"second");
        let versions = Versions(HashMap::from([(first, (first_digest, 5)), (second, (second_digest, 6))]));
        let operation = OperationId::new();
        let deletion = OperationId::new();
        let deleted = ItemRecord {
            item_id: ItemId::new(), parent_id: Some(ItemId::new()), name: "file.bin".to_owned(),
            kind: format::ItemKind::File, item_revision: deletion, content_version_id: Some(first),
            deleted: true, content_operation: operation, location_operation: operation,
            deletion_operation: Some(deletion),
        };
        let cancel = CancellationToken::new();
        let mut resolver = DigestResolver::new(&versions, &cancel);
        let (sha256, size) = resolver.resolve(&deleted).await.unwrap();
        let tombstone = ItemState::from_record(&deleted, sha256, size).unwrap();
        assert!(tombstone.deleted);
        assert_eq!(tombstone.content_version_id, Some(first));
        assert_eq!(tombstone.content_sha256, Some(first_digest));
        assert_eq!(tombstone.content_size, Some(5));
        let current = ItemRecord {
            content_version_id: Some(second), deleted: false, deletion_operation: None,
            item_revision: OperationId::new(), ..deleted
        };
        let (sha256, size) = resolver.resolve(&current).await.unwrap();
        let changed = ItemState::from_record(&current, sha256, size).unwrap();
        assert_eq!(changed.content_sha256, Some(second_digest));
        assert_eq!(changed.content_size, Some(6));
        assert_eq!(resolver.resolve(&tombstone.to_record()).await.unwrap(), (Some(first_digest), Some(5)));
    }

    /// Resolves one version digest against a fresh remote serving `body`, so
    /// no test case mutates storage under a live borrow.
    async fn resolve_version_body(
        workspace: WorkspaceId,
        version: hfdrive_core::ids::VersionId,
        body: Vec<u8>,
    ) -> Result<(Sha256Digest, u64), RemoteError> {
        use bytes::Bytes;
        let remote = crate::sync::test_support::HeadOnlyRemote {
            metadata: Some(Bytes::from(body)),
            ..Default::default()
        };
        let cancel = CancellationToken::new();
        RemoteDigests::new(&remote, workspace).version_digest(version, &cancel).await
    }

    /// A resolved version record must name the exact requested version and the
    /// connection's workspace; anything else is a foreign binding and never
    /// resolves a digest.
    #[tokio::test]
    async fn remote_digests_reject_wrong_version_id_or_workspace() {
        use hfdrive_core::ids::{UploadId, VersionId};
        use hfdrive_core::storage::{PayloadKey, XetFileId};
        let requested = VersionId::new();
        let workspace = WorkspaceId::new();
        let mut record = format::VersionV1 {
            format: format::FORMAT_NAME.to_owned(),
            schema_version: format::SCHEMA_VERSION,
            workspace_id: workspace,
            version_id: requested,
            object_key: PayloadKey::new(UploadId::new()),
            size: 7,
            sha256: Sha256Digest::of(b"seven"),
            xet_file_id: Some(XetFileId::new("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_owned()).unwrap()),
            display: format::DisplayMetadata { name: "file.bin".to_owned(), modified_at: "2026-11-17T00:00:00Z".to_owned() },
        };

        // The exact record resolves.
        let exact = format::to_version_bytes(&record).unwrap();
        assert_eq!(
            resolve_version_body(workspace, requested, exact).await.unwrap(),
            (Sha256Digest::of(b"seven"), 7)
        );

        // A body naming a different version never resolves the request.
        record.version_id = VersionId::new();
        let wrong_version = format::to_version_bytes(&record).unwrap();
        assert!(matches!(
            resolve_version_body(workspace, requested, wrong_version).await,
            Err(RemoteError::InvalidResponse)
        ));

        // A body from another workspace never resolves the request either.
        record.version_id = requested;
        record.workspace_id = WorkspaceId::new();
        let wrong_workspace = format::to_version_bytes(&record).unwrap();
        assert!(matches!(
            resolve_version_body(workspace, requested, wrong_workspace).await,
            Err(RemoteError::InvalidResponse)
        ));
    }
}
