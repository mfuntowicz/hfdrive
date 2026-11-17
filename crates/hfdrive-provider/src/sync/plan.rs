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

use std::collections::HashMap;
use std::path::PathBuf;

use hfdrive_core::catalog::{CatalogReader, CatalogRoot, PageSource};
use hfdrive_core::format::{self, ItemRecord};
use hfdrive_core::ids::{ActionId, CommitId, ConnectionId, ItemId, OperationId, WorkspaceId};
use hfdrive_core::reconcile::{
    CatalogView, ConflictRecord as CoreConflict, IdSource, ItemState, LocalIntent, LocalOrigin,
    OrdinalIgnoreCase, ReconcileError, ReconcileInput, ReconcileMode, ReconcilePlan,
};
use hfdrive_core::storage::Sha256Digest;
use hfdrive_state::{
    AccountStore, ConflictResolution, LocalAction, LocalActionState, OutboxEntry, OutboxState,
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
    pub base: CatalogView,
    pub remote: CatalogView,
    pub intents: Vec<LocalIntent>,
    /// Item names by id for display metadata (base + remote).
    pub names: HashMap<ItemId, String>,
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
pub fn build_local_intents(entries: &[OutboxEntry], names: &HashMap<ItemId, String>) -> Vec<LocalIntent> {
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
        let name = names.get(&intent.item_id()).cloned().unwrap_or_default();
        if let Some(local) = intent.to_local_intent(
            entry.operation_id,
            LocalOrigin::LocalEdit,
            entry.observed_generation,
            &name,
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
    for conflict in &plan.conflicts {
        state.record_conflict(to_state_conflict(connection, conflict)).await?;
    }
    Ok(())
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
/// item records. Batched in bounded transactions.
pub async fn record_common_bases(
    state: &AccountStore,
    connection: ConnectionId,
    commit: CommitId,
    records: &[ItemRecord],
) -> Result<(), PlanError> {
    for record in records {
        let item_json = String::from_utf8(format::to_item_record_bytes(record).map_err(|_| PlanError::UnsupportedFormat)?)
            .map_err(|_| PlanError::UnsupportedFormat)?;
        state
            .put_common_base(hfdrive_state::CommonBaseRecord {
                connection_id: connection,
                item_id: record.item_id,
                commit_id: commit,
                item_json,
            })
            .await?;
    }
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
