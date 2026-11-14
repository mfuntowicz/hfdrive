//! The publication and application loop.
//!
//! Crash-safe ordering, enforced here:
//!
//! 1. **resume first, mutate never**: a dispatched candidate is resolved by
//!    identity only — the live `HEAD` commit, then a bounded committed-
//!    ancestry search for the entry's operation. An absent candidate is
//!    **never** re-driven from incomplete evidence (no fabricated publish
//!    sets, no stale ETag writes); it simply re-plans with fresh immutable
//!    identifiers against the current base, which is self-correcting: a
//!    change that already landed converges instead of rewriting;
//! 2. content-complete local intents merge with the committed namespace via
//!    the pure [`hfdrive_core::reconcile`] planner; local actions and
//!    conflicts persist with file identity/generation/USN expectations
//!    before any effect;
//! 3. one commit batch becomes one candidate whose fresh commit/generation/
//!    version identifiers are persisted as outbox evidence **before** any
//!    external work;
//! 4. exactly one conditional `HEAD` write per candidate (never blind
//!    retries); precondition failures park the entries and re-reconcile
//!    against the fresh head with new identifiers;
//! 5. after a committed publication (or for remote-only/read-only rounds)
//!    the journaled local actions execute through the guarded CFAPI
//!    operations, then entries complete — generation guarded, so a
//!    superseded upload never clears newer edits.
//!
//! Remote-only changes flow through the same pipeline with an empty intent
//! set: they become guarded local actions and never upload anything.
//! Read-only connections materialize committed state the same way and never
//! initialize, upload, or mutate remotely.

use std::collections::{BTreeSet, HashMap};

use hfdrive_core::catalog::{CatalogRoot, CatalogWriter};
use hfdrive_core::format::{self, CommitV1, DisplayMetadata, HeadV1, ItemKind, ItemRecord, VersionV1};
use hfdrive_core::ids::{
    ActionId, CommitId, ConnectionId, DeviceId, GenerationId, ItemId, OperationId, SnapshotId,
    VersionId, WorkspaceId,
};
use hfdrive_core::reconcile::{IntentOutcomeKind, ReconcileMode, ReconcilePlan};
use hfdrive_core::storage::{ObjectRef, StableSnapshot};
use hfdrive_publication::coordinator::{InitOutcome, PublicationCandidate, PublishResult};
use hfdrive_state::{
    BaselineKind, CommitRecord, CommitStatus, LocalAction, LocalActionState, LocalActionKind as StateActionKind,
    OutboxEntry, OutboxState, OutboxTransition, RetryClass, TransferDirection, TransferRecord,
    TransferState,
};
use tokio_util::sync::CancellationToken;

use crate::sync::apply;
use crate::sync::outbox::{
    CaptureEvidence, PayloadCheckpoints, PhaseStep, next_step, parse_intent, staged_payload,
    transfer_id_for,
};
use crate::sync::plan::{
    self, ActionFacts, DigestResolver, PlanError, PlanSources, PlannedRound, RemoteDigests,
    build_base_view, build_local_intents, build_remote_view, record_common_bases, registry_digest,
    registry_item,
};
use crate::sync::remote::{RemoteError, RemoteHead, RemoteOps};

/// Everything one round needs about the connection.
pub struct RoundContext<'a, R: RemoteOps> {
    pub state: &'a hfdrive_state::AccountStore,
    pub remote: &'a R,
    pub connection: ConnectionId,
    pub workspace: WorkspaceId,
    pub root_item_id: ItemId,
    pub device_id: DeviceId,
    pub mode: ReconcileMode,
    pub root: &'a std::path::Path,
    pub staging_dir: &'a std::path::Path,
    pub recovery_dir: &'a std::path::Path,
    pub scheduler: &'a crate::scheduler::Scheduler,
    pub cancel: &'a CancellationToken,
}

/// What one round achieved.
#[derive(Debug, Default)]
pub struct RoundOutcome {
    pub committed: Vec<CommitId>,
    pub published_operations: Vec<OperationId>,
    pub converged_operations: Vec<OperationId>,
    pub conflicted_operations: Vec<OperationId>,
    pub deferred_operations: Vec<OperationId>,
    pub applied_local_actions: usize,
    pub needs_initialize: bool,
}

/// Failure of one round. Transient classes park work instead of dropping it.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error("planning failed: {0}")]
    Plan(#[from] PlanError),
    #[error("remote work failed: {0}")]
    Remote(#[from] RemoteError),
    #[error("durable state failed: {0}")]
    State(#[from] hfdrive_state::StateError),
    #[error("capture failed: {0}")]
    Capture(String),
    #[error("local apply failed: {0}")]
    LocalApply(&'static str),
    #[error("the managed remote format is unsupported")]
    UnsupportedFormat,
    #[error("the round was cancelled")]
    Cancelled,
}

/// The candidate bundle persisted as `candidate_head_json` evidence: the
/// exact head, commit and version records whose identifiers were generated
/// before any external work. It is identity evidence for crash resolution —
/// it is **never** re-driven as a write.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateBundle {
    pub head: serde_json::Value,
    pub commit: serde_json::Value,
    pub versions: Vec<serde_json::Value>,
}

impl CandidateBundle {
    pub fn head_v1(&self) -> Result<HeadV1, PublishError> {
        serde_json::from_value(self.head.clone()).map_err(|_| PublishError::UnsupportedFormat)
    }
    pub fn commit_v1(&self) -> Result<CommitV1, PublishError> {
        serde_json::from_value(self.commit.clone()).map_err(|_| PublishError::UnsupportedFormat)
    }
    pub fn versions_v1(&self) -> Result<Vec<VersionV1>, PublishError> {
        self.versions
            .iter()
            .map(|value| {
                serde_json::from_value(value.clone()).map_err(|_| PublishError::UnsupportedFormat)
            })
            .collect()
    }
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<serde_json::Value, PublishError> {
    serde_json::to_value(value).map_err(|_| PublishError::UnsupportedFormat)
}

// ---------------------------------------------------------------------------
// The round
// ---------------------------------------------------------------------------

/// Runs one full round for the connection's pending durable work.
pub async fn run_round<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    writable: bool,
) -> Result<RoundOutcome, PublishError> {
    let mut outcome = RoundOutcome::default();
    let now_ms = now_ms();
    let all = ctx.state.list_outbox(ctx.connection, None, u32::MAX).await?;

    // 1. Crash-safe resume: dispatched candidates are resolved by identity
    //    and never re-driven; absent candidates re-plan with fresh IDs.
    let mut planning: Vec<OutboxEntry> = Vec::new();
    let mut resumed = Vec::new();
    for entry in all {
        match entry.state {
            OutboxState::Complete | OutboxState::LocalApplyPending | OutboxState::Published => {}
            OutboxState::MetadataReady => resumed.push(entry),
            OutboxState::PublishUnknown => {
                match classify_parked(ctx, &entry).await? {
                    Some(commit_id) => {
                        mark_published_locally(ctx, &entry, &mut outcome, Some(commit_id)).await?
                    }
                    None => planning.push(entry),
                }
            }
            _ => {
                if next_step(&entry, now_ms) != PhaseStep::Wait {
                    planning.push(entry);
                }
            }
        }
    }
    for group in group_by_candidate(&resumed) {
        resume_group(ctx, &group, &mut planning, &mut outcome).await?;
    }
    let mut eligible = Vec::with_capacity(planning.len());
    for entry in planning {
        let excluded = match parse_intent(&entry) {
            Ok(intent) => crate::sync::observe::excluded_here(ctx.state, ctx.connection, intent.item_id()).await,
            Err(_) => true,
        };
        if !excluded {
            eligible.push(entry);
        }
    }
    planning = eligible;

    // 2. Remote head. Read-only connections never initialize; a writable
    //    connection without a head needs an explicit initialization intent.
    let head = match ctx.remote.read_head(ctx.cancel).await? {
        Some(head) => head,
        None => {
            outcome.needs_initialize = writable;
            return Ok(outcome);
        }
    };
    let baseline = ctx.state.baseline(ctx.connection).await?;
    let remote_moved = baseline.applied_commit != Some(head.head.commit_id);
    if planning.is_empty() && !remote_moved {
        return Ok(outcome);
    }

    // 3. Complete views and the pure merge. Read-only rounds reconcile in
    //    read-only mode: zero remote ops, local intents deferred, remote
    //    changes materialized through guarded local actions.
    let catalog_root = catalog_root_of(ctx, &head).await?;
    let digests_source = RemoteDigests(ctx.remote);
    let mut digests = DigestResolver::new(&digests_source, ctx.cancel);
    let base = build_base_view(ctx.state, ctx.connection, &mut digests).await?;
    let remote = build_remote_view(ctx.remote, catalog_root, &mut digests, ctx.cancel).await?;
    let names = collect_names(&base, &remote);
    let intents = build_local_intents(&planning, &names);
    let sources = PlanSources { base, remote, intents, names };

    let mut planned =
        plan::plan_round(ctx.state, ctx.connection, ctx.workspace, ctx.mode, &sources).await?;
    let mut included_actions = Vec::with_capacity(planned.plan.local_actions.len());
    for action in planned.plan.local_actions.drain(..) {
        let excluded = crate::sync::observe::excluded_here(ctx.state, ctx.connection, action.item_id).await;
        if !excluded {
            included_actions.push(action);
        }
    }
    planned.plan.local_actions = included_actions;
    let facts = bind_action_facts(ctx, &planned.plan, &sources).await?;
    plan::persist_plan_records(ctx.state, ctx.connection, &planned.plan, &facts).await?;

    // 4. No remote write needed (read-only, converged-only, remote-only):
    //    apply the journaled local actions, close bookkeeping and absorb the
    //    observed head into the base.
    if !writable || planned.plan.remote_ops.is_empty() {
        outcome.applied_local_actions = execute_pending_actions(ctx).await?;
        close_bookkeeping(ctx, &planning, &planned, &head, &mut outcome).await?;
        advance_base(ctx, head.head.commit_id, &planned, &sources).await?;
        ctx.state
            .set_baseline(ctx.connection, BaselineKind::Applied, Some(head.head.commit_id))
            .await?;
        return Ok(outcome);
    }

    // 5. One commit batch per round; later batches re-reconcile afterwards.
    let mut batches = planned
        .plan
        .commit_batches(format::MAX_COMMIT_OPERATIONS, format::MAX_COMMIT_OPERATIONS)
        .map_err(|_| PublishError::UnsupportedFormat)?;
    let batch = batches.remove(0);
    let batch_ops: BTreeSet<OperationId> = batch.operation_ids.iter().copied().collect();

    // 6. Candidate with fresh immutable identifiers.
    let (candidate, bundle) =
        build_candidate(ctx, &head, &batch.remote_ops, &batch.changes, &planned.plan).await?;

    // 7. Persist candidate evidence before any external effect. Only the one
    //    GET body+ETag response can authorize the conditional write; a
    //    native-only head read never produces an ETag and never fabricates
    //    one.
    let expected_etag = head
        .etag
        .as_ref()
        .ok_or(PublishError::Remote(RemoteError::StorageSetupRequired))?;
    let etag = expected_etag.as_str().to_owned();
    let bundle_json = to_json(&bundle)?;
    let mut round_entries = Vec::new();
    for entry in &planning {
        if batch_ops.contains(&entry.operation_id) || bookkeeping_for(entry, &planned) {
            let updated = ctx
                .state
                .transition_outbox(
                    ctx.connection,
                    entry.operation_id,
                    OutboxTransition::MetadataReady {
                        candidate_commit: candidate.commit.commit_id,
                        candidate_head_json: bundle_json.clone(),
                        expected_etag: etag.clone(),
                    },
                )
                .await?;
            round_entries.push(updated);
        }
    }

    // 8. Exactly one conditional write against the preserved base head.
    match ctx.remote.publish(&head, candidate, ctx.cancel).await? {
        PublishResult::Committed(_) => {
            let commit_id = candidate_commit_id(&round_entries)
                .unwrap_or(head.head.commit_id);
            finish_commit(ctx, &round_entries, &planned, &sources, &head, &batch, commit_id, &mut outcome)
                .await?;
        }
        PublishResult::PreconditionFailed { current } => {
            // Re-reconcile against the fresh head; parking replaces candidate
            // evidence legally and keeps bound payloads bound.
            park_for_rebase(ctx, &round_entries, RetryClass::None, None).await?;
            let _ = current;
        }
        PublishResult::Ambiguous(_) => {
            park_for_rebase(ctx, &round_entries, RetryClass::Backoff, Some(500)).await?;
        }
    }
    Ok(outcome)
}

fn bookkeeping_for(entry: &OutboxEntry, planned: &PlannedRound) -> bool {
    planned.outcomes.iter().any(|(operation, kind)| {
        *operation == entry.operation_id
            && matches!(
                kind,
                plan::IntentOutcomeKind::Converged
                    | plan::IntentOutcomeKind::Superseded
                    | plan::IntentOutcomeKind::Conflicted
            )
    })
}

fn candidate_commit_id(entries: &[OutboxEntry]) -> Option<CommitId> {
    entries.iter().find_map(|entry| entry.candidate_commit)
}

fn group_by_candidate(entries: &[OutboxEntry]) -> Vec<Vec<OutboxEntry>> {
    let mut groups: Vec<(CommitId, Vec<OutboxEntry>)> = Vec::new();
    for entry in entries {
        let Some(commit) = entry.candidate_commit else { continue; };
        match groups.iter_mut().find(|(id, _)| *id == commit) {
            Some((_, group)) => group.push(entry.clone()),
            None => groups.push((commit, vec![entry.clone()])),
        }
    }
    groups.into_iter().map(|(_, group)| group).collect()
}

// ---------------------------------------------------------------------------
// Crash-safe resolution of dispatched candidates (identity only, no writes)
// ---------------------------------------------------------------------------

/// The committed commit of a parked entry's operation, when its dispatched
/// candidate is provably in committed ancestry (its own candidate commit is
/// the live head, or a bounded ancestry walk found the exact operation).
/// `None` means "not found": the entry re-plans with fresh identifiers, which
/// is safe without proof of absence — a change that already landed converges
/// against the current namespace instead of rewriting it.
async fn classify_parked<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    entry: &OutboxEntry,
) -> Result<Option<CommitId>, PublishError> {
    let Some(bundle_json) = entry.candidate_head_json.clone() else {
        return Ok(None);
    };
    let bundle: CandidateBundle =
        serde_json::from_value(bundle_json).map_err(|_| PublishError::UnsupportedFormat)?;
    let commit = bundle.commit_v1()?;
    let Some(head) = ctx.remote.read_head(ctx.cancel).await? else {
        return Ok(None);
    };
    if head.head.commit_id == commit.commit_id {
        return Ok(Some(commit.commit_id));
    }
    Ok(ctx
        .remote
        .find_committed_operation(head.head.commit_id, entry.operation_id, ctx.cancel)
        .await?)
}

/// Resumes one candidate-commit group after a crash. Entries whose operation
/// is committed continue to local application; the rest re-plan. No remote
/// mutation happens here.
async fn resume_group<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    group: &[OutboxEntry],
    planning: &mut Vec<OutboxEntry>,
    outcome: &mut RoundOutcome,
) -> Result<(), PublishError> {
    let Some(first) = group.first() else { return Ok(()); };
    let committed_head = match first.candidate_head_json.as_ref() {
        Some(bundle_json) => {
            let bundle: CandidateBundle = serde_json::from_value(bundle_json.clone())
                .map_err(|_| PublishError::UnsupportedFormat)?;
            let commit = bundle.commit_v1()?;
            match ctx.remote.read_head(ctx.cancel).await? {
                Some(head) if head.head.commit_id == commit.commit_id => Some(commit.commit_id),
                _ => None,
            }
        }
        None => None,
    };
    for entry in group {
        let committed = match committed_head {
            Some(commit_id) => Some(commit_id),
            None => {
                let head = ctx.remote.read_head(ctx.cancel).await?;
                match head {
                    Some(head) => {
                        ctx.remote
                            .find_committed_operation(
                                head.head.commit_id,
                                entry.operation_id,
                                ctx.cancel,
                            )
                            .await?
                    }
                    None => None,
                }
            }
        };
        match committed {
            Some(commit_id) => mark_published_locally(ctx, entry, outcome, Some(commit_id)).await?,
            None => planning.push(entry.clone()),
        }
    }
    Ok(())
}

/// Moves a committed entry to local application (Published -> LocalApplyPending).
async fn mark_published_locally<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    entry: &OutboxEntry,
    outcome: &mut RoundOutcome,
    _commit_id: Option<CommitId>,
) -> Result<(), PublishError> {
    if entry.state == OutboxState::MetadataReady || entry.state == OutboxState::PublishUnknown {
        ctx.state
            .transition_outbox(ctx.connection, entry.operation_id, OutboxTransition::Published)
            .await?;
    }
    if entry.state != OutboxState::LocalApplyPending {
        ctx.state
            .transition_outbox(
                ctx.connection,
                entry.operation_id,
                OutboxTransition::LocalApplyPending,
            )
            .await?;
    }
    outcome.published_operations.push(entry.operation_id);
    Ok(())
}

/// Parks entries in `PublishUnknown` so their candidate evidence can be
/// legally replaced after re-reconciliation (the only re-base path that keeps
/// a bound payload bound and never overwrites an immutable commit).
async fn park_for_rebase<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    entries: &[OutboxEntry],
    retry_class: RetryClass,
    next_attempt_at_ms: Option<u64>,
) -> Result<(), PublishError> {
    for entry in entries {
        if entry.state == OutboxState::MetadataReady {
            ctx.state
                .transition_outbox(
                    ctx.connection,
                    entry.operation_id,
                    OutboxTransition::PublishUnknown { retry_class, next_attempt_at_ms },
                )
                .await?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Candidate construction
// ---------------------------------------------------------------------------

/// Resolves the catalog root of a committed head by reading its commit
/// record. The `HEAD` names the commit; the commit names the catalog.
pub async fn catalog_root_of<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    head: &RemoteHead,
) -> Result<CatalogRoot, PublishError> {
    let record = hfdrive_publication::MetadataRecord::Commit(head.head.commit_id);
    let body = ctx.remote.read_metadata(record, ctx.cancel).await?;
    let commit = format::from_commit_bytes(&body).map_err(|_| PublishError::UnsupportedFormat)?;
    Ok(CatalogRoot::from_digest(commit.catalog_root))
}

/// Applies one batch to the copy-on-write catalog and assembles the candidate
/// records. All identifiers are fresh; the caller persists them before any
/// external effect.
pub async fn build_candidate<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    head: &RemoteHead,
    remote_ops: &[hfdrive_core::reconcile::RemoteOp],
    changes: &[format::ItemChange],
    planned: &ReconcilePlan,
) -> Result<(PublicationCandidate, CandidateBundle), PublishError> {
    let catalog_root = catalog_root_of(ctx, head).await?;
    let mut pages = plan::RemotePages::new(ctx.remote, ctx.cancel);
    let mut writer = CatalogWriter::new(&mut pages, catalog_root);
    for op in remote_ops {
        if op.is_tombstone() {
            writer.tombstone_item(&op.record).await.map_err(|_| PublishError::UnsupportedFormat)?;
        } else {
            writer.insert_item(&op.record).await.map_err(|_| PublishError::UnsupportedFormat)?;
        }
    }
    let publish_set = writer.commit().map_err(|_| PublishError::UnsupportedFormat)?;

    // Version records for exactly this batch's content bindings.
    let batch_versions: BTreeSet<VersionId> = remote_ops
        .iter()
        .filter_map(|op| op.record.content_version_id)
        .collect();
    let mut versions = Vec::new();
    let mut payloads = Vec::new();
    for planned_version in &planned.versions {
        if !batch_versions.contains(&planned_version.version_id) {
            continue;
        }
        versions.push(version_record(
            ctx.workspace,
            planned_version.version_id,
            &planned_version.object,
            &planned_version.display,
        ));
        payloads.push(planned_version.object.clone());
    }

    let operation_ids: Vec<OperationId> = {
        let mut ids = BTreeSet::new();
        for op in remote_ops {
            ids.insert(op.record.item_revision);
            ids.insert(op.record.content_operation);
            ids.insert(op.record.location_operation);
            if let Some(deletion) = op.record.deletion_operation {
                ids.insert(deletion);
            }
        }
        ids.into_iter().collect()
    };
    let commit_id = CommitId::new();
    let generation = GenerationId::new();
    let commit = CommitV1 {
        format: format::FORMAT_NAME.to_owned(),
        schema_version: format::SCHEMA_VERSION,
        workspace_id: ctx.workspace,
        commit_id,
        parent_commit_id: Some(head.head.commit_id),
        catalog_root: publish_set.root.digest(),
        operation_ids,
        changes: changes.to_vec(),
        device_id: ctx.device_id,
        created_at: crate::sync::outbox::display_timestamp(now_100ns()),
    };
    let head_v1 = HeadV1 {
        format: format::FORMAT_NAME.to_owned(),
        schema_version: format::SCHEMA_VERSION,
        workspace_id: ctx.workspace,
        root_item_id: ctx.root_item_id,
        commit_id,
        generation,
        required_features: Vec::new(),
    };
    let bundle = CandidateBundle {
        head: to_json(&head_v1)?,
        commit: to_json(&commit)?,
        versions: versions.iter().map(to_json).collect::<Result<Vec<_>, _>>()?,
    };
    Ok((
        PublicationCandidate { head: head_v1, commit, versions, catalog: publish_set, payloads },
        bundle,
    ))
}

fn version_record(
    workspace: WorkspaceId,
    version_id: VersionId,
    object: &ObjectRef,
    display: &DisplayMetadata,
) -> VersionV1 {
    VersionV1 {
        format: format::FORMAT_NAME.to_owned(),
        schema_version: format::SCHEMA_VERSION,
        workspace_id: workspace,
        version_id,
        object_key: object.key,
        size: object.size,
        sha256: object.sha256,
        xet_file_id: Some(object.xet_file_id.clone()),
        display: display.clone(),
    }
}

// ---------------------------------------------------------------------------
// Bookkeeping closure (converged/superseded intents)
// ---------------------------------------------------------------------------

async fn close_bookkeeping<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    entries: &[OutboxEntry],
    planned: &PlannedRound,
    head: &RemoteHead,
    outcome: &mut RoundOutcome,
) -> Result<(), PublishError> {
    for entry in entries {
        let Some((_, kind)) = planned
            .outcomes
            .iter()
            .find(|(operation, _)| *operation == entry.operation_id)
        else {
            continue;
        };
        match kind {
            plan::IntentOutcomeKind::Converged | plan::IntentOutcomeKind::Superseded => {
                // Legal closure chain: the current committed head IS the
                // evidence that satisfies this intent, so the entry adopts it
                // as its candidate evidence and closes through the ordinary
                // generation-guarded completion.
                let evidence = head_evidence(ctx, head).await?;
                ctx.state
                    .transition_outbox(
                        ctx.connection,
                        entry.operation_id,
                        OutboxTransition::MetadataReady {
                            candidate_commit: head.head.commit_id,
                            candidate_head_json: evidence,
                            expected_etag: head
                                .etag
                                .as_ref()
                                .map(|etag| etag.as_str().to_owned())
                                .unwrap_or_default(),
                        },
                    )
                    .await?;
                ctx.state
                    .transition_outbox(
                        ctx.connection,
                        entry.operation_id,
                        OutboxTransition::Published,
                    )
                    .await?;
                ctx.state
                    .transition_outbox(
                        ctx.connection,
                        entry.operation_id,
                        OutboxTransition::LocalApplyPending,
                    )
                    .await?;
                apply::complete_publication(ctx.state, ctx.connection, entry.operation_id).await?;
                outcome.converged_operations.push(entry.operation_id);
            }
            plan::IntentOutcomeKind::Conflicted => outcome.conflicted_operations.push(entry.operation_id),
            plan::IntentOutcomeKind::Deferred => outcome.deferred_operations.push(entry.operation_id),
            plan::IntentOutcomeKind::Published => {}
        }
    }
    Ok(())
}

/// The identity evidence bundle of the current committed head, used when a
/// converged/superseded intent adopts the committed state as its outcome.
async fn head_evidence<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    head: &RemoteHead,
) -> Result<serde_json::Value, PublishError> {
    let body = ctx
        .remote
        .read_metadata(
            hfdrive_publication::MetadataRecord::Commit(head.head.commit_id),
            ctx.cancel,
        )
        .await?;
    let commit = format::from_commit_bytes(&body).map_err(|_| PublishError::UnsupportedFormat)?;
    let bundle = CandidateBundle {
        head: to_json(&head.head)?,
        commit: to_json(&commit)?,
        versions: Vec::new(),
    };
    to_json(&bundle)
}

// ---------------------------------------------------------------------------
// Post-commit work
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn finish_commit<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    round_entries: &[OutboxEntry],
    planned: &PlannedRound,
    sources: &PlanSources,
    head: &RemoteHead,
    batch: &hfdrive_core::reconcile::CommitBatch,
    commit_id: CommitId,
    outcome: &mut RoundOutcome,
) -> Result<(), PublishError> {
    ctx.state
        .record_commit(CommitRecord {
            connection_id: ctx.connection,
            commit_id,
            parent_id: Some(head.head.commit_id),
            catalog_root: None,
            operation_ids: batch.operation_ids.clone(),
            status: CommitStatus::Committed,
        })
        .await?;
    ctx.state
        .set_baseline(ctx.connection, BaselineKind::Published, Some(commit_id))
        .await?;

    // Guarded local application of the journaled plan actions.
    outcome.applied_local_actions = execute_pending_actions(ctx).await?;

    // Mark locally published content in-sync (guarded), then close entries.
    for entry in round_entries {
        mark_entry_in_sync(ctx, entry).await?;
        ctx.state
            .transition_outbox(ctx.connection, entry.operation_id, OutboxTransition::Published)
            .await?;
        ctx.state
            .transition_outbox(
                ctx.connection,
                entry.operation_id,
                OutboxTransition::LocalApplyPending,
            )
            .await?;
        apply::complete_publication(ctx.state, ctx.connection, entry.operation_id).await?;
        outcome.published_operations.push(entry.operation_id);
    }

    // Advance the remembered base and the durable item registry.
    advance_base(ctx, commit_id, planned, sources).await?;
    ctx.state
        .set_baseline(ctx.connection, BaselineKind::Applied, Some(commit_id))
        .await?;
    outcome.committed.push(commit_id);
    Ok(())
}

/// Remembers the new common base (the full namespace at the observed commit)
/// and refreshes the durable item registry with the applied records.
async fn advance_base<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    commit_id: CommitId,
    planned: &PlannedRound,
    sources: &PlanSources,
) -> Result<(), PublishError> {
    // Post-round namespace = committed remote view overlaid with this round's
    // records (local publications); remote-only rounds overlay nothing.
    let mut namespace: HashMap<ItemId, ItemRecord> = HashMap::new();
    for item in sources.remote.iter() {
        namespace.insert(item.item_id, item.to_record());
    }
    for op in &planned.plan.remote_ops {
        namespace.insert(op.record.item_id, op.record.clone());
    }
    let records: Vec<ItemRecord> = namespace.into_values().collect();
    record_common_bases(ctx.state, ctx.connection, commit_id, &records).await?;
    for record in &records {
        let (digest, size, modified_at) = planned
            .plan
            .versions
            .iter()
            .find(|version| Some(version.version_id) == record.content_version_id)
            .map(|version| {
                (
                    Some(version.object.sha256),
                    Some(version.object.size),
                    Some(version.display.modified_at.clone()),
                )
            })
            .unwrap_or((None, None, None));
        ctx.state
            .upsert_item(registry_item(ctx.connection, record, digest, size, modified_at))
            .await?;
    }
    ctx.state
        .set_baseline(ctx.connection, BaselineKind::Observed, Some(commit_id))
        .await?;
    Ok(())
}

/// Marks a locally published file in-sync only when the live file is still
/// exactly the captured generation. A newer local edit stays dirty and
/// publishes on its own; superseded uploads never clear newer edits.
async fn mark_entry_in_sync<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    entry: &OutboxEntry,
) -> Result<(), PublishError> {
    let Some(intent) = parse_intent(entry).ok() else { return Ok(()); };
    if !intent.has_content() {
        return Ok(());
    }
    let journal = load_journal(ctx.state, ctx.connection, entry.operation_id).await?;
    let Some(evidence) = journal.capture else { return Ok(()); };
    let item_id = intent.item_id();
    let Some(path) = item_path(ctx, item_id).await else { return Ok(()); };
    let observation = ctx.state.observation(ctx.connection, item_id).await?;
    let generation = observation.map(|o| o.generation).unwrap_or(entry.observed_generation);
    apply::mark_published_in_sync(
        &ctx.root.join(&path),
        &evidence,
        generation,
        entry.observed_generation,
    )
    .map_err(PublishError::LocalApply)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Journaled local action execution (single executor for every path)
// ---------------------------------------------------------------------------

/// Executes every pending journaled local action through the guarded CFAPI
/// operations. The journal row is the durable source of truth, so resumed,
/// re-planned and remote-only rounds all run the same code. Guard refusals
/// keep the row pending and the file untouched.
pub async fn execute_pending_actions<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
) -> Result<usize, PublishError> {
    let pending = ctx
        .state
        .list_local_actions(ctx.connection, Some(LocalActionState::Pending))
        .await?;
    let mut applied = 0;
    for row in pending {
        if execute_one_action(ctx, &row).await? {
            ctx.state
                .set_local_action_state(ctx.connection, row.action_id, LocalActionState::Applied)
                .await?;
            applied += 1;
        }
    }
    Ok(applied)
}

/// Executes one journaled action. Returns `false` when a guard refused and
/// the row must stay pending.
async fn execute_one_action<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    row: &LocalAction,
) -> Result<bool, PublishError> {
    let target = row.target_path.clone();
    let source = row.source_path.clone();
    match row.kind {
        StateActionKind::Other => {
            // PreserveDirty: deterministic recovery target from the action id.
            if let Some(source) = &source {
                apply::preserve_dirty(&ctx.root.join(source), ctx.recovery_dir, row.action_id)
                    .map_err(PublishError::LocalApply)?;
            }
        }
        StateActionKind::CreatePlaceholder => {
            let Some(path) = &target else { return Ok(false); };
            let parent = path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                return Ok(false);
            };
            let (identity, size, directory) = placeholder_identity(ctx, row).await?;
            let create = hfdrive_windows::cfapi::ops::PlaceholderCreate {
                name: name.to_owned(),
                metadata: apply::metadata_spec(size, now_100ns(), directory),
                identity,
                mark_in_sync: true,
            };
            apply::create_placeholders(&ctx.root.join(&parent), &[create])
                .map_err(PublishError::LocalApply)?;
        }
        StateActionKind::Rename => {
            let (Some(from), Some(to)) = (&source, &target) else { return Ok(false); };
            let case_only = hfdrive_windows::filesystem::names::windows_case_equivalent(
                &from.to_string_lossy(),
                &to.to_string_lossy(),
            ) && !hfdrive_windows::filesystem::names::windows_exact_equal(
                &from.to_string_lossy(),
                &to.to_string_lossy(),
            );
            let intermediate = to.with_file_name(format!(
                "{}.hfdrive-rename-{}",
                to.file_name().and_then(|n| n.to_str()).unwrap_or("item"),
                row.action_id
            ));
            apply::rename_local(ctx.root, from, to, case_only, &intermediate)
                .map_err(PublishError::LocalApply)?;
        }
        StateActionKind::UpdatePlaceholder => {
            let (Some(path), Some(version)) = (&target, row.new_version) else {
                return Ok(false);
            };
            let Some(expected_state) = expected_guard_state(ctx, row).await else {
                // Expectation cannot be proven: the action stays pending and
                // the file keeps its old state (the designed recovery path).
                return Ok(false);
            };
            let object = version_object(ctx, version).await?;
            let Some(item_id) = row.item_id else { return Ok(false); };
            let identity = apply::file_identity(ctx.workspace, item_id, version);
            let old_size = match row.old_version {
                Some(old) => version_object(ctx, old).await.map(|o| o.size).unwrap_or(0),
                None => 0,
            };
            let range = hfdrive_core::storage::ByteRange::new(0, old_size, old_size)
                .map_err(|_| PublishError::UnsupportedFormat)?;
            let spec = hfdrive_windows::cfapi::ops::UpdateSpec {
                metadata: apply::metadata_spec(object.size, now_100ns(), false),
                identity,
                invalidate: vec![range],
            };
            match apply::update_placeholder(&ctx.root.join(path), &spec, &expected_state) {
                Ok(hfdrive_windows::cfapi::ops::GuardOutcome::Applied { .. }) => {}
                Ok(hfdrive_windows::cfapi::ops::GuardOutcome::Mismatch(_)) => return Ok(false),
                Err(error) => return Err(PublishError::LocalApply(error)),
            }
        }
        StateActionKind::DeletePlaceholder => {
            let Some(path) = source.as_ref().or(target.as_ref()) else { return Ok(false); };
            match apply::delete_local(ctx.root, path) {
                Ok(apply::ApplyOutcome::Applied { .. })
                | Ok(apply::ApplyOutcome::AlreadySatisfied) => {}
                _ => return Ok(false),
            }
        }
        StateActionKind::SetPin
        | StateActionKind::Hydrate
        | StateActionKind::Dehydrate
        | StateActionKind::ConvertToNormal => {
            // Pin/free-space actions run through the controller's dedicated
            // commands, which carry their own evidence bundles.
            return Ok(false);
        }
    }
    Ok(true)
}

/// Builds the placeholder identity and display size for a create action from
/// the durable registry.
async fn placeholder_identity<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    row: &LocalAction,
) -> Result<(hfdrive_windows::cfapi::identity::PlaceholderIdentity, u64, bool), PublishError> {
    let item_id = row.item_id.ok_or(PublishError::LocalApply("journaled action lacks an item"))?;
    let item = ctx
        .state
        .item(ctx.connection, item_id)
        .await?
        .ok_or(PublishError::LocalApply("journaled action references an unknown item"))?;
    let directory = item.kind == hfdrive_state::ItemKind::Directory;
    let (digest_size, size) = registry_digest(&item);
    let _ = digest_size;
    let identity = match (directory, row.new_version) {
        (false, Some(version)) => apply::file_identity(ctx.workspace, item_id, version),
        _ => apply::directory_identity(ctx.workspace, item_id),
    };
    Ok((identity, size.unwrap_or(0), directory))
}

/// Reads one immutable version record for its payload binding. Delegates to
/// the shared remote resolver so the binding rules (workspace agreement,
/// required Xet identifier, missing-record retry class) live in one place.
async fn version_object<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    version: VersionId,
) -> Result<ObjectRef, PublishError> {
    Ok(crate::sync::remote::version_object(ctx.remote, ctx.workspace, version, ctx.cancel).await?)
}

/// Rebuilds the expected guard state from the journaled expectation and the
/// live file. Verification against the journaled file id/generation/USN is
/// what makes the guard honest: on any drift the action stays pending.
async fn expected_guard_state<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    row: &LocalAction,
) -> Option<hfdrive_windows::filesystem::volume::FileState> {
    let source_path = row.source_path.as_ref().or(row.target_path.as_ref())?;
    let live =
        hfdrive_windows::filesystem::volume::query_file_state(&ctx.root.join(source_path)).ok()?;
    let file_id = parse_hex_file_id(row.expected_file_id.as_deref()?)?;
    let expected = crate::sync::apply::ExpectedLocal {
        file_id,
        volume_serial_number: live.identity.volume_serial_number,
        generation: row.expected_generation?,
        usn: row.expected_usn.and_then(|value| i64::try_from(value).ok()),
    };
    let generation = ctx
        .state
        .observation(ctx.connection, row.item_id?)
        .await
        .ok()?
        .map(|observation| observation.generation)
        .unwrap_or(expected.generation);
    crate::sync::apply::verify_expected(&expected, &live, generation).then_some(live)
}

/// Parses a journaled 32-hex-digit NTFS file identity.
pub fn parse_hex_file_id(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 {
        return None;
    }
    let mut file_id = [0u8; 16];
    for index in 0..16 {
        file_id[index] = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(file_id)
}

/// Binds each planned action to the live local file identity, generation and
/// USN at persist time. The target path honours a deterministic local alias.
async fn bind_action_facts<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    planned: &ReconcilePlan,
    sources: &PlanSources,
) -> Result<HashMap<ActionId, ActionFacts>, PublishError> {
    let mut facts = HashMap::new();
    for action in &planned.local_actions {
        let expected_path = action
            .expected
            .as_ref()
            .and_then(|state| item_path_sync(sources, state.item_id));
        let mut target_path = action
            .target
            .as_ref()
            .and_then(|state| item_path_sync(sources, state.item_id));
        if let (Some(alias), Some(path)) = (action.local_alias.as_ref(), target_path.as_mut()) {
            path.set_file_name(alias);
        }
        let mut fact = ActionFacts {
            source_path: expected_path.clone(),
            target_path: target_path.clone(),
            expected_file_id: None,
            expected_generation: None,
            expected_usn: None,
        };
        if let Some(path) = &expected_path {
            if let Ok(live) =
                hfdrive_windows::filesystem::volume::query_file_state(&ctx.root.join(path))
            {
                fact.expected_file_id = Some(hex_file_id(&live.identity.file_id));
                fact.expected_usn = live.usn.and_then(|value| u64::try_from(value).ok());
                fact.expected_generation = ctx
                    .state
                    .observation(ctx.connection, action.item_id)
                    .await?
                    .map(|observation| observation.generation);
            }
        }
        facts.insert(action.action_id, fact);
    }
    Ok(facts)
}

fn hex_file_id(file_id: &[u8; 16]) -> String {
    file_id.iter().map(|byte| format!("{byte:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Payload upload (capture -> Xet checkpoints -> bound object)
// ---------------------------------------------------------------------------

/// Drives one content entry through capture and the three native Xet
/// checkpoints, persisting each durable boundary before the next external
/// effect.
///
/// Durable chain (the state machine's legal edges): a fresh capture binds its
/// staged file through `SnapshotReady` (or `Recaptured` + `SnapshotReady` when
/// an earlier staged capture died), then the upload advances `PayloadReady`.
/// An entry that already staged a usable coherent snapshot resumes upload
/// from that file and never recaptures.
pub async fn upload_entry<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    entry: &OutboxEntry,
) -> Result<(), PublishError> {
    let intent = parse_intent(entry).map_err(|_| PublishError::UnsupportedFormat)?;
    let Some(pending) = intent.pending_content() else {
        return Ok(());
    };
    let item_id = intent.item_id();
    let upload_id = hfdrive_core::ids::UploadId::from_uuid(pending.upload_id)
        .map_err(|_| PublishError::UnsupportedFormat)?;

    // Resume from a durable staged capture when it is uploadable. An
    // unusable staged capture (row missing after reconciliation, still
    // capturing, or missing its size/digest) is a recapture signal, never a
    // silent fallback: the fresh capture is re-bound below through the legal
    // transition edge before any upload.
    let mut journal = load_journal(ctx.state, ctx.connection, entry.operation_id).await?;
    let mut staged = None;
    if let Some(snapshot_id) = entry.snapshot_id {
        let row = ctx
            .state
            .snapshot(ctx.connection, snapshot_id)
            .await?
            .ok_or_else(|| PublishError::Capture("staged snapshot row is missing".to_owned()))?;
        if let Ok(payload) = staged_payload(entry, &row) {
            staged = Some(payload);
        }
    }

    let staged = match staged {
        Some(staged) => {
            if journal.capture.is_none() {
                return Err(PublishError::Capture(
                    "capture evidence is missing for a staged payload".to_owned(),
                ));
            }
            staged
        }
        None => {
            let source = item_path(ctx, item_id)
                .await
                .ok_or_else(|| PublishError::Capture("the source path is unknown".to_owned()))?;
            let snapshot_id = SnapshotId::new();
            let request = crate::sync::capture::CaptureRequest {
                connection_id: ctx.connection,
                source: ctx.root.join(&source),
                staging_dir: ctx.staging_dir.to_path_buf(),
                item_id,
                operation_id: entry.operation_id,
                snapshot_id,
                upload_id,
                expected: None,
                root: ctx.root.to_path_buf(),
            };
            let captured = crate::sync::capture::capture_local_change(
                ctx.state,
                ctx.scheduler,
                *ctx.workspace.as_uuid(),
                &request,
                ctx.cancel,
            )
            .await
            .map_err(|error| PublishError::Capture(error.to_string()))?;
            // Durable capture evidence before any network effect.
            journal.capture = Some(CaptureEvidence {
                volume_serial_number: captured.evidence.volume_serial_number,
                file_id: captured.evidence.file_id,
                size: captured.evidence.size,
                last_write_time_100ns: captured.evidence.last_write_time_100ns,
                usn: captured.evidence.usn,
            });
            save_journal(
                ctx.state,
                ctx.connection,
                entry.operation_id,
                &journal,
                TransferState::InProgress,
            )
            .await?;

            // Bind the staged file to the entry through the legal edge:
            // Observed -> SnapshotReady; a dead prior capture recaptures
            // through Recaptured (-> Observed) first.
            match entry.state {
                OutboxState::Observed => {
                    ctx.state
                        .transition_outbox(
                            ctx.connection,
                            entry.operation_id,
                            OutboxTransition::SnapshotReady { snapshot_id },
                        )
                        .await?;
                }
                OutboxState::SnapshotReady => {
                    ctx.state
                        .transition_outbox(
                            ctx.connection,
                            entry.operation_id,
                            OutboxTransition::Recaptured { snapshot_id },
                        )
                        .await?;
                    ctx.state
                        .transition_outbox(
                            ctx.connection,
                            entry.operation_id,
                            OutboxTransition::SnapshotReady { snapshot_id },
                        )
                        .await?;
                }
                _ => {
                    return Err(PublishError::Capture(
                        "upload is only valid before payload binding".to_owned(),
                    ));
                }
            }
            captured.staged
        }
    };
    let snapshot: StableSnapshot = staged.stable_snapshot();

    // Xet checkpoint 1: ingestion.
    let ingested = ctx.remote.ingest_payload(&snapshot, ctx.cancel).await?;
    journal.ingested = Some(ingested);
    save_journal(
        ctx.state,
        ctx.connection,
        entry.operation_id,
        &journal,
        TransferState::InProgress,
    )
    .await?;

    // Xet checkpoint 2: CAS commit.
    let ingested_ref = journal.ingested.as_ref().unwrap();
    let committed = ctx.remote.commit_payload_cas(&snapshot, ingested_ref, ctx.cancel).await?;
    journal.cas_committed = Some(committed);
    save_journal(
        ctx.state,
        ctx.connection,
        entry.operation_id,
        &journal,
        TransferState::InProgress,
    )
    .await?;

    // Xet checkpoint 3: exact key binding.
    let committed_ref = journal.cas_committed.as_ref().unwrap();
    let object = ctx.remote.bind_payload(&snapshot, committed_ref, ctx.cancel).await?;
    save_journal(
        ctx.state,
        ctx.connection,
        entry.operation_id,
        &journal,
        TransferState::Succeeded,
    )
    .await?;

    ctx.state
        .transition_outbox(
            ctx.connection,
            entry.operation_id,
            OutboxTransition::PayloadReady { object_ref: object },
        )
        .await?;
    Ok(())
}

/// Loads the durable payload journal of one operation.
pub async fn load_journal(
    state: &hfdrive_state::AccountStore,
    connection: ConnectionId,
    operation: OperationId,
) -> Result<PayloadCheckpoints, PublishError> {
    let row = state.transfer(connection, transfer_id_for(operation)).await?;
    Ok(row
        .and_then(|row| row.sdk_resume_json)
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default())
}

/// Persists the durable payload journal before the next external boundary.
pub async fn save_journal(
    state: &hfdrive_state::AccountStore,
    connection: ConnectionId,
    operation: OperationId,
    journal: &PayloadCheckpoints,
    transfer_state: TransferState,
) -> Result<(), PublishError> {
    let transfer_id = transfer_id_for(operation);
    let sdk_resume_json =
        serde_json::to_value(journal).map_err(|_| PublishError::UnsupportedFormat)?;
    let existing = state.transfer(connection, transfer_id).await?;
    if existing.is_some() {
        state
            .update_transfer(
                connection,
                transfer_id,
                transfer_state,
                journal.capture.as_ref().map(|c| c.size).unwrap_or(0),
                0,
                Some(sdk_resume_json),
            )
            .await?;
    } else {
        state
            .record_transfer(TransferRecord {
                connection_id: connection,
                transfer_id,
                operation_id: Some(operation),
                direction: TransferDirection::Upload,
                version_id: None,
                range_start: None,
                range_end: None,
                state: transfer_state,
                sdk_resume_json: Some(sdk_resume_json),
                logical_bytes: journal.capture.as_ref().map(|c| c.size).unwrap_or(0),
                wire_bytes: 0,
            })
            .await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Workspace initialization
// ---------------------------------------------------------------------------

/// Builds and executes the guarded initialization of a brand-new managed
/// prefix. The initial commit's identifiers are persisted before the
/// conditional create; a racing initializer is never overwritten.
pub async fn initialize_workspace<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
) -> Result<InitOutcome, PublishError> {
    let init_operation = OperationId::new();
    let (root, publish_set) = hfdrive_core::catalog::initialize(ctx.root_item_id, init_operation)
        .map_err(|_| PublishError::UnsupportedFormat)?;
    let commit_id = CommitId::new();
    let generation = GenerationId::new();
    let commit = CommitV1 {
        format: format::FORMAT_NAME.to_owned(),
        schema_version: format::SCHEMA_VERSION,
        workspace_id: ctx.workspace,
        commit_id,
        parent_commit_id: None,
        catalog_root: root.digest(),
        operation_ids: vec![init_operation],
        changes: Vec::new(),
        device_id: ctx.device_id,
        created_at: crate::sync::outbox::display_timestamp(now_100ns()),
    };
    let head_v1 = HeadV1 {
        format: format::FORMAT_NAME.to_owned(),
        schema_version: format::SCHEMA_VERSION,
        workspace_id: ctx.workspace,
        root_item_id: ctx.root_item_id,
        commit_id,
        generation,
        required_features: Vec::new(),
    };
    ctx.state
        .record_commit(CommitRecord {
            connection_id: ctx.connection,
            commit_id,
            parent_id: None,
            catalog_root: Some(root.digest()),
            operation_ids: vec![init_operation],
            status: CommitStatus::Candidate,
        })
        .await?;
    let candidate = PublicationCandidate {
        head: head_v1,
        commit,
        versions: Vec::new(),
        catalog: publish_set,
        payloads: Vec::new(),
    };
    let outcome = ctx.remote.initialize(candidate, ctx.cancel).await?;
    if matches!(outcome, InitOutcome::Committed(_)) {
        ctx.state
            .set_commit_status(ctx.connection, commit_id, CommitStatus::Committed)
            .await?;
        let root_record = ItemRecord {
            item_id: ctx.root_item_id,
            parent_id: None,
            name: String::new(),
            kind: ItemKind::Directory,
            item_revision: init_operation,
            content_version_id: None,
            deleted: false,
            content_operation: init_operation,
            location_operation: init_operation,
            deletion_operation: None,
        };
        record_common_bases(ctx.state, ctx.connection, commit_id, &[root_record.clone()]).await?;
        ctx.state
            .upsert_item(registry_item(ctx.connection, &root_record, None, None, None))
            .await?;
        ctx.state
            .set_baseline(ctx.connection, BaselineKind::Applied, Some(commit_id))
            .await?;
    }
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Resolves an item's relative path from a record map.
fn record_path(records: &HashMap<ItemId, ItemRecord>, item_id: ItemId) -> Option<std::path::PathBuf> {
    let mut components = Vec::new();
    let mut current = item_id;
    let mut depth = 0;
    loop {
        if depth > 512 {
            return None;
        }
        let record = records.get(&current)?;
        if record.parent_id.is_none() {
            break;
        }
        components.push(record.name.clone());
        current = record.parent_id?;
        depth += 1;
    }
    components.reverse();
    let mut path = std::path::PathBuf::new();
    for component in components {
        path.push(component);
    }
    Some(path)
}

fn item_path_sync(sources: &PlanSources, item_id: ItemId) -> Option<std::path::PathBuf> {
    let mut map = HashMap::new();
    for item in sources.base.iter() {
        map.insert(item.item_id, item.to_record());
    }
    for item in sources.remote.iter() {
        map.entry(item.item_id).or_insert_with(|| item.to_record());
    }
    record_path(&map, item_id)
}

/// Resolves an item's current relative path from the durable registry.
async fn item_path<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    item_id: ItemId,
) -> Option<std::path::PathBuf> {
    let mut components = Vec::new();
    let mut current = Some(item_id);
    let mut depth = 0;
    while let Some(id) = current {
        if depth > 512 {
            return None;
        }
        let item = ctx.state.item(ctx.connection, id).await.ok()??;
        if item.parent_id.is_none() {
            break;
        }
        components.push(item.name.clone());
        current = item.parent_id;
        depth += 1;
    }
    components.reverse();
    let mut path = std::path::PathBuf::new();
    for component in components {
        path.push(component);
    }
    Some(path)
}

fn collect_names(
    base: &hfdrive_core::reconcile::CatalogView,
    remote: &hfdrive_core::reconcile::CatalogView,
) -> HashMap<ItemId, String> {
    let mut names = HashMap::new();
    for view in [base, remote] {
        for item in view.iter() {
            names.insert(item.item_id, item.name.clone());
        }
    }
    names
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn now_100ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64 / 100 + 116_444_736_000_000_000)
        .unwrap_or(116_444_736_000_000_000)
}

/// Re-exported planning helper used by the controller.
pub use plan::ready_to_plan;
