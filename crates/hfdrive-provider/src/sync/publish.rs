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
use hfdrive_core::reconcile::{ReconcileMode, ReconcilePlan};
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
use crate::sync::remote::{RemoteError, RemoteHead, RemoteIdentity, RemoteOps};

/// Everything one round needs about the connection.
async fn read_valid_head<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
) -> Result<Option<RemoteHead>, RemoteError> {
    let head = ctx.remote.read_head(ctx.cancel).await?;
    if let Some(head) = &head {
        RemoteIdentity { workspace: ctx.workspace, root_item: ctx.root_item_id }
            .check_head(&head.head)?;
    }
    Ok(head)
}

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

impl<R: RemoteOps> RoundContext<'_, R> {
    /// Records one classified failure against an outbox operation (after any
    /// retry transition that cleared stale errors). Safe codes/details only.
    pub(crate) async fn record_outbox_error(
        &self,
        operation: OperationId,
        code: &'static str,
        detail: &str,
    ) {
        crate::sync::work_errors::record_outbox_error(
            self.state,
            self.connection,
            operation,
            code,
            detail,
        )
        .await;
    }

    /// Records one classified failure against a transfer journal row.
    pub(crate) async fn record_transfer_failure(
        &self,
        transfer: hfdrive_core::ids::TransferId,
        error: &PublishError,
    ) {
        crate::sync::work_errors::record_transfer_failure(
            self.state,
            self.connection,
            transfer,
            error,
        )
        .await;
    }

    /// Records one publication-loop failure against an outbox operation.
    /// Cancellation is never recorded as a permanent failure.
    pub(crate) async fn record_outbox_failure(&self, operation: OperationId, error: &PublishError) {
        crate::sync::work_errors::record_outbox_failure(
            self.state,
            self.connection,
            operation,
            error,
        )
        .await;
    }
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
    /// A classified capture failure. `code` is a stable
    /// [`crate::sync::work_errors::codes`] class; `detail` is safe text.
    #[error("capture failed: {detail}")]
    Capture { code: &'static str, detail: String },
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
///
/// Failures are recorded at their owned sites (capture/upload in
/// [`upload_entry`], the conditional publication in step 8, local application
/// in [`execute_pending_actions`]). A round-level abort (head read, catalog/
/// plan, resume) has no single owning work row, so it is recorded against
/// exactly the entries this round was driving — the tracked `driven` set —
/// and only when that entry is still unfinished, not excluded, and carries no
/// newer owned-site record. Parked-for-retry and published work are never
/// stamped. Normal cancellation (shutdown/pause) records nothing anywhere.
pub async fn run_round<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    writable: bool,
) -> Result<RoundOutcome, PublishError> {
    let mut driven: Vec<OperationId> = Vec::new();
    let result = run_round_inner(ctx, writable, &mut driven).await;
    if let Err(error) = &result {
        if !crate::sync::work_errors::publish_is_cancellation(error) {
            for operation in driven {
                // An owned site already recorded the newer failure for this
                // work (after its own retry/state transitions).
                if ctx
                    .state
                    .work_error(ctx.connection, hfdrive_state::WorkErrorKind::Outbox, *operation.as_uuid())
                    .await
                    .ok()
                    .flatten()
                    .is_some()
                {
                    continue;
                }
                let Some(entry) = ctx.state.outbox_entry(ctx.connection, operation).await.ok().flatten()
                else {
                    continue;
                };
                // Never stamp work that reached a published state before the
                // abort (its local apply is separate work) or an excluded
                // subtree (not this round's work).
                if matches!(
                    entry.state,
                    OutboxState::Published | OutboxState::LocalApplyPending | OutboxState::Complete
                ) {
                    continue;
                }
                let excluded = match parse_intent(&entry) {
                    Ok(intent) => {
                        crate::sync::observe::excluded_here(ctx.state, ctx.connection, intent.item_id())
                            .await
                    }
                    Err(_) => true,
                };
                if excluded {
                    continue;
                }
                ctx.record_outbox_failure(operation, error).await;
            }
        }
    }
    result
}

async fn run_round_inner<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    writable: bool,
    driven: &mut Vec<OperationId>,
) -> Result<RoundOutcome, PublishError> {
    let mut outcome = RoundOutcome::default();
    let round_started_ms = now_ms();
    let all = ctx.state.list_outbox(ctx.connection, None, u32::MAX).await?;

    // 1. Crash-safe resume: dispatched candidates are resolved by identity
    //    and never re-driven; absent candidates re-plan with fresh IDs.
    let mut planning: Vec<OutboxEntry> = Vec::new();
    let mut resumed = Vec::new();
    for entry in all {
        match entry.state {
            OutboxState::Complete | OutboxState::LocalApplyPending | OutboxState::Published => {}
            OutboxState::MetadataReady => {
                driven.push(entry.operation_id);
                resumed.push(entry);
            }
            OutboxState::PublishUnknown => {
                driven.push(entry.operation_id);
                match classify_parked(ctx, &entry).await? {
                    Some(commit_id) => {
                        mark_published_locally(ctx, &entry, &mut outcome, Some(commit_id)).await?
                    }
                    None => planning.push(entry),
                }
            }
            _ => {
                if next_step(&entry, round_started_ms) != PhaseStep::Wait {
                    driven.push(entry.operation_id);
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
    let baseline = ctx.state.baseline(ctx.connection).await?;
    let head = match read_valid_head(ctx).await? {
        Some(head) => head,
        None if baseline.applied_commit.is_some()
            || baseline.observed_commit.is_some()
            || baseline.published_commit.is_some() => {
            return Err(RemoteError::RemoteContentUnavailable.into());
        }
        None => {
            outcome.needs_initialize = writable;
            return Ok(outcome);
        }
    };
    let remote_moved = baseline.applied_commit != Some(head.head.commit_id);
    if planning.is_empty() && !remote_moved {
        // A successful quiet poll still proves which commit is observable.
        // Do not leave initialized drives permanently without that evidence.
        if baseline.observed_commit != Some(head.head.commit_id) {
            ctx.state
                .set_baseline(ctx.connection, BaselineKind::Observed, Some(head.head.commit_id))
                .await?;
        }
        return Ok(outcome);
    }

    ctx.state.set_baseline(ctx.connection, BaselineKind::Observed, Some(head.head.commit_id)).await?;
    // 3. Complete views and the pure merge. Read-only rounds reconcile in
    //    read-only mode: zero remote ops, local intents deferred, remote
    //    changes materialized through guarded local actions.
    let catalog_root = catalog_root_of(ctx, &head).await?;
    let digests_source = RemoteDigests::new(ctx.remote, ctx.workspace);
    let mut digests = DigestResolver::new(&digests_source, ctx.cancel);
    let base = build_base_view(ctx.state, ctx.connection, baseline.applied_commit, &mut digests).await?;
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
        finish_remote_application(ctx, &planning, &planned, &sources, &head, &mut outcome).await?;
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
    let published = ctx.remote.publish(&head, candidate, ctx.cancel).await;
    let published = match published {
        Ok(result) => result,
        Err(error) => {
            // The new failure is recorded after the transitions above (which
            // clear stale errors), so this is the current failure.
            let error = PublishError::Remote(error);
            for entry in &round_entries {
                ctx.record_outbox_failure(entry.operation_id, &error).await;
            }
            return Err(error);
        }
    };
    match published {
        PublishResult::Committed(_) => {
            let commit_id = candidate_commit_id(&round_entries)
                .unwrap_or(head.head.commit_id);
            finish_commit(ctx, &round_entries, &planned, &sources, &head, &batch, commit_id, &mut outcome)
                .await?;
        }
        PublishResult::PreconditionFailed { current } => {
            // Re-reconcile against the fresh head; parking replaces candidate
            // evidence legally and keeps bound payloads bound. This is a real
            // publication failure (a racing writer won) and is recorded after
            // the parking transition that cleared stale errors.
            park_for_rebase(ctx, &round_entries, RetryClass::None, None).await?;
            for entry in &round_entries {
                ctx.record_outbox_error(
                    entry.operation_id,
                    crate::sync::work_errors::codes::PUBLISH_PRECONDITION_FAILED,
                    "the conditional publication lost its race; re-reconciling against the fresh head",
                )
                .await;
            }
            let _ = current;
        }
        PublishResult::Ambiguous(_) => {
            // The conditional write may or may not have landed; the entry is
            // parked for identity-based resolution. Recorded as the actual
            // uncertainty it is, never as a fabricated failure.
            // A future retry deadline: an absolute 500 would be in the past
            // and the parked entry would spin instead of backing off.
            park_for_rebase(ctx, &round_entries, RetryClass::Backoff, Some(now_ms() + 500)).await?;
            for entry in &round_entries {
                ctx.record_outbox_error(
                    entry.operation_id,
                    crate::sync::work_errors::codes::PUBLISH_AMBIGUOUS,
                    "the conditional publication result is unknown; resolving by identity",
                )
                .await;
            }
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
    let Some(head) = read_valid_head(ctx).await? else {
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
            match read_valid_head(ctx).await? {
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
                let head = read_valid_head(ctx).await?;
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
/// record. The `HEAD` names the commit; the commit names the catalog. The
/// commit body must prove the head's identity and this connection's
/// workspace: a body naming a different commit or a foreign workspace is
/// never this head's namespace.
pub async fn catalog_root_of<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    head: &RemoteHead,
) -> Result<CatalogRoot, PublishError> {
    Ok(CatalogRoot::from_digest(verified_commit(ctx, head).await?.catalog_root))
}

/// Reads and verifies the commit record named by a committed head.
async fn verified_commit<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    head: &RemoteHead,
) -> Result<CommitV1, PublishError> {
    let record = hfdrive_publication::MetadataRecord::Commit(head.head.commit_id);
    let body = ctx.remote.read_metadata(record, ctx.cancel).await?;
    let commit = format::from_commit_bytes(&body).map_err(|_| PublishError::UnsupportedFormat)?;
    if commit.commit_id != head.head.commit_id || commit.workspace_id != ctx.workspace {
        return Err(PublishError::UnsupportedFormat);
    }
    Ok(commit)
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

async fn finish_remote_application<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    entries: &[OutboxEntry],
    planned: &PlannedRound,
    sources: &PlanSources,
    head: &RemoteHead,
    outcome: &mut RoundOutcome,
) -> Result<(), PublishError> {
    outcome.applied_local_actions = execute_pending_actions(ctx).await?;
    require_namespace_application(ctx).await?;
    close_bookkeeping(ctx, entries, planned, head, outcome).await?;
    // Nothing was published in this round: the complete remote view is the
    // whole post-round namespace.
    advance_base(ctx, head.head.commit_id, &[], planned, sources).await?;
    ctx.state.set_baseline(ctx.connection, BaselineKind::Applied, Some(head.head.commit_id)).await?;
    Ok(())
}

async fn require_namespace_application<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
) -> Result<(), PublishError> {
    if ctx.state.pending_local_actions(ctx.connection).await?.iter().any(|action| matches!(
        action.kind,
        StateActionKind::Other | StateActionKind::CreatePlaceholder | StateActionKind::Rename
            | StateActionKind::UpdatePlaceholder | StateActionKind::DeletePlaceholder
    )) {
        return Err(PublishError::LocalApply("the committed namespace still has guarded local changes pending"));
    }
    Ok(())
}

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
/// The commit body must name the head's commit and this connection's
/// workspace, so the adopted evidence is exactly the committed state.
async fn head_evidence<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    head: &RemoteHead,
) -> Result<serde_json::Value, PublishError> {
    let commit = verified_commit(ctx, head).await?;
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
    require_namespace_application(ctx).await?;

    // Mark locally published content in-sync (guarded), then close entries.
    for entry in round_entries {
        if let Err(error) = mark_entry_in_sync(ctx, entry).await {
            // A guarded local-apply failure at this owned site, recorded
            // before it aborts the round (the transitions below would clear
            // errors; they have not run yet, so this is the newest failure).
            ctx.record_outbox_failure(entry.operation_id, &error).await;
            return Err(error);
        }
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
        if let Err(error) = apply::complete_publication(ctx.state, ctx.connection, entry.operation_id).await {
            // The local-apply/close failure is recorded after the transitions
            // above (which cleared stale errors), so it is the newest one.
            ctx.record_outbox_error(
                entry.operation_id,
                crate::sync::work_errors::codes::LOCAL_APPLY_FAILED,
                &format!(
                    "closing the published work failed: {}",
                    crate::sync::work_errors::state_code(&error)
                ),
            )
            .await;
            return Err(PublishError::State(error));
        }
        outcome.published_operations.push(entry.operation_id);
    }

    // Advance the remembered base and the durable item registry to exactly
    // the committed batch's namespace (later batches re-plan afterwards).
    advance_base(ctx, commit_id, &batch.remote_ops, planned, sources).await?;
    ctx.state
        .set_baseline(ctx.connection, BaselineKind::Applied, Some(commit_id))
        .await?;
    outcome.committed.push(commit_id);
    Ok(())
}

/// Remembers the new common base and refreshes the durable item registry.
///
/// The namespace is the complete remote view overlaid with **only the remote
/// operations that were actually committed** — one commit batch's ops, never
/// the later batches that re-plan in a later round. A remote-only round (or
/// any round without a publication) overlays nothing and adopts the complete
/// remote view as-is.
async fn advance_base<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    commit_id: CommitId,
    committed_ops: &[hfdrive_core::reconcile::RemoteOp],
    planned: &PlannedRound,
    sources: &PlanSources,
) -> Result<(), PublishError> {
    // Post-round namespace = committed remote view overlaid with this
    // commit's records (local publications).
    let mut namespace: HashMap<ItemId, ItemRecord> = HashMap::new();
    for item in sources.remote.iter() {
        namespace.insert(item.item_id, item.to_record());
    }
    for op in committed_ops {
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
    let content = intent.pending_content().ok_or(PublishError::UnsupportedFormat)?;
    let version = VersionId::from_uuid(content.version_id).map_err(|_| PublishError::UnsupportedFormat)?;
    let identity = hfdrive_windows::cfapi::identity::PlaceholderIdentity::file(ctx.workspace, item_id, version);
    let marked = apply::mark_published_in_sync(
        &ctx.root.join(&path),
        &identity,
        &evidence,
        generation,
        entry.observed_generation,
    )
    .map_err(PublishError::LocalApply)?;
    if let Some(usn) = marked {
        if let Ok(usn) = u64::try_from(usn) {
            ctx.state.update_observed_usn(ctx.connection, item_id, entry.observed_generation, usn).await?;
        }
    } else if generation == entry.observed_generation {
        return Err(PublishError::LocalApply("the published source no longer matches its capture"));
    }
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
        match execute_one_action(ctx, &row).await {
            Ok(true) => {
                // Durable state advance clears stale errors for this action;
                // nothing new to record on success.
                ctx.state
                    .set_local_action_state(ctx.connection, row.action_id, LocalActionState::Applied)
                    .await?;
                applied += 1;
            }
            // A guard refusal keeps the row pending: not a failure, no record.
            Ok(false) => {}
            Err(error) => {
                // The failure is recorded after the attempt so the persisted
                // error always describes the most recent actual failure
                // (any earlier state advance already cleared stale errors).
                // Normal cancellation is never recorded as a failure.
                crate::sync::work_errors::record_action_failure(
                    ctx.state,
                    ctx.connection,
                    row.action_id,
                    &error,
                )
                .await;
                return Err(error);
            }
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
/// USN at persist time.
///
/// The **source** path is where the local file exists before the action: the
/// action's expected state resolved in the expected/base namespace. The
/// **target** path is the reconciled location: the action's target state
/// resolved in the complete reconciled target namespace (committed remote
/// view plus the plan's target operations) — never an earlier base location,
/// so a rename whose parent also moved and a case-only rename both get their
/// distinct, correct paths. The target honours a deterministic local alias.
async fn bind_action_facts<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    planned: &ReconcilePlan,
    sources: &PlanSources,
) -> Result<HashMap<ActionId, ActionFacts>, PublishError> {
    let source_locations = source_locations(sources);
    let target_locations = target_locations(sources, planned);
    let mut facts = HashMap::new();
    for action in &planned.local_actions {
        let expected_path = action
            .expected
            .as_ref()
            .and_then(|state| action_path(&source_locations, state));
        let mut target_path = action
            .target
            .as_ref()
            .and_then(|state| action_path(&target_locations, state));
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
///
/// Every real failure (capture, upload checkpoint, journal/state write) is
/// recorded against this operation's transfer and outbox work rows with its
/// classified code, after the attempt — so a stored error always describes
/// the newest actual failure. Normal cancellation records nothing.
pub async fn upload_entry<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    entry: &OutboxEntry,
) -> Result<(), PublishError> {
    let result = upload_entry_inner(ctx, entry).await;
    if let Err(error) = &result {
        let transfer = transfer_id_for(entry.operation_id);
        ctx.record_transfer_failure(transfer, error).await;
        ctx.record_outbox_failure(entry.operation_id, error).await;
    }
    result
}

async fn upload_entry_inner<R: RemoteOps>(
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
        match ctx.state.snapshot(ctx.connection, snapshot_id).await {
            Ok(Some(row)) => {
                if let Ok(payload) = staged_payload(entry, &row) {
                    staged = Some(payload);
                }
            }
            Ok(None) => {
                return Err(PublishError::Capture {
                    code: crate::sync::work_errors::codes::SNAPSHOT_UNAVAILABLE,
                    detail: "staged snapshot row is missing".to_owned(),
                });
            }
            Err(error) => return Err(PublishError::State(error)),
        }
    }

    let staged = match staged {
        Some(staged) => {
            if journal.capture.is_none() {
                return Err(PublishError::Capture {
                    code: crate::sync::work_errors::codes::CAPTURE_EVIDENCE_MISSING,
                    detail: "capture evidence is missing for a staged payload".to_owned(),
                });
            }
            staged
        }
        None => {
            let source = item_path(ctx, item_id).await.ok_or_else(|| PublishError::Capture {
                code: crate::sync::work_errors::codes::SOURCE_UNAVAILABLE,
                detail: "the source path is unknown".to_owned(),
            })?;
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
                workspace: ctx.workspace,
                root: ctx.root.to_path_buf(),
            };
            let captured = match crate::sync::capture::capture_local_change(
                ctx.state,
                ctx.scheduler,
                *ctx.workspace.as_uuid(),
                &request,
                ctx.cancel,
            )
            .await
            {
                Ok(captured) => captured,
                Err(error) => {
                    return Err(PublishError::Capture {
                        code: error.error_code(),
                        detail: error.detail(),
                    });
                }
            };
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
            // through Recaptured (-> Observed) first. These transitions clear
            // stale work errors, so a failure below records its new cause
            // afterwards.
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
                    return Err(PublishError::Capture {
                        code: crate::sync::work_errors::codes::INVALID_STATE,
                        detail: "upload is only valid before payload binding".to_owned(),
                    });
                }
            }
            captured.staged
        }
    };
    let snapshot: StableSnapshot = staged.stable_snapshot();

    // Resume at the first missing durable boundary. Re-ingesting after CAS
    // commitment wastes sessions and cannot add evidence for the key binding.
    if journal.ingested.is_none() && journal.cas_committed.is_none() {
        journal.ingested = Some(ctx.remote.ingest_payload(&snapshot, ctx.cancel).await?);
        save_journal(ctx.state, ctx.connection, entry.operation_id, &journal, TransferState::InProgress).await?;
    }
    if journal.cas_committed.is_none() {
        let ingested = journal.ingested.as_ref().ok_or(PublishError::UnsupportedFormat)?;
        journal.cas_committed = Some(ctx.remote.commit_payload_cas(&snapshot, ingested, ctx.cancel).await?);
        save_journal(ctx.state, ctx.connection, entry.operation_id, &journal, TransferState::InProgress).await?;
    }
    let committed = journal.cas_committed.as_ref().ok_or(PublishError::UnsupportedFormat)?;
    let object = match ctx.remote.bind_payload(&snapshot, committed, ctx.cancel).await {
        Ok(object) => object,
        Err(error) => return Err(PublishError::Remote(error)),
    };
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

/// One item's location (parent and exact name spelling) in a namespace view.
type Locations = HashMap<ItemId, (Option<ItemId>, String)>;

/// The namespace in which a journaled action's **source** path resolves: the
/// expected/base namespace — the remembered base overlaid with this round's
/// local intents — because the source is what exists locally before apply.
fn source_locations(sources: &PlanSources) -> Locations {
    let mut locations: Locations = sources
        .base
        .iter()
        .map(|item| (item.item_id, (item.parent_id, item.name.clone())))
        .collect();
    for intent in &sources.intents {
        apply_intent_location(&mut locations, intent);
    }
    locations
}

/// The namespace in which a journaled action's **target** path resolves: the
/// complete reconciled target namespace — the committed remote view overlaid
/// with the planned target operations — because the target is the reconciled
/// location, never an earlier base location.
fn target_locations(sources: &PlanSources, planned: &ReconcilePlan) -> Locations {
    let mut locations: Locations = sources
        .remote
        .iter()
        .map(|item| (item.item_id, (item.parent_id, item.name.clone())))
        .collect();
    for op in &planned.remote_ops {
        locations.insert(op.record.item_id, (op.record.parent_id, op.record.name.clone()));
    }
    locations
}

/// Applies one local intent's location effect to an expected namespace.
/// Content-only intents leave location untouched; deletion keeps the last
/// location so removals still resolve the path they must clear.
fn apply_intent_location(locations: &mut Locations, intent: &hfdrive_core::reconcile::LocalIntent) {
    use hfdrive_core::reconcile::LocalChange;
    match &intent.change {
        LocalChange::Create { parent_id, name, .. }
        | LocalChange::Move { parent_id, name }
        | LocalChange::MoveAndContent { parent_id, name, .. } => {
            locations.insert(intent.item_id, (Some(*parent_id), name.clone()));
        }
        LocalChange::Delete | LocalChange::Content { .. } => {}
        LocalChange::Materialized { state } => {
            locations.insert(intent.item_id, (state.parent_id, state.name.clone()));
        }
    }
}

/// Resolves an item's relative path, taking the item's own name and parent
/// from `state` (the action's expected/target state is authoritative for the
/// item itself) and its ancestors' locations from `locations`.
fn action_path(locations: &Locations, state: &hfdrive_core::reconcile::ItemState) -> Option<std::path::PathBuf> {
    let mut components = Vec::new();
    let mut name = state.name.clone();
    let mut parent = state.parent_id;
    let mut depth = 0;
    while let Some(parent_id) = parent {
        if depth > 512 {
            return None;
        }
        components.push(name);
        let (grandparent, parent_name) = locations.get(&parent_id)?;
        name = parent_name.clone();
        parent = *grandparent;
        depth += 1;
    }
    components.reverse();
    let mut path = std::path::PathBuf::new();
    for component in components {
        path.push(component);
    }
    Some(path)
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::sync::test_support::{HeadOnlyRemote, connection_fixture};

    fn item_record(
        item_id: ItemId,
        parent_id: Option<ItemId>,
        name: &str,
        kind: ItemKind,
        content_version_id: Option<VersionId>,
        revision: OperationId,
    ) -> ItemRecord {
        ItemRecord {
            item_id,
            parent_id,
            name: name.to_owned(),
            kind,
            item_revision: revision,
            content_version_id,
            deleted: false,
            content_operation: revision,
            location_operation: revision,
            deletion_operation: None,
        }
    }

    /// View state for a test record: file payloads derive their identity from
    /// the bound version, so equal versions mean equal content everywhere.
    fn item_state(record: &ItemRecord) -> hfdrive_core::reconcile::ItemState {
        use hfdrive_core::storage::Sha256Digest;
        let (sha256, size) = match record.content_version_id {
            Some(version) => (Some(Sha256Digest::of(version.as_bytes())), Some(4)),
            None => (None, None),
        };
        hfdrive_core::reconcile::ItemState::from_record(record, sha256, size).unwrap()
    }

    fn rel(components: &[&str]) -> std::path::PathBuf {
        let mut path = std::path::PathBuf::new();
        for component in components {
            path.push(component);
        }
        path
    }

    fn head_record(
        workspace: WorkspaceId,
        root_item: ItemId,
        commit_id: CommitId,
    ) -> HeadV1 {
        HeadV1 {
            format: format::FORMAT_NAME.to_owned(),
            schema_version: format::SCHEMA_VERSION,
            workspace_id: workspace,
            root_item_id: root_item,
            commit_id,
            generation: GenerationId::new(),
            required_features: Vec::new(),
        }
    }

    fn commit_record(
        workspace: WorkspaceId,
        commit_id: CommitId,
        catalog_root: hfdrive_core::storage::Sha256Digest,
    ) -> CommitV1 {
        CommitV1 {
            format: format::FORMAT_NAME.to_owned(),
            schema_version: format::SCHEMA_VERSION,
            workspace_id: workspace,
            commit_id,
            parent_commit_id: Some(CommitId::new()),
            catalog_root,
            operation_ids: vec![OperationId::new()],
            changes: Vec::new(),
            device_id: DeviceId::new(),
            created_at: "2026-11-17T00:00:00Z".to_owned(),
        }
    }

    fn planned_round(
        workspace: WorkspaceId,
        remote_ops: Vec<hfdrive_core::reconcile::RemoteOp>,
    ) -> PlannedRound {
        let plan = ReconcilePlan {
            workspace_id: workspace,
            mode: ReconcileMode::Writable,
            remote_ops,
            versions: Vec::new(),
            changes: Vec::new(),
            operation_ids: Vec::new(),
            local_actions: Vec::new(),
            conflicts: Vec::new(),
            aliases: Vec::new(),
            intents: Vec::new(),
        };
        PlannedRound { plan, outcomes: Vec::new() }
    }

    fn create_op(record: ItemRecord) -> hfdrive_core::reconcile::RemoteOp {
        hfdrive_core::reconcile::RemoteOp {
            record,
            change: format::ChangeKind::Create,
            old_revision: None,
        }
    }

    fn round_context<'a>(
        fixture: &'a crate::sync::test_support::TestConnection,
        remote: &'a HeadOnlyRemote,
        scheduler: &'a crate::scheduler::Scheduler,
        cancel: &'a CancellationToken,
    ) -> RoundContext<'a, HeadOnlyRemote> {
        RoundContext {
            state: &fixture.account,
            remote,
            connection: fixture.connection,
            workspace: fixture.workspace,
            root_item_id: fixture.root_item,
            device_id: DeviceId::new(),
            mode: ReconcileMode::Writable,
            root: &fixture.root,
            staging_dir: fixture.directory.path(),
            recovery_dir: fixture.directory.path(),
            scheduler,
            cancel,
        }
    }

    #[tokio::test]
    async fn quiet_head_poll_records_observation_without_advancing_publication() {
        let fixture = connection_fixture().await;
        let directory = &fixture.directory;
        let root = &fixture.root;
        let account = &fixture.account;
        let workspace = fixture.workspace;
        let root_item = fixture.root_item;
        let connection = fixture.connection;
        let applied = CommitId::new();
        let prior_publication = CommitId::new();
        account.set_baseline(connection, BaselineKind::Applied, Some(applied)).await.unwrap();
        account.set_baseline(connection, BaselineKind::Published, Some(prior_publication)).await.unwrap();
        let remote = HeadOnlyRemote {
            head: Some(RemoteHead {
                head: HeadV1 {
                    format: format::FORMAT_NAME.to_owned(),
                    schema_version: format::SCHEMA_VERSION,
                    workspace_id: workspace,
                    root_item_id: root_item,
                    commit_id: applied,
                    generation: GenerationId::new(),
                    required_features: Vec::new(),
                },
                etag: None,
            }),
            ..Default::default()
        };
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        for (mode, writable) in [(ReconcileMode::ReadOnly, false), (ReconcileMode::Writable, true)] {
            account.set_baseline(connection, BaselineKind::Observed, None).await.unwrap();
            let context = RoundContext {
                state: &account,
                remote: &remote,
                connection,
                workspace,
                root_item_id: root_item,
                device_id: DeviceId::new(),
                mode,
                root: &root,
                staging_dir: directory.path(),
                recovery_dir: directory.path(),
                scheduler: &scheduler,
                cancel: &cancel,
            };
            run_round(&context, writable).await.unwrap();
            let baseline = account.baseline(connection).await.unwrap();
            assert_eq!(baseline.observed_commit, Some(applied));
            assert_eq!(baseline.applied_commit, Some(applied));
            assert_eq!(baseline.published_commit, Some(prior_publication));
        }
        fixture.state.close().await.unwrap();
    }

    fn read_only_context<'a>(
        fixture: &'a crate::sync::test_support::TestConnection,
        remote: &'a HeadOnlyRemote,
        scheduler: &'a crate::scheduler::Scheduler,
        cancel: &'a CancellationToken,
    ) -> RoundContext<'a, HeadOnlyRemote> {
        RoundContext {
            state: &fixture.account, remote, connection: fixture.connection,
            workspace: fixture.workspace, root_item_id: fixture.root_item,
            device_id: DeviceId::new(), mode: ReconcileMode::ReadOnly,
            root: &fixture.root, staging_dir: fixture.directory.path(),
            recovery_dir: fixture.directory.path(), scheduler, cancel,
        }
    }

    #[tokio::test]
    async fn an_established_missing_head_preserves_baselines_and_local_bytes() {
        let fixture = connection_fixture().await;
        let path = fixture.root.join("keep.bin");
        std::fs::write(&path, b"unsynchronized local bytes").unwrap();
        let committed = CommitId::new();
        for kind in [BaselineKind::Applied, BaselineKind::Observed, BaselineKind::Published] {
            fixture.account.set_baseline(fixture.connection, kind, Some(committed)).await.unwrap();
        }
        let remote = HeadOnlyRemote::default();
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let mut context = read_only_context(&fixture, &remote, &scheduler, &cancel);
        for (mode, writable) in [(ReconcileMode::ReadOnly, false), (ReconcileMode::Writable, true)] {
            context.mode = mode;
            assert!(matches!(run_round(&context, writable).await,
                Err(PublishError::Remote(RemoteError::RemoteContentUnavailable))));
            let baseline = fixture.account.baseline(fixture.connection).await.unwrap();
            assert_eq!(baseline.observed_commit, Some(committed));
            assert_eq!(baseline.applied_commit, Some(committed));
            assert_eq!(baseline.published_commit, Some(committed));
            assert_eq!(std::fs::read(&path).unwrap(), b"unsynchronized local bytes");
        }
        fixture.state.close().await.unwrap();
    }

    #[tokio::test]
    async fn refused_namespace_application_keeps_the_old_baseline_and_original_guard() {
        use hfdrive_core::reconcile::{CatalogView, ItemState};
        use hfdrive_core::storage::Sha256Digest;
        let fixture = connection_fixture().await;
        let path = std::path::PathBuf::from("guarded.bin");
        std::fs::write(fixture.root.join(&path), b"local bytes must survive").unwrap();
        let operation = OperationId::new();
        let root = ItemRecord {
            item_id: fixture.root_item, parent_id: None, name: String::new(),
            kind: ItemKind::Directory, item_revision: operation, content_version_id: None,
            deleted: false, content_operation: operation, location_operation: operation,
            deletion_operation: None,
        };
        let file = ItemRecord {
            item_id: ItemId::new(), parent_id: Some(fixture.root_item), name: "guarded.bin".to_owned(),
            kind: ItemKind::File, content_version_id: Some(VersionId::new()), ..root.clone()
        };
        let next_operation = OperationId::new();
        let changed = ItemRecord {
            content_version_id: Some(VersionId::new()), item_revision: next_operation,
            content_operation: next_operation, ..file.clone()
        };
        let root_state = ItemState::from_record(&root, None, None).unwrap();
        let base = CatalogView::new(vec![root_state.clone(), ItemState::from_record(
            &file, Some(Sha256Digest::of(b"base")), Some(4),
        ).unwrap()]).unwrap();
        let remote_view = CatalogView::new(vec![root_state, ItemState::from_record(
            &changed, Some(Sha256Digest::of(b"remote")), Some(6),
        ).unwrap()]).unwrap();
        let names = collect_names(&base, &remote_view);
        let sources = PlanSources { base, remote: remote_view, intents: Vec::new(), names };
        let previous = CommitId::new();
        let target = CommitId::new();
        record_common_bases(&fixture.account, fixture.connection, previous, &[root, file.clone()]).await.unwrap();
        fixture.account.upsert_item(registry_item(fixture.connection, &file, Some(Sha256Digest::of(b"base")), Some(4), None)).await.unwrap();
        fixture.account.set_baseline(fixture.connection, BaselineKind::Applied, Some(previous)).await.unwrap();
        fixture.account.set_baseline(fixture.connection, BaselineKind::Observed, Some(target)).await.unwrap();

        let planned = plan::plan_round(&fixture.account, fixture.connection, fixture.workspace, ReconcileMode::ReadOnly, &sources).await.unwrap();
        let facts = planned.plan.local_actions.iter().map(|action| (action.action_id, ActionFacts {
            source_path: Some(path.clone()), target_path: Some(path.clone()),
            expected_file_id: None, expected_generation: None, expected_usn: None,
        })).collect();
        plan::persist_plan_records(&fixture.account, fixture.connection, &planned.plan, &facts).await.unwrap();
        let original = fixture.account.pending_local_actions(fixture.connection).await.unwrap();
        assert_eq!(original.len(), 1);
        assert_eq!(original[0].kind, StateActionKind::UpdatePlaceholder);

        let retry = plan::plan_round(&fixture.account, fixture.connection, fixture.workspace, ReconcileMode::ReadOnly, &sources).await.unwrap();
        let changed_facts = retry.plan.local_actions.iter().map(|action| (action.action_id, ActionFacts {
            source_path: Some(path.clone()), target_path: Some(path.clone()),
            expected_file_id: Some("00000000000000000000000000000001".to_owned()),
            expected_generation: Some(7), expected_usn: Some(9),
        })).collect();
        plan::persist_plan_records(&fixture.account, fixture.connection, &retry.plan, &changed_facts).await.unwrap();
        let pending = fixture.account.pending_local_actions(fixture.connection).await.unwrap();
        assert_eq!(pending.len(), 1, "retry must not accumulate a second namespace action");
        assert_eq!(pending[0].action_id, original[0].action_id);
        assert_eq!(pending[0].expected_file_id, None);
        assert_eq!(pending[0].expected_usn, None);

        let remote = HeadOnlyRemote::default();
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let context = read_only_context(&fixture, &remote, &scheduler, &cancel);
        let head = RemoteHead { head: HeadV1 {
            format: format::FORMAT_NAME.to_owned(), schema_version: format::SCHEMA_VERSION,
            workspace_id: fixture.workspace, root_item_id: fixture.root_item, commit_id: target,
            generation: GenerationId::new(), required_features: Vec::new(),
        }, etag: None };
        let mut outcome = RoundOutcome::default();
        assert!(matches!(finish_remote_application(&context, &[], &retry, &sources, &head, &mut outcome).await,
            Err(PublishError::LocalApply(_))));
        let baseline = fixture.account.baseline(fixture.connection).await.unwrap();
        assert_eq!(baseline.applied_commit, Some(previous));
        assert_eq!(baseline.observed_commit, Some(target));
        assert_eq!(fixture.account.pending_local_actions(fixture.connection).await.unwrap()[0].state, LocalActionState::Pending);
        assert_eq!(std::fs::read(fixture.root.join(path)).unwrap(), b"local bytes must survive");
        fixture.state.close().await.unwrap();
    }

    // -- K01: the base advances by the committed batch only ----------------

    #[tokio::test]
    async fn later_batch_operations_never_enter_the_committed_base() {
        use hfdrive_core::reconcile::CatalogView;
        let fixture = connection_fixture().await;
        let revision = OperationId::new();
        let root = item_record(fixture.root_item, None, "", ItemKind::Directory, None, revision);
        let dir = item_record(ItemId::new(), Some(fixture.root_item), "alpha", ItemKind::Directory, None, revision);
        let first = item_record(ItemId::new(), Some(fixture.root_item), "beta.bin", ItemKind::File, Some(VersionId::new()), revision);
        let second = item_record(ItemId::new(), Some(fixture.root_item), "gamma.bin", ItemKind::File, Some(VersionId::new()), revision);
        let sources = PlanSources {
            base: CatalogView::new(vec![item_state(&root)]).unwrap(),
            remote: CatalogView::new(vec![item_state(&root)]).unwrap(),
            intents: Vec::new(),
            names: HashMap::new(),
        };
        let planned = planned_round(
            fixture.workspace,
            vec![create_op(dir.clone()), create_op(first.clone()), create_op(second.clone())],
        );
        let remote = HeadOnlyRemote::default();
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel);
        let commit = CommitId::new();
        // Only the first operation committed in this batch; the other two
        // belong to later batches and re-plan afterwards.
        advance_base(&ctx, commit, &planned.plan.remote_ops[..1], &planned, &sources).await.unwrap();
        let rows = fixture.account.list_common_bases(fixture.connection, commit).await.unwrap();
        let sealed: HashMap<ItemId, String> = rows
            .iter()
            .map(|row| {
                let record = format::from_item_record_bytes(row.item_json.as_bytes()).unwrap();
                (record.item_id, record.name)
            })
            .collect();
        assert_eq!(sealed.len(), 2, "only the root and the committed operation belong to this base");
        assert_eq!(sealed.get(&fixture.root_item).map(String::as_str), Some(""));
        assert_eq!(sealed.get(&dir.item_id).map(String::as_str), Some("alpha"));
        assert!(!sealed.contains_key(&first.item_id), "a later batch's operation must not enter this base");
        assert!(!sealed.contains_key(&second.item_id), "a later batch's operation must not enter this base");
        // The durable registry mirrors exactly the committed records.
        assert!(fixture.account.item(fixture.connection, dir.item_id).await.unwrap().is_some());
        assert!(fixture.account.item(fixture.connection, first.item_id).await.unwrap().is_none());
        assert!(fixture.account.item(fixture.connection, second.item_id).await.unwrap().is_none());
        fixture.state.close().await.unwrap();
    }

    #[tokio::test]
    async fn more_than_a_commit_bound_of_operations_cannot_enter_one_base() {
        use hfdrive_core::reconcile::CatalogView;
        let fixture = connection_fixture().await;
        let revision = OperationId::new();
        let root = item_record(fixture.root_item, None, "", ItemKind::Directory, None, revision);
        let mut records = vec![root];
        for index in 0..(format::MAX_COMMIT_OPERATIONS + 1) {
            records.push(item_record(
                ItemId::new(),
                Some(fixture.root_item),
                &format!("file-{index:04}"),
                ItemKind::File,
                Some(VersionId::new()),
                OperationId::new(),
            ));
        }
        let sources = PlanSources {
            base: CatalogView::new(vec![item_state(&records[0])]).unwrap(),
            remote: CatalogView::new(vec![item_state(&records[0])]).unwrap(),
            intents: Vec::new(),
            names: HashMap::new(),
        };
        let planned =
            planned_round(fixture.workspace, records[1..].iter().cloned().map(create_op).collect());
        let batches = planned
            .plan
            .commit_batches(format::MAX_COMMIT_OPERATIONS, format::MAX_COMMIT_OPERATIONS)
            .unwrap();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].remote_ops.len(), format::MAX_COMMIT_OPERATIONS);
        assert_eq!(batches[1].remote_ops.len(), 1);
        let last = batches[1].remote_ops[0].record.item_id;

        let remote = HeadOnlyRemote::default();
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel);
        let first_commit = CommitId::new();
        advance_base(&ctx, first_commit, &batches[0].remote_ops, &planned, &sources).await.unwrap();
        let rows = fixture.account.list_common_bases(fixture.connection, first_commit).await.unwrap();
        assert_eq!(
            rows.len(),
            format::MAX_COMMIT_OPERATIONS + 1,
            "the earlier base holds the root plus exactly the committed batch"
        );
        assert!(
            fixture.account.get_common_base(fixture.connection, last, first_commit).await.unwrap().is_none(),
            "the 1001st operation must not enter the earlier base"
        );
        // The later batch's single operation lands only in its own later base.
        let second_commit = CommitId::new();
        advance_base(&ctx, second_commit, &batches[1].remote_ops, &planned, &sources).await.unwrap();
        assert!(
            fixture.account.get_common_base(fixture.connection, last, second_commit).await.unwrap().is_some()
        );
        assert_eq!(
            fixture.account.list_common_bases(fixture.connection, second_commit).await.unwrap().len(),
            2
        );
        fixture.state.close().await.unwrap();
    }

    #[tokio::test]
    async fn a_remote_only_round_seals_the_complete_remote_view() {
        use hfdrive_core::reconcile::CatalogView;
        let fixture = connection_fixture().await;
        let revision = OperationId::new();
        let root = item_record(fixture.root_item, None, "", ItemKind::Directory, None, revision);
        let remote_only = item_record(
            ItemId::new(), Some(fixture.root_item), "remote-only.txt", ItemKind::File,
            Some(VersionId::new()), revision,
        );
        let sources = PlanSources {
            base: CatalogView::new(vec![item_state(&root)]).unwrap(),
            remote: CatalogView::new(vec![item_state(&root), item_state(&remote_only)]).unwrap(),
            intents: Vec::new(),
            names: HashMap::new(),
        };
        // The plan is empty of remote ops: the round published nothing.
        let planned = planned_round(fixture.workspace, Vec::new());
        let remote = HeadOnlyRemote::default();
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel);
        let head_commit = CommitId::new();
        advance_base(&ctx, head_commit, &[], &planned, &sources).await.unwrap();
        let rows = fixture.account.list_common_bases(fixture.connection, head_commit).await.unwrap();
        assert_eq!(rows.len(), 2, "the remote-only base is the complete remote view");
        assert!(
            fixture.account
                .get_common_base(fixture.connection, remote_only.item_id, head_commit)
                .await
                .unwrap()
                .is_some()
        );
        fixture.state.close().await.unwrap();
    }

    // -- K10: head evidence proves its identity ---------------------------

    /// Evaluates `catalog_root_of` against a fresh remote serving `body`, so
    /// no test case mutates storage under a live borrow.
    async fn catalog_root_of_body(
        fixture: &crate::sync::test_support::TestConnection,
        scheduler: &crate::scheduler::Scheduler,
        cancel: &CancellationToken,
        head: &RemoteHead,
        body: Vec<u8>,
    ) -> Result<CatalogRoot, PublishError> {
        let remote = HeadOnlyRemote { metadata: Some(bytes::Bytes::from(body)), ..Default::default() };
        let ctx = round_context(fixture, &remote, scheduler, cancel);
        catalog_root_of(&ctx, head).await
    }

    /// Evaluates `head_evidence` against a fresh remote serving `body`, so no
    /// test case mutates storage under a live borrow.
    async fn head_evidence_body(
        fixture: &crate::sync::test_support::TestConnection,
        scheduler: &crate::scheduler::Scheduler,
        cancel: &CancellationToken,
        head: &RemoteHead,
        body: Vec<u8>,
    ) -> Result<serde_json::Value, PublishError> {
        let remote = HeadOnlyRemote { metadata: Some(bytes::Bytes::from(body)), ..Default::default() };
        let ctx = round_context(fixture, &remote, scheduler, cancel);
        head_evidence(&ctx, head).await
    }

    #[tokio::test]
    async fn committed_head_evidence_rejects_wrong_commit_or_workspace() {
        use hfdrive_core::storage::Sha256Digest;
        let fixture = connection_fixture().await;
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let commit_id = CommitId::new();
        let catalog_root = Sha256Digest::of(b"catalog-root");
        let head = RemoteHead {
            head: head_record(fixture.workspace, fixture.root_item, commit_id),
            etag: None,
        };

        // The correct body resolves the catalog root and the evidence bundle.
        let correct = format::to_commit_bytes(&commit_record(fixture.workspace, commit_id, catalog_root)).unwrap();
        let resolved = catalog_root_of_body(&fixture, &scheduler, &cancel, &head, correct.clone()).await;
        assert_eq!(resolved.unwrap().digest(), catalog_root);
        let evidence = head_evidence_body(&fixture, &scheduler, &cancel, &head, correct).await.unwrap();
        let bundle: CandidateBundle = serde_json::from_value(evidence).unwrap();
        assert_eq!(bundle.commit_v1().unwrap().commit_id, commit_id);

        // A body naming another commit is not this head's namespace.
        let wrong_commit =
            format::to_commit_bytes(&commit_record(fixture.workspace, CommitId::new(), catalog_root)).unwrap();
        assert!(matches!(
            catalog_root_of_body(&fixture, &scheduler, &cancel, &head, wrong_commit.clone()).await,
            Err(PublishError::UnsupportedFormat)
        ));
        assert!(matches!(
            head_evidence_body(&fixture, &scheduler, &cancel, &head, wrong_commit).await,
            Err(PublishError::UnsupportedFormat)
        ));

        // A body from another workspace is foreign storage, never evidence.
        let wrong_workspace =
            format::to_commit_bytes(&commit_record(WorkspaceId::new(), commit_id, catalog_root)).unwrap();
        assert!(matches!(
            catalog_root_of_body(&fixture, &scheduler, &cancel, &head, wrong_workspace.clone()).await,
            Err(PublishError::UnsupportedFormat)
        ));
        assert!(matches!(
            head_evidence_body(&fixture, &scheduler, &cancel, &head, wrong_workspace).await,
            Err(PublishError::UnsupportedFormat)
        ));
        fixture.state.close().await.unwrap();
    }

    // -- G07: action source/target paths --------------------------------

    #[tokio::test]
    async fn rename_binding_uses_distinct_expected_and_target_paths() {
        use hfdrive_core::reconcile::{CatalogView, LocalActionKind};
        let fixture = connection_fixture().await;
        let base_revision = OperationId::new();
        let move_op = OperationId::new();
        let case_op = OperationId::new();
        let root = item_record(fixture.root_item, None, "", ItemKind::Directory, None, base_revision);
        let docs = item_record(ItemId::new(), Some(fixture.root_item), "docs", ItemKind::Directory, None, base_revision);
        let report = item_record(
            ItemId::new(), Some(fixture.root_item), "report.txt", ItemKind::File,
            Some(VersionId::new()), base_revision,
        );
        let photo = item_record(
            ItemId::new(), Some(fixture.root_item), "photo.jpg", ItemKind::File,
            Some(VersionId::new()), base_revision,
        );
        // Remote round: `report.txt` moved into `docs` **and** renamed;
        // `photo.jpg` renamed to its case-only spelling `Photo.JPG`.
        let moved = ItemRecord {
            name: "report-2026.txt".to_owned(),
            parent_id: Some(docs.item_id),
            item_revision: move_op,
            content_operation: move_op,
            location_operation: move_op,
            ..report.clone()
        };
        let case_renamed = ItemRecord {
            name: "Photo.JPG".to_owned(),
            item_revision: case_op,
            content_operation: case_op,
            location_operation: case_op,
            ..photo.clone()
        };
        let base = CatalogView::new(vec![
            item_state(&root),
            item_state(&docs),
            item_state(&report),
            item_state(&photo),
        ])
        .unwrap();
        let remote_view = CatalogView::new(vec![
            item_state(&root),
            item_state(&docs),
            item_state(&moved),
            item_state(&case_renamed),
        ])
        .unwrap();
        let names = collect_names(&base, &remote_view);
        let sources = PlanSources { base, remote: remote_view, intents: Vec::new(), names };
        let planned =
            plan::plan_round(&fixture.account, fixture.connection, fixture.workspace, ReconcileMode::Writable, &sources)
                .await
                .unwrap();
        let renames: Vec<_> = planned
            .plan
            .local_actions
            .iter()
            .filter(|action| action.action == LocalActionKind::Rename)
            .collect();
        assert_eq!(renames.len(), 2, "exactly the moved file and the case-only rename apply locally");

        let remote = HeadOnlyRemote::default();
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel);
        let facts = bind_action_facts(&ctx, &planned.plan, &sources).await.unwrap();
        for action in renames {
            let fact = &facts[&action.action_id];
            let source = fact.source_path.as_ref().unwrap();
            let target = fact.target_path.as_ref().unwrap();
            assert_ne!(source, target, "a rename's source and target paths must differ");
            match action.item_id {
                id if id == report.item_id => {
                    // Source is the expected/base location; target is the
                    // reconciled location in the planned target namespace.
                    assert_eq!(source, &rel(&["report.txt"]));
                    assert_eq!(target, &rel(&["docs", "report-2026.txt"]));
                }
                id if id == photo.item_id => {
                    assert_eq!(source, &rel(&["photo.jpg"]));
                    assert_eq!(target, &rel(&["Photo.JPG"]));
                    assert!(hfdrive_windows::filesystem::names::windows_case_equivalent(
                        &source.to_string_lossy(),
                        &target.to_string_lossy()
                    ));
                    assert!(!hfdrive_windows::filesystem::names::windows_exact_equal(
                        &source.to_string_lossy(),
                        &target.to_string_lossy()
                    ));
                }
                other => panic!("unexpected rename item {other}"),
            }
        }
        fixture.state.close().await.unwrap();
    }

    #[tokio::test]
    async fn update_binding_follows_a_renamed_parent_directory() {
        use hfdrive_core::reconcile::{CatalogView, LocalActionKind};
        let fixture = connection_fixture().await;
        let base_revision = OperationId::new();
        let move_op = OperationId::new();
        let content_op = OperationId::new();
        let root = item_record(fixture.root_item, None, "", ItemKind::Directory, None, base_revision);
        let old_parent = item_record(ItemId::new(), Some(fixture.root_item), "docs", ItemKind::Directory, None, base_revision);
        let notes = item_record(
            ItemId::new(), Some(old_parent.item_id), "notes.txt", ItemKind::File,
            Some(VersionId::new()), base_revision,
        );
        // Remote round: the parent directory is renamed and the file's
        // content version changes.
        let new_parent = ItemRecord {
            name: "docs-2026".to_owned(),
            item_revision: move_op,
            content_operation: move_op,
            location_operation: move_op,
            ..old_parent.clone()
        };
        let updated = ItemRecord {
            content_version_id: Some(VersionId::new()),
            item_revision: content_op,
            content_operation: content_op,
            ..notes.clone()
        };
        let base = CatalogView::new(vec![item_state(&root), item_state(&old_parent), item_state(&notes)]).unwrap();
        let remote_view =
            CatalogView::new(vec![item_state(&root), item_state(&new_parent), item_state(&updated)]).unwrap();
        let names = collect_names(&base, &remote_view);
        let sources = PlanSources { base, remote: remote_view, intents: Vec::new(), names };
        let planned =
            plan::plan_round(&fixture.account, fixture.connection, fixture.workspace, ReconcileMode::Writable, &sources)
                .await
                .unwrap();
        let update = planned
            .plan
            .local_actions
            .iter()
            .find(|action| action.action == LocalActionKind::UpdatePlaceholder && action.item_id == notes.item_id)
            .expect("the content change applies locally");
        let remote = HeadOnlyRemote::default();
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel);
        let facts = bind_action_facts(&ctx, &planned.plan, &sources).await.unwrap();
        let fact = &facts[&update.action_id];
        // The source resolves in the expected/base namespace (old parent);
        // the target resolves in the reconciled target namespace (new parent).
        assert_eq!(fact.source_path.as_ref().unwrap(), &rel(&["docs", "notes.txt"]));
        assert_eq!(fact.target_path.as_ref().unwrap(), &rel(&["docs-2026", "notes.txt"]));
        assert_ne!(fact.source_path, fact.target_path);
        fixture.state.close().await.unwrap();
    }

    #[tokio::test]
    async fn local_ancestor_move_and_remote_child_change_resolve_in_their_own_namespaces() {
        use hfdrive_core::reconcile::{CatalogView, LocalActionKind, LocalChange, LocalIntent, LocalOrigin};
        let fixture = connection_fixture().await;
        let base_revision = OperationId::new();
        let remote_op = OperationId::new();
        let local_op = OperationId::new();
        let root = item_record(fixture.root_item, None, "", ItemKind::Directory, None, base_revision);
        // Base: `work/draft/notes.txt`. The local edit moves the top ancestor
        // `work` -> `archive`; the remote round renames the middle directory
        // and publishes new content for the leaf.
        let work = item_record(ItemId::new(), Some(fixture.root_item), "work", ItemKind::Directory, None, base_revision);
        let draft = item_record(ItemId::new(), Some(work.item_id), "draft", ItemKind::Directory, None, base_revision);
        let notes = item_record(
            ItemId::new(), Some(draft.item_id), "notes.txt", ItemKind::File,
            Some(VersionId::new()), base_revision,
        );
        let moved_draft = ItemRecord {
            name: "draft-2026".to_owned(),
            item_revision: remote_op,
            content_operation: remote_op,
            location_operation: remote_op,
            ..draft.clone()
        };
        let updated = ItemRecord {
            content_version_id: Some(VersionId::new()),
            item_revision: remote_op,
            content_operation: remote_op,
            location_operation: remote_op,
            ..notes.clone()
        };
        let intents = vec![LocalIntent {
            operation_id: local_op,
            item_id: work.item_id,
            origin: LocalOrigin::LocalEdit,
            observed_generation: 1,
            change: LocalChange::Move { parent_id: fixture.root_item, name: "archive".to_owned() },
        }];
        let base = CatalogView::new(vec![
            item_state(&root),
            item_state(&work),
            item_state(&draft),
            item_state(&notes),
        ])
        .unwrap();
        let remote_view = CatalogView::new(vec![
            item_state(&root),
            item_state(&work),
            item_state(&moved_draft),
            item_state(&updated),
        ])
        .unwrap();
        let names = collect_names(&base, &remote_view);
        let sources = PlanSources { base, remote: remote_view, intents, names };
        let planned =
            plan::plan_round(&fixture.account, fixture.connection, fixture.workspace, ReconcileMode::Writable, &sources)
                .await
                .unwrap();
        let update = planned
            .plan
            .local_actions
            .iter()
            .find(|action| action.action == LocalActionKind::UpdatePlaceholder && action.item_id == notes.item_id)
            .expect("the remote content change materializes locally");

        let remote = HeadOnlyRemote::default();
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel);
        let facts = bind_action_facts(&ctx, &planned.plan, &sources).await.unwrap();
        let fact = &facts[&update.action_id];
        // The source resolves its ancestors in the base overlaid with the
        // local intents: the locally moved top ancestor is already `archive`
        // (the base alone knows only `work`) and the middle directory keeps
        // its base spelling `draft`. The target resolves its ancestors in the
        // remote view overlaid with the plan's target operations: the middle
        // directory is `draft-2026` and the top ancestor is `archive` because
        // the planned move operation published it (the remote view alone
        // still knows `work`).
        assert_eq!(fact.source_path.as_ref().unwrap(), &rel(&["archive", "draft", "notes.txt"]));
        assert_eq!(fact.target_path.as_ref().unwrap(), &rel(&["archive", "draft-2026", "notes.txt"]));
        assert_ne!(fact.source_path, fact.target_path);
        // The remote directory rename materializes the same way: its source
        // ancestor comes from the intent overlay, its target ancestor from
        // the planned target operations.
        let rename = planned
            .plan
            .local_actions
            .iter()
            .find(|action| action.action == LocalActionKind::Rename && action.item_id == draft.item_id)
            .expect("the remote directory rename applies locally");
        let rename_fact = &facts[&rename.action_id];
        assert_eq!(rename_fact.source_path.as_ref().unwrap(), &rel(&["archive", "draft"]));
        assert_eq!(rename_fact.target_path.as_ref().unwrap(), &rel(&["archive", "draft-2026"]));
        fixture.state.close().await.unwrap();
    }

    #[tokio::test]
    async fn target_path_resolves_through_planned_target_operations() {
        use hfdrive_core::reconcile::{CatalogView, LocalActionKind, RemoteOp};
        let fixture = connection_fixture().await;
        let base_revision = OperationId::new();
        let recover_op = OperationId::new();
        let root = item_record(fixture.root_item, None, "", ItemKind::Directory, None, base_revision);
        let report = item_record(
            ItemId::new(), Some(fixture.root_item), "report.txt", ItemKind::File,
            Some(VersionId::new()), base_revision,
        );
        // The plan itself creates the recovered directory and re-homes the
        // file into it: the target parent exists only among the planned
        // target operations, never in the committed remote view.
        let recovered = ItemRecord {
            item_id: ItemId::new(),
            parent_id: Some(fixture.root_item),
            name: "Recovered (conflict 0000000000000000)".to_owned(),
            kind: ItemKind::Directory,
            item_revision: recover_op,
            content_version_id: None,
            deleted: false,
            content_operation: recover_op,
            location_operation: recover_op,
            deletion_operation: None,
        };
        let rehomed = ItemRecord {
            parent_id: Some(recovered.item_id),
            item_revision: recover_op,
            content_operation: recover_op,
            location_operation: recover_op,
            ..report.clone()
        };
        let base = CatalogView::new(vec![item_state(&root), item_state(&report)]).unwrap();
        let remote_view = CatalogView::new(vec![item_state(&root), item_state(&report)]).unwrap();
        let names = collect_names(&base, &remote_view);
        let sources = PlanSources { base, remote: remote_view, intents: Vec::new(), names };
        let plan = ReconcilePlan {
            workspace_id: fixture.workspace,
            mode: ReconcileMode::Writable,
            remote_ops: vec![
                RemoteOp {
                    record: recovered.clone(),
                    change: format::ChangeKind::Create,
                    old_revision: None,
                },
                RemoteOp {
                    record: rehomed.clone(),
                    change: format::ChangeKind::Location,
                    old_revision: Some(report.item_revision),
                },
            ],
            versions: Vec::new(),
            changes: Vec::new(),
            operation_ids: Vec::new(),
            local_actions: vec![hfdrive_core::reconcile::LocalAction {
                action_id: ActionId::new(),
                item_id: report.item_id,
                action: LocalActionKind::Rename,
                expected: Some(item_state(&report)),
                target: Some(item_state(&rehomed)),
                local_alias: None,
            }],
            conflicts: Vec::new(),
            aliases: Vec::new(),
            intents: Vec::new(),
        };
        let remote = HeadOnlyRemote::default();
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel);
        let facts = bind_action_facts(&ctx, &plan, &sources).await.unwrap();
        let fact = &facts[&plan.local_actions[0].action_id];
        assert_eq!(fact.source_path.as_ref().unwrap(), &rel(&["report.txt"]));
        assert_eq!(
            fact.target_path.as_ref().unwrap(),
            &rel(&["Recovered (conflict 0000000000000000)", "report.txt"]),
            "the target parent comes from the planned target operations"
        );
        assert_ne!(fact.source_path, fact.target_path);
        fixture.state.close().await.unwrap();
    }
}
