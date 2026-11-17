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
//!    superseded upload never clears newer edits. Refused actions retain the
//!    original common base and source registry until replacement work settles.
//!    A replacement's payload must be bound before another round can plan
//!    destructive local work; capture/admission failures leave its source intact.
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
    UploadId, VersionId, WorkspaceId,
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
    CaptureEvidence, PayloadCheckpoints, PendingContent, PhaseStep, SyncIntent, display_timestamp,
    intent_entry, next_step, parse_intent, staged_payload, transfer_id_for,
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
    pub echo: &'a tokio::sync::Mutex<crate::sync::observe::EchoTable>,
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
    // Reconstruct every replacement lost between retiring its action and
    // recording its outbox row before planning anything against fresh guards.
    // Unbound content cannot participate in the merge: replaying a refused
    // delete/rename would destroy bytes that capture has not secured.
    let mut replacements_pending = false;
    for action in ctx.state.list_local_actions(ctx.connection, Some(LocalActionState::Requeued)).await? {
        let operation = OperationId::from_uuid(*action.action_id.as_uuid())
            .map_err(|_| PublishError::UnsupportedFormat)?;
        match ctx.state.outbox_entry(ctx.connection, operation).await? {
            None => {
                record_requeued_intent(ctx, &action).await?;
                replacements_pending = true;
            }
            Some(entry) => {
                replacements_pending |= entry.object_ref.is_none()
                    && parse_intent(&entry).map_err(|_| PublishError::UnsupportedFormat)?.has_content();
            }
        }
    }
    if replacements_pending {
        return Ok(outcome);
    }
    let round_started_ms = now_ms();
    // Active work only: completed rows are durable history and are never
    // scanned, deserialized or sorted by a round.
    let all = ctx.state.list_active_outbox(ctx.connection, u32::MAX).await?;

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
    let actions = execute_pending_actions(ctx).await?;
    outcome.applied_local_actions = actions.applied;
    require_namespace_application(ctx).await?;
    close_bookkeeping(ctx, entries, planned, head, outcome).await?;
    if actions.requeued != 0 && !requeued_intents_complete(ctx).await? {
        return Ok(());
    }
    // Nothing was published in this round: the complete remote view is the
    // whole post-round namespace.
    advance_base(ctx, head.head.commit_id, &[], planned, sources).await?;
    ctx.state.set_baseline(ctx.connection, BaselineKind::Applied, Some(head.head.commit_id)).await?;
    Ok(())
}

async fn require_namespace_application<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
) -> Result<(), PublishError> {
    if ctx.state.pending_local_actions(ctx.connection).await?.iter().any(|action|
        action.state != LocalActionState::Requeued && matches!(
            action.kind,
            StateActionKind::Other | StateActionKind::CreatePlaceholder | StateActionKind::Rename
                | StateActionKind::UpdatePlaceholder | StateActionKind::DeletePlaceholder
        )
    ) {
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
    let actions = execute_pending_actions(ctx).await?;
    outcome.applied_local_actions = actions.applied;
    require_namespace_application(ctx).await?;

    // Mark locally published content in-sync (guarded), then close entries.
    for entry in round_entries {
        if let Err(error) = mark_entry_in_sync(ctx, entry, &planned.plan).await {
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
    outcome.committed.push(commit_id);
    if actions.requeued != 0 && !requeued_intents_complete(ctx).await? {
        return Ok(());
    }

    // Advance the remembered base and the durable item registry to exactly
    // the committed batch's namespace (later batches re-plan afterwards).
    advance_base(ctx, commit_id, &batch.remote_ops, planned, sources).await?;
    ctx.state
        .set_baseline(ctx.connection, BaselineKind::Applied, Some(commit_id))
        .await?;
    Ok(())
}

/// Remembers the new common base and refreshes the durable item registry.
///
/// The namespace is the complete remote view overlaid with **only the remote
/// operations that were actually committed** — one commit batch's ops, never
/// the later batches that re-plan in a later round. A remote-only round (or
/// any round without a publication) overlays nothing and adopts the complete
/// remote view as-is.
///
/// Registry rows carry the payload identity and display metadata of their
/// bound version: this round's planned version metadata for newly published
/// content, otherwise the remote view's content facts and the registry's last
/// known `modified_at`. A remote-only or unchanged version keeps its metadata
/// across the base advance — a known remote file is never rewritten as an
/// unknown zero-length payload.
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
    // The registry's last known display metadata is read once for the whole
    // refresh (one listing, never one lookup per item): a remote-only or
    // unchanged version keeps the `modified_at` its row already proved.
    let prior_rows = ctx.state.list_all_items(ctx.connection, true).await?;
    let prior: HashMap<ItemId, &hfdrive_state::ItemRecord> = prior_rows
        .iter()
        .map(|row| (row.item_id, row))
        .collect();
    // One worker command and one transaction for the whole registry refresh:
    // every record lands or none does, and no other command can interleave
    // with the batch. The per-row write flags are a diagnostic only — success
    // is the completed batch command, never a per-row flag (an identical row
    // reports `false` and is not rewritten).
    let registry: Vec<hfdrive_state::ItemRecord> = records
        .iter()
        .map(|record| {
            // Newly published content carries its planned version metadata.
            let planned_version = planned
                .plan
                .versions
                .iter()
                .find(|version| Some(version.version_id) == record.content_version_id);
            let (digest, size, modified_at) = match planned_version {
                Some(version) => (
                    Some(version.object.sha256),
                    Some(version.object.size),
                    Some(version.display.modified_at.clone()),
                ),
                // A remote-only or unchanged version keeps the content facts
                // the remote view proved and the display metadata the registry
                // already bound to that exact version. A known remote file is
                // never re-defaulted to an unknown zero-length payload by a
                // base advance, and no digest is borrowed from another version.
                None => {
                    let remote_state = sources
                        .remote
                        .get(record.item_id)
                        .filter(|state| state.content_version_id == record.content_version_id);
                    let prior_row = prior
                        .get(&record.item_id)
                        .copied()
                        .filter(|row| row.content_version_id == record.content_version_id);
                    let (digest, size) = match remote_state {
                        Some(state) => (state.content_sha256, state.content_size),
                        None => prior_row.map(registry_digest).unwrap_or((None, None)),
                    };
                    let modified_at = prior_row.and_then(|row| {
                        row.metadata_json.get("modified_at")?.as_str().map(str::to_owned)
                    });
                    (digest, size, modified_at)
                }
            };
            registry_item(ctx.connection, record, digest, size, modified_at)
        })
        .collect();
    let written = ctx.state.upsert_items(registry).await?;
    debug_assert_eq!(written.len(), records.len(), "one flag is reported per requested record");
    ctx.state
        .set_baseline(ctx.connection, BaselineKind::Observed, Some(commit_id))
        .await?;
    Ok(())
}

/// Marks a locally published file in-sync only when the live file is still
/// exactly the captured generation. A newer local edit stays dirty and
/// publishes on its own; superseded uploads never clear newer edits.
/// An applied rename's journal supplies the target, not the still-old registry.
/// Its changed USN is rebound only after a coherent digest check of those bytes.
async fn mark_entry_in_sync<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    entry: &OutboxEntry,
    planned: &ReconcilePlan,
) -> Result<(), PublishError> {
    let intent = parse_intent(entry).map_err(|_| PublishError::UnsupportedFormat)?;
    if !intent.has_content() {
        return Ok(());
    }
    let journal = load_journal(ctx.state, ctx.connection, entry.operation_id).await?;
    let mut evidence = journal.capture
        .ok_or(PublishError::LocalApply("the published payload lacks capture evidence"))?;
    let item_id = intent.item_id();
    let mut applied_target = None;
    for action in &planned.local_actions {
        if action.item_id != item_id || action.action != hfdrive_core::reconcile::LocalActionKind::Rename {
            continue;
        }
        let row = ctx.state.local_action(ctx.connection, action.action_id).await?
            .ok_or(PublishError::LocalApply("the published rename lacks its action journal"))?;
        if row.state == LocalActionState::Applied {
            applied_target = Some(row.target_path
                .ok_or(PublishError::LocalApply("the applied rename lacks its target path"))?);
        }
    }
    let renamed = applied_target.is_some();
    let path = match applied_target {
        Some(path) => path,
        None => match &intent {
            SyncIntent::Create { parent_id, name, .. }
            | SyncIntent::MoveAndContent { parent_id, name, .. } => {
                let parent = ItemId::from_uuid(*parent_id).map_err(|_| PublishError::UnsupportedFormat)?;
                item_path(ctx, parent).await
                    .ok_or(PublishError::LocalApply("the published target parent is unknown"))?
                    .join(name)
            }
            _ => item_path(ctx, item_id).await
                .ok_or(PublishError::LocalApply("the published source path is unknown"))?,
        },
    };
    let observation = ctx.state.observation(ctx.connection, item_id).await?;
    let generation = observation.map(|o| o.generation).unwrap_or(entry.observed_generation);
    if generation != entry.observed_generation {
        return Ok(());
    }
    if renamed {
        // A rename changes the USN. Same identity/size/mtime alone cannot prove
        // that no edit happened afterwards; re-read coherently before rebinding
        // the strict in-sync guard to the target's new USN.
        let target = ctx.root.join(&path);
        let (live, digest, size) = tokio::task::spawn_blocking(move ||
            hfdrive_windows::filesystem::snapshot::read_hashed_coherent(&target)
        ).await
            .map_err(|_| PublishError::LocalApply("the renamed publication proof was interrupted"))?
            .map_err(|_| PublishError::LocalApply("the renamed publication could not be verified"))?;
        let object = entry.object_ref.as_ref().ok_or(PublishError::UnsupportedFormat)?;
        if live.identity.volume_serial_number != evidence.volume_serial_number
            || live.identity.file_id != evidence.file_id
            || size != evidence.size
            || size != object.size
            || digest != *object.sha256.as_bytes()
        {
            return Err(PublishError::LocalApply("the renamed publication no longer matches its capture"));
        }
        evidence.last_write_time_100ns = live.last_write_time_100ns;
        evidence.usn = live.usn;
    }
    let content = intent.pending_content().ok_or(PublishError::UnsupportedFormat)?;
    let version = VersionId::from_uuid(content.version_id).map_err(|_| PublishError::UnsupportedFormat)?;
    let identity = hfdrive_windows::cfapi::identity::PlaceholderIdentity::file(ctx.workspace, item_id, version);
    let mark = apply::mark_published_in_sync;
    #[cfg(test)]
    let mark = tests::publication_marker(mark);
    let marked = mark(
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

/// Successful applications and replacement intents are distinct outcomes.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LocalActionOutcome {
    pub applied: usize,
    /// Refused actions whose replacement work has not completed yet.
    pub requeued: usize,
}

/// Executes pending local actions with durable `InProgress` coverage before
/// any filesystem effect, then hands successful actions to the observer's
/// echo table. Execution failures return to `Pending`; a changed guard keeps
/// the original common base and source path until its replacement completes.
pub async fn execute_pending_actions<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
) -> Result<LocalActionOutcome, PublishError> {
    let mut pending = ctx
        .state
        .list_local_actions(ctx.connection, Some(LocalActionState::Pending))
        .await?;
    // Resume a crash between retiring an action and recording its replacement.
    // The action UUID also identifies that replacement, so retries do not
    // duplicate work, even after the replacement has completed.
    pending.extend(ctx.state.list_local_actions(ctx.connection, Some(LocalActionState::Requeued)).await?);
    let mut outcome = LocalActionOutcome::default();
    for row in pending {
        let result = if row.state == LocalActionState::Requeued {
            Ok(false)
        } else {
            ctx.state
                .set_local_action_state(ctx.connection, row.action_id, LocalActionState::InProgress)
                .await?;
            execute_one_action(ctx, &row).await
        };
        match result {
            Ok(true) => {
                let mut echo = ctx.echo.lock().await;
                apply::complete_action(ctx.state, &row, ctx.root, &mut echo).await?;
                outcome.applied += 1;
            }
            Ok(false) => {
                if row.state != LocalActionState::Requeued {
                    ctx.state
                        .set_local_action_state(ctx.connection, row.action_id, LocalActionState::Requeued)
                        .await?;
                    crate::sync::work_errors::record_action_failure(
                        ctx.state,
                        ctx.connection,
                        row.action_id,
                        &PublishError::LocalApply("the local guard changed; replacement local work is required"),
                    )
                    .await;
                }
                match record_requeued_intent(ctx, &row).await {
                    Ok(true) => outcome.requeued += 1,
                    Ok(false) => {}
                    Err(error) => {
                        crate::sync::work_errors::record_action_failure(
                            ctx.state, ctx.connection, row.action_id, &error,
                        )
                        .await;
                        return Err(error);
                    }
                }
            }
            Err(error) => {
                ctx.state
                    .set_local_action_state(ctx.connection, row.action_id, LocalActionState::Pending)
                    .await?;
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
    Ok(outcome)
}

/// Recheck after this round closes its entries: a replacement may have just
/// published or converged. Until then, adopting R as B would lose its original
/// location/deletion context and could send its next capture to the wrong path.
async fn requeued_intents_complete<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
) -> Result<bool, PublishError> {
    for action in ctx.state.list_local_actions(ctx.connection, Some(LocalActionState::Requeued)).await? {
        let operation = OperationId::from_uuid(*action.action_id.as_uuid())
            .map_err(|_| PublishError::UnsupportedFormat)?;
        if !ctx.state.outbox_entry(ctx.connection, operation).await?
            .is_some_and(|entry| entry.state == OutboxState::Complete)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Replaces an interrupted action with an observation of the current file,
/// never with an acknowledgement that the interrupted mutation succeeded.
/// Returns whether the replacement still needs reconciliation/publication.
async fn record_requeued_intent<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    row: &LocalAction,
) -> Result<bool, PublishError> {
    let operation = OperationId::from_uuid(*row.action_id.as_uuid())
        .map_err(|_| PublishError::UnsupportedFormat)?;
    if let Some(entry) = ctx.state.outbox_entry(ctx.connection, operation).await? {
        return Ok(entry.state != OutboxState::Complete);
    }
    let item_id = row.item_id.ok_or(PublishError::LocalApply("requeued action lacks an item"))?;
    let path = row.source_path.as_ref().or(row.target_path.as_ref())
        .ok_or(PublishError::LocalApply("requeued action lacks a local path"))?;
    let intent = match std::fs::symlink_metadata(ctx.root.join(path)) {
        Ok(metadata) if metadata.is_file() => SyncIntent::Content {
            item_id: *item_id.as_uuid(),
            content: PendingContent {
                upload_id: *UploadId::new().as_uuid(),
                version_id: *VersionId::new().as_uuid(),
                modified_at: display_timestamp(now_100ns()),
            },
        },
        Ok(metadata) if metadata.is_dir() => {
            let item = ctx.state.item(ctx.connection, item_id).await?
                .ok_or(PublishError::LocalApply("requeued directory is not registered"))?;
            SyncIntent::Move {
                item_id: *item_id.as_uuid(),
                parent_id: *item.parent_id
                    .ok_or(PublishError::LocalApply("the sync root cannot be requeued"))?
                    .as_uuid(),
                name: item.name,
            }
        }
        Ok(_) => return Err(PublishError::LocalApply("requeued path is not an ordinary file or directory")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            SyncIntent::Delete { item_id: *item_id.as_uuid() }
        }
        Err(_) => return Err(PublishError::LocalApply("requeued local metadata could not be read")),
    };
    let base = ctx.state.baseline(ctx.connection).await?.applied_commit;
    let base_json = match base {
        Some(commit) => ctx.state.get_common_base(ctx.connection, item_id, commit).await?
            .map(|base| base.item_json),
        None => None,
    };
    let observation = ctx.state.bump_observation(ctx.connection, item_id, None).await?;
    let entry = intent_entry(
        ctx.connection, operation, Some(item_id), base, base_json, observation.generation, &intent,
    )
    .map_err(|_| PublishError::UnsupportedFormat)?;
    ctx.state.record_observed_work(None, entry, None).await?;
    Ok(true)
}

/// Executes one journaled action. Returns `false` when a guard refused and
/// fresh local work must replace the interrupted action.
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
            let mut outcomes =
                apply::create_placeholders(&ctx.root.join(&parent), &[create])
                    .map_err(PublishError::LocalApply)?;
            // K04/G14: every per-entry outcome is inspected; only a real
            // `Created`, or an `AlreadyExists` target holding this item's
            // exact expected HFDR placeholder identity, ever succeeds.
            let absolute = ctx.root.join(path);
            let mut satisfied = false;
            for outcome in &mut outcomes {
                if outcome.name != name {
                    return Err(PublishError::LocalApply(
                        "placeholder creation returned an outcome for a different entry",
                    ));
                }
                match apply::classify_creation(path, &outcome.outcome, || {
                    apply::occupant_at(&absolute, ctx.workspace, &identity)
                }) {
                    apply::CreationOutcome::Created { .. }
                    | apply::CreationOutcome::AlreadyCreated => satisfied = true,
                    // A foreign or unverifiable occupant is preserved untouched
                    // and becomes fresh local work for reconciliation.
                    apply::CreationOutcome::Occupied(_) => return Ok(false),
                    // The entry itself failed with an OS error: a real failure,
                    // recorded by the caller and retried; never "created".
                    apply::CreationOutcome::EntryFailed { .. } => {
                        return Err(PublishError::LocalApply(
                            "placeholder creation failed for one entry",
                        ));
                    }
                }
            }
            outcomes.clear();
            if !satisfied {
                return Err(PublishError::LocalApply("placeholder creation returned no outcome"));
            }
        }
        StateActionKind::Rename => {
            let (Some(from), Some(to)) = (&source, &target) else { return Ok(false); };
            let Some((_expected_state, expected, generation)) = expected_guard_state(ctx, row).await? else {
                return Ok(false);
            };
            let case_only = hfdrive_windows::filesystem::names::windows_case_equivalent(
                &from.to_string_lossy(),
                &to.to_string_lossy(),
            ) && !hfdrive_windows::filesystem::names::windows_exact_equal(
                &from.to_string_lossy(),
                &to.to_string_lossy(),
            );
            let intermediate = apply::rename_intermediate(to, row.action_id);
            match apply::rename_local(
                ctx.root,
                from,
                to,
                case_only,
                &intermediate,
                Some(&expected),
                generation,
            ) {
                Ok(_) => {}
                Err(
                    apply::RENAME_UNPROVEN
                    | apply::RENAME_OCCUPIED,
                ) => return Ok(false),
                Err(error) => return Err(PublishError::LocalApply(error)),
            }
        }
        StateActionKind::UpdatePlaceholder => {
            let (Some(path), Some(version)) = (&target, row.new_version) else {
                return Ok(false);
            };
            let Some((expected_state, _, _)) = expected_guard_state(ctx, row).await? else {
                // Expectation cannot be proven: preserve the old bytes and
                // replace this action with a fresh local intent.
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
            let Some((_expected_state, expected, generation)) = expected_guard_state(ctx, row).await? else {
                // Proven absence already satisfies deletion. Every other
                // guard/query failure preserves the path for reconciliation.
                return Ok(matches!(
                    apply::probe(&ctx.root.join(path)),
                    apply::Probe::Missing
                ));
            };
            let Some(item_id) = row.item_id else { return Ok(false); };
            let identity = apply::journaled_identity(ctx.workspace, item_id, row.old_version);
            match apply::delete_local(
                ctx.root,
                path,
                Some(&expected),
                generation,
                Some(&identity),
            ) {
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
/// live file. A half-finished case-only rename proves its intermediate by
/// identity/generation; its own first hop necessarily changed the USN.
/// Unreadable metadata is a retryable failure, never a changed/missing guard.
async fn expected_guard_state<R: RemoteOps>(
    ctx: &RoundContext<'_, R>,
    row: &LocalAction,
) -> Result<Option<(
    hfdrive_windows::filesystem::volume::FileState,
    crate::sync::apply::ExpectedLocal,
    u64,
)>, PublishError> {
    let Some(source_path) = row.source_path.as_ref().or(row.target_path.as_ref()) else {
        return Ok(None);
    };
    let (live, relocated) = match apply::probe(&ctx.root.join(source_path)) {
        apply::Probe::Present(live) => (live, false),
        apply::Probe::Missing => {
            let Some(intermediate) = apply::case_rename_intermediate(row) else {
                return Ok(None);
            };
            match apply::probe(&ctx.root.join(intermediate)) {
                apply::Probe::Present(live) => (live, true),
                apply::Probe::Missing => return Ok(None),
                apply::Probe::Unreadable => {
                    return Err(PublishError::LocalApply("local rename intermediate could not be inspected"));
                }
            }
        }
        apply::Probe::Unreadable => {
            return Err(PublishError::LocalApply("local action source could not be inspected"));
        }
    };
    let (Some(file_id), Some(expected_generation), Some(item_id)) = (
        row.expected_file_id.as_deref().and_then(parse_hex_file_id),
        row.expected_generation,
        row.item_id,
    ) else {
        return Ok(None);
    };
    let expected = crate::sync::apply::ExpectedLocal {
        file_id,
        volume_serial_number: live.identity.volume_serial_number,
        generation: expected_generation,
        usn: row.expected_usn.and_then(|value| i64::try_from(value).ok()),
    };
    let generation = ctx
        .state
        .observation(ctx.connection, item_id)
        .await?
        .map(|observation| observation.generation)
        .unwrap_or(expected.generation);
    let verified = if relocated {
        apply::relocated_object(&live, &expected, generation)
    } else {
        apply::verify_expected(&expected, &live, generation)
    };
    Ok(verified.then_some((live, expected, generation)))
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

    type PublicationMarker = fn(
        &std::path::Path,
        &hfdrive_windows::cfapi::identity::PlaceholderIdentity,
        &CaptureEvidence,
        u64,
        u64,
    ) -> Result<Option<i64>, &'static str>;

    thread_local! {
        static MARK_TARGET: std::cell::RefCell<Option<(
            std::path::PathBuf, hfdrive_windows::cfapi::identity::PlaceholderIdentity,
        )>> = const { std::cell::RefCell::new(None) };
    }

    // This boundary checks the exact native call inputs without registering a
    // CFAPI root. Capture, journal, rename and completion use their real paths;
    // this is not a native in-sync acceptance test.
    pub(super) fn publication_marker(native: PublicationMarker) -> PublicationMarker {
        if MARK_TARGET.with(|target| target.borrow().is_some()) {
            checked_publication_marker
        } else {
            native
        }
    }

    fn checked_publication_marker(
        path: &std::path::Path,
        identity: &hfdrive_windows::cfapi::identity::PlaceholderIdentity,
        evidence: &CaptureEvidence,
        generation: u64,
        expected_generation: u64,
    ) -> Result<Option<i64>, &'static str> {
        let (target, expected_identity) = MARK_TARGET.with(|target| target.borrow_mut().take().unwrap());
        assert_eq!(path, target);
        assert_eq!(identity, &expected_identity);
        assert_eq!(generation, expected_generation);
        let live = hfdrive_windows::filesystem::volume::query_file_state(path).unwrap();
        assert_eq!(evidence.volume_serial_number, live.identity.volume_serial_number);
        assert_eq!(evidence.file_id, live.identity.file_id);
        assert_eq!(evidence.size, live.size);
        assert_eq!(evidence.last_write_time_100ns, live.last_write_time_100ns);
        assert_eq!(evidence.usn, live.usn);
        Ok(Some(live.usn.expect("the strict native mark needs a known target USN")))
    }

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
        echo: &'a tokio::sync::Mutex<crate::sync::observe::EchoTable>,
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
            echo,
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
            let echo = tokio::sync::Mutex::new(crate::sync::observe::EchoTable::default());
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
                echo: &echo,
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
        echo: &'a tokio::sync::Mutex<crate::sync::observe::EchoTable>,
    ) -> RoundContext<'a, HeadOnlyRemote> {
        RoundContext {
            state: &fixture.account, remote, connection: fixture.connection,
            workspace: fixture.workspace, root_item_id: fixture.root_item,
            device_id: DeviceId::new(), mode: ReconcileMode::ReadOnly,
            root: &fixture.root, staging_dir: fixture.directory.path(),
            recovery_dir: fixture.directory.path(), scheduler, cancel,
            echo,
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
        let echo = tokio::sync::Mutex::new(crate::sync::observe::EchoTable::default());
        let mut context = read_only_context(&fixture, &remote, &scheduler, &cancel, &echo);
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
    async fn requeued_actions_rebuild_missing_replacements_before_any_round_replay() {
        let mut fixture = connection_fixture().await;
        let previous = CommitId::new();
        fixture.account.set_baseline(fixture.connection, BaselineKind::Applied, Some(previous)).await.unwrap();
        let remote = HeadOnlyRemote::default();
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let echo = tokio::sync::Mutex::new(crate::sync::observe::EchoTable::default());
        let mut actions = Vec::new();
        let mut records = Vec::new();
        for (name, kind) in [
            ("already-queued.txt", StateActionKind::DeletePlaceholder),
            ("missing-delete.txt", StateActionKind::DeletePlaceholder),
            ("missing-rename.txt", StateActionKind::Rename),
        ] {
            std::fs::write(fixture.root.join(name), b"uncaptured local bytes").unwrap();
            let file = item_record(
                ItemId::new(), Some(fixture.root_item), name, ItemKind::File,
                Some(VersionId::new()), OperationId::new(),
            );
            record_common_bases(&fixture.account, fixture.connection, previous, std::slice::from_ref(&file))
                .await.unwrap();
            fixture.account.upsert_item(registry_item(
                fixture.connection, &file, None, None, None,
            )).await.unwrap();
            // Crash boundary: the action was retired, but its replacement
            // has not yet been persisted. No fresh planner may rebind it.
            let action = fixture.account.record_local_action(LocalAction {
                connection_id: fixture.connection, action_id: ActionId::new(),
                item_id: Some(file.item_id), kind, expected_file_id: None,
                expected_generation: Some(0), expected_usn: None,
                old_version: file.content_version_id, new_version: file.content_version_id,
                source_path: Some(name.into()),
                target_path: (kind == StateActionKind::Rename).then(|| "remote-target.txt".into()),
                recovery_path: None, state: LocalActionState::Requeued,
            }).await.unwrap();
            actions.push(action);
            records.push(file);
        }
        record_requeued_intent(
            &round_context(&fixture, &remote, &scheduler, &cancel, &echo), &actions[0],
        ).await.unwrap();
        let account_key = fixture.account.account_key();
        fixture.state.close().await.unwrap();
        fixture.state = hfdrive_state::StateStore::open(hfdrive_state::StatePaths::new(
            fixture.directory.path().join("state"),
        )).await.unwrap();
        fixture.account = fixture.state.open_account(account_key).await.unwrap();
        let mut context = round_context(&fixture, &remote, &scheduler, &cancel, &echo);
        let before_actions = fixture.account.list_local_actions(fixture.connection, None).await.unwrap();
        for (mode, writable) in [(ReconcileMode::ReadOnly, false), (ReconcileMode::Writable, true)] {
            context.mode = mode;
            let outcome = run_round(&context, writable).await.unwrap();
            assert_eq!(outcome.applied_local_actions, 0);
            assert!(outcome.committed.is_empty());
            assert_eq!(remote.head_reads.load(std::sync::atomic::Ordering::Relaxed), 0);
            assert_eq!(fixture.account.list_local_actions(fixture.connection, None).await.unwrap(), before_actions);
            let entries = fixture.account.list_active_outbox(fixture.connection, u32::MAX).await.unwrap();
            assert_eq!(entries.len(), actions.len(), "every missing row must be reconstructed before returning");
            for (action, file) in actions.iter().zip(&records) {
                let operation = OperationId::from_uuid(*action.action_id.as_uuid()).unwrap();
                let entry = entries.iter().find(|entry| entry.operation_id == operation).unwrap();
                assert_eq!(entry.state, OutboxState::Observed);
                assert_eq!(entry.base_commit, Some(previous));
                assert!(entry.object_ref.is_none());
                assert!(matches!(parse_intent(entry).unwrap(), SyncIntent::Content { item_id, .. }
                    if item_id == *file.item_id.as_uuid()));
                assert_eq!(fixture.account.observation(fixture.connection, file.item_id)
                    .await.unwrap().unwrap().generation, entry.observed_generation);
                assert_eq!(std::fs::read(fixture.root.join(&file.name)).unwrap(), b"uncaptured local bytes");
                let registry = fixture.account.item(fixture.connection, file.item_id).await.unwrap().unwrap();
                assert_eq!(registry.name, file.name);
                assert!(!registry.deleted);
            }
            assert_eq!(fixture.account.baseline(fixture.connection).await.unwrap().applied_commit, Some(previous));
            assert!(!fixture.root.join("remote-target.txt").exists());
        }
        fixture.state.close().await.unwrap();
    }

    #[tokio::test]
    async fn refused_remote_rename_captures_original_path_and_finishes_next_writable_round() {
        refused_namespace_keeps_base_until_replacement(false).await;
    }

    #[tokio::test]
    async fn refused_remote_delete_reconciles_content_against_live_base_next_writable_round() {
        refused_namespace_keeps_base_until_replacement(true).await;
    }

    async fn refused_namespace_keeps_base_until_replacement(remote_deleted: bool) {
        use hfdrive_core::reconcile::CatalogView;
        use hfdrive_core::storage::{PayloadKey, Sha256Digest, XetFileId};

        let fixture = connection_fixture().await;
        let path = std::path::PathBuf::from("a");
        let bytes = b"local bytes must survive";
        std::fs::write(fixture.root.join(&path), bytes).unwrap();
        let revision = OperationId::new();
        let root = item_record(fixture.root_item, None, "", ItemKind::Directory, None, revision);
        let file = item_record(
            ItemId::new(), Some(fixture.root_item), "a", ItemKind::File,
            Some(VersionId::new()), revision,
        );
        let remote_operation = OperationId::new();
        let changed = if remote_deleted {
            ItemRecord {
                deleted: true, deletion_operation: Some(remote_operation),
                item_revision: remote_operation, ..file.clone()
            }
        } else {
            ItemRecord {
                name: "b".to_owned(), location_operation: remote_operation,
                item_revision: remote_operation, ..file.clone()
            }
        };
        let base = CatalogView::new(vec![item_state(&root), item_state(&file)]).unwrap();
        let remote_view = CatalogView::new(vec![item_state(&root), item_state(&changed)]).unwrap();
        let names = collect_names(&base, &remote_view);
        let sources = PlanSources { base, remote: remote_view, intents: Vec::new(), names };
        let previous = CommitId::new();
        let target = CommitId::new();
        record_common_bases(
            &fixture.account, fixture.connection, previous, &[root, file.clone()],
        ).await.unwrap();
        let base_file = item_state(&file);
        fixture.account.upsert_item(registry_item(
            fixture.connection, &file, base_file.content_sha256, base_file.content_size, None,
        )).await.unwrap();
        fixture.account.set_baseline(fixture.connection, BaselineKind::Applied, Some(previous)).await.unwrap();
        fixture.account.set_baseline(fixture.connection, BaselineKind::Observed, Some(target)).await.unwrap();
        let remote = HeadOnlyRemote::default();
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let echo = tokio::sync::Mutex::new(crate::sync::observe::EchoTable::default());
        let context = round_context(&fixture, &remote, &scheduler, &cancel, &echo);
        let head = RemoteHead {
            head: head_record(fixture.workspace, fixture.root_item, target), etag: None,
        };

        let planned = plan::plan_round(
            &fixture.account, fixture.connection, fixture.workspace, ReconcileMode::Writable, &sources,
        ).await.unwrap();
        assert!(planned.plan.remote_ops.is_empty());
        let mut facts = bind_action_facts(&context, &planned.plan, &sources).await.unwrap();
        for fact in facts.values_mut() {
            fact.expected_file_id = None; // The journal cannot prove the current occupant.
        }
        plan::persist_plan_records(
            &fixture.account, fixture.connection, &planned.plan, &facts,
        ).await.unwrap();
        let original = fixture.account.pending_local_actions(fixture.connection).await.unwrap();
        assert_eq!(original.len(), 1);
        assert_eq!(original[0].kind, if remote_deleted {
            StateActionKind::DeletePlaceholder
        } else {
            StateActionKind::Rename
        });
        assert_eq!(original[0].source_path.as_ref(), Some(&path));

        // Replanning must retain the original refused guard, not bless drift.
        let retry = plan::plan_round(
            &fixture.account, fixture.connection, fixture.workspace, ReconcileMode::Writable, &sources,
        ).await.unwrap();
        let retry_facts = bind_action_facts(&context, &retry.plan, &sources).await.unwrap();
        plan::persist_plan_records(
            &fixture.account, fixture.connection, &retry.plan, &retry_facts,
        ).await.unwrap();
        let pending = fixture.account.pending_local_actions(fixture.connection).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].action_id, original[0].action_id);
        assert_eq!(pending[0].expected_file_id, None);

        let mut outcome = RoundOutcome::default();
        finish_remote_application(
            &context, &[], &retry, &sources, &head, &mut outcome,
        ).await.unwrap();
        assert_eq!(outcome.applied_local_actions, 0);
        let baseline = fixture.account.baseline(fixture.connection).await.unwrap();
        assert_eq!(baseline.applied_commit, Some(previous), "refusal must not adopt R as B");
        assert_eq!(baseline.observed_commit, Some(target));
        assert!(fixture.account.list_common_bases(fixture.connection, target).await.unwrap().is_empty());
        let registry = fixture.account.item(fixture.connection, file.item_id).await.unwrap().unwrap();
        assert_eq!(registry.name, "a");
        assert!(!registry.deleted, "the replacement content still needs a live base");
        assert_eq!(std::fs::read(fixture.root.join(&path)).unwrap(), bytes);
        assert!(!fixture.root.join("b").exists());
        let action = fixture.account.local_action(
            fixture.connection, original[0].action_id,
        ).await.unwrap().unwrap();
        assert_eq!(action.state, LocalActionState::Requeued);
        assert_eq!(action.expected_file_id, None);
        assert!(fixture.account.pending_local_actions(fixture.connection).await.unwrap().is_empty());
        let error = fixture.account.work_error(
            fixture.connection, hfdrive_state::WorkErrorKind::Action, *action.action_id.as_uuid(),
        ).await.unwrap().unwrap();
        assert_eq!(error.error_code, crate::sync::work_errors::codes::LOCAL_APPLY_FAILED);
        let entries = fixture.account.list_active_outbox(fixture.connection, u32::MAX).await.unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.state, OutboxState::Observed);
        assert_eq!(entry.base_commit, Some(previous));
        assert_eq!(
            format::from_item_record_bytes(entry.base_json.as_ref().unwrap().as_bytes()).unwrap(), file,
        );
        let SyncIntent::Content { item_id, content } = parse_intent(entry).unwrap() else {
            panic!("surviving bytes must queue content against the original live file");
        };
        assert_eq!(item_id, *file.item_id.as_uuid());
        let observation = fixture.account.observation(
            fixture.connection, file.item_id,
        ).await.unwrap().unwrap();
        assert!(observation.dirty);
        assert_eq!(entry.observed_generation, observation.generation);
        assert_eq!(
            execute_pending_actions(&context).await.unwrap(),
            LocalActionOutcome { applied: 0, requeued: 1 },
        );
        assert_eq!(
            fixture.account.list_active_outbox(fixture.connection, u32::MAX).await.unwrap(), entries,
            "revisiting a requeued action must not duplicate its intent",
        );

        // The controller still runs publication rounds when upload admission
        // fails. An unbound replacement must stop before any fresh action can
        // legitimize the remote delete/rename against the surviving source.
        let blocked_scheduler = crate::scheduler::Scheduler::new(crate::scheduler::SchedulerConfig {
            staging_admission_bytes: 1,
            minimum_free_bytes: 0,
            ..Default::default()
        });
        let mut blocked_context = round_context(
            &fixture, &remote, &blocked_scheduler, &cancel, &echo,
        );
        assert!(matches!(
            upload_entry(&blocked_context, entry).await,
            Err(PublishError::Capture { code: "reservation_too_large", .. }),
        ));
        let before_actions = fixture.account.list_local_actions(fixture.connection, None).await.unwrap();
        for (mode, writable) in [(ReconcileMode::ReadOnly, false), (ReconcileMode::Writable, true)] {
            blocked_context.mode = mode;
            let blocked = run_round(&blocked_context, writable).await.unwrap();
            assert_eq!(blocked.applied_local_actions, 0);
            assert!(blocked.committed.is_empty());
            assert_eq!(fixture.account.list_local_actions(fixture.connection, None).await.unwrap(), before_actions);
            assert_eq!(fixture.account.item(fixture.connection, file.item_id).await.unwrap().unwrap(), registry);
            assert_eq!(
                fixture.account.baseline(fixture.connection).await.unwrap().applied_commit, Some(previous),
            );
            assert_eq!(std::fs::read(fixture.root.join(&path)).unwrap(), bytes);
            assert!(!fixture.root.join("b").exists());
        }
        assert_eq!(remote.head_reads.load(std::sync::atomic::Ordering::Relaxed), 0);
        let unbound = fixture.account.outbox_entry(fixture.connection, entry.operation_id).await.unwrap().unwrap();
        assert_eq!(unbound.state, OutboxState::Observed);
        assert!(unbound.object_ref.is_none());
        assert!(unbound.snapshot_id.is_none());

        // This is the same registry path lookup used by upload_entry. Capture
        // real source bytes before the second round, never the remote target b.
        let source = item_path(&context, file.item_id).await.unwrap();
        assert_eq!(source, path);
        let request = crate::sync::capture::CaptureRequest {
            connection_id: fixture.connection, source: fixture.root.join(source),
            staging_dir: fixture.directory.path().to_path_buf(), item_id: file.item_id,
            operation_id: entry.operation_id, snapshot_id: SnapshotId::new(),
            upload_id: UploadId::from_uuid(content.upload_id).unwrap(),
            expected: None, workspace: fixture.workspace,
        };
        let captured = crate::sync::capture::capture_local_change(
            &fixture.account, &scheduler, *fixture.workspace.as_uuid(), &request, &cancel,
        ).await.unwrap();
        assert_eq!(std::fs::read(&captured.staged.staged_path).unwrap(), bytes);
        assert_eq!(captured.staged.sha256, Sha256Digest::of(bytes));
        save_journal(
            &fixture.account, fixture.connection, entry.operation_id,
            &PayloadCheckpoints { capture: Some(captured.evidence.clone()), ..Default::default() },
            TransferState::InProgress,
        ).await.unwrap();
        fixture.account.transition_outbox(
            fixture.connection, entry.operation_id,
            OutboxTransition::SnapshotReady { snapshot_id: request.snapshot_id },
        ).await.unwrap();
        let object = ObjectRef {
            key: PayloadKey::new(request.upload_id), sha256: captured.staged.sha256,
            size: captured.staged.size,
            xet_file_id: XetFileId::new("0123456789abcdef".repeat(4)).unwrap(),
        };
        let ready = fixture.account.transition_outbox(
            fixture.connection, entry.operation_id, OutboxTransition::PayloadReady { object_ref: object },
        ).await.unwrap();

        // Rebuild B from the persisted applied commit, not the remote view.
        // In particular a deletion's content intent must not see a tombstone.
        let base_rows = fixture.account.list_common_bases(
            fixture.connection, baseline.applied_commit.unwrap(),
        ).await.unwrap();
        let base = CatalogView::new(base_rows.iter().map(|row| {
            item_state(&format::from_item_record_bytes(row.item_json.as_bytes()).unwrap())
        }).collect()).unwrap();
        assert!(!base.get(file.item_id).unwrap().deleted);
        let names = collect_names(&base, &sources.remote);
        let second_sources = PlanSources {
            intents: build_local_intents(std::slice::from_ref(&ready), &names),
            base, remote: sources.remote, names,
        };
        assert_eq!(second_sources.intents.len(), 1);
        let second = plan::plan_round(
            &fixture.account, fixture.connection, fixture.workspace, ReconcileMode::Writable, &second_sources,
        ).await.unwrap();
        assert_eq!(second.plan.remote_ops.len(), 1);
        let replacement = &second.plan.remote_ops[0].record;
        assert_eq!(replacement.item_id, file.item_id);
        assert!(!replacement.deleted);
        assert_eq!(replacement.name, if remote_deleted { "a" } else { "b" });
        assert_eq!(replacement.content_version_id, Some(VersionId::from_uuid(content.version_id).unwrap()));
        assert_eq!(second.plan.local_actions.len(), if remote_deleted { 0 } else { 1 });
        let facts = bind_action_facts(&context, &second.plan, &second_sources).await.unwrap();
        plan::persist_plan_records(
            &fixture.account, fixture.connection, &second.plan, &facts,
        ).await.unwrap();

        // Exercise the durable post-publication boundary with this real plan;
        // this regression does not perform or claim a remote service write.
        let batch = second.plan.commit_batches(
            format::MAX_COMMIT_OPERATIONS, format::MAX_COMMIT_OPERATIONS,
        ).unwrap().remove(0);
        let committed = CommitId::new();
        let published_entry = fixture.account.transition_outbox(
            fixture.connection, ready.operation_id, OutboxTransition::MetadataReady {
                candidate_commit: committed,
                candidate_head_json: to_json(&head_record(
                    fixture.workspace, fixture.root_item, committed,
                )).unwrap(),
                expected_etag: "fixture-etag".to_owned(),
            },
        ).await.unwrap();
        let mut second_outcome = RoundOutcome::default();
        let target = fixture.root.join(&replacement.name);
        let identity = hfdrive_windows::cfapi::identity::PlaceholderIdentity::file(
            fixture.workspace, file.item_id, VersionId::from_uuid(content.version_id).unwrap(),
        );
        MARK_TARGET.with(|expected| {
            assert!(expected.borrow_mut().replace((target, identity)).is_none());
        });
        finish_commit(
            &context, &[published_entry], &second, &second_sources, &head,
            &batch, committed, &mut second_outcome,
        ).await.unwrap();
        assert!(MARK_TARGET.with(|expected| expected.borrow().is_none()),
            "a real capture journal must reach in-sync marking at the applied target");
        assert_eq!(
            load_journal(&fixture.account, fixture.connection, ready.operation_id).await.unwrap().capture,
            Some(captured.evidence),
            "target USN rebinding must not rewrite the original capture journal",
        );
        assert_eq!(second_outcome.committed, vec![committed]);
        assert_eq!(second_outcome.published_operations, vec![ready.operation_id]);
        assert_eq!(second_outcome.applied_local_actions, if remote_deleted { 0 } else { 1 });
        let baseline = fixture.account.baseline(fixture.connection).await.unwrap();
        assert_eq!(baseline.applied_commit, Some(committed));
        assert_eq!(baseline.published_commit, Some(committed));
        let registry = fixture.account.item(fixture.connection, file.item_id).await.unwrap().unwrap();
        assert_eq!(registry.name, replacement.name);
        assert!(!registry.deleted);
        assert_eq!(std::fs::read(fixture.root.join(&registry.name)).unwrap(), bytes);
        assert!(fixture.account.list_active_outbox(fixture.connection, u32::MAX).await.unwrap().is_empty());
        assert_eq!(
            execute_pending_actions(&context).await.unwrap(), LocalActionOutcome::default(),
            "a completed replacement must not cause a permanent LocalApply loop",
        );
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
        let echo = tokio::sync::Mutex::new(crate::sync::observe::EchoTable::default());
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel, &echo);
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
        let echo = tokio::sync::Mutex::new(crate::sync::observe::EchoTable::default());
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel, &echo);
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
        let echo = tokio::sync::Mutex::new(crate::sync::observe::EchoTable::default());
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel, &echo);
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

    // -- K07/G13: one batch command refreshes the whole registry ----------

    /// The registry refresh is one transaction over the complete post-round
    /// namespace: a mid-batch failure leaves no partial write, an identical
    /// replay rewrites nothing, and a later batch's operation never enters an
    /// earlier base.
    #[tokio::test]
    async fn registry_refresh_is_one_transaction_and_skips_identical_rows() {
        use hfdrive_core::reconcile::CatalogView;
        let fixture = connection_fixture().await;
        let revision = OperationId::new();
        let root = item_record(fixture.root_item, None, "", ItemKind::Directory, None, revision);
        let committed = item_record(
            ItemId::new(), Some(fixture.root_item), "committed.bin", ItemKind::File,
            Some(VersionId::new()), revision,
        );
        let later = item_record(
            ItemId::new(), Some(fixture.root_item), "later-batch.bin", ItemKind::File,
            Some(VersionId::new()), revision,
        );
        let sources = PlanSources {
            base: CatalogView::new(vec![item_state(&root)]).unwrap(),
            remote: CatalogView::new(vec![item_state(&root)]).unwrap(),
            intents: Vec::new(),
            names: HashMap::new(),
        };
        let planned = planned_round(
            fixture.workspace,
            vec![create_op(committed.clone()), create_op(later.clone())],
        );
        let remote = HeadOnlyRemote::default();
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let echo = tokio::sync::Mutex::new(crate::sync::observe::EchoTable::default());
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel, &echo);
        let commit = CommitId::new();
        let database = hfdrive_state::StatePaths::new(fixture.directory.path().join("state"))
            .account(fixture.account.account_key())
            .database();

        // A failure at the second row of the registry batch rolls the whole
        // registry batch back: one transaction, one durable step. Per-row
        // upserts would leave the first row behind, so a partial registry
        // refresh is impossible.
        let root_before = fixture.account.item(fixture.connection, fixture.root_item).await.unwrap();
        {
            let raw = rusqlite::Connection::open(&database).unwrap();
            raw.execute_batch(&format!(
                "CREATE TRIGGER abort_second_item BEFORE INSERT ON items
                   WHEN NEW.item_id = X'{:032x}'
                   BEGIN SELECT RAISE(ABORT, 'injected batch failure'); END;",
                committed.item_id.as_uuid().as_u128()
            ))
            .unwrap();
        }
        assert!(matches!(
            advance_base(&ctx, commit, &planned.plan.remote_ops[..1], &planned, &sources).await,
            Err(PublishError::State(_))
        ));
        assert!(
            fixture.account.item(fixture.connection, committed.item_id).await.unwrap().is_none(),
            "an aborted registry batch leaves no partial write behind"
        );
        assert_eq!(
            fixture.account.item(fixture.connection, fixture.root_item).await.unwrap(),
            root_before,
            "the row written earlier in the same batch is rolled back with it"
        );
        {
            let raw = rusqlite::Connection::open(&database).unwrap();
            raw.execute_batch("DROP TRIGGER abort_second_item").unwrap();
        }

        // The retry lands the complete committed namespace in both stores.
        advance_base(&ctx, commit, &planned.plan.remote_ops[..1], &planned, &sources).await.unwrap();
        let rows = fixture.account.list_common_bases(fixture.connection, commit).await.unwrap();
        assert_eq!(rows.len(), 2, "the root and the committed operation belong to this base");
        assert!(!rows.iter().any(|row| row.item_id == later.item_id));
        assert!(fixture.account.item(fixture.connection, committed.item_id).await.unwrap().is_some());
        assert!(
            fixture.account.item(fixture.connection, later.item_id).await.unwrap().is_none(),
            "a later batch's operation must not enter this base"
        );

        // An identical replay rewrites nothing: a trigger aborting any UPDATE
        // of the table stays silent only if the batch truly writes no row.
        {
            let raw = rusqlite::Connection::open(&database).unwrap();
            raw.execute_batch(
                "CREATE TRIGGER refuse_item_rewrite BEFORE UPDATE ON items
                 BEGIN SELECT RAISE(ABORT, 'identical row rewritten'); END;",
            )
            .unwrap();
        }
        advance_base(&ctx, commit, &planned.plan.remote_ops[..1], &planned, &sources).await.unwrap();
        {
            let raw = rusqlite::Connection::open(&database).unwrap();
            raw.execute_batch("DROP TRIGGER refuse_item_rewrite").unwrap();
        }

        // A genuinely changed row *is* written, and the change rolls back with
        // its batch if the write is refused.
        let mut renamed = committed.clone();
        renamed.name = "renamed.bin".to_owned();
        let renamed_plan = planned_round(fixture.workspace, vec![create_op(renamed)]);
        {
            let raw = rusqlite::Connection::open(&database).unwrap();
            raw.execute_batch(
                "CREATE TRIGGER refuse_item_rewrite BEFORE UPDATE ON items
                 BEGIN SELECT RAISE(ABORT, 'identical row rewritten'); END;",
            )
            .unwrap();
        }
        assert!(matches!(
            advance_base(&ctx, commit, &renamed_plan.plan.remote_ops, &renamed_plan, &sources).await,
            Err(PublishError::State(_))
        ));
        assert_eq!(
            fixture.account.item(fixture.connection, committed.item_id).await.unwrap().unwrap().name,
            "committed.bin",
            "the aborted change is rolled back"
        );
        {
            let raw = rusqlite::Connection::open(&database).unwrap();
            raw.execute_batch("DROP TRIGGER refuse_item_rewrite").unwrap();
        }
        advance_base(&ctx, commit, &renamed_plan.plan.remote_ops, &renamed_plan, &sources).await.unwrap();
        assert_eq!(
            fixture.account.item(fixture.connection, committed.item_id).await.unwrap().unwrap().name,
            "renamed.bin",
            "the changed row is persisted once the guard is gone"
        );

        // The later batch's operation lands only in its own later base, and
        // the earlier base keeps every row it sealed.
        let later_commit = CommitId::new();
        advance_base(&ctx, later_commit, &planned.plan.remote_ops[1..], &planned, &sources).await.unwrap();
        assert!(fixture.account.item(fixture.connection, later.item_id).await.unwrap().is_some());
        assert_eq!(
            fixture.account.list_common_bases(fixture.connection, commit).await.unwrap().len(),
            2,
            "the earlier sealed namespace is untouched"
        );
        fixture.state.close().await.unwrap();
    }

    /// A bound version's digest/size/modification metadata reaches the
    /// registry row of the record that names it, and only that row.
    #[tokio::test]
    async fn registry_refresh_binds_the_planned_version_metadata() {
        use hfdrive_core::ids::UploadId;
        use hfdrive_core::reconcile::CatalogView;
        use hfdrive_core::storage::{PayloadKey, Sha256Digest, XetFileId};
        let fixture = connection_fixture().await;
        let revision = OperationId::new();
        let root = item_record(fixture.root_item, None, "", ItemKind::Directory, None, revision);
        let version = VersionId::new();
        let file = item_record(
            ItemId::new(), Some(fixture.root_item), "bound.bin", ItemKind::File,
            Some(version), revision,
        );
        let sources = PlanSources {
            base: CatalogView::new(vec![item_state(&root)]).unwrap(),
            remote: CatalogView::new(vec![item_state(&root)]).unwrap(),
            intents: Vec::new(),
            names: HashMap::new(),
        };
        let digest = Sha256Digest::of(b"bound payload");
        let object = ObjectRef {
            key: PayloadKey::new(UploadId::new()),
            xet_file_id: XetFileId::new(
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_owned(),
            )
            .unwrap(),
            size: 13,
            sha256: digest,
        };
        let mut planned = planned_round(fixture.workspace, vec![create_op(file.clone())]);
        planned.plan.versions.push(hfdrive_core::reconcile::PlannedVersion {
            version_id: version,
            object,
            display: format::DisplayMetadata {
                name: "bound.bin".to_owned(),
                modified_at: "2026-11-17T00:00:00Z".to_owned(),
            },
        });
        let remote = HeadOnlyRemote::default();
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let echo = tokio::sync::Mutex::new(crate::sync::observe::EchoTable::default());
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel, &echo);
        advance_base(&ctx, CommitId::new(), &planned.plan.remote_ops, &planned, &sources).await.unwrap();

        let bound = fixture.account.item(fixture.connection, file.item_id).await.unwrap().unwrap();
        let (stored_digest, stored_size) = registry_digest(&bound);
        assert_eq!(stored_digest, Some(digest));
        assert_eq!(stored_size, Some(13));
        assert_eq!(
            bound.metadata_json.get("modified_at").and_then(|v| v.as_str()),
            Some("2026-11-17T00:00:00Z")
        );
        // The directory record has no content version, so it carries no digest.
        let root_row = fixture.account.item(fixture.connection, fixture.root_item).await.unwrap().unwrap();
        assert_eq!(registry_digest(&root_row), (None, None));
        fixture.state.close().await.unwrap();
    }

    /// G04: a base advance never erases a remote version's digest, size or
    /// display metadata. Planned version metadata wins for newly published
    /// content; a remote-only or unchanged version keeps the content facts the
    /// remote view proved and the `modified_at` the registry already bound to
    /// that exact version. A known remote file is never re-defaulted to an
    /// unknown zero-length payload.
    #[tokio::test]
    async fn base_advance_preserves_nonempty_remote_version_metadata() {
        use hfdrive_core::ids::UploadId;
        use hfdrive_core::reconcile::{CatalogView, ItemState};
        use hfdrive_core::storage::{PayloadKey, Sha256Digest, XetFileId};
        let modified_at = |row: &hfdrive_state::ItemRecord| {
            row.metadata_json.get("modified_at").and_then(|value| value.as_str()).map(str::to_owned)
        };
        let fixture = connection_fixture().await;
        let revision = OperationId::new();
        let root = item_record(fixture.root_item, None, "", ItemKind::Directory, None, revision);

        // A nonempty remote-only file: the round published nothing for it.
        let remote_file = item_record(
            ItemId::new(), Some(fixture.root_item), "remote.bin", ItemKind::File,
            Some(VersionId::new()), revision,
        );
        let remote_digest = Sha256Digest::of(b"remote payload bytes");
        let remote_size = 20u64;

        // A locally published file: its committed record names a fresh
        // version, and the planned version metadata must replace the stale
        // facts of the version it supersedes.
        let published_item = ItemId::new();
        let old_version = VersionId::new();
        let published_old = item_record(
            published_item, Some(fixture.root_item), "published.bin", ItemKind::File,
            Some(old_version), revision,
        );
        let new_version = VersionId::new();
        let published_new = item_record(
            published_item, Some(fixture.root_item), "published.bin", ItemKind::File,
            Some(new_version), OperationId::new(),
        );
        // A second committed operation belonging to a later batch.
        let later = item_record(
            ItemId::new(), Some(fixture.root_item), "later.bin", ItemKind::File,
            Some(VersionId::new()), revision,
        );
        let new_digest = Sha256Digest::of(b"fresh payload");
        let new_size = 13u64;

        let root_state = ItemState::from_record(&root, None, None).unwrap();
        let remote_state =
            ItemState::from_record(&remote_file, Some(remote_digest), Some(remote_size)).unwrap();
        let old_state =
            ItemState::from_record(&published_old, Some(Sha256Digest::of(b"stale")), Some(1)).unwrap();
        let sources = PlanSources {
            base: CatalogView::new(vec![root_state.clone()]).unwrap(),
            remote: CatalogView::new(vec![root_state.clone(), remote_state.clone(), old_state]).unwrap(),
            intents: Vec::new(),
            names: HashMap::new(),
        };
        let object = ObjectRef {
            key: PayloadKey::new(UploadId::new()),
            xet_file_id: XetFileId::new(
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_owned(),
            )
            .unwrap(),
            size: new_size,
            sha256: new_digest,
        };
        let mut planned = planned_round(
            fixture.workspace,
            vec![
                hfdrive_core::reconcile::RemoteOp {
                    record: published_new.clone(),
                    change: format::ChangeKind::Content,
                    old_revision: Some(revision),
                },
                create_op(later.clone()),
            ],
        );
        planned.plan.versions.push(hfdrive_core::reconcile::PlannedVersion {
            version_id: new_version,
            object,
            display: format::DisplayMetadata {
                name: "published.bin".to_owned(),
                modified_at: "2026-11-18T00:00:00Z".to_owned(),
            },
        });

        // Earlier rounds already proved both files' display metadata.
        fixture.account.upsert_item(registry_item(
            fixture.connection,
            &remote_file,
            Some(remote_digest),
            Some(remote_size),
            Some("2026-06-01T00:00:00Z".to_owned()),
        ))
        .await
        .unwrap();
        fixture.account.upsert_item(registry_item(
            fixture.connection,
            &published_old,
            Some(Sha256Digest::of(b"stale")),
            Some(1),
            Some("2020-01-01T00:00:00Z".to_owned()),
        ))
        .await
        .unwrap();

        let remote = HeadOnlyRemote::default();
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let echo = tokio::sync::Mutex::new(crate::sync::observe::EchoTable::default());
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel, &echo);
        let commit = CommitId::new();
        // Only the first operation committed in this batch; `later.bin`
        // belongs to a later batch and re-plans afterwards.
        advance_base(&ctx, commit, &planned.plan.remote_ops[..1], &planned, &sources).await.unwrap();

        // The remote-only nonempty file keeps its content facts and its
        // display metadata through the base advance.
        let remote_row = fixture.account.item(fixture.connection, remote_file.item_id).await.unwrap().unwrap();
        let (stored_digest, stored_size) = registry_digest(&remote_row);
        assert_eq!(stored_digest, Some(remote_digest));
        assert_eq!(stored_size, Some(remote_size));
        assert!(stored_size.is_some_and(|size| size > 0), "a known remote file is never zeroed");
        assert_eq!(modified_at(&remote_row).as_deref(), Some("2026-06-01T00:00:00Z"));

        // The published version adopts its planned metadata, not the stale
        // facts of the version it replaced.
        let published_row = fixture.account.item(fixture.connection, published_item).await.unwrap().unwrap();
        let (published_digest, published_size) = registry_digest(&published_row);
        assert_eq!(published_digest, Some(new_digest));
        assert_eq!(published_size, Some(new_size));
        assert_eq!(modified_at(&published_row).as_deref(), Some("2026-11-18T00:00:00Z"));
        assert_eq!(published_row.content_version_id, Some(new_version));

        // The sealed base is the complete remote view overlaid with the
        // committed batch only; the later batch's operation never enters it.
        let rows = fixture.account.list_common_bases(fixture.connection, commit).await.unwrap();
        assert_eq!(rows.len(), 3, "the root and the complete remote view are sealed");
        assert!(rows.iter().any(|row| row.item_id == fixture.root_item));
        assert!(rows.iter().any(|row| row.item_id == remote_file.item_id));
        assert!(rows.iter().any(|row| row.item_id == published_item));
        assert!(!rows.iter().any(|row| row.item_id == later.item_id));
        assert!(fixture.account.item(fixture.connection, later.item_id).await.unwrap().is_none());

        // A later round that publishes nothing leaves every unchanged
        // version's metadata in place — including the display metadata that
        // round no longer has planned version records for.
        let published_kept =
            ItemState::from_record(&published_new, Some(new_digest), Some(new_size)).unwrap();
        let later_sources = PlanSources {
            base: CatalogView::new(vec![root_state.clone()]).unwrap(),
            remote: CatalogView::new(vec![root_state, remote_state, published_kept]).unwrap(),
            intents: Vec::new(),
            names: HashMap::new(),
        };
        let later_planned = planned_round(fixture.workspace, Vec::new());
        let second_commit = CommitId::new();
        advance_base(&ctx, second_commit, &[], &later_planned, &later_sources).await.unwrap();

        let remote_row = fixture.account.item(fixture.connection, remote_file.item_id).await.unwrap().unwrap();
        assert_eq!(registry_digest(&remote_row), (Some(remote_digest), Some(remote_size)));
        assert_eq!(modified_at(&remote_row).as_deref(), Some("2026-06-01T00:00:00Z"));
        let published_row = fixture.account.item(fixture.connection, published_item).await.unwrap().unwrap();
        assert_eq!(registry_digest(&published_row), (Some(new_digest), Some(new_size)));
        assert_eq!(modified_at(&published_row).as_deref(), Some("2026-11-18T00:00:00Z"));
        fixture.state.close().await.unwrap();
    }

    /// K17: a publication round reads active durable work only. Completed
    /// rows are durable history: a round never scans, decodes or sorts them,
    /// so a corrupted history row can never fail one.
    #[tokio::test]
    async fn a_round_never_scans_completed_outbox_history() {
        use crate::sync::outbox::SyncIntent;
        let fixture = connection_fixture().await;
        let completed_op = OperationId::new();
        let queued_item = ItemId::new();
        let queued_op = OperationId::new();

        // The history row: a metadata-only intent driven through its whole
        // legal lifecycle to a durable completion.
        let completed = crate::sync::outbox::intent_entry(
            fixture.connection,
            completed_op,
            None,
            None,
            None,
            0,
            &SyncIntent::Move {
                item_id: *ItemId::new().as_uuid(),
                parent_id: *fixture.root_item.as_uuid(),
                name: "history.bin".to_owned(),
            },
        )
        .unwrap();
        fixture.account.record_outbox(completed).await.unwrap();
        for transition in [
            OutboxTransition::MetadataReady {
                candidate_commit: CommitId::new(),
                candidate_head_json: serde_json::json!({ "generation": "g1" }),
                expected_etag: "etag-1".to_owned(),
            },
            OutboxTransition::Published,
            OutboxTransition::LocalApplyPending,
        ] {
            fixture.account
                .transition_outbox(fixture.connection, completed_op, transition)
                .await
                .unwrap();
        }
        fixture.account.complete_outbox(fixture.connection, completed_op).await.unwrap();

        // One active metadata-only intent: the round still drives real work.
        let queued = crate::sync::outbox::intent_entry(
            fixture.connection,
            queued_op,
            Some(queued_item),
            None,
            None,
            1,
            &SyncIntent::Move {
                item_id: *queued_item.as_uuid(),
                parent_id: *fixture.root_item.as_uuid(),
                name: "queued.bin".to_owned(),
            },
        )
        .unwrap();
        fixture.account.record_outbox(queued).await.unwrap();

        // The history row's intent payload is corrupted in place. Any pass
        // that decodes completed history fails on it — the publication round
        // never issues that pass.
        let database = hfdrive_state::StatePaths::new(fixture.directory.path().join("state"))
            .account(fixture.account.account_key())
            .database();
        {
            let raw = rusqlite::Connection::open(&database).unwrap();
            raw.execute(
                "UPDATE outbox SET intent_json = '{'
                  WHERE connection_id = ?1 AND operation_id = ?2",
                rusqlite::params![
                    fixture.connection.as_bytes().as_slice(),
                    completed_op.as_bytes().as_slice()
                ],
            )
            .unwrap();
        }
        // Proof the poison is load-bearing: the full-history listing still
        // decodes every row and fails on this one.
        assert!(fixture.account.list_outbox(fixture.connection, None, u32::MAX).await.is_err());

        let remote = HeadOnlyRemote::default();
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let echo = tokio::sync::Mutex::new(crate::sync::observe::EchoTable::default());
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel, &echo);
        // The round completes normally: completed history was never read.
        let outcome = run_round(&ctx, true).await.unwrap();
        assert!(outcome.needs_initialize);
        // The active row is still queued work; only history is skipped.
        let active = fixture.account.list_active_outbox(fixture.connection, u32::MAX).await.unwrap();
        assert_eq!(active.len(), 1, "only the active row is work");
        assert_eq!(active[0].operation_id, queued_op);
        assert_ne!(active[0].state, OutboxState::Complete);
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
        let echo = tokio::sync::Mutex::new(crate::sync::observe::EchoTable::default());
        let ctx = round_context(fixture, &remote, scheduler, cancel, &echo);
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
        let echo = tokio::sync::Mutex::new(crate::sync::observe::EchoTable::default());
        let ctx = round_context(fixture, &remote, scheduler, cancel, &echo);
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

    // -- K03/G01: destructive actions keep their journaled identity -------

    #[tokio::test]
    async fn rename_and_delete_preserve_replacement_b() {
        let fixture = connection_fixture().await;
        let remote = HeadOnlyRemote::default();
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let echo = tokio::sync::Mutex::new(crate::sync::observe::EchoTable::default());
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel, &echo);

        for kind in [StateActionKind::Rename, StateActionKind::DeletePlaceholder] {
            let from = std::path::PathBuf::from(format!("{kind:?}-source.txt"));
            let to = std::path::PathBuf::from(format!("{kind:?}-target.txt"));
            let source = fixture.root.join(&from);
            let target = fixture.root.join(&to);
            std::fs::write(&source, b"original A").unwrap();
            let original = hfdrive_windows::filesystem::volume::query_file_state(&source).unwrap();
            let row = LocalAction {
                connection_id: fixture.connection,
                action_id: ActionId::new(),
                item_id: Some(ItemId::new()),
                kind,
                expected_file_id: Some(hex_file_id(&original.identity.file_id)),
                expected_generation: Some(3),
                expected_usn: Some(
                    u64::try_from(original.usn.expect("the NTFS guard fixture needs a USN"))
                        .unwrap(),
                ),
                old_version: None,
                new_version: None,
                source_path: Some(from.clone()),
                target_path: (kind == StateActionKind::Rename).then_some(to),
                recovery_path: None,
                state: LocalActionState::Pending,
            };

            // The journaled object A is replaced at the same path by B after
            // planning. Neither destructive action may treat B as A.
            std::fs::remove_file(&source).unwrap();
            std::fs::write(&source, b"replacement B").unwrap();
            let replacement = hfdrive_windows::filesystem::volume::query_file_state(&source).unwrap();
            assert_ne!(replacement.identity.file_id, original.identity.file_id);

            assert!(!execute_one_action(&ctx, &row).await.unwrap());
            assert_eq!(std::fs::read(&source).unwrap(), b"replacement B");
            if kind == StateActionKind::Rename {
                assert!(!target.exists());
            } else {
                // Once absence is actually proven, deletion is already done.
                std::fs::remove_file(&source).unwrap();
                assert!(execute_one_action(&ctx, &row).await.unwrap());
            }
        }
        fixture.state.close().await.unwrap();
    }

    // -- G04: target metadata is durable before any effect ---------------

    #[tokio::test]
    async fn create_target_metadata_is_persisted_before_any_effect() {
        use hfdrive_core::reconcile::LocalActionKind;
        let fixture = connection_fixture().await;
        let revision = OperationId::new();
        // A remote child of the root: its only ancestor is the fixture's
        // registered root, so creation must work without any intermediate
        // registry row.
        let child = item_record(
            ItemId::new(),
            Some(fixture.root_item),
            "remote.txt",
            ItemKind::File,
            Some(VersionId::new()),
            revision,
        );
        let planned = PlannedRound {
            plan: ReconcilePlan {
                workspace_id: fixture.workspace,
                mode: ReconcileMode::ReadOnly,
                remote_ops: Vec::new(),
                versions: Vec::new(),
                changes: Vec::new(),
                operation_ids: Vec::new(),
                local_actions: vec![hfdrive_core::reconcile::LocalAction {
                    action_id: ActionId::new(),
                    item_id: child.item_id,
                    action: LocalActionKind::CreatePlaceholder,
                    expected: None,
                    target: Some(item_state(&child)),
                    local_alias: None,
                }],
                conflicts: Vec::new(),
                aliases: Vec::new(),
                intents: Vec::new(),
            },
            outcomes: Vec::new(),
        };
        plan::persist_plan_records(
            &fixture.account,
            fixture.connection,
            &planned.plan,
            &HashMap::new(),
        )
        .await
        .unwrap();

        // The target record is durable before any effect and before
        // `advance_base`: the create's registry lookup resolves it here.
        let row = fixture
            .account
            .item(fixture.connection, child.item_id)
            .await
            .unwrap()
            .expect("the create target's metadata is persisted with the plan");
        assert_eq!(row.name, "remote.txt");
        assert_eq!(row.parent_id, Some(fixture.root_item));
        assert_eq!(row.kind, hfdrive_state::ItemKind::File);
        assert_eq!(row.content_version_id, child.content_version_id);
        let (_, size) = plan::registry_digest(&row);
        assert_eq!(size, Some(4), "the bound version's size is durable too");

        // The executor's create resolves its identity and size from exactly
        // this row (`placeholder_identity`'s lookup) and never needs
        // `advance_base` to have run first.
        let remote = HeadOnlyRemote::default();
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let echo = tokio::sync::Mutex::new(crate::sync::observe::EchoTable::default());
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel, &echo);
        let action = fixture
            .account
            .pending_local_actions(fixture.connection)
            .await
            .unwrap()
            .remove(0);
        let (identity, size, directory) = placeholder_identity(&ctx, &action).await.unwrap();
        assert_eq!(identity, apply::file_identity(
            fixture.workspace,
            child.item_id,
            child.content_version_id.unwrap(),
        ));
        assert_eq!(size, 4);
        assert!(!directory);
        fixture.state.close().await.unwrap();
    }

    #[tokio::test]
    async fn a_create_target_occupied_by_a_foreign_object_is_preserved() {
        let fixture = connection_fixture().await;
        let remote = HeadOnlyRemote::default();
        let scheduler = crate::scheduler::Scheduler::new(Default::default());
        let cancel = CancellationToken::new();
        let echo = tokio::sync::Mutex::new(crate::sync::observe::EchoTable::default());
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel, &echo);

        // The target is a plain local file the plan knows nothing about.
        let path = std::path::PathBuf::from("occupied.txt");
        std::fs::write(fixture.root.join(&path), b"foreign bytes").unwrap();
        let version = VersionId::new();
        let row = LocalAction {
            connection_id: fixture.connection,
            action_id: ActionId::new(),
            item_id: Some(ItemId::new()),
            kind: StateActionKind::CreatePlaceholder,
            expected_file_id: None,
            expected_generation: None,
            expected_usn: None,
            old_version: None,
            new_version: Some(version),
            source_path: None,
            target_path: Some(path.clone()),
            recovery_path: None,
            state: LocalActionState::Pending,
        };
        fixture
            .account
            .upsert_item(hfdrive_state::ItemRecord {
                connection_id: fixture.connection,
                item_id: row.item_id.unwrap(),
                parent_id: Some(fixture.root_item),
                name: "occupied.txt".to_owned(),
                name_key: "occupied.txt".to_owned(),
                kind: hfdrive_state::ItemKind::File,
                revision: OperationId::new(),
                content_version_id: Some(version),
                deleted: false,
                metadata_json: serde_json::json!({ "size": 13 }),
            })
            .await
            .unwrap();
        fixture
            .account
            .bump_observation(fixture.connection, row.item_id.unwrap(), None)
            .await
            .unwrap();

        // A real creation entry reports `AlreadyExists` for the occupied
        // path; the occupant is not this item's placeholder, so its bytes
        // become fresh local work instead of retrying the create forever.
        fixture.account.record_local_action(row.clone()).await.unwrap();
        assert_eq!(execute_pending_actions(&ctx).await.unwrap(), LocalActionOutcome { applied: 0, requeued: 1 });
        assert_eq!(std::fs::read(fixture.root.join(&path)).unwrap(), b"foreign bytes");
        let actions = fixture.account.list_local_actions(fixture.connection, None).await.unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].state, LocalActionState::Requeued);
        let entries = fixture.account.list_active_outbox(fixture.connection, u32::MAX).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert!(matches!(parse_intent(&entries[0]).unwrap(), SyncIntent::Content { .. }));
        assert_eq!(execute_pending_actions(&ctx).await.unwrap(), LocalActionOutcome { applied: 0, requeued: 1 });
        require_namespace_application(&ctx).await.unwrap();
        assert_eq!(fixture.account.list_active_outbox(fixture.connection, u32::MAX).await.unwrap(), entries);
        assert_eq!(std::fs::read(fixture.root.join(&path)).unwrap(), b"foreign bytes");
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
        let echo = tokio::sync::Mutex::new(crate::sync::observe::EchoTable::default());
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel, &echo);
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
        let echo = tokio::sync::Mutex::new(crate::sync::observe::EchoTable::default());
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel, &echo);
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
        let echo = tokio::sync::Mutex::new(crate::sync::observe::EchoTable::default());
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel, &echo);
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
        let echo = tokio::sync::Mutex::new(crate::sync::observe::EchoTable::default());
        let ctx = round_context(&fixture, &remote, &scheduler, &cancel, &echo);
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
