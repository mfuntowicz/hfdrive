//! Bounded committed-ancestry tests: validation at every fetch, resumable
//! bounded walks, exact operation accounting (including partial multi-commit
//! workflows), retryable missing records versus corruption, and cancellation.

mod common;

use std::future::Future;
use std::sync::Arc;

use common::*;
use hfdrive_core::format::{self, CommitV1};
use hfdrive_core::ids::{CommitId, DeviceId, OperationId, WorkspaceId};
use hfdrive_core::storage::Sha256Digest;
use hfdrive_hf::NativeLease;
use hfdrive_publication::ancestry::{
    self, AncestryBounds, AncestryCursor, AncestryGoal, AncestryProgress, AncestrySource,
    AncestryStop,
};
use hfdrive_publication::transport::BoundedRecord;
use hfdrive_publication::{OpaqueEtag, PublicationError};
use tokio_util::sync::CancellationToken;

/// Canonical timestamp required by the format.
const EPOCH: &str = "1970-01-01T00:00:00Z";

/// A parent chain where `chain[0]` is the initial commit (parent `null`) and
/// `chain[len - 1]` is the current tip. Each commit carries one unique
/// operation UUID.
fn commit_chain(length: usize) -> Vec<CommitV1> {
    let workspace = WorkspaceId::new();
    let device = DeviceId::new();
    let mut chain = Vec::with_capacity(length);
    let mut parent: Option<CommitId> = None;
    for index in 0..length {
        let commit = CommitV1 {
            format: format::FORMAT_NAME.to_owned(),
            schema_version: format::SCHEMA_VERSION,
            workspace_id: workspace,
            commit_id: CommitId::new(),
            parent_commit_id: parent,
            catalog_root: Sha256Digest::of(format!("catalog-root-{index}").as_bytes()),
            operation_ids: vec![OperationId::new()],
            changes: Vec::new(),
            device_id: device,
            created_at: EPOCH.to_owned(),
        };
        parent = Some(commit.commit_id);
        chain.push(commit);
    }
    chain
}

/// Commit source over the exact production seam, backed by the in-memory remote.
struct Source {
    remote: Arc<std::sync::Mutex<Remote>>,
}

impl Source {
    fn new() -> Self {
        Self { remote: Remote::new() }
    }

    fn seed(&self, commit: &CommitV1) {
        let bytes = format::to_commit_bytes(commit).unwrap();
        let key = format!("commits/{}.json", commit.commit_id);
        self.remote.lock().unwrap().seed(&key, bytes);
    }
}

impl AncestrySource for Source {
    fn read_commit(
        &self,
        _lease: &NativeLease,
        commit: CommitId,
        _cancel: &CancellationToken,
    ) -> impl Future<Output = Result<BoundedRecord, PublicationError>> + Send {
        async move {
            let key = format!("commits/{commit}.json");
            let (body, _etag) = self
                .remote
                .lock()
                .unwrap()
                .get(&key)
                .ok_or(PublicationError::Absent)?;
            Ok(BoundedRecord::from_parts(
                OpaqueEtag::new("\"ancestry\"".to_owned()).unwrap(),
                body.into(),
            ))
        }
    }
}

async fn walk(
    source: &Source,
    workspace: WorkspaceId,
    cursor: AncestryCursor,
    goal: AncestryGoal,
    stop: AncestryStop,
    bounds: AncestryBounds,
) -> Result<AncestryProgress, PublicationError> {
    let cancel = CancellationToken::new();
    let lease = common::lease();
    ancestry::walk_ancestry(source, &lease, workspace, cursor, &goal, stop, bounds, &cancel).await
}

#[tokio::test]
async fn bounded_walk_pauses_and_resumes_without_losing_accounting() {
    let chain = commit_chain(10);
    let workspace = chain[0].workspace_id;
    let source = Source::new();
    for commit in &chain {
        source.seed(commit);
    }
    let tip = chain[chain.len() - 1].commit_id;
    let candidate = chain[0].commit_id;
    let goal = AncestryGoal { candidate: Some(candidate), operations: Vec::new() };

    // The bound stops the search before the chain is consumed; the cursor
    // resumes exactly where the walk paused.
    let first = walk(
        &source,
        workspace,
        AncestryCursor::begin(tip),
        goal.clone(),
        AncestryStop::CandidateOrComplete,
        AncestryBounds { max_commits: 3, max_bytes: 1024 * 1024 },
    )
    .await
    .unwrap();
    let AncestryProgress::Paused { cursor, matches } = &first else {
        panic!("the bound must pause before reaching the candidate: {first:?}");
    };
    assert!(matches.is_empty(), "no goal location exists in the first segment");
    assert_eq!(cursor.scanned, 3);

    let second = walk(
        &source,
        workspace,
        cursor.clone(),
        goal,
        AncestryStop::CandidateOrComplete,
        AncestryBounds::default(),
    )
    .await
    .unwrap();
    assert!(
        matches!(second, AncestryProgress::Candidate { commit_id, .. } if commit_id == candidate),
        "the resumed walk must find the exact candidate"
    );
}

#[tokio::test]
async fn partial_workflow_chunk_is_not_mistaken_for_completion() {
    let chain = commit_chain(2);
    let workspace = chain[0].workspace_id;
    let source = Source::new();
    for commit in &chain {
        source.seed(commit);
    }

    // The workflow's candidate is unpublished and carries two operations; only
    // `landed` has been committed so far — by the tip commit, not by the
    // candidate (a first chunk or a rebase by another device).
    let landed = chain[1].operation_ids[0];
    let pending = OperationId::new();
    let mut operations = [landed, pending];
    operations.sort();
    let candidate_id = CommitId::new();

    let outcome = walk(
        &source,
        workspace,
        AncestryCursor::begin(chain[1].commit_id),
        AncestryGoal { candidate: Some(candidate_id), operations: operations.to_vec() },
        AncestryStop::CandidateOrComplete,
        AncestryBounds::default(),
    )
    .await
    .unwrap();
    let AncestryProgress::Complete { matches } = outcome else {
        panic!("chain fully consumed without the candidate: {outcome:?}");
    };
    assert_eq!(matches.len(), 1, "only the landed operation is located");
    assert_eq!(matches[0].commit_id, chain[1].commit_id);
    assert_eq!(matches[0].operations, vec![landed], "partial workflows never report the pending half");
    assert!(!matches[0].is_candidate, "the candidate itself was not published");
}

#[tokio::test]
async fn first_match_stops_at_the_first_operation_location() {
    let chain = commit_chain(3);
    let workspace = chain[0].workspace_id;
    let source = Source::new();
    for commit in &chain {
        source.seed(commit);
    }
    let landed = chain[1].operation_ids[0];

    let outcome = walk(
        &source,
        workspace,
        AncestryCursor::begin(chain[2].commit_id),
        AncestryGoal { candidate: None, operations: vec![landed] },
        AncestryStop::FirstMatch,
        AncestryBounds::default(),
    )
    .await
    .unwrap();
    let AncestryProgress::Complete { matches } = outcome else {
        panic!("FirstMatch returns Complete with the located match: {outcome:?}");
    };
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].commit_id, chain[1].commit_id);

    // Absence is only proven by consuming the chain inside the bound.
    let absent = walk(
        &source,
        workspace,
        AncestryCursor::begin(chain[2].commit_id),
        AncestryGoal { candidate: None, operations: vec![OperationId::new()] },
        AncestryStop::FirstMatch,
        AncestryBounds::default(),
    )
    .await
    .unwrap();
    assert!(absent.matches().is_empty(), "an unlocated operation yields no match");
}

#[tokio::test]
async fn chain_with_repeated_commit_is_corruption() {
    let chain = commit_chain(2);
    let workspace = chain[0].workspace_id;
    let source = Source::new();
    // A cycle: the root's parent points at itself.
    let mut cyclic = chain[0].clone();
    cyclic.parent_commit_id = Some(cyclic.commit_id);
    source.seed(&cyclic);
    source.seed(&chain[1]);

    let outcome = walk(
        &source,
        workspace,
        AncestryCursor::begin(chain[1].commit_id),
        AncestryGoal { candidate: None, operations: Vec::new() },
        AncestryStop::FirstMatch,
        AncestryBounds::default(),
    )
    .await;
    assert!(matches!(outcome, Err(PublicationError::InvalidResponse)));
}

#[tokio::test]
async fn missing_referenced_commit_is_retryable_not_deletion() {
    let chain = commit_chain(2);
    let workspace = chain[0].workspace_id;
    let source = Source::new();
    // Only the tip record exists; its referenced parent is absent.
    source.seed(&chain[1]);

    let outcome = walk(
        &source,
        workspace,
        AncestryCursor::begin(chain[1].commit_id),
        AncestryGoal { candidate: None, operations: Vec::new() },
        AncestryStop::FirstMatch,
        AncestryBounds::default(),
    )
    .await;
    assert!(matches!(outcome, Err(PublicationError::RemoteContentUnavailable)));
}

#[tokio::test]
async fn cancellation_is_exact_and_discards_partial_progress() {
    let chain = commit_chain(3);
    let workspace = chain[0].workspace_id;
    let source = Source::new();
    for commit in &chain {
        source.seed(commit);
    }
    let cancel = CancellationToken::new();
    cancel.cancel();
    let lease = common::lease();
    let outcome = ancestry::walk_ancestry(
        &source,
        &lease,
        workspace,
        AncestryCursor::begin(chain[2].commit_id),
        &AncestryGoal { candidate: None, operations: Vec::new() },
        AncestryStop::FirstMatch,
        AncestryBounds::default(),
        &cancel,
    )
    .await;
    assert!(matches!(outcome, Err(PublicationError::Cancelled)));
}

#[tokio::test]
async fn load_commit_enforces_key_workspace_and_record_validity() {
    let chain = commit_chain(1);
    let workspace = chain[0].workspace_id;
    let source = Source::new();
    source.seed(&chain[0]);
    let lease = common::lease();
    let cancel = CancellationToken::new();

    // Exact key/body agreement is validated by `load_commit`.
    let loaded =
        ancestry::load_commit(&source, &lease, workspace, chain[0].commit_id, &cancel).await.unwrap();
    assert_eq!(loaded.commit_id, chain[0].commit_id);

    // A record for another workspace is a binding mismatch, never trusted.
    let foreign = ancestry::load_commit(
        &source,
        &lease,
        WorkspaceId::new(),
        chain[0].commit_id,
        &cancel,
    )
    .await;
    assert!(matches!(foreign, Err(PublicationError::BindingMismatch)));

    // A corrupt record is a contract violation, never an absence.
    source
        .remote
        .lock()
        .unwrap()
        .seed(&format!("commits/{}.json", chain[0].commit_id), b"{".to_vec());
    let corrupt = ancestry::load_commit(&source, &lease, workspace, chain[0].commit_id, &cancel).await;
    assert!(matches!(corrupt, Err(PublicationError::InvalidResponse)));
}
