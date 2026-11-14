//! Deterministic CAS and uncertain-write recovery tests over the guarded
//! publication coordinator. Fixtures implement the production seams in
//! `common`; conditional semantics are exact (one winner per validator).

mod common;

use common::*;
use hfdrive_core::ids::OperationId;
use hfdrive_publication::coordinator::{
    InitOutcome, PublishResult, UncertainResolution,
};
use hfdrive_publication::{OpaqueEtag, PublicationError};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn absent_head_reads_as_none_before_initialization() {
    let fixture = Fixture::new();
    let cancel = CancellationToken::new();
    assert!(fixture.coordinator.read_head_with_etag(&cancel).await.unwrap().is_none());
}

#[tokio::test]
async fn two_writers_with_one_validator_yield_exactly_one_cas_winner() {
    let fixture = Fixture::new();
    let (base, root) = initialize_base(&fixture).await;
    let bind = binding();
    let a = next_candidate(&bind, &base, root);
    let b = next_candidate(&bind, &base, root);
    let a_commit = a.commit.commit_id;
    let b_commit = b.commit.commit_id;
    let cancel = CancellationToken::new();

    let (first, second) = tokio::join!(
        fixture.coordinator.publish_if_match(&base, a, &cancel),
        fixture.coordinator.publish_if_match(&base, b, &cancel)
    );
    let outcomes = [first.unwrap(), second.unwrap()];
    let committed = outcomes
        .iter()
        .filter(|result| matches!(result, PublishResult::Committed(_)))
        .count();
    assert_eq!(committed, 1, "exactly one writer may win the validator");
    for result in &outcomes {
        if let PublishResult::PreconditionFailed { current } = result {
            let current = current.as_ref().expect("winner published a HEAD");
            assert_ne!(current.head.commit_id, base.head.commit_id);
            assert!(
                current.head.commit_id == a_commit || current.head.commit_id == b_commit,
                "the reported current HEAD must be one of the racing candidates"
            );
        }
    }
    // The loser re-reconciles against the current state with NEW identities
    // and then commits; nothing is replayed under a reused id.
    let cancel = CancellationToken::new();
    let current = fixture.coordinator.read_head_with_etag(&cancel).await.unwrap().unwrap();
    let rebased = next_candidate(&bind, &current, root);
    let outcome = fixture.coordinator.publish_if_match(&current, rebased, &cancel).await.unwrap();
    assert!(matches!(outcome, PublishResult::Committed(_)));
}

#[tokio::test]
async fn stale_and_misquoted_validators_never_overwrite() {
    let fixture = Fixture::new();
    let (base, root) = initialize_base(&fixture).await;
    let bind = binding();
    let cancel = CancellationToken::new();

    // Move the HEAD forward once.
    let advance = next_candidate(&bind, &base, root);
    fixture.coordinator.publish_if_match(&base, advance, &cancel).await.unwrap().unwrap_ish();

    // The old validator is now stale and must be refused with a fresh re-read.
    let stale = next_candidate(&bind, &base, root);
    match fixture.coordinator.publish_if_match(&base, stale, &cancel).await.unwrap() {
        PublishResult::PreconditionFailed { current } => {
            let current = current.expect("HEAD still exists");
            assert_ne!(current.head.commit_id, base.head.commit_id);
        }
        other => panic!("stale validator must not commit: {other:?}"),
    }

    // A forged but well-formed validator is equally refused.
    let current = fixture.coordinator.read_head_with_etag(&cancel).await.unwrap().unwrap();
    let forged = hfdrive_publication::coordinator::HeadVersion {
        head: current.head.clone(),
        etag: OpaqueEtag::new("\"definitely-not-the-current-etag\"".to_owned()).unwrap(),
    };
    let candidate = next_candidate(&bind, &current, root);
    match fixture.coordinator.publish_if_match(&forged, candidate, &cancel).await.unwrap() {
        PublishResult::PreconditionFailed { .. } => {}
        other => panic!("forged validator must not commit: {other:?}"),
    }
}

#[tokio::test]
async fn racing_initializers_cannot_relabel_or_overwrite_the_winner() {
    let fixture = Fixture::new();
    let bind = binding();
    let first = initial_candidate(&bind);
    let second = initial_candidate(&bind);
    let first_commit = first.commit.commit_id;
    let second_commit = second.commit.commit_id;
    let cancel = CancellationToken::new();

    let (a, b) = tokio::join!(
        fixture.coordinator.initialize_if_absent(first, &cancel),
        fixture.coordinator.initialize_if_absent(second, &cancel)
    );
    let results = [a.unwrap(), b.unwrap()];
    let winners = results
        .iter()
        .filter(|result| matches!(result, InitOutcome::Committed(_)))
        .count();
    assert_eq!(winners, 1, "exactly one initializer may win If-None-Match: *");
    for result in &results {
        if let InitOutcome::AlreadyInitialized { current } = result {
            let current = current.as_ref().expect("winner published a HEAD");
            assert_eq!(current.head.workspace_id, bind.workspace_id());
            assert!(
                current.head.commit_id == first_commit || current.head.commit_id == second_commit,
                "the reported winner must be one of the racing candidates"
            );
        }
    }

    // A candidate for a different workspace is refused outright: queued local
    // work is never relabeled onto a winning foreign identity.
    let cancel = CancellationToken::new();
    let mut foreign = initial_candidate(&bind);
    foreign.head.workspace_id = hfdrive_core::ids::WorkspaceId::new();
    foreign.commit.workspace_id = foreign.head.workspace_id;
    assert!(matches!(
        fixture.coordinator.initialize_if_absent(foreign, &cancel).await,
        Err(PublicationError::BindingMismatch)
    ));
}

#[tokio::test]
async fn lost_cas_response_is_recovered_through_committed_ancestry() {
    let fixture = Fixture::new();
    let (base, root) = initialize_base(&fixture).await;
    let bind = binding();
    let candidate = next_candidate(&bind, &base, root);
    let candidate_commit = candidate.commit.commit_id;
    let candidate_op = candidate.commit.operation_ids[0];
    let cancel = CancellationToken::new();

    fixture.remote.lock().unwrap().drop_replace_responses = 1;
    let result = fixture.coordinator.publish_if_match(&base, candidate.clone(), &cancel).await.unwrap();
    assert!(matches!(result, PublishResult::Ambiguous(_)), "the response was dropped: {result:?}");

    // Resolution uses committed ancestry only — no replay, no rollback claim.
    let resolution = fixture.coordinator.resolve_uncertain_write(&candidate, None, &cancel).await.unwrap();
    match resolution {
        UncertainResolution::Committed { commit_id } => assert_eq!(commit_id, candidate_commit),
        other => panic!("the applied candidate must be found: {other:?}"),
    }
    assert_eq!(
        fixture.coordinator.find_committed_operation(candidate_commit, candidate_op, &cancel).await.unwrap(),
        Some(candidate_commit)
    );
}

#[tokio::test]
async fn never_dispatched_candidate_resolves_as_not_committed() {
    let fixture = Fixture::new();
    let (base, root) = initialize_base(&fixture).await;
    let bind = binding();
    let candidate = next_candidate(&bind, &base, root);
    let cancel = CancellationToken::new();

    let resolution = fixture.coordinator.resolve_uncertain_write(&candidate, None, &cancel).await.unwrap();
    match resolution {
        UncertainResolution::NotCommitted { current } => {
            assert_eq!(current.unwrap().head.commit_id, base.head.commit_id);
        }
        other => panic!("an undispatched candidate cannot be committed: {other:?}"),
    }
}

#[tokio::test]
async fn operation_committed_elsewhere_is_not_the_candidate_completing() {
    let fixture = Fixture::new();
    let (base, root) = initialize_base(&fixture).await;
    let bind = binding();
    let cancel = CancellationToken::new();

    // Our candidate never publishes; another commit on the chain carries the
    // same operation UUID (a rebase by another device).
    let candidate = next_candidate(&bind, &base, root);
    let mut rebased = next_candidate(&bind, &base, root);
    rebased.commit.operation_ids = candidate.commit.operation_ids.clone();
    rebased.head.commit_id = rebased.commit.commit_id;
    let rebased_commit = rebased.commit.commit_id;
    fixture.coordinator.publish_if_match(&base, rebased, &cancel).await.unwrap().unwrap_ish();

    let resolution = fixture.coordinator.resolve_uncertain_write(&candidate, None, &cancel).await.unwrap();
    match resolution {
        UncertainResolution::CommittedElsewhere { matches } => {
            assert_eq!(matches.len(), 1);
            assert_eq!(matches[0].commit_id, rebased_commit);
            assert!(!matches[0].is_candidate);
        }
        other => panic!("a foreign commit holding the operation is not our candidate: {other:?}"),
    }
}

#[tokio::test]
async fn first_chunk_of_a_multi_commit_workflow_is_not_completion() {
    let fixture = Fixture::new();
    let (base, root) = initialize_base(&fixture).await;
    let bind = binding();
    let cancel = CancellationToken::new();

    let mut low = OperationId::new();
    let mut high = OperationId::new();
    if high < low {
        std::mem::swap(&mut low, &mut high);
    }

    // The workflow's candidate carries both operations in one commit; only
    // `low` has landed so far, in a different commit.
    let mut candidate = next_candidate(&bind, &base, root);
    candidate.commit.operation_ids = vec![low, high];

    let mut chunk = next_candidate(&bind, &base, root);
    chunk.commit.operation_ids = vec![low];
    chunk.head.commit_id = chunk.commit.commit_id;
    let chunk_commit = chunk.commit.commit_id;
    fixture.coordinator.publish_if_match(&base, chunk, &cancel).await.unwrap().unwrap_ish();

    let resolution = fixture.coordinator.resolve_uncertain_write(&candidate, None, &cancel).await.unwrap();
    match resolution {
        UncertainResolution::CommittedElsewhere { matches } => {
            // The located commit holds only part of the workflow; the caller
            // must reconcile the exact intent and keep the rest pending.
            assert_eq!(matches.len(), 1);
            assert_eq!(matches[0].commit_id, chunk_commit);
            assert_eq!(matches[0].operations, vec![low]);
        }
        other => panic!("a partial workflow is never reported complete: {other:?}"),
    }
}

/// Small helper trait so tests can assert on outcomes without extra imports.
trait UnwrapIsh {
    fn unwrap_ish(&self);
}

impl UnwrapIsh for PublishResult {
    fn unwrap_ish(&self) {
        assert!(matches!(self, PublishResult::Committed(_)), "expected Committed: {self:?}");
    }
}

impl UnwrapIsh for hfdrive_publication::coordinator::InitOutcome {
    fn unwrap_ish(&self) {
        assert!(matches!(self, InitOutcome::Committed(_)), "expected Committed: {self:?}");
    }
}
