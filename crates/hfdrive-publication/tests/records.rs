//! Immutable-record and binding-integrity tests: missing, corrupt and newer
//! managed records stay distinct error classes; cross-binding state is
//! refused; an immutable key is never overwritten with different bytes.

mod common;

use common::*;
use hfdrive_core::format::{self, CommitV1, SCHEMA_VERSION};
use hfdrive_core::ids::{CommitId, DeviceId, OperationId, WorkspaceId};
use hfdrive_core::storage::ImmutableKey;
use hfdrive_publication::coordinator::{
    InitOutcome, PublicationCoordinator, PublishResult,
};
use hfdrive_publication::transport::MetadataRecord;
use hfdrive_publication::PublicationError;
use tokio_util::sync::CancellationToken;

/// Commits `candidate` and returns its commit id.
async fn commit_one(
    fixture: &Fixture,
    base: &hfdrive_publication::coordinator::HeadVersion,
    root: hfdrive_core::storage::Sha256Digest,
) -> (CommitId, OperationId) {
    let cancel = CancellationToken::new();
    let bind = binding();
    let candidate = next_candidate(&bind, base, root);
    let ids = (candidate.commit.commit_id, candidate.commit.operation_ids[0]);
    fixture.coordinator.publish_if_match(base, candidate, &cancel).await.unwrap().unwrap_ish();
    ids
}

fn commit_key(commit: CommitId) -> String {
    binding().prefix().immutable_key(ImmutableKey::Commit(commit)).as_str().to_owned()
}

#[tokio::test]
async fn missing_referenced_commit_is_retryable_remote_content_unavailable() {
    let fixture = Fixture::new();
    let (base, root) = initialize_base(&fixture).await;
    let (commit, operation) = commit_one(&fixture, &base, root).await;
    let cancel = CancellationToken::new();

    fixture.remote.lock().unwrap().delete(&commit_key(commit));
    assert!(matches!(
        fixture.coordinator.find_committed_operation(commit, operation, &cancel).await,
        Err(PublicationError::RemoteContentUnavailable)
    ));

    // A direct read of a missing referenced record maps identically.
    assert!(matches!(
        fixture.coordinator.read_metadata(MetadataRecord::Commit(CommitId::new()), &cancel).await,
        Err(PublicationError::RemoteContentUnavailable)
    ));
}

#[tokio::test]
async fn corrupt_commit_record_is_a_violated_contract_not_an_absence() {
    let fixture = Fixture::new();
    let (base, root) = initialize_base(&fixture).await;
    let (commit, operation) = commit_one(&fixture, &base, root).await;
    let cancel = CancellationToken::new();

    fixture.remote.lock().unwrap().seed(&commit_key(commit), b"this is not canonical JSON".to_vec());
    assert!(matches!(
        fixture.coordinator.find_committed_operation(commit, operation, &cancel).await,
        Err(PublicationError::InvalidResponse)
    ));
}

#[tokio::test]
async fn newer_schema_record_is_unsupported_format() {
    let fixture = Fixture::new();
    let (base, root) = initialize_base(&fixture).await;
    let bind = binding();
    let candidate = next_candidate(&bind, &base, root);
    let commit = candidate.commit.commit_id;
    let operation = candidate.commit.operation_ids[0];
    let device = candidate.commit.device_id;
    let cancel = CancellationToken::new();
    fixture.coordinator.publish_if_match(&base, candidate, &cancel).await.unwrap().unwrap_ish();

    // Canonical JSON naming schema 2: the same record shape with a schema this
    // build cannot read. It must be refused as unsupported, never rewritten
    // and never treated as corrupt/absent.
    let body = format!(
        concat!(
            r#"{{"catalog_root":"{root}","changes":[],"commit_id":"{commit}","created_at":"1970-01-01T00:00:00Z","#,
            r#""device_id":"{device}","format":"hfdrive","operation_ids":["{operation}"],"#,
            r#""parent_commit_id":"{parent}","schema_version":2,"workspace_id":"{workspace}"}}"#
        ),
        root = root,
        commit = commit,
        device = device,
        operation = operation,
        parent = base.head.commit_id,
        workspace = bind.workspace_id(),
    );
    fixture.remote.lock().unwrap().seed(&commit_key(commit), body.into_bytes());
    assert!(matches!(
        fixture.coordinator.find_committed_operation(commit, operation, &cancel).await,
        Err(PublicationError::UnsupportedFormat)
    ));
}

#[tokio::test]
async fn cross_binding_state_is_refused_at_construction_and_in_ancestry() {
    let remote = Remote::new();

    // Store bound to a different workspace than the coordinator's binding.
    let mut other_drive = drive_binding();
    other_drive.workspace_id = WorkspaceId::new();
    let (issuer, subject) = identity();
    let other_binding = hfdrive_publication::binding::PublicationBinding::new(
        &other_drive,
        &hfdrive_publication::binding::AccountIdentity { issuer: &issuer, subject: &subject },
    )
    .unwrap();
    assert!(matches!(
        PublicationCoordinator::new(
            binding(),
            FixtureNative::new(remote.clone()),
            FixtureStore::with_binding(remote.clone(), other_binding),
        ),
        Err(PublicationError::BindingMismatch)
    ));

    // Native drive bound to a different workspace than the publication binding.
    assert!(matches!(
        PublicationCoordinator::new(
            binding(),
            FixtureNative::with_drive(remote.clone(), other_drive.clone()),
            FixtureStore::new(remote.clone()),
        ),
        Err(PublicationError::BindingMismatch)
    ));

    // A candidate for a foreign workspace is refused before any effect.
    let fixture = Fixture::new();
    let (base, root) = initialize_base(&fixture).await;
    let bind = binding();
    let mut candidate = next_candidate(&bind, &base, root);
    candidate.head.workspace_id = WorkspaceId::new();
    candidate.commit.workspace_id = candidate.head.workspace_id;
    let cancel = CancellationToken::new();
    assert!(matches!(
        fixture.coordinator.publish_if_match(&base, candidate, &cancel).await,
        Err(PublicationError::BindingMismatch)
    ));

    // A foreign-workspace commit record found in ancestry is refused as
    // binding disagreement, not trusted and not reported as absent.
    let (commit, operation) = commit_one(&fixture, &base, root).await;
    let foreign_commit = CommitV1 {
        format: format::FORMAT_NAME.to_owned(),
        schema_version: SCHEMA_VERSION,
        workspace_id: WorkspaceId::new(),
        commit_id: commit,
        parent_commit_id: Some(base.head.commit_id),
        catalog_root: root,
        operation_ids: vec![operation],
        changes: Vec::new(),
        device_id: DeviceId::new(),
        created_at: "1970-01-01T00:00:00Z".to_owned(),
    };
    let bytes = format::to_commit_bytes(&foreign_commit).unwrap();
    fixture.remote.lock().unwrap().seed(&commit_key(commit), bytes);
    assert!(matches!(
        fixture.coordinator.find_committed_operation(commit, operation, &cancel).await,
        Err(PublicationError::BindingMismatch)
    ));
}

#[tokio::test]
async fn a_reused_commit_id_never_overwrites_the_immutable_record() {
    let fixture = Fixture::new();
    let (base, root) = initialize_base(&fixture).await;
    let bind = binding();
    let cancel = CancellationToken::new();

    let candidate = next_candidate(&bind, &base, root);
    let commit = candidate.commit.commit_id;
    fixture.coordinator.publish_if_match(&base, candidate, &cancel).await.unwrap().unwrap_ish();
    let stored = fixture.remote.lock().unwrap().bytes(&commit_key(commit)).unwrap();

    // Same commit id, different operation set: the immutable record must be
    // refused and left byte-identical.
    let mut reused = next_candidate(&bind, &base, root);
    reused.commit.commit_id = commit;
    reused.head.commit_id = commit;
    reused.commit.operation_ids = vec![OperationId::new()];
    assert!(matches!(
        fixture.coordinator.publish_if_match(&base, reused, &cancel).await,
        Err(PublicationError::ImmutableRecordConflict)
    ));
    assert_eq!(
        fixture.remote.lock().unwrap().bytes(&commit_key(commit)).unwrap(),
        stored,
        "the committed immutable record must remain byte-identical"
    );
}

#[tokio::test]
async fn a_rebased_candidate_requires_fresh_commit_and_generation_identities() {
    let fixture = Fixture::new();
    let (base, root) = initialize_base(&fixture).await;
    let bind = binding();
    let cancel = CancellationToken::new();

    let candidate = next_candidate(&bind, &base, root);
    // A candidate that reuses the preserved base's identities is refused
    // before staging anything.
    let mut lazy = next_candidate(&bind, &base, root);
    lazy.head.generation = base.head.generation;
    assert!(matches!(
        fixture.coordinator.publish_if_match(&base, lazy, &cancel).await,
        Err(PublicationError::ImmutableRecordConflict)
    ));

    let mut lazier = next_candidate(&bind, &base, root);
    lazier.head.commit_id = base.head.commit_id;
    lazier.commit.commit_id = base.head.commit_id;
    assert!(matches!(
        fixture.coordinator.publish_if_match(&base, lazier, &cancel).await,
        Err(PublicationError::ImmutableRecordConflict)
    ));

    // The untouched candidate still commits normally.
    fixture.coordinator.publish_if_match(&base, candidate, &cancel).await.unwrap().unwrap_ish();
}

trait UnwrapIsh {
    fn unwrap_ish(&self);
}

impl UnwrapIsh for PublishResult {
    fn unwrap_ish(&self) {
        assert!(matches!(self, PublishResult::Committed(_)), "expected Committed: {self:?}");
    }
}

impl UnwrapIsh for InitOutcome {
    fn unwrap_ish(&self) {
        assert!(matches!(self, InitOutcome::Committed(_)), "expected Committed: {self:?}");
    }
}
