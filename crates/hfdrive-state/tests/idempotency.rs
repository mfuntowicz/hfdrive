//! Idempotent IPC mutations: one operation id binds to one exact request; a
//! completed operation replays its persisted result; an interrupted external
//! operation is never blindly replayed.

mod common;

use common::*;
use hfdrive_core::ids::OperationId;
use hfdrive_state::{
    BeginOperationRequest, BeginOutcome, EffectClass, OperationResolution, OperationState,
    ProbeKeyRecord, ProbeKeyState, SetupDraft, StateError, StatePaths, StateStore,
};
use hfdrive_core::ids::GenerationId;

fn request(op: OperationId, kind: &str, body: serde_json::Value) -> BeginOperationRequest {
    BeginOperationRequest {
        operation_id: op,
        kind: kind.to_owned(),
        request: body,
        effect_class: EffectClass::External,
        account_key: None,
        connection_id: None,
        bucket_creation_operation_id: None,
    }
}

#[tokio::test]
async fn completed_operation_replays_persisted_result() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let op = OperationId::new();
    let body = serde_json::json!({"bucket": "bucket-test-1"});

    let first = store.begin_operation(request(op, "create_bucket", body.clone())).await.unwrap();
    let BeginOutcome::Fresh(record) = &first else {
        panic!("the first begin must be fresh: {first:?}");
    };
    assert_eq!(record.state, OperationState::Pending);

    let second = store.begin_operation(request(op, "create_bucket", body)).await.unwrap();
    let BeginOutcome::Replayed(record) = &second else {
        panic!("an identical repeat must replay, not re-run: {second:?}");
    };
    assert_eq!(record.operation_id, op);

    // Persist the acknowledged result, then replay must return it without any
    // new effect.
    let result = serde_json::json!({"bucket_id": "bucket-stable-1", "created": true});
    let committed = store.finish_operation(op, result.clone()).await.unwrap();
    assert_eq!(committed.state, OperationState::Committed);
    assert_eq!(committed.result_json.as_ref(), Some(&result));

    let third = store.begin_operation(request(op, "create_bucket", serde_json::json!({"bucket": "bucket-test-1"})))
        .await
        .unwrap();
    let BeginOutcome::Replayed(record) = &third else {
        panic!("a completed operation must replay its result: {third:?}");
    };
    assert_eq!(record.state, OperationState::Committed);
    assert_eq!(record.result_json.as_ref(), Some(&result));
    store.close().await.unwrap();
}

#[tokio::test]
async fn operation_id_reuse_with_different_request_conflicts() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let op = OperationId::new();
    store
        .begin_operation(request(op, "create_bucket", serde_json::json!({"bucket": "a"})))
        .await
        .unwrap();
    let error = store
        .begin_operation(request(op, "create_bucket", serde_json::json!({"bucket": "b"})))
        .await
        .unwrap_err();
    assert!(
        matches!(error, StateError::OperationConflict { operation_id } if operation_id == op),
        "the same operation id with a different request must conflict, found {error:?}"
    );
    store.close().await.unwrap();
}

#[tokio::test]
async fn interrupted_external_operation_is_never_blindly_replayed() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let op = OperationId::new();
    let body = serde_json::json!({"put": "objects/1"});
    store.begin_operation(request(op, "put_object", body.clone())).await.unwrap();
    let dispatched = store.mark_dispatched(op).await.unwrap();
    assert_eq!(dispatched.state, OperationState::ExternalPending);

    // The effect may already exist remotely: listed for reconciliation and
    // refused as a replay.
    let pending = store.pending_external_operations().await.unwrap();
    assert!(pending.iter().any(|record| record.operation_id == op));

    let error = store.begin_operation(request(op, "put_object", body)).await.unwrap_err();
    assert!(
        matches!(error, StateError::OperationNotReplayable { state: OperationState::ExternalPending, .. }),
        "an uncertain external operation must not be replayed, found {error:?}"
    );

    // Reconciliation is explicit. Finding the effect commits the persisted
    // result; then replay answers from it.
    let result = serde_json::json!({"etag": "etag-1"});
    let committed = store
        .reconcile_operation(op, OperationResolution::EffectFound { result: result.clone() })
        .await
        .unwrap();
    assert_eq!(committed.state, OperationState::Committed);
    assert_eq!(committed.result_json.as_ref(), Some(&result));
    let replay = store.begin_operation(request(op, "put_object", serde_json::json!({"put": "objects/1"})))
        .await
        .unwrap();
    assert!(matches!(replay, BeginOutcome::Replayed(_)));
    store.close().await.unwrap();
}

#[tokio::test]
async fn failed_operations_require_explicit_resolution() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let op = OperationId::new();
    let body = serde_json::json!({"create": "prefix"});
    store.begin_operation(request(op, "create_prefix", body.clone())).await.unwrap();
    let failed = store.fail_operation(op, "permission_denied".to_owned()).await.unwrap();
    assert_eq!(failed.state, OperationState::Failed);
    assert_eq!(failed.error_code.as_deref(), Some("permission_denied"));

    let error = store.begin_operation(request(op, "create_prefix", body)).await.unwrap_err();
    assert!(
        matches!(error, StateError::OperationNotReplayable { state: OperationState::Failed, .. }),
        "found {error:?}"
    );

    // Proven absence allows one safe retry; then it behaves like fresh work.
    let retryable = store
        .reconcile_operation(op, OperationResolution::EffectAbsentSafeToRetry)
        .await
        .unwrap();
    assert_eq!(retryable.state, OperationState::Pending);
    store.mark_dispatched(op).await.unwrap();
    store.fail_operation(op, "network".to_owned()).await.unwrap();
    let abandoned = store
        .reconcile_operation(op, OperationResolution::GiveUp { reason: "run superseded".to_owned() })
        .await
        .unwrap();
    assert_eq!(abandoned.state, OperationState::Abandoned);

    // A second account-side replay after abandonment is refused, and
    // abandonment of an uncertain operation is refused while its external
    // effect is unknown.
    let op2 = OperationId::new();
    store.begin_operation(request(op2, "put_object", serde_json::json!({}))).await.unwrap();
    store.mark_dispatched(op2).await.unwrap();
    let error = store.abandon_operation(op2).await.unwrap_err();
    assert!(
        matches!(error, StateError::OperationNotMutable { state: OperationState::ExternalPending, .. }),
        "abandoning an uncertain external operation must be refused, found {error:?}"
    );
    store.close().await.unwrap();
}

#[tokio::test]
async fn reserve_setup_is_idempotent_and_conflict_checked() {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::open(StatePaths::new(tmp.path().to_path_buf())).await.unwrap();
    let key = account_key();
    store.record_account(account_record(key)).await.unwrap();

    let op = OperationId::new();
    let bound = binding(key);
    let draft = SetupDraft {
        operation_id: op,
        account_key: key,
        binding: bound.clone(),
        initialize: true,
    };
    let first = store.reserve_setup(draft.clone()).await.unwrap();
    let second = store.reserve_setup(draft).await.unwrap();
    assert_eq!(first.setup_id, second.setup_id, "the same operation yields the same setup");
    assert_eq!(first.connection_id, second.connection_id);
    assert_eq!(first.initialize, true);

    // Same operation id, different request: refused.
    let conflicting = SetupDraft {
        operation_id: op,
        account_key: key,
        binding: binding(key),
        initialize: true,
    };
    let error = store.reserve_setup(conflicting).await.unwrap_err();
    assert!(
        matches!(error, StateError::OperationConflict { .. }),
        "a different binding under the same operation id must conflict, found {error:?}"
    );

    // The immutable initialize flag is part of the fingerprint: flipping it
    // under the same binding and operation id also conflicts.
    let flipped = SetupDraft {
        operation_id: op,
        account_key: key,
        binding: bound,
        initialize: false,
    };
    assert!(matches!(
        store.reserve_setup(flipped).await.unwrap_err(),
        StateError::OperationConflict { .. }
    ));

    let found = store.get_setup_by_connection(first.connection_id).await.unwrap();
    assert_eq!(found.unwrap().setup_id, first.setup_id);
    store.close().await.unwrap();
}

#[tokio::test]
async fn probe_journal_reserves_before_create_and_scopes_cleanup() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let key = account_key();
    let store = StateStore::open(paths).await.unwrap();
    store.record_account(account_record(key)).await.unwrap();
    let account = store.open_account(key).await.unwrap();
    let draft = SetupDraft {
        operation_id: OperationId::new(),
        account_key: key,
        binding: binding(key),
        initialize: true,
    };
    let reservation = store.reserve_setup(draft).await.unwrap();
    let connection_id = reservation.connection_id;

    let run_a = GenerationId::new();
    let run_b = GenerationId::new();
    for (run, key_text) in [(run_a, "hfdrive/probe/k1"), (run_a, "hfdrive/probe/k2"), (run_b, "hfdrive/probe/k3")] {
        account
            .reserve_probe_key(ProbeKeyRecord::reserved(run, connection_id, Some(reservation.setup_id), key_text.to_owned()))
            .await
            .unwrap();
    }

    // k1's create effect is confirmed; k2's never happened.
    account
        .set_probe_key_state(connection_id, run_a, "hfdrive/probe/k1".to_owned(), ProbeKeyState::CreateInFlight)
        .await
        .unwrap();
    account
        .set_probe_key_state(connection_id, run_a, "hfdrive/probe/k1".to_owned(), ProbeKeyState::Created)
        .await
        .unwrap();
    account
        .set_probe_key_state(connection_id, run_a, "hfdrive/probe/k2".to_owned(), ProbeKeyState::NotCreated)
        .await
        .unwrap();

    let all = account.probe_keys(connection_id, run_a).await.unwrap();
    assert_eq!(all.len(), 2, "the run knows exactly its own keys");
    let cleanup = account.probe_cleanup_candidates(connection_id, run_a).await.unwrap();
    assert_eq!(cleanup.len(), 1);
    assert_eq!(cleanup[0].key, "hfdrive/probe/k1", "only confirmed-created keys are deletable");

    let other = account.probe_cleanup_candidates(connection_id, run_b).await.unwrap();
    assert!(other.is_empty(), "k3 is only reserved: cleanup of run B must not delete it");

    // Cross-run key leakage is impossible: run B must not see run A's keys.
    let b_keys = account.probe_keys(connection_id, run_b).await.unwrap();
    assert_eq!(b_keys.len(), 1);
    assert_eq!(b_keys[0].key, "hfdrive/probe/k3");
    store.close().await.unwrap();
}
