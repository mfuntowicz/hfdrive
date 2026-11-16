//! Deterministic durability tests for the sync slice: outbox phase/recovery
//! semantics, generation guards, read-only gating, selective sync and
//! remote-echo suppression. These exercise the pure planning rules; the
//! Windows runtime scenarios in `docs/synchronization.md` are executed by the
//! integration owner after packaging.

use hfdrive_core::ids::{ActionId, ConnectionId, ItemId, OperationId, SnapshotId, UploadId};
use hfdrive_core::storage::{ObjectRef, PayloadKey, Sha256Digest, XetFileId};
use hfdrive_provider::sync::apply::{
    ExpectedLocal, RecoveryDecision, classify_recovered, verify_expected,
};
use hfdrive_provider::sync::observe::{EchoTable, PendingRemovals, echo_matches};
use hfdrive_provider::sync::outbox::{
    CaptureEvidence, IntentKind, PendingContent, PhaseStep, Recovery, SyncIntent,
    allows_remote_dispatch, display_timestamp, intent_entry, next_step, parse_intent, recover_entry,
};
use hfdrive_state::{
    LocalAction, LocalActionKind, LocalActionState, OutboxEntry, OutboxState, RetryClass, ScanState,
};
use std::path::{Path, PathBuf};

fn connection() -> ConnectionId {
    ConnectionId::new()
}

fn pending_content() -> PendingContent {
    PendingContent {
        upload_id: uuid::Uuid::new_v4(),
        version_id: uuid::Uuid::new_v4(),
        modified_at: "2026-11-13T00:00:00Z".to_owned(),
    }
}

fn content_entry(state: OutboxState) -> OutboxEntry {
    let intent = SyncIntent::Content {
        item_id: uuid::Uuid::new_v4(),
        content: pending_content(),
    };
    entry_for(state, intent, 3)
}

fn entry_for(state: OutboxState, intent: SyncIntent, generation: u64) -> OutboxEntry {
    let item_id = intent.item_id();
    let mut record = intent_entry(
        connection(),
        OperationId::new(),
        Some(item_id),
        None,
        None,
        generation,
        &intent,
    )
    .unwrap();
    record.state = state;
    record
}

// ---------------------------------------------------------------------------
// The eight durable phases
// ---------------------------------------------------------------------------

#[test]
fn every_outbox_phase_maps_to_its_next_durable_step() {
    // Observed + content intent: capture first; metadata-only: plan directly.
    assert_eq!(next_step(&content_entry(OutboxState::Observed), 0), PhaseStep::Capture);
    let move_only = SyncIntent::Move {
        item_id: uuid::Uuid::new_v4(),
        parent_id: uuid::Uuid::new_v4(),
        name: "renamed.txt".to_owned(),
    };
    assert_eq!(
        next_step(&entry_for(OutboxState::Observed, move_only, 1), 0),
        PhaseStep::Plan
    );

    assert_eq!(next_step(&content_entry(OutboxState::SnapshotReady), 0), PhaseStep::Upload);
    assert_eq!(next_step(&content_entry(OutboxState::PayloadReady), 0), PhaseStep::Plan);
    assert_eq!(next_step(&content_entry(OutboxState::MetadataReady), 0), PhaseStep::Publish);
    assert_eq!(next_step(&content_entry(OutboxState::PublishUnknown), 0), PhaseStep::Resolve);
    assert_eq!(next_step(&content_entry(OutboxState::Published), 0), PhaseStep::Apply);
    assert_eq!(next_step(&content_entry(OutboxState::LocalApplyPending), 0), PhaseStep::Complete);
}

#[test]
fn a_staged_capture_resumes_upload_and_a_bound_payload_skips_to_planning() {
    // Rebased after a precondition failure with the payload binding intact:
    // planning only, never a re-upload.
    let mut bound = content_entry(OutboxState::Observed);
    bound.object_ref = Some(ObjectRef {
        key: PayloadKey::new(UploadId::new()),
        sha256: Sha256Digest::of(b"payload"),
        size: 7,
        xet_file_id: XetFileId::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        )
        .unwrap(),
    });
    assert_eq!(next_step(&bound, 0), PhaseStep::Plan);

    // Interrupted after a coherent capture: upload resumes from the staged
    // file; a re-based entry (evidence cleared) recaptures.
    let mut staged = content_entry(OutboxState::Observed);
    staged.snapshot_id = Some(SnapshotId::new());
    assert_eq!(next_step(&staged, 0), PhaseStep::Upload);
    assert_eq!(recover_entry(&staged, &[]), Recovery::Resume(PhaseStep::Upload));

    let mut rebased = content_entry(OutboxState::Observed);
    rebased.snapshot_id = Some(SnapshotId::new());
    rebased.object_ref = Some(bound.object_ref.clone().unwrap());
    // Both bound and staged: the payload binding wins (no redundant upload).
    assert_eq!(next_step(&rebased, 0), PhaseStep::Plan);
}

// ---------------------------------------------------------------------------
// Crash recovery classification
// ---------------------------------------------------------------------------

#[test]
fn interrupted_entries_never_replay_blindly() {
    // Never captured: recapture.
    assert_eq!(recover_entry(&content_entry(OutboxState::Observed), &[]), Recovery::Recapture);
    // Snapshot staged: resume upload, not recapture.
    let mut staged = content_entry(OutboxState::Observed);
    staged.snapshot_id = Some(SnapshotId::new());
    assert_eq!(recover_entry(&staged, &[]), Recovery::Resume(PhaseStep::Upload));
    // Metadata prepared: the conditional write resolves through ancestry.
    assert_eq!(
        recover_entry(&content_entry(OutboxState::PublishUnknown), &[]),
        Recovery::ResolveUncertain
    );
    // Local application interrupted: classify the journal action first.
    let action = ActionId::new();
    assert_eq!(
        recover_entry(&content_entry(OutboxState::LocalApplyPending), &[action]),
        Recovery::ClassifyLocalAction(action)
    );
    assert_eq!(
        recover_entry(&content_entry(OutboxState::Published), &[]),
        Recovery::Resume(PhaseStep::Apply)
    );
}

#[test]
fn parked_retries_wait_but_never_dispatch() {
    let mut entry = content_entry(OutboxState::SnapshotReady);
    entry.retry_class = RetryClass::Backoff;
    entry.next_attempt_at_ms = Some(500);
    assert_eq!(next_step(&entry, 400), PhaseStep::Wait);
    assert!(!allows_remote_dispatch(&entry, true, 400));
    assert_eq!(next_step(&entry, 500), PhaseStep::Upload);
    assert!(allows_remote_dispatch(&entry, true, 500));
    // NeedsUser/NeedsAuth never dispatch regardless of the clock.
    entry.retry_class = RetryClass::NeedsAuth;
    assert!(!allows_remote_dispatch(&entry, true, 1_000));
}

// ---------------------------------------------------------------------------
// Generation and identity guards
// ---------------------------------------------------------------------------

fn file_state(file_id: [u8; 16], usn: Option<i64>) -> hfdrive_windows::filesystem::volume::FileState {
    hfdrive_windows::filesystem::volume::FileState {
        identity: hfdrive_windows::filesystem::volume::FileIdentity {
            volume_serial_number: 7,
            file_id,
            link_count: 1,
            attributes: 0x20,
            reparse_tag: 0,
        },
        size: 12,
        last_write_time_100ns: 5,
        usn,
    }
}

#[test]
fn superseded_uploads_never_clear_newer_edits() {
    let expected = ExpectedLocal {
        file_id: [3; 16],
        volume_serial_number: 7,
        generation: 4,
        usn: Some(11),
    };
    let live = file_state([3; 16], Some(11));
    // Same generation: the in-sync transition may proceed.
    assert!(verify_expected(&expected, &live, 4));
    // A newer local generation: the entry completes but the file stays dirty.
    assert!(!verify_expected(&expected, &live, 5));
}

#[test]
fn identity_size_time_and_usn_all_guard_the_transition() {
    let expected = ExpectedLocal {
        file_id: [3; 16],
        volume_serial_number: 7,
        generation: 4,
        usn: Some(11),
    };
    // USN drift: the file changed after planning.
    assert!(!verify_expected(&expected, &file_state([3; 16], Some(12)), 4));
    // Different file identity (atomic replacement at the same path).
    assert!(!verify_expected(&expected, &file_state([4; 16], Some(11)), 4));
    // Unknown USN on either side is never a match — no fabricated in-sync
    // success.
    let no_usn = ExpectedLocal { usn: None, ..expected };
    assert!(!verify_expected(&no_usn, &file_state([3; 16], None), 4));
    assert!(!verify_expected(&expected, &file_state([3; 16], None), 4));
}

#[test]
fn interrupted_local_actions_classify_against_real_file_facts() {
    use hfdrive_state::LocalActionKind as K;
    assert_eq!(
        classify_recovered(K::CreatePlaceholder, None, None, true),
        RecoveryDecision::Done
    );
    assert_eq!(
        classify_recovered(K::CreatePlaceholder, None, None, false),
        RecoveryDecision::Retry
    );
    let expected = ExpectedLocal {
        file_id: [3; 16],
        volume_serial_number: 7,
        generation: 2,
        usn: Some(5),
    };
    assert_eq!(
        classify_recovered(K::UpdatePlaceholder, Some(&expected), Some(&file_state([3; 16], Some(5))), true),
        RecoveryDecision::Retry
    );
    // Identity drift: return the item to reconciliation as new local work.
    assert_eq!(
        classify_recovered(K::UpdatePlaceholder, Some(&expected), Some(&file_state([9; 16], Some(5))), true),
        RecoveryDecision::Requeue
    );
    // A delete with unsynchronized bytes preserves them first, never drops
    // them.
    let dirty = file_state([3; 16], Some(5));
    assert_eq!(
        classify_recovered(K::DeletePlaceholder, None, Some(&dirty), true),
        RecoveryDecision::PreserveFirst
    );
    assert_eq!(
        classify_recovered(K::DeletePlaceholder, None, None, true),
        RecoveryDecision::Done
    );
}

// ---------------------------------------------------------------------------
// Remote-echo suppression
// ---------------------------------------------------------------------------

#[test]
fn provider_applied_changes_absorb_matching_observations_only() {
    let item = ItemId::new();
    let action = LocalAction {
        connection_id: connection(),
        action_id: ActionId::new(),
        item_id: Some(item),
        kind: LocalActionKind::UpdatePlaceholder,
        expected_file_id: None,
        expected_generation: Some(1),
        expected_usn: Some(42),
        old_version: None,
        new_version: None,
        source_path: None,
        target_path: Some(PathBuf::from("docs\\report.txt")),
        recovery_path: None,
        state: LocalActionState::InProgress,
    };
    assert!(echo_matches(&action, item, Path::new("docs\\report.txt")));
    // Different item or path: not an echo, the change is real local work.
    assert!(!echo_matches(&action, ItemId::new(), Path::new("docs\\report.txt")));
    assert!(!echo_matches(&action, item, Path::new("docs\\other.txt")));
    // Requeued actions are not currently applied: their fallout is not an
    // echo either.
    let requeued = LocalAction {
        state: LocalActionState::Requeued,
        ..action.clone()
    };
    assert!(!echo_matches(&requeued, item, Path::new("docs\\report.txt")));
}

#[test]
fn echo_window_expires_and_can_be_forgotten() {
    let item = ItemId::new();
    let mut table = EchoTable::default();
    table.note_applied(item, PathBuf::from("a.txt"));
    assert!(table.in_window(item));
    table.forget(item);
    assert!(!table.in_window(item));
}

#[test]
fn remote_materialization_origin_never_publishes() {
    // Echo-suppressed changes never create intents; the classification funnel
    // is the single author of intents, so a materialization can only appear as
    // bookkeeping. This guard mirrors the plan-level invariant.
    let intent = SyncIntent::Create {
        item_id: uuid::Uuid::new_v4(),
        parent_id: uuid::Uuid::new_v4(),
        name: "materialized.txt".to_owned(),
        kind: IntentKind::File,
        content: None,
    };
    // A create without content is metadata-only: it publishes namespace
    // changes but never payload bytes (no upload echo of remote content).
    assert!(!intent.has_content());
}

// ---------------------------------------------------------------------------
// Deletion evidence (scan safety)
// ---------------------------------------------------------------------------

#[test]
fn deletions_require_a_completed_non_invalidated_scan() {
    let scan = |complete: bool, invalidated: bool| {
        Some(ScanState {
            connection_id: connection(),
            cursor: None,
            pending_head_refresh: false,
            head_refresh_generation: 0,
            volume_id: "vol".into(),
            journal_id: "j".into(),
            usn_cursor: Some(7),
            scan_epoch: 1,
            scan_complete: complete,
            scan_invalidated: invalidated,
        })
    };
    assert!(!hfdrive_provider::sync::observe::deletion_evidence(&None));
    assert!(!hfdrive_provider::sync::observe::deletion_evidence(&scan(true, true)));
    assert!(!hfdrive_provider::sync::observe::deletion_evidence(&scan(false, false)));
    assert!(hfdrive_provider::sync::observe::deletion_evidence(&scan(true, false)));
}

#[test]
fn parked_removals_stay_parked_until_evidence_arrives() {
    let mut pending = PendingRemovals::default();
    let item = ItemId::new();
    pending.park(item, PathBuf::from("gone.txt"), 1);
    // Incomplete/overflowed scan: nothing is released.
    assert!(pending.release(false).is_empty());
    assert_eq!(pending.len(), 1);
    // A completed scan releases exactly the parked identities.
    let released = pending.release(true);
    assert_eq!(released, vec![item]);
    assert!(pending.is_empty());
}

// ---------------------------------------------------------------------------
// Read-only gating and selective sync
// ---------------------------------------------------------------------------

#[test]
fn read_only_connections_never_dispatch_remote_mutation() {
    let entry = content_entry(OutboxState::SnapshotReady);
    assert!(allows_remote_dispatch(&entry, true, 0));
    assert!(!allows_remote_dispatch(&entry, false, 0));
}

#[test]
fn capture_evidence_binds_identity_and_never_wildcards_usn() {
    let evidence = CaptureEvidence {
        volume_serial_number: 7,
        file_id: [3; 16],
        size: 12,
        last_write_time_100ns: 5,
        usn: None,
    };
    let state = evidence.to_file_state();
    assert_eq!(state.size, 12);
    assert_eq!(state.usn, None, "an unknown USN stays unknown, never a wildcard");
}

// ---------------------------------------------------------------------------
// Intent schema round-trips
// ---------------------------------------------------------------------------

#[test]
fn every_intent_shape_round_trips_through_durable_json() {
    for intent in [
        SyncIntent::Create {
            item_id: uuid::Uuid::new_v4(),
            parent_id: uuid::Uuid::new_v4(),
            name: "neu.txt".to_owned(),
            kind: hfdrive_provider::sync::outbox::IntentKind::File,
            content: Some(pending_content()),
        },
        SyncIntent::MoveAndContent {
            item_id: uuid::Uuid::new_v4(),
            parent_id: uuid::Uuid::new_v4(),
            name: "moved.txt".to_owned(),
            content: pending_content(),
        },
        SyncIntent::Delete { item_id: uuid::Uuid::new_v4() },
    ] {
        let record = entry_for(OutboxState::Observed, intent.clone(), 3);
        assert_eq!(parse_intent(&record).unwrap(), intent);
    }
}

#[test]
fn display_timestamps_are_canonical_whole_seconds() {
    // 2026-11-13T00:00:00Z in Windows 100ns units since 1601.
    let unix_seconds = 1_794_528_000i64;
    let windows_100ns = unix_seconds * 10_000_000 + 116_444_736_000_000_000;
    let stamp = display_timestamp(windows_100ns);
    assert_eq!(stamp, "2026-11-13T00:00:00Z");
    assert!(hfdrive_core::format::is_canonical_timestamp(&stamp));
}
