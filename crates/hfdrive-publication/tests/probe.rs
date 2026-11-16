//! Capability-probe tests: exact-key journaling before every effect, owned
//! cleanup of provably-created keys only, interrupted-run resume, and the
//! read-only mode that requires no S3 keys and runs no write probe.

mod common;

use std::sync::Arc;

use common::*;
use hfdrive_core::ids::{ConnectionId, GenerationId, WorkspaceId};
use hfdrive_core::storage::RemotePrefix;
use hfdrive_hf::wire_budget::{BudgetConfig, WireBudget};
use hfdrive_protocol::ProbeOutcome;
use hfdrive_publication::probe::{
    CapabilityProbe, ProbeMode, ProbeRequest, ProbeTransport,
};
use hfdrive_publication::transport::ProbeKey;
use hfdrive_publication::PublicationError;
use hfdrive_state::ProbeKeyState;
use tokio_util::sync::CancellationToken;

fn probe_setup() -> (
    Arc<std::sync::Mutex<Remote>>,
    CapabilityProbe<FixtureJournal, FixtureNative, FixtureProbeTransport>,
    FixtureJournal,
    ProbeRequest,
    tempfile::TempDir,
) {
    let remote = Remote::new();
    let run_id = GenerationId::new();
    let mut drive = drive_binding();
    drive.prefix = RemotePrefix::new(format!("hfdrive-probe/{}", run_id.as_uuid())).unwrap();
    drive.workspace_id = WorkspaceId::new();
    let native = FixtureNative::with_drive(remote.clone(), drive);
    let transport = FixtureProbeTransport::new(remote.clone(), run_id);
    let journal = FixtureJournal::default();
    let probe = CapabilityProbe::new(
        journal.clone(),
        native,
        transport,
        WireBudget::new(BudgetConfig::default()),
    );
    let staging = tempfile::tempdir().unwrap();
    let request = ProbeRequest {
        run_id,
        connection_id: ConnectionId::new(),
        setup_id: None,
        mode: ProbeMode::Full,
        staging_dir: staging.path().to_owned(),
    };
    (remote, probe, journal, request, staging)
}

#[tokio::test]
async fn full_probe_measures_every_dimension_and_cleans_up_only_owned_keys() {
    let (remote, probe, journal, request, _staging) = probe_setup();
    let cancel = CancellationToken::new();

    let report = probe.run(&request, &cancel).await.unwrap();
    assert_eq!(report.checks.len(), 8, "every dimension is reported exactly once");
    for check in &report.checks {
        assert_eq!(
            check.outcome,
            ProbeOutcome::Passed,
            "dimension {:?} must pass against exact fixture semantics: {check:?}",
            check.kind
        );
    }
    assert!(report.all_passed());
    assert!(report.capabilities.native_write);
    assert!(report.capabilities.xet_upload);
    assert!(report.capabilities.xet_range);
    assert!(report.capabilities.s3_read);
    assert!(report.capabilities.conditional_create);
    assert!(report.capabilities.conditional_replace);
    assert!(report.capabilities.strong_etag);
    assert!(!report.capabilities.read_only);
    assert!(report.wire_bytes.is_some());

    // Cleanup deleted exactly the keys this run created, and every journal row
    // ended `Deleted`.
    assert!(!report.cleanup.deleted.is_empty());
    assert!(report.cleanup.retained.is_empty());
    assert_eq!(report.cleanup.deleted.len(), report.created_keys.len());
    for key in &report.cleanup.deleted {
        assert!(
            key.starts_with(&format!("hfdrive-probe/{}/", request.run_id.as_uuid())),
            "cleanup may touch only this run's namespace: {key}"
        );
    }
    for (key, state) in journal.states() {
        assert_eq!(state, ProbeKeyState::Deleted, "key {key} must end deleted");
    }
    let prefix = format!("hfdrive-probe/{}/", request.run_id.as_uuid());
    let remaining: Vec<String> = {
        let remote = remote.lock().unwrap();
        remote.keys_owned().filter(|key| key.starts_with(&prefix)).collect()
    };
    assert!(remaining.is_empty(), "the run's remote keys are gone: {remaining:?}");
}

#[tokio::test]
async fn mismatched_native_namespace_cannot_write_to_a_drive_or_another_probe() {
    for prefix in [
        "hfdrive/work".to_owned(),
        format!("hfdrive-probe/{}", GenerationId::new().as_uuid()),
    ] {
        let remote = Remote::new();
        let mut drive = drive_binding();
        drive.prefix = RemotePrefix::new(prefix).unwrap();
        let existing_key = drive.prefix.head_key().to_string();
        let existing_bytes = b"preexisting remote content".to_vec();
        remote.lock().unwrap().seed(&existing_key, existing_bytes.clone());

        let run_id = GenerationId::new();
        let journal = FixtureJournal::default();
        let probe = CapabilityProbe::new(
            journal.clone(),
            FixtureNative::with_drive(remote.clone(), drive),
            FixtureProbeTransport::new(remote.clone(), run_id),
            WireBudget::new(BudgetConfig::default()),
        );
        let staging = tempfile::tempdir().unwrap();
        let request = ProbeRequest {
            run_id,
            connection_id: ConnectionId::new(),
            setup_id: None,
            mode: ProbeMode::Full,
            staging_dir: staging.path().to_owned(),
        };

        assert!(matches!(
            probe.run(&request, &CancellationToken::new()).await,
            Err(hfdrive_publication::probe::ProbeError::Publication(PublicationError::KeyOutOfScope))
        ));
        assert!(journal.states().is_empty(), "a rejected scope must not reserve remote effects");
        let remote = remote.lock().unwrap();
        assert_eq!(remote.bytes(&existing_key), Some(existing_bytes));
        assert_eq!(remote.keys_owned().collect::<Vec<_>>(), vec![existing_key]);
    }
}

#[tokio::test]
async fn interrupted_probe_resumes_reconciles_and_cleans_up() {
    let (remote, probe, journal, request, _staging) = probe_setup();
    let cancel = CancellationToken::new();

    // Fail the first native upload: its key stays `CreateInFlight` (the effect
    // is uncertain only for ambiguous failures; this one is definite) — the
    // run aborts with every partial effect preserved in the journal.
    remote.lock().unwrap().fail_next_upload = true;
    let error = probe.run(&request, &cancel).await.unwrap_err();
    assert!(matches!(error, hfdrive_publication::probe::ProbeError::Native(_)));
    let states = journal.states();
    assert_eq!(states.len(), 1, "exactly the payload key was reserved");
    assert!(states[0].0.starts_with(&format!("hfdrive-probe/{}/objects/", request.run_id.as_uuid())));

    // Resume with the same run id: the interrupted key is reconciled against
    // observed absence and marked `NotCreated`; the fresh run completes.
    let report = probe.run(&request, &cancel).await.unwrap();
    assert!(report.resumed);
    assert!(report.all_passed(), "{:?}", report.checks);
    let states = journal.states();
    let reconciled = states
        .iter()
        .find(|(key, _)| key.starts_with(&format!("hfdrive-probe/{}/objects/", request.run_id.as_uuid()))
            && !report.created_keys.contains(key))
        .expect("the interrupted key is still journaled");
    assert_eq!(reconciled.1, ProbeKeyState::NotCreated, "the aborted upload was absent");
    for key in &report.created_keys {
        assert_eq!(
            journal
                .states()
                .iter()
                .find(|(row, _)| row == key)
                .map(|(_, state)| *state),
            Some(ProbeKeyState::Deleted)
        );
    }

    // Cleanup is idempotent: nothing further to delete.
    let again = probe.cleanup(&request, &cancel).await.unwrap();
    assert!(again.deleted.is_empty());
    assert!(again.retained.is_empty());
}

#[tokio::test]
async fn read_only_probe_requires_no_s3_keys_and_runs_no_write_dimension() {
    let (remote, probe, journal, mut request, _staging) = probe_setup();
    request.mode = ProbeMode::ReadOnly;
    let cancel = CancellationToken::new();

    let report = probe.run(&request, &cancel).await.unwrap();
    assert_eq!(report.checks.len(), 8);
    for check in &report.checks {
        assert_eq!(check.outcome, ProbeOutcome::NotRun, "{check:?}");
        let detail = check.detail.as_deref().unwrap_or_default();
        assert!(detail.contains("read-only"), "the reason must be explicit: {detail}");
    }
    assert!(report.capabilities.read_only);
    assert!(!report.capabilities.native_write);
    assert!(report.created_keys.is_empty());
    assert!(journal.states().is_empty(), "no key is journaled without a write probe");

    // No S3 or native payload traffic happened at all.
    let remote = remote.lock().unwrap();
    assert_eq!(remote.s3_reads, 0);
    assert_eq!(remote.s3_writes, 0);
    assert!(!remote.keys_owned().next().is_some(), "the remote is untouched");
}

#[tokio::test]
async fn probe_transport_refuses_foreign_run_keys() {
    let remote = Remote::new();
    let run_id = GenerationId::new();
    let transport = FixtureProbeTransport::new(remote.clone(), run_id);
    let cancel = CancellationToken::new();
    let lease = common::lease();
    let foreign = ProbeKey::new(GenerationId::new().as_uuid().clone(), "record").unwrap();
    let body = hfdrive_publication::transport::ProbeRecord::new(b"x".to_vec()).unwrap();
    assert!(matches!(
        ProbeTransport::create(&transport, &lease, &foreign, body, &cancel).await,
        Err(PublicationError::KeyOutOfScope)
    ));
    assert!(matches!(
        ProbeTransport::delete_owned(&transport, &lease, &[foreign], &cancel).await,
        Err(PublicationError::KeyOutOfScope)
    ));
    assert!(remote.lock().unwrap().keys_owned().next().is_none());
}
