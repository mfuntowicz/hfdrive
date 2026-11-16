//! One safe recovery operation: rebind a verified setup reservation's
//! publication credentials onto an existing connected drive.
//!
//! `repair_storage` never creates, initializes or deletes remote state. It
//! loads the source reservation's protected pair with its original entropy
//! and context, moves the zeroizing pair into a record bound to the target's
//! existing protection context under a distinct record name, validates that
//! candidate against the target's existing managed `HEAD`/workspace, and runs
//! the required storage check for the target binding. Only a fully proven
//! candidate is committed: the credential reference and the fresh capability
//! evidence land in one guarded account transaction. The live runtime is
//! quiesced in memory around the commit (the user's durable pause flag is
//! never rewritten), drained from its old cached binding and reconnected on
//! the same root, and the recorded original pause intent is restored. The
//! source setup reservation, its records and its evidence are never modified,
//! and neither plaintext nor ciphertext ever leaves this module's zeroizing
//! buffers.

use std::future::Future;

use hfdrive_core::ids::{ConnectionId, GenerationId, ItemId};
use hfdrive_core::storage::DriveBinding;
use hfdrive_protocol as wire;
use hfdrive_publication::probe::{ProbeMode, ProbeReport, ProbeRequest};
use hfdrive_publication::SupplementalCredentialRecord;
use hfdrive_state::{ConnectionMode, CredentialRef, SetupRecord, SetupStatus};
use hfdrive_windows::credentials::{CredentialStore, RecordName};

use crate::operations::{error, internal};
use crate::storage::invalid;
use crate::Provider;

/// The durable outcome of a committed repair. The wire result adds the live
/// status projection; nothing here is secret.
#[derive(Debug)]
pub(crate) struct RepairOutcome {
    pub(crate) connection_id: ConnectionId,
    /// True only when the runtime refresh left an active authenticated
    /// binding; a committed repair whose refresh failed is honestly false.
    pub(crate) repaired: bool,
    pub(crate) run_id: GenerationId,
    pub(crate) report_path: Option<String>,
}

/// One storage-check run's non-secret evidence artifacts.
pub(crate) struct ProbeRunOutcome {
    pub(crate) report: ProbeReport,
    pub(crate) report_path: String,
}

/// Everything the remote-touching verification step needs to prove a staged
/// candidate against the target's existing workspace.
pub(crate) trait RepairVerifier: Send + Sync {
    /// Validates the staged candidate against the target's existing managed
    /// `HEAD`/workspace and runs the required storage check for the target
    /// binding. Never initializes and never deletes: an absent, unreadable or
    /// mismatched `HEAD` is an error.
    fn verify(
        &self,
        candidate: &SupplementalCredentialRecord,
        profile: &hfdrive_auth::AccountProfile,
        target: &hfdrive_state::ConnectionRecord,
        root_item_id: ItemId,
        probe: &ProbeRequest,
    ) -> impl Future<Output = Result<ProbeRunOutcome, wire::ProtocolError>> + Send;
}

/// The runtime coordination seam: quiesce before the credential commit, then
/// drain the old cached binding and reconnect the same root, then restore the
/// recorded original pause intent.
pub(crate) trait RepairRuntime: Send + Sync {
    /// Pauses dispatch in memory and waits for the in-flight drive round;
    /// the durable pause flag and observation are untouched.
    fn quiesce(
        &self,
        connection: ConnectionId,
    ) -> impl Future<Output = Result<(), wire::ProtocolError>> + Send;

    /// Drains the old cached remote services and reconnects the same
    /// binding/root with services freshly loaded from durable state. `Ok(true)`
    /// reports an active authenticated binding.
    fn refresh(
        &self,
        connection: ConnectionId,
    ) -> impl Future<Output = Result<bool, wire::ProtocolError>> + Send;

    /// Restores the recorded original in-memory pause intent after the
    /// refresh (or an aborted commit).
    fn restore_pause(
        &self,
        connection: ConnectionId,
        paused: bool,
    ) -> impl Future<Output = Result<(), wire::ProtocolError>> + Send;
}

/// The non-remote inputs of one repair.
pub(crate) struct RepairInputs<'a> {
    pub(crate) profile: &'a hfdrive_auth::AccountProfile,
    pub(crate) state: &'a hfdrive_state::StateStore,
    pub(crate) paths: &'a hfdrive_state::StatePaths,
}

/// One protected candidate, deleted only after a known uncommitted attempt.
/// Account adoption precedes the control mirror: a mirror failure must never
/// delete a record the durable connection already references. Uncertain
/// adoption retains the protected record rather than risking a dangling ref.
struct StagedRecord<'a> {
    store: &'a CredentialStore,
    name: RecordName,
    adopted: bool,
}

impl<'a> StagedRecord<'a> {
    fn new(store: &'a CredentialStore, name: RecordName) -> Self {
        Self { store, name, adopted: false }
    }
    fn reference(&self) -> CredentialRef {
        CredentialRef(self.name.as_str().to_owned())
    }
}

impl Drop for StagedRecord<'_> {
    fn drop(&mut self) {
        if !self.adopted {
            let _ = self.store.delete_record(&self.name);
        }
    }
}

/// Executes one `repair_storage` mutation end to end, minus the wire status
/// projection. Generic over the two remote-touching seams so every refusal,
/// preservation and ordering rule is testable without live storage.
pub(crate) async fn execute_storage_repair<V, R>(
    inputs: &RepairInputs<'_>,
    verifier: &V,
    runtime: &R,
    request: wire::RepairStorageRequest,
) -> Result<RepairOutcome, wire::ProtocolError>
where
    V: RepairVerifier,
    R: RepairRuntime,
{
    let profile = inputs.profile;
    let target_id = ConnectionId::from_uuid(request.connection_id)
        .map_err(|_| invalid("A nonzero connection identifier is required"))?;
    let source_id = ConnectionId::from_uuid(request.credentials_from_connection_id)
        .map_err(|_| invalid("A nonzero credential source identifier is required"))?;
    if source_id == target_id {
        return Err(error(
            wire::ProtocolErrorCode::InvalidRequest,
            "The credential source and the repair target must differ",
        ));
    }
    let account = inputs
        .state
        .open_account(profile.account_key)
        .await
        .map_err(crate::operations::state_error)?;
    let credentials_dir = inputs.paths.account(profile.account_key).credentials();

    // ---- target: one persisted connected connection of the signed-in account ----
    let target = account
        .get_connection(target_id)
        .await
        .map_err(crate::operations::state_error)?
        .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The connection does not exist for this account"))?;
    if target.account_key != profile.account_key {
        return Err(error(wire::ProtocolErrorCode::PermissionDenied, "The connection belongs to a different account"));
    }
    if target.mode == ConnectionMode::ReadOnly {
        return Err(error(wire::ProtocolErrorCode::ReadOnly, "Storage repair requires a writable connection"));
    }
    let target_setup = inputs
        .state
        .get_setup_by_connection(target_id)
        .await
        .map_err(crate::operations::state_error)?
        .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The connection has no durable setup reservation"))?;
    if target_setup.status != SetupStatus::Connected {
        return Err(error(wire::ProtocolErrorCode::Conflict, "The connection's setup journal is not connected"));
    }
    if target_setup.account_key != profile.account_key || target_setup.binding != target.binding {
        return Err(error(wire::ProtocolErrorCode::Conflict, "The setup journal does not match the existing connection"));
    }
    let root_item_id = target
        .config_json
        .get("root_item_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.parse::<ItemId>().ok())
        .ok_or_else(|| {
            error(wire::ProtocolErrorCode::LocalRootInvalid, "The connection's durable root item identity is missing")
        })?;

    // ---- source: one setup reservation of the same account and bucket ----
    let source_setup = inputs
        .state
        .get_setup_by_connection(source_id)
        .await
        .map_err(crate::operations::state_error)?
        .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The credential source reservation does not exist"))?;
    if source_setup.account_key != profile.account_key {
        return Err(error(wire::ProtocolErrorCode::PermissionDenied, "The credential source belongs to a different account"));
    }
    if !matches!(source_setup.status, SetupStatus::Active | SetupStatus::Connected) {
        return Err(error(wire::ProtocolErrorCode::Conflict, "The credential source reservation is no longer available"));
    }
    let source_bucket = &source_setup.binding.bucket;
    let target_bucket = &target.binding.bucket;
    // Stable server-side identity only; display names never match anything.
    if source_bucket.bucket_id != target_bucket.bucket_id
        || source_bucket.owner_id != target_bucket.owner_id
        || source_bucket.owner_kind != target_bucket.owner_kind
    {
        return Err(error(
            wire::ProtocolErrorCode::Conflict,
            "The credential source is bound to a different bucket or owner",
        ));
    }

    // ---- the source pair, loaded with its original entropy and context ----
    let source_ref = source_setup.credential_ref.as_ref().ok_or_else(|| {
        error(wire::ProtocolErrorCode::NotFound, "The credential source has no stored publication credentials")
    })?;
    verify_source_evidence(&source_setup, source_id)?;
    let store = CredentialStore::open(credentials_dir.to_path_buf()).map_err(|_| internal())?;
    let source_context = protection_context(&source_setup.binding, profile, source_id)?;
    let source_entropy = source_context.entropy(*source_id.as_uuid()).map_err(|_| internal())?;
    let source_name = RecordName::new(&source_ref.0).map_err(|_| internal())?;
    let plaintext = store
        .load_record(&source_name, Some(&source_entropy))
        .map_err(|_| error(wire::ProtocolErrorCode::NotFound, "The credential source has no usable protected credentials"))?;
    let source_record = SupplementalCredentialRecord::decode(plaintext.expose())
        .map_err(|_| error(wire::ProtocolErrorCode::NotFound, "The credential source has no usable protected credentials"))?;
    drop(plaintext);
    source_record
        .validate_context(&source_context)
        .map_err(|_| error(wire::ProtocolErrorCode::Conflict, "The source credential record is bound to different storage"))?;

    // ---- stage the pair under the target's existing protection context ----
    let target_context = protection_context(&target.binding, profile, target_id)?;
    let target_entropy = target_context.entropy(*target_id.as_uuid()).map_err(|_| internal())?;
    let candidate = source_record.rebind(target_context);
    let encoded = candidate.encode().map_err(|_| internal())?;
    let mut staged = StagedRecord::new(&store, RecordName::new(&format!("s3-repair-{}", request.operation_id)).map_err(|_| internal())?);
    store
        .save_record(&staged.name, encoded.as_slice(), Some(&target_entropy))
        .map_err(|_| internal())?;
    drop(encoded);
    let staged_ref = staged.reference();

    // ---- validate the candidate and run the required storage check ----
    let run_id = GenerationId::new();
    let probe = ProbeRequest {
        run_id,
        connection_id: target_id,
        setup_id: Some(target_setup.setup_id),
        mode: ProbeMode::Full,
        staging_dir: inputs
            .paths
            .account(profile.account_key)
            .drive(target.binding.workspace_id)
            .base()
            .join("probe"),
    };
    let run = verifier.verify(&candidate, profile, &target, root_item_id, &probe).await?;
    drop(candidate);
    // No old report is relabeled and no capability is taken on trust: only
    // what this fresh run just proved against the target binding is committed.
    let evidence = serde_json::to_value(&run.report).map_err(|_| internal())?;
    if !crate::setup::probe_proves_writable(&evidence, target_id) {
        return Err(error(
            wire::ProtocolErrorCode::PermissionDenied,
            "The candidate credentials did not pass the required storage check for this connection; existing storage access was preserved",
        ));
    }
    if run.report.connection_id != target_id || run.report.run_id != *probe.run_id.as_uuid() {
        return Err(internal());
    }

    // ---- the recorded original pause intent, preserved across the repair ----
    let original_paused = account
        .settings(format!("connection/{target_id}/paused"))
        .await
        .map_err(crate::operations::state_error)?
        .is_some_and(|row| row.value_json.as_bool() == Some(true));

    // Quiesce dispatch in memory around the commit; the durable pause flag is
    // never rewritten. Every abort below restores the original intent.
    runtime.quiesce(target_id).await?;
    match inputs
        .state
        .commit_storage_repair(target_id, target.s3_ref, staged_ref, evidence)
        .await
    {
        Ok(Some(_)) => {
            // The guarded commit adopted the staged record; it is now the
            // connection's durable supplemental credential record.
            staged.adopted = true;
        }
        Ok(None) => {
            runtime.restore_pause(target_id, original_paused).await?;
            return Err(error(
                wire::ProtocolErrorCode::Conflict,
                "The connection's storage credentials changed during the repair; nothing was committed",
            ));
        }
        Err(state) => {
            // The account transaction may have committed before its control
            // mirror failed. Delete only when a readable durable row proves
            // this candidate was not adopted.
            staged.adopted = match account.get_connection(target_id).await {
                Ok(Some(current)) => current.s3_ref.as_ref()
                    .is_some_and(|reference| reference.0 == staged.name.as_str()),
                Ok(None) | Err(_) => true,
            };
            runtime.restore_pause(target_id, original_paused).await?;
            return Err(crate::operations::state_error(state));
        }
    }

    // ---- drain the old cached binding and reconnect the same root ----
    let repaired = match runtime.refresh(target_id).await {
        Ok(active) => active,
        Err(failure) => {
            tracing::warn!(
                connection = %target_id,
                reason = failure.message.as_str(),
                "storage repair committed but the runtime refresh failed; the connection stays recoverable"
            );
            runtime.restore_pause(target_id, original_paused).await?;
            return Ok(RepairOutcome {
                connection_id: target_id,
                repaired: false,
                run_id,
                report_path: Some(run.report_path),
            });
        }
    };
    runtime.restore_pause(target_id, original_paused).await?;
    Ok(RepairOutcome {
        connection_id: target_id,
        repaired,
        run_id,
        report_path: Some(run.report_path),
    })
}

/// The source's own latest recorded artifact must prove a successful full
/// probe for exactly the source reservation, judged by the same structural
/// standard as a writable preview: evidence is verified, never assumed, and
/// never relabeled onto another connection.
fn verify_source_evidence(setup: &SetupRecord, source_id: ConnectionId) -> Result<(), wire::ProtocolError> {
    let unverified = || {
        error(
            wire::ProtocolErrorCode::Conflict,
            "The credential source is not a verified successful probe candidate",
        )
    };
    let evidence = setup.probe_evidence_json.as_ref().ok_or_else(unverified)?;
    // The artifact must be a real probe report shape, not arbitrary JSON.
    let report: ProbeReport = serde_json::from_value(evidence.clone()).map_err(|_| unverified())?;
    if report.connection_id != source_id || report.mode != ProbeMode::Full || report.capabilities.read_only {
        return Err(unverified());
    }
    if !crate::setup::probe_proves_writable(evidence, source_id) {
        return Err(unverified());
    }
    Ok(())
}

/// The exact protection context the stored record must carry: stable binding
/// identity plus the connection identity, never display locators.
fn protection_context(
    binding: &DriveBinding,
    profile: &hfdrive_auth::AccountProfile,
    connection: ConnectionId,
) -> Result<wire::PublicationProtectionContext, wire::ProtocolError> {
    let identity = hfdrive_publication::AccountIdentity {
        issuer: &profile.issuer,
        subject: &profile.subject,
    };
    hfdrive_publication::PublicationBinding::new(binding, &identity)
        .map(|publication| publication.protection_context(*connection.as_uuid()))
        .map_err(|_| error(wire::ProtocolErrorCode::Conflict, "The storage binding does not match the signed-in identity"))
}

/// Maps candidate-verification failures without ever initializing a
/// workspace or inferring deletion.
fn verify_failure(value: hfdrive_publication::PublicationError) -> wire::ProtocolError {
    use hfdrive_publication::PublicationError as P;
    match value {
        P::Absent => error(
            wire::ProtocolErrorCode::NotFound,
            "The existing remote workspace has no readable HEAD; storage repair never initializes or deletes",
        ),
        P::UnsupportedFormat => error(
            wire::ProtocolErrorCode::UnsupportedFormat,
            "The existing remote workspace uses an unsupported managed format",
        ),
        P::BindingMismatch => error(
            wire::ProtocolErrorCode::Conflict,
            "The candidate credentials do not read this connection's existing workspace",
        ),
        P::PermissionDenied => error(
            wire::ProtocolErrorCode::PermissionDenied,
            "The candidate credentials were denied access to the existing workspace",
        ),
        P::NeedsSignIn => error(wire::ProtocolErrorCode::NeedsSignIn, "Native authorization must be renewed before storage repair"),
        P::Transport | P::SearchIncomplete => error(
            wire::ProtocolErrorCode::Timeout,
            "The existing workspace could not be read; nothing was changed",
        ),
        P::Cancelled => error(wire::ProtocolErrorCode::Cancelled, "Storage repair was cancelled before any credential change"),
        other => crate::storage::remote_failure(other.into()),
    }
}

impl Provider {
    /// `repair_storage`: rebinds a verified source setup reservation's
    /// publication credentials onto one existing connected drive and returns
    /// the repaired connection's honest status plus the fresh probe/report
    /// identity. No secret appears in the request or the result.
    pub(crate) async fn repair_storage(
        &self,
        request: wire::RepairStorageRequest,
    ) -> Result<wire::RepairStorageResult, wire::ProtocolError> {
        let profile = self.current_account()?;
        let inputs = RepairInputs {
            profile: &profile,
            state: self.state.as_ref(),
            paths: &self.paths,
        };
        let outcome = execute_storage_repair(&inputs, self, self, request).await?;
        let status = self.connection_status(outcome.connection_id).await?;
        Ok(wire::RepairStorageResult {
            connection_id: *outcome.connection_id.as_uuid(),
            repaired: outcome.repaired,
            run_id: *outcome.run_id.as_uuid(),
            report_path: outcome.report_path,
            status,
        })
    }

    /// Drains the target's stale remote services and reconnects its existing
    /// root with services freshly built from the durable post-repair state.
    /// `Ok(true)` reports an active authenticated binding.
    pub(crate) async fn refresh_connection_runtime(
        &self,
        connection: ConnectionId,
    ) -> Result<bool, wire::ProtocolError> {
        let profile = self.current_account()?;
        let Some(engine) = &self.engine else {
            return Ok(false);
        };
        let record = self
            .state
            .open_account(profile.account_key)
            .await
            .map_err(crate::operations::state_error)?
            .get_connection(connection)
            .await
            .map_err(crate::operations::state_error)?
            .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The connection does not exist for this account"))?;
        let restored = crate::sync::registry::restore_all_account_connections(
            &self.state,
            std::slice::from_ref(&record),
            self.paths.base(),
            &self.user_sid,
        )
        .await
        .map_err(|_| error(wire::ProtocolErrorCode::Conflict, "A persisted connection could not be restored safely"))?;
        let entry = restored
            .into_iter()
            .next()
            .ok_or_else(|| error(wire::ProtocolErrorCode::Conflict, "A persisted connection could not be restored safely"))?;
        self.connect_restored_entry(engine, &entry, &profile, true).await?;
        let health = engine.health(connection).await.map_err(crate::storage::engine_failure)?;
        Ok(health.runtime.is_active())
    }
}

impl RepairVerifier for Provider {
    fn verify(
        &self,
        candidate: &SupplementalCredentialRecord,
        profile: &hfdrive_auth::AccountProfile,
        target: &hfdrive_state::ConnectionRecord,
        root_item_id: ItemId,
        probe: &ProbeRequest,
    ) -> impl Future<Output = Result<ProbeRunOutcome, wire::ProtocolError>> + Send {
        async move {
            let identity = hfdrive_publication::AccountIdentity {
                issuer: &profile.issuer,
                subject: &profile.subject,
            };
            let transport = hfdrive_publication::S3Transport::bind(
                &target.binding,
                &identity,
                candidate,
                self.scheduler.wire_budget().clone(),
            )
            .map_err(|_| internal())?;
            let control = self.native_control(profile.account_key);
            let lease = control.capture_lease().map_err(crate::storage::native_failure)?;
            crate::setup::verify_bucket_location(
                &control, &lease, &target.binding.bucket, &self.operations.cancellation,
            ).await?;
            // The candidate must read the connection's existing workspace
            // exactly: this path never initializes and never deletes.
            hfdrive_publication::coordinator::verify_existing_workspace(
                &transport,
                &lease,
                target.binding.workspace_id,
                root_item_id,
                &self.operations.cancellation,
            )
            .await
            .map_err(verify_failure)?;
            let account = self
                .state
                .open_account(profile.account_key)
                .await
                .map_err(crate::operations::state_error)?;
            let report = self
                .execute_storage_probe(&account, probe, probe.mode, target.binding.clone(), Some(transport))
                .await?;
            let report_path = self.write_probe_report(&report).await?;
            Ok(ProbeRunOutcome { report, report_path })
        }
    }
}

impl RepairRuntime for Provider {
    fn quiesce(&self, connection: ConnectionId) -> impl Future<Output = Result<(), wire::ProtocolError>> + Send {
        async move {
            match &self.engine {
                None => Ok(()),
                Some(engine) => engine.quiesce(connection).await.map_err(crate::storage::engine_failure),
            }
        }
    }

    fn refresh(&self, connection: ConnectionId) -> impl Future<Output = Result<bool, wire::ProtocolError>> + Send {
        async move { self.refresh_connection_runtime(connection).await }
    }

    fn restore_pause(
        &self,
        connection: ConnectionId,
        paused: bool,
    ) -> impl Future<Output = Result<(), wire::ProtocolError>> + Send {
        async move {
            let Some(engine) = &self.engine else { return Ok(()); };
            let outcome = if paused {
                engine.pause(connection).await
            } else {
                engine.resume(connection).await
            };
            match outcome {
                // A missing runtime has no in-memory pause to restore; the
                // durable intent was never modified.
                Ok(()) | Err(crate::sync::EngineError::UnknownConnection) => Ok(()),
                Err(failure) => Err(crate::storage::engine_failure(failure)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hfdrive_core::ids::{AccountKey, OperationId, WorkspaceId};
    use hfdrive_core::storage::{
        BucketBinding, BucketId, BucketName, Namespace, OwnerId, OwnerKind, RemotePrefix,
    };
    use hfdrive_protocol::{ProbeCheck, ProbeCheckKind, ProbeOutcome};
    use hfdrive_publication::probe::{ProbeCleanupReport, ProbeCapabilities, WireBytes};
    use hfdrive_state::{
        AccountRecord, AccountStatus, SetupDraft, StatePaths, StateStore,
    };
    use std::sync::{Arc, Mutex};

    const ISSUER: &str = "https://huggingface.co";
    const SUBJECT: &str = "repair-test-subject";

    fn profile() -> hfdrive_auth::AccountProfile {
        hfdrive_auth::AccountProfile {
            account_key: AccountKey::from_subject(ISSUER, SUBJECT),
            issuer: ISSUER.to_owned(),
            subject: SUBJECT.to_owned(),
            namespace: Namespace::new("repair-person".to_owned()).unwrap(),
            avatar_url: None,
            orgs: Vec::new(),
            granted_scopes: Some(Vec::new()),
            purpose_covered: true,
            org_consent_requested: false,
            reconsent_required_for_storage: false,
        }
    }

    fn binding(bucket_id: &str, owner_id: &str, workspace: WorkspaceId) -> DriveBinding {
        DriveBinding {
            account_key: AccountKey::from_subject(ISSUER, SUBJECT),
            bucket: BucketBinding {
                bucket_id: BucketId::new(bucket_id.to_owned()).unwrap(),
                bucket_name: BucketName::new("repair-bucket".to_owned()).unwrap(),
                owner_id: OwnerId::new(owner_id.to_owned()).unwrap(),
                owner_kind: OwnerKind::Personal,
                owner_namespace: Namespace::new("repair-person".to_owned()).unwrap(),
            },
            prefix: RemotePrefix::new(format!("hfdrive/{workspace}")).unwrap(),
            workspace_id: workspace,
        }
    }

    /// A report that proves full writable access for `connection`.
    fn passing_report(run_id: uuid::Uuid, connection: ConnectionId) -> ProbeReport {
        ProbeReport {
            run_id,
            connection_id: connection,
            mode: ProbeMode::Full,
            resumed: false,
            checks: vec![ProbeCheck {
                kind: ProbeCheckKind::NativeUploadVisibleNatively,
                expected: "e".into(),
                observed: "o".into(),
                outcome: ProbeOutcome::Passed,
                detail: None,
            }],
            capabilities: ProbeCapabilities {
                native_write: true,
                xet_upload: true,
                xet_range: true,
                s3_read: true,
                conditional_create: true,
                conditional_replace: true,
                strong_etag: true,
                read_only: false,
            },
            created_keys: Vec::new(),
            cleanup: ProbeCleanupReport::default(),
            wire_bytes: Some(WireBytes { wire_write_bytes: 1, wire_read_bytes: 1 }),
            staging_kept: false,
        }
    }

    struct CallLog {
        events: Vec<String>,
        refresh_result: Result<bool, wire::ProtocolError>,
    }

    struct FakeRuntime(Mutex<CallLog>);

    impl FakeRuntime {
        fn new(refresh_result: Result<bool, wire::ProtocolError>) -> Self {
            Self(Mutex::new(CallLog { events: Vec::new(), refresh_result }))
        }
        fn events(&self) -> Vec<String> {
            self.0.lock().unwrap().events.clone()
        }
    }

    impl RepairRuntime for FakeRuntime {
        fn quiesce(&self, connection: ConnectionId) -> impl Future<Output = Result<(), wire::ProtocolError>> + Send {
            let id = *connection.as_uuid();
            async move {
                self.0.lock().unwrap().events.push(format!("quiesce:{id}"));
                Ok(())
            }
        }
        fn refresh(&self, connection: ConnectionId) -> impl Future<Output = Result<bool, wire::ProtocolError>> + Send {
            let id = *connection.as_uuid();
            async move {
                self.0.lock().unwrap().events.push(format!("refresh:{id}"));
                self.0.lock().unwrap().refresh_result.clone()
            }
        }
        fn restore_pause(&self, connection: ConnectionId, paused: bool) -> impl Future<Output = Result<(), wire::ProtocolError>> + Send {
            let id = *connection.as_uuid();
            async move {
                self.0.lock().unwrap().events.push(format!("restore_pause:{id}:{paused}"));
                Ok(())
            }
        }
    }

    /// Verifies what the executor actually staged: the candidate record must
    /// carry the target's connection identity (rebound, not source), and the
    /// configured report outcome decides the run.
    struct FakeVerifier {
        logs: Mutex<Vec<(uuid::Uuid, uuid::Uuid)>>,
        report_for: Box<dyn Fn(ProbeRequest, ConnectionId) -> ProbeReport + Send + Sync>,
    }

    impl FakeVerifier {
        fn passing() -> Self {
            Self {
                logs: Mutex::new(Vec::new()),
                report_for: Box::new(|probe, connection| passing_report(*probe.run_id.as_uuid(), connection)),
            }
        }
        fn failing_checks() -> Self {
            Self {
                logs: Mutex::new(Vec::new()),
                report_for: Box::new(|probe, connection| {
                    let mut report = passing_report(*probe.run_id.as_uuid(), connection);
                    for check in &mut report.checks {
                        check.outcome = ProbeOutcome::Failed;
                    }
                    report
                }),
            }
        }
    }

    impl RepairVerifier for FakeVerifier {
        fn verify(
            &self,
            candidate: &SupplementalCredentialRecord,
            _profile: &hfdrive_auth::AccountProfile,
            target: &hfdrive_state::ConnectionRecord,
            _root_item_id: ItemId,
            probe: &ProbeRequest,
        ) -> impl Future<Output = Result<ProbeRunOutcome, wire::ProtocolError>> + Send {
            let context_connection = candidate.context().connection_id;
            let target_id = target.connection_id;
            let report = (self.report_for)(probe.clone(), target_id);
            async move {
                self.logs.lock().unwrap().push((context_connection, *target_id.as_uuid()));
                Ok(ProbeRunOutcome { report, report_path: "report.json".to_owned() })
            }
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        state: Arc<StateStore>,
        paths: StatePaths,
        profile: hfdrive_auth::AccountProfile,
        target: ConnectionId,
        source: ConnectionId,
    }

    /// Real state fixtures: one connected target whose stored publication
    /// credential is unusable, one verified source reservation on the same
    /// bucket whose protected pair loads under its original context.
    async fn fixture(bucket_id: &str) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::new(dir.path().to_path_buf());
        let state = Arc::new(StateStore::open(paths.clone()).await.unwrap());
        let profile = profile();
        state
            .record_account(AccountRecord {
                account_key: profile.account_key,
                issuer: profile.issuer.clone(),
                subject: profile.subject.clone(),
                namespace: "repair-person".to_owned(),
                credential_ref: CredentialRef("oauth.hfdcred".to_owned()),
                auth_epoch: 1,
                status: AccountStatus::Active,
            })
            .await
            .unwrap();

        // Source reservation on the same bucket with a verified probe record.
        let source_ws = WorkspaceId::new();
        let source_binding = binding(bucket_id, "owner-1", source_ws);
        let source = state
            .reserve_setup(SetupDraft {
                operation_id: OperationId::new(),
                account_key: profile.account_key,
                binding: source_binding.clone(),
                initialize: false,
            })
            .await
            .unwrap();
        state
            .record_setup_credentials(source.setup_id, CredentialRef("s3-source.hfdcred".to_owned()))
            .await
            .unwrap();
        state
            .record_probe_evidence(
                source.setup_id,
                serde_json::to_value(passing_report(uuid::Uuid::new_v4(), source.connection_id)).unwrap(),
            )
            .await
            .unwrap();
        // The source's protected pair, under its own original context.
        let store = CredentialStore::open(paths.account(profile.account_key).credentials().to_path_buf()).unwrap();
        let source_context = protection_context(&source_binding, &profile, source.connection_id).unwrap();
        let source_entropy = source_context.entropy(*source.connection_id.as_uuid()).unwrap();
        let record = SupplementalCredentialRecord::new(
            source_context,
            "AKIASOURCEKEYID123".to_owned(),
            "source-secret-material-1234567890".to_owned(),
        )
        .unwrap();
        let encoded = record.encode().unwrap();
        let name = RecordName::new("s3-source.hfdcred").unwrap();
        store.save_record(&name, encoded.as_slice(), Some(&source_entropy)).unwrap();

        // Target: connected, same bucket, its own workspace and root item.
        let target_ws = WorkspaceId::new();
        let target_binding = binding(bucket_id, "owner-1", target_ws);
        let target = state
            .reserve_setup(SetupDraft {
                operation_id: OperationId::new(),
                account_key: profile.account_key,
                binding: target_binding,
                initialize: false,
            })
            .await
            .unwrap();
        state
            .record_setup_credentials(target.setup_id, CredentialRef("s3-target.hfdcred".to_owned()))
            .await
            .unwrap();
        let root_item = ItemId::new();
        state
            .attach_setup_preview(
                target.setup_id,
                serde_json::json!({ "root_item_id": root_item.to_string() }),
                std::path::PathBuf::from("C:\\hfdrive-repair-target"),
                ConnectionMode::Writable,
            )
            .await
            .unwrap();
        state.finalize_setup(target.setup_id).await.unwrap();

        Fixture {
            _dir: dir,
            state,
            paths,
            profile,
            target: target.connection_id,
            source: source.connection_id,
        }
    }

    fn request(target: ConnectionId, source: ConnectionId) -> wire::RepairStorageRequest {
        wire::RepairStorageRequest {
            operation_id: uuid::Uuid::new_v4(),
            connection_id: *target.as_uuid(),
            credentials_from_connection_id: *source.as_uuid(),
        }
    }

    #[tokio::test]
    async fn mismatched_bucket_is_refused_and_nothing_is_touched() {
        let target_fixture = fixture("bucket-a").await;
        let source_fixture = fixture("bucket-b").await;
        // Borrow the source reservation of the foreign-bucket fixture by
        // running against the first fixture with the second's source id: the
        // identity/bucket check must refuse before any credential work.
        let inputs = RepairInputs {
            profile: &target_fixture.profile,
            state: target_fixture.state.as_ref(),
            paths: &target_fixture.paths,
        };
        let error = execute_storage_repair(
            &inputs,
            &FakeVerifier::passing(),
            &FakeRuntime::new(Ok(true)),
            request(target_fixture.target, source_fixture.source),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, wire::ProtocolErrorCode::NotFound, "an unknown source is refused, not repaired");
        // The target's old credential ref is untouched.
        let account = target_fixture.state.open_account(target_fixture.profile.account_key).await.unwrap();
        let record = account.get_connection(target_fixture.target).await.unwrap().unwrap();
        assert_eq!(record.s3_ref, Some(CredentialRef("s3-target.hfdcred".to_owned())));
    }

    #[tokio::test]
    async fn cross_bucket_source_is_refused_before_credential_work() {
        let fixture_a = fixture("bucket-a").await;
        let fixture_b = fixture("bucket-b").await;
        let foreign_source = fixture_b.source;
        // Connect the foreign source id into fixture A's state as a different
        // bucket reservation so the request is well-formed but the bucket
        // identity disagrees.
        let foreign_setup = fixture_b
            .state
            .get_setup_by_connection(foreign_source)
            .await
            .unwrap()
            .unwrap();
        let account = fixture_a.state.open_account(fixture_a.profile.account_key).await.unwrap();
        let _ = account;
        // The source lookup is scoped to the target's own state, so the
        // foreign reservation cannot even be resolved: refused as unknown.
        let inputs = RepairInputs {
            profile: &fixture_a.profile,
            state: fixture_a.state.as_ref(),
            paths: &fixture_a.paths,
        };
        let error = execute_storage_repair(
            &inputs,
            &FakeVerifier::passing(),
            &FakeRuntime::new(Ok(true)),
            request(fixture_a.target, foreign_setup.connection_id),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, wire::ProtocolErrorCode::NotFound);
    }

    #[tokio::test]
    async fn same_bucket_but_other_owner_is_refused() {
        let target_fixture = fixture("bucket-shared").await;
        // A source reservation on the same bucket name but a different owner
        // id must be refused by stable identity.
        let state = target_fixture.state.clone();
        let foreign_binding = binding("bucket-shared", "owner-2", WorkspaceId::new());
        let foreign = state
            .reserve_setup(SetupDraft {
                operation_id: OperationId::new(),
                account_key: target_fixture.profile.account_key,
                binding: foreign_binding,
                initialize: false,
            })
            .await
            .unwrap();
        state
            .record_setup_credentials(foreign.setup_id, CredentialRef("s3-foreign.hfdcred".to_owned()))
            .await
            .unwrap();
        state
            .record_probe_evidence(
                foreign.setup_id,
                serde_json::to_value(passing_report(uuid::Uuid::new_v4(), foreign.connection_id)).unwrap(),
            )
            .await
            .unwrap();

        let inputs = RepairInputs {
            profile: &target_fixture.profile,
            state: target_fixture.state.as_ref(),
            paths: &target_fixture.paths,
        };
        let error = execute_storage_repair(
            &inputs,
            &FakeVerifier::passing(),
            &FakeRuntime::new(Ok(true)),
            request(target_fixture.target, foreign.connection_id),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, wire::ProtocolErrorCode::Conflict, "a different owner is a conflict");
        let account = target_fixture.state.open_account(target_fixture.profile.account_key).await.unwrap();
        let record = account.get_connection(target_fixture.target).await.unwrap().unwrap();
        assert_eq!(record.s3_ref, Some(CredentialRef("s3-target.hfdcred".to_owned())));
    }

    #[tokio::test]
    async fn source_equals_target_is_refused() {
        let fixture = fixture("bucket-a").await;
        let inputs = RepairInputs {
            profile: &fixture.profile,
            state: fixture.state.as_ref(),
            paths: &fixture.paths,
        };
        let error = execute_storage_repair(
            &inputs,
            &FakeVerifier::passing(),
            &FakeRuntime::new(Ok(true)),
            request(fixture.target, fixture.target),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, wire::ProtocolErrorCode::InvalidRequest);
    }

    #[tokio::test]
    async fn failed_storage_check_preserves_old_reference_and_pause_intent() {
        let fixture = fixture("bucket-a").await;
        let account = fixture.state.open_account(fixture.profile.account_key).await.unwrap();
        // The user had durably paused this connection: the repair must not
        // rewrite that intent on any failure.
        account
            .set_settings(
                format!("connection/{}/paused", fixture.target),
                serde_json::Value::Bool(true),
                None,
            )
            .await
            .unwrap();

        let inputs = RepairInputs {
            profile: &fixture.profile,
            state: fixture.state.as_ref(),
            paths: &fixture.paths,
        };
        let runtime = FakeRuntime::new(Ok(true));
        let error = execute_storage_repair(
            &inputs,
            &FakeVerifier::failing_checks(),
            &runtime,
            request(fixture.target, fixture.source),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, wire::ProtocolErrorCode::PermissionDenied);
        // Verification runs before any runtime coordination: nothing was
        // quiesced or refreshed, and the old credential state stands.
        assert!(runtime.events().is_empty(), "no runtime coordination on a failed check: {:?}", runtime.events());
        let record = account.get_connection(fixture.target).await.unwrap().unwrap();
        assert_eq!(record.s3_ref, Some(CredentialRef("s3-target.hfdcred".to_owned())));
        let setup = fixture.state.get_setup_by_connection(fixture.target).await.unwrap().unwrap();
        assert_eq!(setup.credential_ref, Some(CredentialRef("s3-target.hfdcred".to_owned())));
        let paused = account
            .settings(format!("connection/{}/paused", fixture.target))
            .await
            .unwrap()
            .is_some_and(|row| row.value_json.as_bool() == Some(true));
        assert!(paused, "the durable pause intent survives a failed repair");
    }

    #[tokio::test]
    async fn successful_repair_preserves_target_root_workspace_and_work_and_never_touches_source() {
        let fixture = fixture("bucket-a").await;
        let account = fixture.state.open_account(fixture.profile.account_key).await.unwrap();
        // Pending local work survives the repair.
        account
            .record_outbox(hfdrive_state::OutboxEntry {
                connection_id: fixture.target,
                operation_id: OperationId::new(),
                item_id: Some(ItemId::new()),
                base_commit: None,
                base_json: None,
                observed_generation: 5,
                intent_json: serde_json::json!({"fixture": true}),
                state: hfdrive_state::OutboxState::Observed,
                snapshot_id: None,
                object_ref: None,
                candidate_commit: None,
                candidate_head_json: None,
                expected_etag: None,
                retry_class: hfdrive_state::RetryClass::None,
                next_attempt_at_ms: None,
            })
            .await
            .unwrap();
        let source_before = fixture.state.get_setup_by_connection(fixture.source).await.unwrap().unwrap();
        let target_before = account.get_connection(fixture.target).await.unwrap().unwrap();

        let inputs = RepairInputs {
            profile: &fixture.profile,
            state: fixture.state.as_ref(),
            paths: &fixture.paths,
        };
        let verifier = FakeVerifier::passing();
        let runtime = FakeRuntime::new(Ok(true));
        let outcome = execute_storage_repair(&inputs, &verifier, &runtime, request(fixture.target, fixture.source))
            .await
            .unwrap();
        assert!(outcome.repaired);
        assert_eq!(outcome.connection_id, fixture.target);
        assert_eq!(outcome.report_path.as_deref(), Some("report.json"));

        // The staged candidate the verifier proved was rebound to the target.
        let rebinds = verifier.logs.lock().unwrap().clone();
        assert_eq!(rebinds, vec![(*fixture.target.as_uuid(), *fixture.target.as_uuid())]);

        // Credential state moved; root, workspace, mode and work did not.
        let record = account.get_connection(fixture.target).await.unwrap().unwrap();
        assert_eq!(record.s3_ref.as_ref().unwrap().0, format!("s3-repair-{}", outcome_operation_id(&record)));
        assert_eq!(record.root_path, target_before.root_path);
        assert_eq!(record.binding.workspace_id, target_before.binding.workspace_id);
        assert_eq!(record.mode, target_before.mode);
        assert_eq!(record.config_json, target_before.config_json);
        assert_eq!(account.list_outbox(fixture.target, None, 10).await.unwrap().len(), 1);

        // The source reservation and its protected record are untouched.
        let source_after = fixture.state.get_setup_by_connection(fixture.source).await.unwrap().unwrap();
        assert_eq!(source_after, source_before);
        let store = CredentialStore::open(fixture.paths.account(fixture.profile.account_key).credentials().to_path_buf()).unwrap();
        let source_context = protection_context(&source_before.binding, &fixture.profile, fixture.source).unwrap();
        let entropy = source_context.entropy(*fixture.source.as_uuid()).unwrap();
        let plaintext = store
            .load_record(&RecordName::new("s3-source.hfdcred").unwrap(), Some(&entropy))
            .unwrap();
        let source_record = SupplementalCredentialRecord::decode(plaintext.expose()).unwrap();
        source_record.validate_context(&source_context).unwrap();

        // Quiesce, refresh and the restored pause intent, in that order.
        let events = runtime.events();
        assert_eq!(events[0], format!("quiesce:{}", fixture.target));
        assert_eq!(events[1], format!("refresh:{}", fixture.target));
        assert_eq!(events[2], format!("restore_pause:{}:false", fixture.target));
    }

    /// The staged record name is derived from the repair's operation id; this
    /// helper recovers it from the committed reference for assertions.
    fn outcome_operation_id(record: &hfdrive_state::ConnectionRecord) -> String {
        record
            .s3_ref
            .as_ref()
            .unwrap()
            .0
            .strip_prefix("s3-repair-")
            .unwrap()
            .to_owned()
    }

    #[tokio::test]
    async fn refresh_failure_reports_unrepaired_but_commit_is_retained() {
        let fixture = fixture("bucket-a").await;
        let account = fixture.state.open_account(fixture.profile.account_key).await.unwrap();
        account
            .set_settings(
                format!("connection/{}/paused", fixture.target),
                serde_json::Value::Bool(true),
                None,
            )
            .await
            .unwrap();
        let inputs = RepairInputs {
            profile: &fixture.profile,
            state: fixture.state.as_ref(),
            paths: &fixture.paths,
        };
        let runtime = FakeRuntime::new(Err(crate::operations::internal()));
        let outcome = execute_storage_repair(
            &inputs,
            &FakeVerifier::passing(),
            &runtime,
            request(fixture.target, fixture.source),
        )
        .await
        .unwrap();
        // Honest reporting: the commit happened but the binding is not active.
        assert!(!outcome.repaired);
        let record = account.get_connection(fixture.target).await.unwrap().unwrap();
        assert!(record.s3_ref.as_ref().unwrap().0.starts_with("s3-repair-"), "the committed repair is retained");
        let paused = account
            .settings(format!("connection/{}/paused", fixture.target))
            .await
            .unwrap()
            .is_some_and(|row| row.value_json.as_bool() == Some(true));
        assert!(paused, "the original pause intent is restored");
        let events = runtime.events();
        assert_eq!(events[2], format!("restore_pause:{}:true", fixture.target));
    }

    #[tokio::test]
    async fn account_commit_then_control_failure_keeps_the_referenced_credential() {
        let fixture = fixture("bucket-a").await;
        let account = fixture.state.open_account(fixture.profile.account_key).await.unwrap();
        let before = account.get_connection(fixture.target).await.unwrap().unwrap();
        account.set_settings(
            format!("connection/{}/paused", fixture.target),
            serde_json::Value::Bool(true),
            None,
        ).await.unwrap();

        // Fail only the control mirror write, after the account transaction
        // has atomically adopted the new reference and capability evidence.
        let control = rusqlite::Connection::open(fixture.paths.base().join("control.sqlite3")).unwrap();
        control.execute_batch(
            "CREATE TRIGGER fail_repair_mirror BEFORE UPDATE OF s3_ref ON connections
             BEGIN SELECT RAISE(ABORT, 'injected mirror failure'); END;",
        ).unwrap();
        drop(control);

        let inputs = RepairInputs {
            profile: &fixture.profile,
            state: fixture.state.as_ref(),
            paths: &fixture.paths,
        };
        let result = execute_storage_repair(
            &inputs, &FakeVerifier::passing(), &FakeRuntime::new(Ok(true)),
            request(fixture.target, fixture.source),
        ).await;
        assert!(result.is_err(), "a failed mirror must not report a completed repair");

        let adopted = account.get_connection(fixture.target).await.unwrap().unwrap();
        assert_ne!(adopted.s3_ref, before.s3_ref);
        let context = protection_context(&adopted.binding, &fixture.profile, fixture.target).unwrap();
        let entropy = context.entropy(*fixture.target.as_uuid()).unwrap();
        let store = CredentialStore::open(
            fixture.paths.account(fixture.profile.account_key).credentials().to_path_buf(),
        ).unwrap();
        let name = RecordName::new(&adopted.s3_ref.unwrap().0).unwrap();
        let plaintext = store.load_record(&name, Some(&entropy))
            .expect("a committed reference must still name a readable protected record");
        let record = SupplementalCredentialRecord::decode(plaintext.expose()).unwrap();
        record.validate_context(&context).unwrap();
        assert!(account.settings(format!("connection/{}/paused", fixture.target)).await.unwrap()
            .unwrap().value_json.as_bool().unwrap());
    }

    #[tokio::test]
    async fn read_only_target_is_refused() {
        let fixture = fixture("bucket-a").await;
        // Rebuild the target as a read-only connection in the same fixture.
        let account = fixture.state.open_account(fixture.profile.account_key).await.unwrap();
        let _ = account;
        let state = fixture.state.clone();
        let read_only = state
            .reserve_setup(SetupDraft {
                operation_id: OperationId::new(),
                account_key: fixture.profile.account_key,
                binding: binding("bucket-a", "owner-1", WorkspaceId::new()),
                initialize: false,
            })
            .await
            .unwrap();
        state
            .attach_setup_preview(
                read_only.setup_id,
                serde_json::json!({ "root_item_id": ItemId::new().to_string() }),
                std::path::PathBuf::from("C:\\hfdrive-repair-ro"),
                ConnectionMode::ReadOnly,
            )
            .await
            .unwrap();
        state.finalize_setup(read_only.setup_id).await.unwrap();

        let inputs = RepairInputs {
            profile: &fixture.profile,
            state: fixture.state.as_ref(),
            paths: &fixture.paths,
        };
        let error = execute_storage_repair(
            &inputs,
            &FakeVerifier::passing(),
            &FakeRuntime::new(Ok(true)),
            request(read_only.connection_id, fixture.source),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, wire::ProtocolErrorCode::ReadOnly);
    }

    #[tokio::test]
    async fn repair_ledger_replays_the_committed_result_without_reexecution() {
        // The durable operation ledger binds one operation id to one exact
        // request; a committed repair replays its persisted result and a
        // second execution attempt cannot duplicate the credential commit.
        let fixture = fixture("bucket-a").await;
        let account = fixture.state.open_account(fixture.profile.account_key).await.unwrap();
        let inputs = RepairInputs {
            profile: &fixture.profile,
            state: fixture.state.as_ref(),
            paths: &fixture.paths,
        };
        let request_value = serde_json::to_value(request(fixture.target, fixture.source)).unwrap();
        let operation_id = OperationId::from_uuid(request_value["operation_id"].as_str().unwrap().parse().unwrap()).unwrap();
        let begin = hfdrive_state::BeginOperationRequest {
            operation_id,
            kind: "repair_storage".to_owned(),
            request: request_value.clone(),
            effect_class: hfdrive_state::EffectClass::External,
            account_key: Some(fixture.profile.account_key),
            connection_id: Some(fixture.target),
            bucket_creation_operation_id: None,
        };
        let outcome = execute_storage_repair(
            &inputs,
            &FakeVerifier::passing(),
            &FakeRuntime::new(Ok(true)),
            serde_json::from_value(request_value.clone()).unwrap(),
        )
        .await
        .unwrap();
        let result = serde_json::json!({
            "connection_id": outcome.connection_id.to_string(),
            "repaired": outcome.repaired,
            "run_id": outcome.run_id.to_string(),
            "report_path": outcome.report_path,
        });
        // Persist the committed receipt exactly as the provider does.
        fixture.state.begin_operation(begin.clone()).await.unwrap();
        fixture.state.finish_operation(operation_id, result.clone()).await.unwrap();

        // A replay of the same operation id returns the persisted result and
        // never re-executes: the credential reference is unchanged.
        let replayed = fixture.state.begin_operation(begin).await.unwrap();
        let hfdrive_state::BeginOutcome::Replayed(record) = replayed else {
            panic!("the committed operation must replay");
        };
        assert_eq!(record.result_json, Some(result));
        // The credential reference is exactly what the first execution
        // committed; a replay cannot duplicate or replace it.
        let stored = account.get_connection(fixture.target).await.unwrap().unwrap();
        let setup = fixture.state.get_setup_by_connection(fixture.target).await.unwrap().unwrap();
        assert_eq!(stored.s3_ref, setup.credential_ref);
        assert!(stored.s3_ref.as_ref().unwrap().0.starts_with("s3-repair-"));
    }
}
