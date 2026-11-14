//! Explicit owned-prefix capability probes and durable non-secret evidence.

use hfdrive_core::ids::{ConnectionId, GenerationId};
use hfdrive_publication::probe::{CapabilityProbe, ProbeError, ProbeMode, ProbeRequest, ProbeTransport};
use hfdrive_publication::{BoundedRecord, ProbeKey, ProbeRecord, PublicationError, PublishOutcome};
use hfdrive_protocol as wire;

use crate::{Provider, operations::error, storage::{invalid, native_failure, remote_failure}};

impl Provider {
    pub(crate) async fn probe_storage(
        &self,
        request: wire::ProbeStorageRequest,
    ) -> Result<wire::ProbeStorageResult, wire::ProtocolError> {
        let profile = self.current_account()?;
        let connection = ConnectionId::from_uuid(request.connection_id)
            .map_err(|_| invalid("A nonzero connection identifier is required"))?;
        let run_id = GenerationId::from_uuid(request.run_id)
            .map_err(|_| invalid("A nonzero probe run identifier is required"))?;
        let setup = self.state.get_setup_by_connection(connection).await.map_err(crate::operations::state_error)?
            .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The connection has no durable setup reservation"))?;
        if setup.account_key != profile.account_key {
            return Err(error(wire::ProtocolErrorCode::PermissionDenied, "The probe belongs to a different account"));
        }
        // Probes run before Connect finalizes a ConnectionRecord. The setup
        // reservation is the authoritative binding at this phase.
        let mode = match setup.mode {
            Some(hfdrive_state::ConnectionMode::ReadOnly) => ProbeMode::ReadOnly,
            _ => ProbeMode::Full,
        };
        let record = setup_connection_record(&setup, mode);
        let parts = self.native_parts(&record, &profile)?;
        let staging_dir = self.paths.account(profile.account_key)
            .drive(record.binding.workspace_id)
            .base()
            .join("probe");
        let request = ProbeRequest {
            run_id,
            connection_id: connection,
            setup_id: Some(setup.setup_id),
            mode,
            staging_dir,
        };
        let account = self.state.open_account(profile.account_key).await.map_err(crate::operations::state_error)?;
        let native = parts.native;
        let budget = self.scheduler.wire_budget().clone();
        let report = match (mode, parts.transport) {
            (ProbeMode::Full, Some(transport)) => {
                let namespace = transport.probe(*run_id.as_uuid());
                CapabilityProbe::new(account, native, namespace, budget)
                    .run(&request, &self.operations.cancellation)
                    .await
                    .map_err(probe_failure)?
            }
            (ProbeMode::Full, None) => {
                return Err(error(wire::ProtocolErrorCode::StorageSetupRequired, "A full capability probe requires supplemental S3 credentials"));
            }
            (ProbeMode::ReadOnly, _) => {
                CapabilityProbe::new(account, native, UnavailableTransport, budget)
                    .run(&request, &self.operations.cancellation)
                    .await
                    .map_err(probe_failure)?
            }
        };
        let evidence = serde_json::to_value(&report).map_err(|_| crate::operations::internal())?;
        self.state.record_probe_evidence(setup.setup_id, evidence).await.map_err(crate::operations::state_error)?;
        let report_path = self.write_probe_report(&report).await?;
        let capability = if report.capabilities.read_only {
            wire::CapabilityState::ReadOnly
        } else if report.all_passed() {
            wire::CapabilityState::Writable
        } else {
            wire::CapabilityState::StorageSetupRequired
        };
        Ok(wire::ProbeStorageResult {
            run_id: request.run_id.as_uuid().clone(),
            capability,
            checks: report.checks,
            report_path: Some(report_path),
        })
    }

    async fn write_probe_report(
        &self,
        report: &hfdrive_publication::probe::ProbeReport,
    ) -> Result<String, wire::ProtocolError> {
        let directory = self.paths.base().join("capabilities");
        std::fs::create_dir_all(&directory).map_err(|_| crate::operations::internal())?;
        // Harden the report directory to the current user and SYSTEM, matching
        // other provider-owned state even though the report contains no secrets.
        let _ = hfdrive_windows::credentials::CredentialStore::open(directory.clone())
            .map_err(|_| crate::operations::internal())?;
        let base = directory.join(report.run_id.to_string());
        let json = serde_json::to_vec_pretty(report).map_err(|_| crate::operations::internal())?;
        let markdown = probe_markdown(report);
        std::fs::write(base.with_extension("json"), json).map_err(|_| crate::operations::internal())?;
        std::fs::write(base.with_extension("md"), markdown).map_err(|_| crate::operations::internal())?;
        Ok(base.with_extension("json").to_string_lossy().into_owned())
    }
}

fn setup_connection_record(
    setup: &hfdrive_state::SetupRecord,
    mode: ProbeMode,
) -> hfdrive_state::ConnectionRecord {
    hfdrive_state::ConnectionRecord {
        connection_id: setup.connection_id,
        account_key: setup.account_key,
        binding: setup.binding.clone(),
        root_path: setup.root_path.clone().unwrap_or_default(),
        volume_guid: None,
        volume_serial: None,
        sync_root_id: None,
        oauth_ref: None,
        s3_ref: setup.credential_ref.clone(),
        schema_version: 1,
        mode: if matches!(mode, ProbeMode::ReadOnly) {
            hfdrive_state::ConnectionMode::ReadOnly
        } else {
            hfdrive_state::ConnectionMode::Writable
        },
        config_json: serde_json::json!({}),
        registered: false,
    }
}

fn probe_markdown(report: &hfdrive_publication::probe::ProbeReport) -> String {
    let mut out = format!("# HF Drive capability probe {}\n\n", report.run_id);
    out.push_str(&format!("- Mode: {:?}\n- Resumed: {}\n\n", report.mode, report.resumed));
    out.push_str("| Check | Expected | Observed | Outcome | Detail |\n| --- | --- | --- | --- | --- |\n");
    for check in &report.checks {
        out.push_str(&format!(
            "| {:?} | {} | {} | {:?} | {} |\n",
            check.kind,
            check.expected,
            check.observed,
            check.outcome,
            check.detail.as_deref().unwrap_or("")
        ));
    }
    out
}

struct UnavailableTransport;

impl ProbeTransport for UnavailableTransport {
    fn read(
        &self,
        _lease: &hfdrive_hf::NativeLease,
        _key: &ProbeKey,
        _max_bytes: usize,
        _cancel: &tokio_util::sync::CancellationToken,
    ) -> impl Future<Output = Result<BoundedRecord, PublicationError>> + Send {
        async move { Err(PublicationError::StorageSetupRequired) }
    }

    fn create(
        &self,
        _lease: &hfdrive_hf::NativeLease,
        _key: &ProbeKey,
        _body: ProbeRecord,
        _cancel: &tokio_util::sync::CancellationToken,
    ) -> impl Future<Output = Result<PublishOutcome, PublicationError>> + Send {
        async move { Err(PublicationError::StorageSetupRequired) }
    }

    fn replace(
        &self,
        _lease: &hfdrive_hf::NativeLease,
        _key: &ProbeKey,
        _expected: &hfdrive_publication::OpaqueEtag,
        _body: ProbeRecord,
        _cancel: &tokio_util::sync::CancellationToken,
    ) -> impl Future<Output = Result<PublishOutcome, PublicationError>> + Send {
        async move { Err(PublicationError::StorageSetupRequired) }
    }

    fn delete_owned(
        &self,
        _lease: &hfdrive_hf::NativeLease,
        _keys: &[ProbeKey],
        _cancel: &tokio_util::sync::CancellationToken,
    ) -> impl Future<Output = Result<u32, PublicationError>> + Send {
        async move { Err(PublicationError::StorageSetupRequired) }
    }
}

fn probe_failure(error_value: ProbeError) -> wire::ProtocolError {
    match error_value {
        ProbeError::Journal(error) => crate::operations::state_error(error),
        ProbeError::Publication(error) => remote_failure(error.into()),
        ProbeError::Native(error) => native_failure(error),
        ProbeError::Staging => error(wire::ProtocolErrorCode::LocalRootInvalid, "The probe staging capture could not be prepared"),
    }
}
