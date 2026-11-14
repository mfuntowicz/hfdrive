//! Real capability probing over the native Xet path and the owned probe namespace.
//!
//! One probe run is an explicit setup/CLI action against a dedicated
//! connection. It never touches the live managed workspace: every external
//! create happens under the isolated owned prefix `hfdrive-probe/<run-id>/`,
//! and every key is journaled (reserved) in durable state **before** its
//! effect. Cleanup deletes exactly the keys this run provably created —
//! there is no listing, prefix delete, or general garbage collection.
//!
//! Measured dimensions (Full mode):
//! - a deterministic 16 MiB payload uploaded through the actual native Xet
//!   path (ingestion -> CAS commit -> binding) and verified natively
//!   (full and ranged reads against the known source bytes);
//! - S3 visibility and GET body/ETag coherence of the same object;
//! - guarded create (`If-None-Match: *`), two simultaneous same-validator
//!   writers (exactly one winner), and stale/incorrect-validator rejection;
//! - discarded-response recovery: a tiny publication chain (`HEAD` plus two
//!   commit records) whose conditional `HEAD` replacement verdict is dropped
//!   on purpose, then resolved purely from validated committed ancestry.
//!
//! Read-only connections run no write probe and require no S3 credentials:
//! every write dimension is reported `NotRun` with its reason. Every
//! dimension the run could not execute is reported `NotRun` explicitly;
//! nothing is silently skipped or reported as success.
//!
//! Interrupted runs resume: the journal preserves exact created keys and
//! ambiguous effects are reconciled against remote existence before the run
//! converges. Wall-clock-free deterministic payload bytes keep the fixture
//! tests and the live probe measuring identical data.
#![forbid(unsafe_code)]

use std::future::Future;
use std::path::PathBuf;

use hfdrive_core::catalog;
use hfdrive_core::format::{self, CommitV1, HeadV1, ItemChange};
use hfdrive_core::ids::{
    CommitId, ConnectionId, DeviceId, GenerationId, ItemId, OperationId, SetupId, UploadId,
    WorkspaceId,
};
use hfdrive_core::storage::{ByteRange, Sha256Digest, StableSnapshot};
use hfdrive_hf::wire_budget::WireBudget;
use hfdrive_hf::{NativeError, NativeLease};
use hfdrive_protocol::{ProbeCheck, ProbeCheckKind, ProbeOutcome};
use hfdrive_state::{AccountStore, ProbeKeyRecord, ProbeKeyState, StateError};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::ancestry::{self, AncestryCursor, AncestryGoal, AncestryProgress, AncestrySource, AncestryStop};
use crate::coordinator::{
    decode_head, map_native_error, to_head_bytes, PublicationNative, PayloadPlacement, RangeSource,
};
use crate::transport::{BoundedRecord, ProbeKey, ProbeNamespace, ProbeRecord};
use crate::{OpaqueEtag, PublicationError, PublishOutcome};

/// Probe payload block size; blocks are generated independently so any range
/// can be materialized without buffering the whole file.
pub const PROBE_BLOCK_BYTES: usize = 32 * 1024;
/// Probe payload blocks: 512 * 32 KiB = the deterministic 16 MiB file.
pub const PROBE_BLOCKS: u64 = 512;

/// Length of the deterministic probe payload.
pub fn probe_payload_len() -> u64 {
    PROBE_BLOCK_BYTES as u64 * PROBE_BLOCKS
}

/// Deterministic probe payload bytes for one block index.
///
/// The generator is pure integer arithmetic (xorshift64* seeded by the block
/// index), so the live probe and the local fixture tests agree on every byte
/// without sharing state. It is test-data generation only; production content
/// never passes through it.
pub fn probe_payload_block(index: u64, out: &mut [u8]) {
    debug_assert!(out.len() <= PROBE_BLOCK_BYTES);
    let mut state = 0x2545F491_4F6CDD1Du64 ^ index.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    if state == 0 {
        state = 0x2545F491_4F6CDD1D;
    }
    let fill = |state: &mut u64| -> u64 {
        *state ^= *state >> 12;
        *state ^= *state << 25;
        *state ^= *state >> 27;
        state.wrapping_mul(0x2545F491_4F6CDD1D)
    };
    let mut offset = 0usize;
    while offset < out.len() {
        let word = fill(&mut state).to_le_bytes();
        let take = (out.len() - offset).min(word.len());
        out[offset..offset + take].copy_from_slice(&word[..take]);
        offset += take;
    }
}

/// Deterministic probe payload bytes for one bounded range.
pub fn probe_payload_range(range: ByteRange) -> Vec<u8> {
    let mut out = vec![0u8; range.len() as usize];
    let mut written = 0usize;
    let mut block = [0u8; PROBE_BLOCK_BYTES];
    while written < out.len() {
        let absolute = range.start() + written as u64;
        let index = absolute / PROBE_BLOCK_BYTES as u64;
        let offset = (absolute % PROBE_BLOCK_BYTES as u64) as usize;
        probe_payload_block(index, &mut block);
        let take = (out.len() - written).min(PROBE_BLOCK_BYTES - offset);
        out[written..written + take].copy_from_slice(&block[offset..offset + take]);
        written += take;
    }
    out
}

/// SHA-256 of the full deterministic probe payload.
pub fn probe_payload_sha256() -> Sha256Digest {
    let mut hasher = Sha256::new();
    let mut block = [0u8; PROBE_BLOCK_BYTES];
    for index in 0..PROBE_BLOCKS {
        probe_payload_block(index, &mut block);
        hasher.update(block);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    Sha256Digest::from_bytes(out)
}

/// Probe execution mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeMode {
    /// Full capability measurement (explicit setup/CLI action).
    Full,
    /// Read-only connection: no S3 credentials required, no write probes.
    ReadOnly,
}

/// One probe run request. `run_id` is a fresh generation UUID persisted by
/// the caller; the same id resumes an interrupted run.
#[derive(Clone, Debug)]
pub struct ProbeRequest {
    /// The probe run identity; also the owned namespace segment.
    pub run_id: GenerationId,
    /// The connection being probed (journal partition).
    pub connection_id: ConnectionId,
    /// The owning setup reservation, when probing during setup.
    pub setup_id: Option<SetupId>,
    /// Measurement mode.
    pub mode: ProbeMode,
    /// Caller-owned staging directory for the deterministic payload capture.
    pub staging_dir: PathBuf,
}

/// Probe journal seam. Production: [`AccountStore`] (see the impl below); the
/// journal rows are the durable record of every key the run may create.
pub trait ProbeJournal: Send + Sync {
    /// Reserves the exact key before any external create effect.
    fn reserve(
        &self,
        record: ProbeKeyRecord,
    ) -> impl Future<Output = Result<ProbeKeyRecord, StateError>> + Send;

    /// Advances one journaled key's state.
    fn set_state(
        &self,
        connection_id: ConnectionId,
        run_id: GenerationId,
        key: &str,
        state: ProbeKeyState,
    ) -> impl Future<Output = Result<ProbeKeyRecord, StateError>> + Send;

    /// Every key reserved by exactly this run.
    fn keys(
        &self,
        connection_id: ConnectionId,
        run_id: GenerationId,
    ) -> impl Future<Output = Result<Vec<ProbeKeyRecord>, StateError>> + Send;

    /// The confirmed-created keys of this run: the only deletable set.
    fn cleanup_candidates(
        &self,
        connection_id: ConnectionId,
        run_id: GenerationId,
    ) -> impl Future<Output = Result<Vec<ProbeKeyRecord>, StateError>> + Send;
}

impl ProbeJournal for AccountStore {
    fn reserve(
        &self,
        record: ProbeKeyRecord,
    ) -> impl Future<Output = Result<ProbeKeyRecord, StateError>> + Send {
        self.reserve_probe_key(record)
    }

    fn set_state(
        &self,
        connection_id: ConnectionId,
        run_id: GenerationId,
        key: &str,
        state: ProbeKeyState,
    ) -> impl Future<Output = Result<ProbeKeyRecord, StateError>> + Send {
        self.set_probe_key_state(connection_id, run_id, key.to_owned(), state)
    }

    fn keys(
        &self,
        connection_id: ConnectionId,
        run_id: GenerationId,
    ) -> impl Future<Output = Result<Vec<ProbeKeyRecord>, StateError>> + Send {
        self.probe_keys(connection_id, run_id)
    }

    fn cleanup_candidates(
        &self,
        connection_id: ConnectionId,
        run_id: GenerationId,
    ) -> impl Future<Output = Result<Vec<ProbeKeyRecord>, StateError>> + Send {
        self.probe_cleanup_candidates(connection_id, run_id)
    }
}

/// Owned probe-namespace seam. Production: [`ProbeNamespace`] over the
/// explicitly credentialed S3 transport (see the impl below).
pub trait ProbeTransport: Send + Sync {
    /// One bounded GET of an owned probe key.
    fn read(
        &self,
        lease: &NativeLease,
        key: &ProbeKey,
        max_bytes: usize,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<BoundedRecord, PublicationError>> + Send;

    /// Conditional creation of an owned probe key (`If-None-Match: *`).
    fn create(
        &self,
        lease: &NativeLease,
        key: &ProbeKey,
        body: ProbeRecord,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<PublishOutcome, PublicationError>> + Send;

    /// Conditional replacement of an owned probe key (exactly one `If-Match`).
    fn replace(
        &self,
        lease: &NativeLease,
        key: &ProbeKey,
        expected: &OpaqueEtag,
        body: ProbeRecord,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<PublishOutcome, PublicationError>> + Send;

    /// Deletes exactly the listed owned keys and returns the count.
    fn delete_owned(
        &self,
        lease: &NativeLease,
        keys: &[ProbeKey],
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<u32, PublicationError>> + Send;
}

impl ProbeTransport for ProbeNamespace<'_> {
    fn read(
        &self,
        lease: &NativeLease,
        key: &ProbeKey,
        max_bytes: usize,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<BoundedRecord, PublicationError>> + Send {
        ProbeNamespace::read(self, lease, key, max_bytes, cancel)
    }

    fn create(
        &self,
        lease: &NativeLease,
        key: &ProbeKey,
        body: ProbeRecord,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<PublishOutcome, PublicationError>> + Send {
        ProbeNamespace::create(self, lease, key, body, cancel)
    }

    fn replace(
        &self,
        lease: &NativeLease,
        key: &ProbeKey,
        expected: &OpaqueEtag,
        body: ProbeRecord,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<PublishOutcome, PublicationError>> + Send {
        ProbeNamespace::replace(self, lease, key, expected, body, cancel)
    }

    fn delete_owned(
        &self,
        lease: &NativeLease,
        keys: &[ProbeKey],
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<u32, PublicationError>> + Send {
        ProbeNamespace::delete_owned(self, lease, keys, cancel)
    }
}

/// Structural probe failure. Measurement differences are outcomes in
/// [`ProbeReport`], never errors; nothing here carries user paths or secrets.
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("probe journal write failed")]
    Journal(#[from] StateError),
    #[error("probe publication transport failed")]
    Publication(#[from] PublicationError),
    #[error("probe native storage failed")]
    Native(#[from] NativeError),
    #[error("the probe staging capture could not be prepared")]
    Staging,
}

/// Per-dimension capability flags derived from the recorded checks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ProbeCapabilities {
    /// Fresh native write authorization was observed.
    pub native_write: bool,
    /// Native Xet upload and binding succeeded.
    pub xet_upload: bool,
    /// Native ranged reads matched the known source bytes.
    pub xet_range: bool,
    /// The bound object was readable through S3.
    pub s3_read: bool,
    /// `If-None-Match: *` create semantics were observed.
    pub conditional_create: bool,
    /// `If-Match` replace semantics were observed.
    pub conditional_replace: bool,
    /// Strong opaque entity tags were observed on GET/PUT.
    pub strong_etag: bool,
    /// The run executed in read-only mode (no write probe required).
    pub read_only: bool,
}

/// Measured wire-byte delta across this run's S3/native traffic. Encoded body
/// bytes only, from the shared wire budget; never reconstructed content.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct WireBytes {
    /// Encoded upload body bytes admitted at metered boundaries.
    pub wire_write_bytes: u64,
    /// Encoded download body bytes admitted at metered boundaries.
    pub wire_read_bytes: u64,
}

/// Cleanup result of one run.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ProbeCleanupReport {
    /// Keys deleted in this run.
    pub deleted: Vec<String>,
    /// Keys that could not be deleted (retained; retried on resume).
    pub retained: Vec<String>,
}

/// One probe run's evidence. Serializes to the capability report persisted by
/// the caller (`artifacts/capabilities/<run-id>` and the setup record); no
/// secret, signed URL, or user path is ever included.
#[derive(Clone, Debug, Serialize)]
pub struct ProbeReport {
    /// The probe run identity.
    pub run_id: Uuid,
    /// The probed connection.
    pub connection_id: ConnectionId,
    /// Executed mode.
    pub mode: ProbeMode,
    /// True when journal state from an earlier interrupted run was present.
    pub resumed: bool,
    /// One record per measured or explicitly not-run dimension.
    pub checks: Vec<ProbeCheck>,
    /// Derived capability flags.
    pub capabilities: ProbeCapabilities,
    /// Exact keys this run created (or reconciled as created).
    pub created_keys: Vec<String>,
    /// Owned cleanup result.
    pub cleanup: ProbeCleanupReport,
    /// Shared wire-budget delta for this run; `None` in read-only mode when no
    /// traffic flowed.
    pub wire_bytes: Option<WireBytes>,
    /// Whether the staging capture was kept on disk (interrupted run).
    #[serde(skip)]
    pub staging_kept: bool,
}

impl ProbeReport {
    /// Whether every measured dimension passed. `NotRun` dimensions do not
    /// pass; the caller reports them as named gates.
    pub fn all_passed(&self) -> bool {
        self.checks.iter().all(|check| check.outcome == ProbeOutcome::Passed)
    }
}

/// The real capability probe: native Xet upload/verification plus owned
/// probe-namespace conditional-publication measurement, journaled before
/// every external create.
pub struct CapabilityProbe<J, N, T> {
    journal: J,
    native: N,
    transport: T,
    budget: WireBudget,
}

/// Canonical check order used to report every dimension exactly once.
const ALL_CHECKS: [ProbeCheckKind; 8] = [
    ProbeCheckKind::NativeUploadVisibleNatively,
    ProbeCheckKind::XetRangeReads,
    ProbeCheckKind::NativeUploadVisibleS3,
    ProbeCheckKind::GetBodyEtagCoherence,
    ProbeCheckKind::GuardedCreate,
    ProbeCheckKind::ConcurrentSameEtag,
    ProbeCheckKind::StaleOverwriteRejected,
    ProbeCheckKind::AmbiguousCasRecovery,
];

#[derive(Default)]
struct CheckLog {
    entries: Vec<(ProbeCheckKind, ProbeCheck)>,
}

impl CheckLog {
    fn record(
        &mut self,
        kind: ProbeCheckKind,
        expected: &str,
        observed: &str,
        outcome: ProbeOutcome,
        detail: Option<String>,
    ) {
        self.entries.push((
            kind,
            ProbeCheck {
                kind,
                expected: expected.to_owned(),
                observed: observed.to_owned(),
                outcome,
                detail,
            },
        ));
    }

    fn passed(&mut self, kind: ProbeCheckKind, expected: &str, observed: &str) {
        self.record(kind, expected, observed, ProbeOutcome::Passed, None);
    }

    fn failed(&mut self, kind: ProbeCheckKind, expected: &str, observed: &str, detail: &str) {
        self.record(kind, expected, observed, ProbeOutcome::Failed, Some(detail.to_owned()));
    }

    fn not_run(&mut self, kind: ProbeCheckKind, reason: &str) {
        self.record(kind, "dimension executed", "not executed", ProbeOutcome::NotRun, Some(reason.to_owned()));
    }

    /// Fills every dimension not yet recorded as `NotRun`, in canonical order.
    fn finalize(&mut self, reason: &str) {
        for kind in ALL_CHECKS {
            if !self.entries.iter().any(|(recorded, _)| *recorded == kind) {
                self.not_run(kind, reason);
            }
        }
        self.entries.sort_by_key(|(kind, _)| ALL_CHECKS.iter().position(|k| k == kind).unwrap_or(usize::MAX));
    }

    fn into_checks(self) -> Vec<ProbeCheck> {
        self.entries.into_iter().map(|(_, check)| check).collect()
    }
}

/// Reads a just-created object through S3 with a bounded, cancellable
/// absence window. Only `Absent` is retried; authorization, format and
/// transport errors are returned immediately.
async fn read_with_absence_retry<T: ProbeTransport>(
    transport: &T,
    lease: &NativeLease,
    key: &ProbeKey,
    max_bytes: usize,
    cancel: &CancellationToken,
) -> Result<BoundedRecord, PublicationError> {
    const DELAYS_MS: [u64; 6] = [0, 200, 500, 1000, 2000, 4000];
    for (attempt, delay) in DELAYS_MS.iter().copied().enumerate() {
        if delay > 0 {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_millis(delay)) => {}
                _ = cancel.cancelled() => return Err(PublicationError::Cancelled),
            }
        }
        match transport.read(lease, key, max_bytes, cancel).await {
            Err(PublicationError::Absent) if attempt + 1 < DELAYS_MS.len() => continue,
            result => return result,
        }
    }
    unreachable!("the final bounded absence attempt returns its outcome")
}

/// Commit-reader over the tiny publication records of one probe run.
struct MiniSource<'a, T: ProbeTransport> {
    transport: &'a T,
    run_id: Uuid,
}

impl<T: ProbeTransport> AncestrySource for MiniSource<'_, T> {
    fn read_commit(
        &self,
        lease: &NativeLease,
        commit: CommitId,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<BoundedRecord, PublicationError>> + Send {
        async move {
            let name = format!("commits/{commit}.json");
            let key = ProbeKey::new(self.run_id, &name).map_err(|_| PublicationError::KeyOutOfScope)?;
            read_with_absence_retry(self.transport, lease, &key, format::MAX_COMMIT_BYTES, cancel).await
        }
    }
}

impl<J, N, T> CapabilityProbe<J, N, T>
where
    J: ProbeJournal,
    N: PublicationNative,
    T: ProbeTransport,
{
    /// Builds a probe over the real adapters. `budget` must be the same shared
    /// wire-budget handle the adapters meter with; it is used only to report
    /// measured wire-byte deltas.
    pub fn new(journal: J, native: N, transport: T, budget: WireBudget) -> Self {
        Self { journal, native, transport, budget }
    }

    /// Executes one probe run (or resumes an interrupted one with the same
    /// `run_id`).
    ///
    /// Returns `Ok(report)` for measurement outcomes, including permission
    /// denials (every dimension then reports `NotRun` with its reason).
    /// Structural failures — journal write failures, an uncreatable staging
    /// capture, or cancellation — return `Err`; the journal keeps every
    /// reserved key so a later run can reconcile and clean up.
    pub async fn run(
        &self,
        request: &ProbeRequest,
        cancel: &CancellationToken,
    ) -> Result<ProbeReport, ProbeError> {
        let run_id = *request.run_id.as_uuid();
        let mut log = CheckLog::default();
        let mut capabilities = ProbeCapabilities {
            read_only: request.mode == ProbeMode::ReadOnly,
            ..ProbeCapabilities::default()
        };
        let wire_before = self.budget.counters();
        let mut created_keys: Vec<String> = Vec::new();

        // Reconcile an interrupted run first: ambiguous create effects become
        // `Created`/`NotCreated` against observed remote existence, then every
        // provably-owned key of the old run is deleted idempotently.
        let prior = self.journal.keys(request.connection_id, request.run_id).await?;
        let resumed = !prior.is_empty();
        if resumed {
            self.reconcile_and_clean(request, run_id, &prior, cancel).await?;
        }

        let mut cleanup = ProbeCleanupReport::default();
        if request.mode == ProbeMode::ReadOnly {
            // Read-only connections require no S3 keys and run no write probe.
            log.finalize("read-only connection: no S3 publication credentials and no write probes");
            return Ok(ProbeReport {
                run_id,
                connection_id: request.connection_id,
                mode: request.mode,
                resumed,
                checks: log.into_checks(),
                capabilities,
                created_keys,
                cleanup,
                wire_bytes: None,
                staging_kept: false,
            });
        }

        let lease = self.native.capture_lease()?;
        if self.native.check_write(&lease, cancel).await.is_err() {
            // A denied run still reports: every dimension is `NotRun` with the
            // denial as its reason, and the capability flags stay false. The
            // sanitized failure class is intentionally not embedded.
            log.finalize("native write authorization was denied; no probe effect was attempted");
            return Ok(ProbeReport {
                run_id,
                connection_id: request.connection_id,
                mode: request.mode,
                resumed,
                checks: log.into_checks(),
                capabilities,
                created_keys,
                cleanup,
                wire_bytes: Some(wire_delta(wire_before, self.budget.counters())),
                staging_kept: false,
            });
        }
        capabilities.native_write = true;

        // ---- deterministic payload capture (local, journaled key later) ----
        let upload_id = UploadId::new();
        let staging_path = request.staging_dir.join(format!("hfdrive-probe-{run_id}.bin"));
        let (size, sha256) = write_probe_capture(&staging_path, cancel).await?;
        let snapshot = StableSnapshot {
            snapshot_id: hfdrive_core::ids::SnapshotId::new(),
            upload_id,
            path: staging_path.clone(),
            size,
            sha256,
        };

        // ---- native Xet upload with journal-before-effect ----
        let payload_name = format!("objects/{upload_id}");
        let payload_key = self.reserve(request, &payload_name).await?;
        self.mark(request, &payload_key, ProbeKeyState::CreateInFlight).await?;
        let placement = match self.native.upload_snapshot(&lease, snapshot, cancel).await {
            Ok(evidence) => {
                self.mark(request, &payload_key, ProbeKeyState::Created).await?;
                created_keys.push(payload_key.as_str().to_owned());
                PayloadPlacement {
                    object: hfdrive_core::storage::ObjectRef {
                        key: hfdrive_core::storage::PayloadKey::new(upload_id),
                        sha256,
                        size,
                        xet_file_id: evidence.bound.xet_file_id.clone(),
                    },
                    upload: Some(evidence),
                    reused: false,
                }
            }
            Err(err) => {
                // Ambiguous dispatches (cancelled/transport-class) leave the
                // key `CreateInFlight`; a resume reconciles it against remote
                // existence. Definite rejections become `NotCreated`.
                if !native_effect_unknown(&err) {
                    self.mark(request, &payload_key, ProbeKeyState::NotCreated).await?;
                }
                return Err(ProbeError::Native(err));
            }
        };

        // ---- native visibility ----
        let payload_full = probe_key(self.native.drive().prefix.as_str(), &payload_name);
        match self.native.paths_info(&lease, std::slice::from_ref(&payload_full), cancel).await {
            Ok(report) => {
                let key = payload_full;
                let found = report.found.iter().find(|info| info.key == key);
                match found {
                    Some(info)
                        if info.size == size
                            && info.xet_file_id.as_ref() == Some(&placement.object.xet_file_id) =>
                    {
                        capabilities.xet_upload = true;
                        log.passed(
                            ProbeCheckKind::NativeUploadVisibleNatively,
                            "bound payload visible natively with exact size and Xet identity",
                            "payload bound with exact size and Xet identity",
                        );
                    }
                    Some(_) => log.failed(
                        ProbeCheckKind::NativeUploadVisibleNatively,
                        "bound payload visible natively with exact size and Xet identity",
                        "payload visible with a different size or identity",
                        "native metadata disagrees with the bound upload",
                    ),
                    None => log.failed(
                        ProbeCheckKind::NativeUploadVisibleNatively,
                        "bound payload visible natively with exact size and Xet identity",
                        "payload not visible",
                        "bound upload was not observable (retryable; never a deletion)",
                    ),
                }
            }
            Err(err) => {
                let detail = format!("native lookup failed: {}", map_native_error(err));
                log.failed(
                    ProbeCheckKind::NativeUploadVisibleNatively,
                    "bound payload visible natively with exact size and Xet identity",
                    "native lookup failed",
                    &detail,
                );
            }
        }

        // ---- ranged verification against known source bytes ----
        self.verify_ranges(&lease, &placement, size, &mut log, &mut capabilities, cancel).await?;

        // ---- S3 visibility and body/ETag coherence ----
        self.measure_s3(&lease, request, run_id, &placement, size, sha256, &mut log, &mut capabilities, &mut created_keys, cancel).await?;

        // ---- conditional-publication measurements ----
        self.measure_conditional(&lease, request, &mut log, &mut capabilities, &mut created_keys, cancel).await?;

        // ---- discarded-response recovery through committed ancestry ----
        self.measure_recovery(&lease, request, run_id, &mut log, &mut created_keys, cancel).await?;

        // ---- owned cleanup of everything this run created ----
        cleanup = self.cleanup(request, cancel).await?;
        let staging_kept = false;
        let _ = tokio::fs::remove_file(&staging_path).await;

        log.finalize("dimension not executed");
        let wire_bytes = Some(wire_delta(wire_before, self.budget.counters()));
        Ok(ProbeReport {
            run_id,
            connection_id: request.connection_id,
            mode: request.mode,
            resumed,
            checks: log.into_checks(),
            capabilities,
            created_keys,
            cleanup,
            wire_bytes,
            staging_kept,
        })
    }

    /// Deletes exactly the confirmed-created keys of this run and returns the
    /// outcome. Idempotent: a cancelled half-cleanup converges by re-running
    /// the same recorded list.
    pub async fn cleanup(
        &self,
        request: &ProbeRequest,
        cancel: &CancellationToken,
    ) -> Result<ProbeCleanupReport, ProbeError> {
        let run_id = *request.run_id.as_uuid();
        let candidates = self.journal.cleanup_candidates(request.connection_id, request.run_id).await?;
        let mut keys = Vec::with_capacity(candidates.len());
        for record in &candidates {
            let name = owned_name(run_id, &record.key).ok_or(PublicationError::KeyOutOfScope)?;
            keys.push(ProbeKey::new(run_id, &name).map_err(|_| PublicationError::KeyOutOfScope)?);
        }
        let mut report = ProbeCleanupReport::default();
        let lease = self.native.capture_lease()?;
        for (record, key) in candidates.iter().zip(&keys) {
            match self.transport.delete_owned(&lease, std::slice::from_ref(key), cancel).await {
                Ok(_) => {
                    self.mark(request, key, ProbeKeyState::Deleted).await?;
                    report.deleted.push(record.key.clone());
                }
                Err(PublicationError::Cancelled) => {
                    report.retained.push(record.key.clone());
                    return Ok(report);
                }
                Err(_) => report.retained.push(record.key.clone()),
            }
        }
        Ok(report)
    }

    // ---- journal helpers ----

    /// Reserves one exact key before its external create effect. Existing
    /// journal rows (resume) keep their state.
    async fn reserve(&self, request: &ProbeRequest, name: &str) -> Result<ProbeKey, ProbeError> {
        let run_id = *request.run_id.as_uuid();
        let key = ProbeKey::new(run_id, name).map_err(|_| PublicationError::KeyOutOfScope)?;
        let known = self.journal.keys(request.connection_id, request.run_id).await?;
        if !known.iter().any(|record| record.key == key.as_str()) {
            self.journal
                .reserve(ProbeKeyRecord::reserved(
                    request.run_id,
                    request.connection_id,
                    request.setup_id,
                    key.as_str().to_owned(),
                ))
                .await?;
        }
        Ok(key)
    }

    async fn mark(
        &self,
        request: &ProbeRequest,
        key: &ProbeKey,
        state: ProbeKeyState,
    ) -> Result<(), ProbeError> {
        self.journal.set_state(request.connection_id, request.run_id, key.as_str(), state).await?;
        Ok(())
    }

    /// Reconciles ambiguous create effects of an interrupted run against
    /// observed remote existence, then deletes every confirmed key of the old
    /// run so the resumed run starts from a known-empty owned namespace.
    async fn reconcile_and_clean(
        &self,
        request: &ProbeRequest,
        run_id: Uuid,
        prior: &[ProbeKeyRecord],
        cancel: &CancellationToken,
    ) -> Result<(), ProbeError> {
        let lease = self.native.capture_lease()?;
        for record in prior {
            if record.state != ProbeKeyState::CreateInFlight {
                continue;
            }
            let name = owned_name(run_id, &record.key).ok_or(PublicationError::KeyOutOfScope)?;
            let key = ProbeKey::new(run_id, &name).map_err(|_| PublicationError::KeyOutOfScope)?;
            let exists = if name.starts_with("objects/") {
                let full = probe_key(self.native.drive().prefix.as_str(), &name);
                self.native
                    .object_metadata(&lease, &full, cancel)
                    .await
                    .map_err(map_native_error)?
                    .is_some()
            } else {
                match self.transport.read(&lease, &key, format::MAX_COMMIT_BYTES, cancel).await {
                    Ok(_) => true,
                    Err(PublicationError::Absent) => false,
                    Err(err) => return Err(ProbeError::Publication(err)),
                }
            };
            let state = if exists { ProbeKeyState::Created } else { ProbeKeyState::NotCreated };
            self.mark(request, &key, state).await?;
        }
        self.cleanup(request, cancel).await?;
        Ok(())
    }

    // ---- measurement steps ----

    /// Full and ranged native reads of the bound payload against the known
    /// deterministic source bytes.
    async fn verify_ranges(
        &self,
        lease: &NativeLease,
        placement: &PayloadPlacement,
        size: u64,
        log: &mut CheckLog,
        capabilities: &mut ProbeCapabilities,
        cancel: &CancellationToken,
    ) -> Result<(), ProbeError> {
        let expected = probe_payload_sha256();
        // Whole-object read: digest and length must match the capture.
        match self.read_range(lease, placement, ByteRange::new(0, size, size).unwrap(), cancel).await {
            Ok(bytes) if bytes.len() as u64 == size && Sha256Digest::of(&bytes) == expected => {}
            Ok(_) => {
                log.failed(
                    ProbeCheckKind::XetRangeReads,
                    "full and ranged reads equal the known source bytes",
                    "full read differs from the source",
                    "digest or length mismatch on the full read",
                );
                return Ok(());
            }
            Err(err) => {
                let detail = format!("full read failed: {}", map_native_error(err));
                log.failed(
                    ProbeCheckKind::XetRangeReads,
                    "full and ranged reads equal the known source bytes",
                    "full read failed",
                    &detail,
                );
                return Ok(());
            }
        }
        // Boundary and EOF slices plus one empty range.
        let slices: [(u64, u64); 5] =
            [(0, 4096), (4095, 4097), (size / 2, size / 2 + 8192), (size - 1, size), (0, 0)];
        let mut ok = true;
        let mut detail = String::new();
        for (start, end) in slices {
            let range = ByteRange::new(start, end, size).unwrap();
            let want = probe_payload_range(range);
            match self.read_range(lease, placement, range, cancel).await {
                Ok(got) if got == want => {}
                Ok(_) => {
                    ok = false;
                    detail = format!("range {start}..{end} differs from the source slice");
                    break;
                }
                Err(err) => {
                    ok = false;
                    detail = format!("range {start}..{end} failed: {}", map_native_error(err));
                    break;
                }
            }
        }
        if ok {
            capabilities.xet_range = true;
            log.passed(
                ProbeCheckKind::XetRangeReads,
                "full and ranged reads equal the known source bytes",
                "full read and five boundary slices (including empty) matched",
            );
        } else {
            log.failed(
                ProbeCheckKind::XetRangeReads,
                "full and ranged reads equal the known source bytes",
                "one or more slices differed",
                &detail,
            );
        }
        Ok(())
    }

    async fn read_range(
        &self,
        lease: &NativeLease,
        placement: &PayloadPlacement,
        range: ByteRange,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, NativeError> {
        let mut reader = self.native.open_range(lease, &placement.object, range, cancel).await?;
        let mut out = Vec::with_capacity(range.len() as usize);
        while let Some(chunk) = reader.next_chunk(cancel).await? {
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    /// S3 visibility of the bound payload plus body/ETag coherence of a small
    /// owned record.
    #[allow(clippy::too_many_arguments)]
    async fn measure_s3(
        &self,
        lease: &NativeLease,
        request: &ProbeRequest,
        run_id: Uuid,
        placement: &PayloadPlacement,
        size: u64,
        sha256: Sha256Digest,
        log: &mut CheckLog,
        capabilities: &mut ProbeCapabilities,
        created_keys: &mut Vec<String>,
        cancel: &CancellationToken,
    ) -> Result<(), ProbeError> {
        let payload_name = placement.object.key.to_string();
        let payload_key = ProbeKey::new(run_id, &payload_name).map_err(|_| PublicationError::KeyOutOfScope)?;
        match read_with_absence_retry(&self.transport, lease, &payload_key, crate::transport::MAX_PROBE_READ_BYTES, cancel).await {
            Ok(record) => {
                if record.len() as u64 == size && Sha256Digest::of(record.body()) == sha256 {
                    capabilities.s3_read = true;
                    log.passed(
                        ProbeCheckKind::NativeUploadVisibleS3,
                        "native upload visible through S3 with exact bytes",
                        "S3 body matched the uploaded digest and length",
                    );
                } else {
                    log.failed(
                        ProbeCheckKind::NativeUploadVisibleS3,
                        "native upload visible through S3 with exact bytes",
                        "S3 body differs from the uploaded bytes",
                        "digest or length mismatch on the S3 read-back",
                    );
                }
            }
            Err(PublicationError::Absent) => log.failed(
                ProbeCheckKind::NativeUploadVisibleS3,
                "native upload visible through S3 with exact bytes",
                "object absent at the bound key",
                "not observable (retryable; never a deletion)",
            ),
            Err(err) => {
                let detail = format!("S3 read failed: {}", err);
                log.failed(
                    ProbeCheckKind::NativeUploadVisibleS3,
                    "native upload visible through S3 with exact bytes",
                    "S3 read failed",
                    &detail,
                );
            }
        }

        // GET body/ETag coherence on a small owned record.
        let name = "records/coherence.json";
        let key = self.reserve(request, name).await?;
        let body = ProbeRecord::new(br#"{"probe":"coherence"}"#.to_vec()).unwrap();
        self.mark(request, &key, ProbeKeyState::CreateInFlight).await?;
        match self.transport.create(&lease, &key, body.clone(), cancel).await {
            Ok(PublishOutcome::Committed) => {
                self.mark(request, &key, ProbeKeyState::Created).await?;
                created_keys.push(key.as_str().to_owned());
            }
            Ok(_) => {
                // The guard was lost to something already at the key; record
                // observed existence honestly (the namespace is run-owned).
                let exists = matches!(
                    self.transport.read(&lease, &key, crate::transport::MAX_PROBE_RECORD_BYTES, cancel).await,
                    Ok(_)
                );
                let state = if exists { ProbeKeyState::Created } else { ProbeKeyState::NotCreated };
                self.mark(request, &key, state).await?;
                if state == ProbeKeyState::Created {
                    created_keys.push(key.as_str().to_owned());
                }
                log.failed(
                    ProbeCheckKind::GetBodyEtagCoherence,
                    "GET body and entity tag come from one coherent response",
                    "owned record creation lost its guard",
                    "If-None-Match: * did not guard the create",
                );
                return Ok(());
            }
            Err(err) => {
                if !publication_effect_unknown(&err) {
                    self.mark(request, &key, ProbeKeyState::NotCreated).await?;
                }
                let detail = format!("create failed: {}", err);
                log.failed(
                    ProbeCheckKind::GetBodyEtagCoherence,
                    "GET body and entity tag come from one coherent response",
                    "owned record creation failed",
                    &detail,
                );
                return Ok(());
            }
        }
        let first = self.transport.read(&lease, &key, crate::transport::MAX_PROBE_RECORD_BYTES, cancel).await;
        let second = self.transport.read(&lease, &key, crate::transport::MAX_PROBE_RECORD_BYTES, cancel).await;
        match (first, second) {
            (Ok(a), Ok(b)) => {
                let strong = a.etag().as_str().starts_with('"') && !a.etag().as_str().starts_with("W/");
                if a.body() == b.body()
                    && a.etag() == b.etag()
                    && a.body() == body.as_bytes()
                    && strong
                {
                    capabilities.strong_etag = true;
                    log.passed(
                        ProbeCheckKind::GetBodyEtagCoherence,
                        "GET body and entity tag come from one coherent response",
                        "body and strong entity tag coherent across two GETs",
                    );
                } else {
                    log.failed(
                        ProbeCheckKind::GetBodyEtagCoherence,
                        "GET body and entity tag come from one coherent response",
                        "body or entity tag changed between GETs",
                        "coherence or strong-tag expectation not met",
                    );
                }
            }
            (Err(err), _) | (_, Err(err)) => {
                let detail = format!("GET failed: {}", err);
                log.failed(
                    ProbeCheckKind::GetBodyEtagCoherence,
                    "GET body and entity tag come from one coherent response",
                    "GET failed",
                    &detail,
                );
            }
        }
        Ok(())
    }

    /// Guarded create, two same-validator writers, and stale/incorrect
    /// validator rejection on one owned record.
    async fn measure_conditional(
        &self,
        lease: &NativeLease,
        request: &ProbeRequest,
        log: &mut CheckLog,
        capabilities: &mut ProbeCapabilities,
        created_keys: &mut Vec<String>,
        cancel: &CancellationToken,
    ) -> Result<(), ProbeError> {
        let name = "records/guarded.json";
        let key = self.reserve(request, name).await?;
        let body = ProbeRecord::new(br#"{"probe":"guarded"}"#.to_vec()).unwrap();

        // Guarded create: the second create must lose its guard.
        self.mark(request, &key, ProbeKeyState::CreateInFlight).await?;
        match self.transport.create(&lease, &key, body.clone(), cancel).await {
            Ok(PublishOutcome::Committed) => {
                self.mark(request, &key, ProbeKeyState::Created).await?;
                created_keys.push(key.as_str().to_owned());
            }
            Ok(_) | Err(_) => {
                let state = matches!(
                    self.transport.read(&lease, &key, crate::transport::MAX_PROBE_RECORD_BYTES, cancel).await,
                    Ok(_)
                );
                let observed_state = if state { ProbeKeyState::Created } else { ProbeKeyState::NotCreated };
                self.mark(request, &key, observed_state).await?;
                if observed_state == ProbeKeyState::Created {
                    created_keys.push(key.as_str().to_owned());
                }
                log.failed(
                    ProbeCheckKind::GuardedCreate,
                    "If-None-Match: * creates exactly once",
                    "first guarded create did not commit",
                    "create outcome was not a clean commit",
                );
                return Ok(());
            }
        }
        match self.transport.create(&lease, &key, body.clone(), cancel).await {
            Ok(PublishOutcome::PreconditionFailed) => {
                capabilities.conditional_create = true;
                log.passed(
                    ProbeCheckKind::GuardedCreate,
                    "If-None-Match: * creates exactly once",
                    "second guarded create was refused",
                );
            }
            Ok(_) => log.failed(
                ProbeCheckKind::GuardedCreate,
                "If-None-Match: * creates exactly once",
                "second guarded create also committed",
                "conditional create is not guarded",
            ),
            Err(err) => {
                let detail = format!("second create failed: {}", err);
                log.failed(
                    ProbeCheckKind::GuardedCreate,
                    "If-None-Match: * creates exactly once",
                    "second guarded create errored",
                    &detail,
                );
            }
        }

        // Two simultaneous writers with the same preserved validator.
        let current = self.transport.read(&lease, &key, crate::transport::MAX_PROBE_RECORD_BYTES, cancel).await?;
        let etag = current.etag().clone();
        let left = ProbeRecord::new(br#"{"probe":"writer-a"}"#.to_vec()).unwrap();
        let right = ProbeRecord::new(br#"{"probe":"writer-b"}"#.to_vec()).unwrap();
        let (first, second) = tokio::join!(
            self.transport.replace(&lease, &key, &etag, left, cancel),
            self.transport.replace(&lease, &key, &etag, right, cancel)
        );
        let wins = [&first, &second]
            .iter()
            .filter(|result| matches!(result, Ok(PublishOutcome::Committed)))
            .count();
        let losses = [&first, &second]
            .iter()
            .filter(|result| matches!(result, Ok(PublishOutcome::PreconditionFailed)))
            .count();
        if wins == 1 && losses == 1 {
            capabilities.conditional_replace = true;
            log.passed(
                ProbeCheckKind::ConcurrentSameEtag,
                "two same-validator writers produce exactly one winner",
                "exactly one writer committed and one lost its precondition",
            );
        } else {
            let detail = format!("observed {wins} winners and {losses} precondition losses");
            log.failed(
                ProbeCheckKind::ConcurrentSameEtag,
                "two same-validator writers produce exactly one winner",
                "winner count was not exactly one",
                &detail,
            );
        }

        // Stale validator: the record moved above `etag` in the previous step,
        // so the old validator must now be refused. An incorrectly spelled
        // validator is refused locally before any dispatch.
        match self.transport.replace(&lease, &key, &etag, body.clone(), cancel).await {
            Ok(PublishOutcome::PreconditionFailed) => {
                let wrong_rejected = OpaqueEtag::new("not-an-etag".to_owned()).is_err()
                    && OpaqueEtag::new("W/\"weak\"".to_owned()).is_err();
                if wrong_rejected {
                    log.passed(
                        ProbeCheckKind::StaleOverwriteRejected,
                        "stale and incorrect validators never overwrite",
                        "stale validator refused; malformed validators refused locally",
                    );
                } else {
                    log.failed(
                        ProbeCheckKind::StaleOverwriteRejected,
                        "stale and incorrect validators never overwrite",
                        "malformed validator was accepted",
                        "validator validation is weaker than the contract",
                    );
                }
            }
            Ok(_) => log.failed(
                ProbeCheckKind::StaleOverwriteRejected,
                "stale and incorrect validators never overwrite",
                "stale validator overwrote the record",
                "conditional replace does not guard against stale validators",
            ),
            Err(err) => {
                let detail = format!("stale replace failed: {}", err);
                log.failed(
                    ProbeCheckKind::StaleOverwriteRejected,
                    "stale and incorrect validators never overwrite",
                    "stale replace errored",
                    &detail,
                );
            }
        }
        Ok(())
    }

    /// Tiny publication chain whose conditional `HEAD` replacement verdict is
    /// discarded on purpose; the outcome is then resolved purely from
    /// validated committed ancestry — the exact recovery code path used for
    /// an uncertain publication.
    #[allow(clippy::too_many_arguments)]
    async fn measure_recovery(
        &self,
        lease: &NativeLease,
        request: &ProbeRequest,
        run_id: Uuid,
        log: &mut CheckLog,
        created_keys: &mut Vec<String>,
        cancel: &CancellationToken,
    ) -> Result<(), ProbeError> {
        let workspace = WorkspaceId::new();
        let root_item_id = ItemId::new();
        let device_id = DeviceId::new();
        let op0 = OperationId::new();
        let op1 = OperationId::new();
        let c0 = CommitId::new();
        let c1 = CommitId::new();

        let (catalog_root, publish_set) =
            catalog::initialize(root_item_id, op0).map_err(crate::coordinator::map_format_error)?;
        let (page_hash, page_bytes) = catalog::encode_and_hash(
            &publish_set.pages.first().expect("initial catalog has exactly one page").1,
        )
        .map_err(crate::coordinator::map_format_error)?;

        let commit0 = CommitV1 {
            format: format::FORMAT_NAME.to_owned(),
            schema_version: format::SCHEMA_VERSION,
            workspace_id: workspace,
            commit_id: c0,
            parent_commit_id: None,
            catalog_root: catalog_root.digest(),
            operation_ids: vec![op0],
            changes: Vec::<ItemChange>::new(),
            device_id,
            created_at: "1970-01-01T00:00:00Z".to_owned(),
        };
        let commit1 = CommitV1 {
            commit_id: c1,
            parent_commit_id: Some(c0),
            operation_ids: vec![op1],
            ..commit0.clone()
        };
        let head0 = HeadV1 {
            format: format::FORMAT_NAME.to_owned(),
            schema_version: format::SCHEMA_VERSION,
            workspace_id: workspace,
            root_item_id,
            commit_id: c0,
            generation: GenerationId::new(),
            required_features: Vec::new(),
        };
        let head1 = HeadV1 {
            commit_id: c1,
            generation: GenerationId::new(),
            ..head0.clone()
        };

        // Tiny publication records, all native-Xet-written and journaled.
        for (name, target, bytes) in [
            (
                format!("catalog/{page_hash}.json"),
                hfdrive_core::storage::ImmutableKey::Catalog(page_hash),
                page_bytes,
            ),
            (
                format!("commits/{c0}.json"),
                hfdrive_core::storage::ImmutableKey::Commit(c0),
                format::to_commit_bytes(&commit0).map_err(crate::coordinator::map_format_error)?,
            ),
            (
                format!("commits/{c1}.json"),
                hfdrive_core::storage::ImmutableKey::Commit(c1),
                format::to_commit_bytes(&commit1).map_err(crate::coordinator::map_format_error)?,
            ),
        ] {
            let key = self.reserve(request, &name).await?;
            self.mark(request, &key, ProbeKeyState::CreateInFlight).await?;
            match self
                .native
                .upload_record(lease, target, bytes, cancel)
                .await
            {
                Ok(_) => {
                    self.mark(request, &key, ProbeKeyState::Created).await?;
                    created_keys.push(key.as_str().to_owned());
                }
                Err(err) => {
                    if !native_effect_unknown(&err) {
                        self.mark(request, &key, ProbeKeyState::NotCreated).await?;
                    }
                    let detail = format!("mini publication record upload failed: {}", map_native_error(err));
                    log.not_run(ProbeCheckKind::AmbiguousCasRecovery, &detail);
                    return Ok(());
                }
            }
        }

        // `HEAD` create, then a replacement whose verdict is dropped.
        let head_name = "HEAD";
        let head_key = self.reserve(request, head_name).await?;
        let head0_bytes = to_head_bytes(&head0)?;
        self.mark(request, &head_key, ProbeKeyState::CreateInFlight).await?;
        match self
            .transport
            .create(&lease, &head_key, ProbeRecord::new(head0_bytes).unwrap(), cancel)
            .await
        {
            Ok(PublishOutcome::Committed) => {
                self.mark(request, &head_key, ProbeKeyState::Created).await?;
                created_keys.push(head_key.as_str().to_owned());
            }
            Ok(_) | Err(_) => {
                let exists = matches!(
                    self.transport.read(&lease, &head_key, format::MAX_HEAD_BYTES, cancel).await,
                    Ok(_)
                );
                let state = if exists { ProbeKeyState::Created } else { ProbeKeyState::NotCreated };
                self.mark(request, &head_key, state).await?;
                if state == ProbeKeyState::Created {
                    created_keys.push(head_key.as_str().to_owned());
                }
                log.not_run(ProbeCheckKind::AmbiguousCasRecovery, "mini HEAD create did not commit cleanly");
                return Ok(());
            }
        }
        let head_record = self.transport.read(&lease, &head_key, format::MAX_HEAD_BYTES, cancel).await?;
        let etag = head_record.etag().clone();

        // The verdict of this replacement is deliberately discarded.
        let _ignored = self
            .transport
            .replace(&lease, &head_key, &etag, ProbeRecord::new(to_head_bytes(&head1)?).unwrap(), cancel)
            .await;

        // Recovery: resolve the candidate purely from committed ancestry.
        let current = match self.transport.read(&lease, &head_key, format::MAX_HEAD_BYTES, cancel).await {
            Ok(record) => match decode_head(record.body()) {
                Ok(head) => head,
                Err(err) => {
                    let detail = format!("mini HEAD record rejected: {}", err);
                    log.failed(
                        ProbeCheckKind::AmbiguousCasRecovery,
                        "discarded CAS response recovered through committed ancestry",
                        "mini HEAD record is unreadable",
                        &detail,
                    );
                    return Ok(());
                }
            },
            Err(err) => {
                let detail = format!("mini HEAD read failed: {}", err);
                log.failed(
                    ProbeCheckKind::AmbiguousCasRecovery,
                    "discarded CAS response recovered through committed ancestry",
                    "mini HEAD is unavailable",
                    &detail,
                );
                return Ok(());
            }
        };
        let source = MiniSource { transport: &self.transport, run_id };
        let goal = AncestryGoal { candidate: Some(c1), operations: vec![op1] };
        let outcome = ancestry::walk_ancestry(
            &source,
            lease,
            workspace,
            AncestryCursor::begin(current.commit_id),
            &goal,
            AncestryStop::CandidateOrComplete,
            ancestry::AncestryBounds { max_commits: 8, max_bytes: 256 * 1024 },
            cancel,
        )
        .await;
        match outcome {
            Ok(AncestryProgress::Candidate { commit_id, .. }) if commit_id == c1 => {
                log.passed(
                    ProbeCheckKind::AmbiguousCasRecovery,
                    "discarded CAS response recovered through committed ancestry",
                    "candidate commit found in validated ancestry without using the verdict",
                );
            }
            Ok(AncestryProgress::Candidate { .. }) | Ok(AncestryProgress::Complete { .. }) => {
                log.failed(
                    ProbeCheckKind::AmbiguousCasRecovery,
                    "discarded CAS response recovered through committed ancestry",
                    "candidate commit not found in committed ancestry",
                    "the discarded replacement did not land or the chain is inconsistent",
                );
            }
            Ok(AncestryProgress::Paused { .. }) => {
                log.not_run(
                    ProbeCheckKind::AmbiguousCasRecovery,
                    "bounded mini-ancestry search did not finish",
                );
            }
            Err(err) => {
                let detail = format!("ancestry resolution failed: {}", err);
                log.failed(
                    ProbeCheckKind::AmbiguousCasRecovery,
                    "discarded CAS response recovered through committed ancestry",
                    "ancestry resolution failed",
                    &detail,
                );
            }
        }
        Ok(())
    }
}

/// Writes the deterministic 16 MiB probe capture to `path`, streaming the
/// digest while writing. An existing file at the right size is verified and
/// reused (interrupted-run resume).
async fn write_probe_capture(path: &std::path::Path, cancel: &CancellationToken) -> Result<(u64, Sha256Digest), ProbeError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|_| ProbeError::Staging)?;
    }
    if let Ok(metadata) = tokio::fs::metadata(path).await {
        if metadata.len() == probe_payload_len() {
            let digest = hash_file(path, cancel).await?;
            if digest == probe_payload_sha256() {
                return Ok((probe_payload_len(), digest));
            }
        }
    }
    let mut file = tokio::fs::File::create(path).await.map_err(|_| ProbeError::Staging)?;
    let mut hasher = Sha256::new();
    let mut block = [0u8; PROBE_BLOCK_BYTES];
    for index in 0..PROBE_BLOCKS {
        if cancel.is_cancelled() {
            return Err(ProbeError::Publication(PublicationError::Cancelled));
        }
        probe_payload_block(index, &mut block);
        file.write_all(&block).await.map_err(|_| ProbeError::Staging)?;
        hasher.update(block);
    }
    file.flush().await.map_err(|_| ProbeError::Staging)?;
    file.sync_all().await.map_err(|_| ProbeError::Staging)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    Ok((probe_payload_len(), Sha256Digest::from_bytes(out)))
}

async fn hash_file(path: &std::path::Path, cancel: &CancellationToken) -> Result<Sha256Digest, ProbeError> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path).await.map_err(|_| ProbeError::Staging)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; PROBE_BLOCK_BYTES];
    loop {
        if cancel.is_cancelled() {
            return Err(ProbeError::Publication(PublicationError::Cancelled));
        }
        let read = file.read(&mut buffer).await.map_err(|_| ProbeError::Staging)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    Ok(Sha256Digest::from_bytes(out))
}

/// The full bucket-relative key of an owned probe record under this run's
/// native handle prefix.
fn probe_key(prefix: &str, name: &str) -> hfdrive_core::storage::RelativeKey {
    let full = if prefix.is_empty() { name.to_owned() } else { format!("{prefix}/{name}") };
    hfdrive_core::storage::RelativeKey::new(full).expect("probe keys are validated shapes")
}

/// Native effects whose dispatch outcome is unknown when they fail: the
/// journal keeps the key `CreateInFlight` and a resume reconciles it.
fn native_effect_unknown(err: &NativeError) -> bool {
    matches!(err, NativeError::Cancelled | NativeError::Transport | NativeError::RateLimited { .. })
}

/// S3 effects whose dispatch outcome is unknown when they fail.
fn publication_effect_unknown(err: &PublicationError) -> bool {
    matches!(err, PublicationError::Cancelled | PublicationError::Transport)
}

/// Verifies a journal key belongs to this run and returns its name segment.
fn owned_name(run_id: Uuid, full: &str) -> Option<String> {
    let prefix = format!("hfdrive-probe/{run_id}/");
    full.strip_prefix(&prefix).map(str::to_owned).filter(|name| !name.is_empty())
}

fn wire_delta(before: hfdrive_hf::wire_budget::WireCounters, after: hfdrive_hf::wire_budget::WireCounters) -> WireBytes {
    WireBytes {
        wire_write_bytes: after.wire_write_bytes.saturating_sub(before.wire_write_bytes),
        wire_read_bytes: after.wire_read_bytes.saturating_sub(before.wire_read_bytes),
    }
}
