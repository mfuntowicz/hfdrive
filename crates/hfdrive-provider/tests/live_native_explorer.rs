//! Authorized live acceptance: native HF content hydrated through real
//! Windows CFAPI, read-only, independent of the known S3 native-object
//! visibility failure.
//!
//! # Gates
//!
//! Ignored by default. Requires `HFDRIVE_LIVE_ACCEPTANCE=1`, the registered
//! public OAuth client id in `HFDRIVE_OAUTH_CLIENT_ID`, and a completed setup
//! wizard sign-in + supplemental S3 record for `mfuntowicz/drive-dev`. Real
//! network operations run only against that development fixture; the CFAPI
//! root is the explicitly authorized disposable directory
//! `F:\Workspace\hfdrive\artifacts\acceptance\live-hf-root`, which must be
//! empty before the run.
//!
//! # Flow
//!
//! 1. Restore the provider `AuthManager` (real OAuth state) and read the
//!    current account profile.
//! 2. `NativeApi::new_with_budget` + `NativeControl` against
//!    `https://huggingface.co` with a temp Xet cache; verify the fixture's
//!    stable owner/bucket identities.
//! 3. Load the persisted `SetupRecord` for `mfuntowicz/drive-dev` and its
//!    `credential_ref` supplemental record through the exact connection-bound
//!    DPAPI context/entropy production storage uses
//!    (`hfdrive_provider::{setup, storage}`).
//! 4. Publish a valid managed workspace under a fresh owned
//!    `hfdrive-probe/<uuid>/` prefix with one small text file: real native Xet
//!    payload upload, `initialize`, `CatalogWriter`, `CommitV1`, `HeadV1`,
//!    `VersionV1`, `PublicationCandidate`, guarded `initialize_if_absent`.
//!    Payload bytes never travel over S3.
//! 5. Read the actual native HEAD/catalog/commit/version records and ranged
//!    payload back through `NativeControl`/`NativeBucketStore`, asserting
//!    exact bytes and metadata. No read-back path consults S3.
//! 6. Start a real read-only `SyncEngine`/`LiveRemote` runtime on the
//!    authorized root with a temporary engine state directory, connect CFAPI,
//!    wait bounded for the placeholder, open it to force hydration, and assert
//!    the exact bytes. `engine.drain`, unregister and probe-prefix cleanup run
//!    best-effort even when the run fails.
//!
//! # Security
//!
//! Real OAuth credentials and the DPAPI supplemental record are used exactly
//! as production loads them. No secret, token, credential or raw ciphertext is
//! printed or formatted anywhere; the decrypted record lives in the zeroizing
//! buffer returned by `CredentialStore::load_record` and is only handed to
//! `SupplementalCredentialRecord::decode`. There is no fake auth, bucket, or
//! remote response in this file. Cleanup deletes exactly the keys recorded
//! before this run's first external effect, all under this run's unique
//! `hfdrive-probe/<run-id>/` prefix — never user data.
//!
//! # Why a probe store sits under `PublicationCoordinator`
//!
//! The persisted supplemental record is bound (workspace + prefix) to the
//! wizard's managed prefix, and `PublicationBinding::matches_record` requires
//! exact workspace/prefix agreement, so `S3Transport` cannot act as the
//! coordinator's `PublicationStore` for a fresh probe workspace. The public
//! `PublicationStore` seam is implemented below over `S3Transport::probe()`
//! (`hfdrive-probe/<run-id>/…`, exactly the namespace `CapabilityProbe` uses),
//! keeping both required guarantees: the production DPAPI-bound
//! `S3Transport::bind` and a new unique probe prefix per run. S3 is used only
//! for the conditional HEAD create; every read-back assertion is native.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hfdrive_auth::{AuthConfig, AuthManager};
use hfdrive_core::catalog::{CatalogWriter, InMemoryPageStore, PageSink};
use hfdrive_core::format::{
    self, ChangeKind, CommitV1, DisplayMetadata, HeadV1, IndexValue, ItemChange, ItemKind,
    ItemRecord, VersionV1,
};
use hfdrive_core::ids::{
    CommitId, ConnectionId, DeviceId, GenerationId, ItemId, OperationId, SnapshotId, UploadId,
    VersionId, WorkspaceId,
};
use hfdrive_core::storage::{
    BucketBinding, BucketId, BucketName, ByteRange, DriveBinding, ImmutableKey, Namespace, ObjectRef,
    OwnerId, OwnerKind, RemotePrefix, Sha256Digest, StableSnapshot,
};
use hfdrive_hf::wire_budget::WireBudget;
use hfdrive_hf::{
    HeadFormat, HeadRead, NativeApi, NativeBucketStore, NativeConfig, NativeControl, NativeError,
    OwnerLocator,
};
use hfdrive_provider::scheduler::Scheduler;
use hfdrive_provider::sync::remote::LiveRemote;
use hfdrive_provider::sync::{
    registry, ConnectionConfig, ConnectionServices, EngineConfig, SyncEngine,
};
use hfdrive_publication::coordinator::{
    HeadVersion, InitOutcome, PublicationCandidate, PublicationCoordinator, PublicationStore,
};
use hfdrive_publication::transport::{MetadataRecord, ProbeNamespace};
use hfdrive_publication::{
    AccountIdentity, BoundedRecord, OpaqueEtag, ProbeKey, ProbeRecord,
    PublicationBinding, PublicationError, PublishOutcome, S3Transport, SupplementalCredentialRecord,
};
use hfdrive_state::{ConnectionMode, StatePaths, StateStore};
use hfdrive_windows::credentials::{CredentialStore, RecordName};
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Authorized development fixture (only this bucket is ever touched)
// ---------------------------------------------------------------------------

const FIXTURE_OWNER: &str = "mfuntowicz";
const FIXTURE_BUCKET: &str = "drive-dev";
const FIXTURE_OWNER_ID: &str = "5e67c47c100906368940747e";
const FIXTURE_BUCKET_ID: &str = "6af82718bf8a687cc9db3396";
const HF_ENDPOINT: &str = "https://huggingface.co";
const LIVE_ROOT: &str = r"F:\Workspace\hfdrive\artifacts\acceptance\live-hf-root";
const FILE_NAME: &str = "hello-xet.txt";
const FILE_BYTES: &[u8] = b"Hello from the HF Drive live native acceptance harness.\n";
const FILE_MODIFIED_AT: &str = "2026-11-14T00:00:00Z";
const PLACEHOLDER_WAIT: Duration = Duration::from_secs(120);

type LiveResult<T> = Result<T, String>;
type ProbeRemote = LiveRemote<AuthManager, ProbeStore>;

fn err(context: &str, detail: impl std::fmt::Display) -> String {
    format!("{context}: {detail}")
}

/// Every check is an assertion expressed as `Err`; the test fails on the
/// returned error only after best-effort cleanup has run.
fn ensure(condition: bool, message: &str) -> LiveResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

// ---------------------------------------------------------------------------
// Entry point: gates first, cleanup always
// ---------------------------------------------------------------------------

#[ignore = "authorized live HF and CFAPI acceptance only; requires HFDRIVE_LIVE_ACCEPTANCE=1 and HFDRIVE_OAUTH_CLIENT_ID"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_xet_file_hydrates_through_cfapi() {
    if std::env::var_os("HFDRIVE_LIVE_ACCEPTANCE").is_none() {
        eprintln!("skipped: set HFDRIVE_LIVE_ACCEPTANCE=1 to authorize live network and CFAPI effects");
        return;
    }
    let client_id = std::env::var("HFDRIVE_OAUTH_CLIENT_ID")
        .expect("HFDRIVE_OAUTH_CLIENT_ID must hold the registered public OAuth client id");
    assert!(!client_id.trim().is_empty(), "HFDRIVE_OAUTH_CLIENT_ID must not be empty");

    let run_id = uuid::Uuid::new_v4();
    let mut cleanup = Cleanup::new(run_id);
    let outcome = live_run(&client_id, run_id, &mut cleanup).await;
    cleanup.run().await;
    if let Err(failure) = outcome {
        panic!("live native acceptance failed: {failure}");
    }
}

// ---------------------------------------------------------------------------
// Best-effort teardown (always runs: engine drain, unregister, prefix cleanup)
// ---------------------------------------------------------------------------

struct Cleanup {
    probe_prefix: RemotePrefix,
    engine: Option<Arc<SyncEngine<ProbeRemote>>>,
    connection: Option<ConnectionId>,
    user_sid: String,
    native: Option<NativeBucketStore<AuthManager>>,
    /// Full bucket-relative keys created by this run, recorded before dispatch.
    created: Vec<hfdrive_core::storage::RelativeKey>,
    root: PathBuf,
    root_was_empty: bool,
    temp_dirs: Vec<PathBuf>,
}

impl Cleanup {
    fn new(run_id: uuid::Uuid) -> Self {
        Self {
            probe_prefix: RemotePrefix::new(format!("hfdrive-probe/{run_id}"))
                .expect("run-scoped probe prefix is valid"),
            engine: None,
            connection: None,
            user_sid: String::new(),
            native: None,
            created: Vec::new(),
            root: PathBuf::from(LIVE_ROOT),
            root_was_empty: false,
            temp_dirs: Vec::new(),
        }
    }

    async fn run(&mut self) {
        if let Some(engine) = self.engine.take() {
            if let Err(failure) = engine.drain().await {
                eprintln!("best-effort engine drain failed: {failure}");
            }
        }
        if let (Some(connection), false) = (self.connection.take(), self.user_sid.is_empty()) {
            if let Err(failure) = registry::unregister_connection(&self.user_sid, connection) {
                eprintln!("best-effort sync-root unregister failed: {failure}");
            }
        }
        self.delete_created_keys().await;
        // The acceptance root must end as it began: empty. Only this run's own
        // files are ever removed; a pre-existing file is never touched.
        if self.root_was_empty {
            if let Ok(entries) = std::fs::read_dir(&self.root) {
                for entry in entries.flatten() {
                    let removed = if entry.path().is_dir() {
                        std::fs::remove_dir_all(entry.path())
                    } else {
                        std::fs::remove_file(entry.path())
                    };
                    if let Err(failure) = removed {
                        eprintln!("best-effort local cleanup of this run's file failed: {failure}");
                    }
                }
            }
        }
        for dir in &self.temp_dirs {
            if let Err(failure) = std::fs::remove_dir_all(dir) {
                eprintln!("best-effort temp directory cleanup failed: {failure}");
            }
        }
    }

    /// Deletes exactly the recorded keys of this run. Each key is re-validated
    /// to live under this run's unique probe prefix first; anything else is
    /// kept untouched.
    async fn delete_created_keys(&mut self) {
        let Some(native) = self.native.take() else { return };
        let owned_prefix = format!("{}/", self.probe_prefix.as_str());
        let ops: Vec<_> = self
            .created
            .drain(..)
            .filter(|key| key.as_str().starts_with(&owned_prefix))
            .map(hfdrive_hf::BatchOp::Delete)
            .collect();
        if ops.is_empty() {
            return;
        }
        let cancel = CancellationToken::new();
        match native.capture_lease() {
            Ok(lease) => {
                if let Err(failure) = native.apply_batch(&lease, ops, &cancel).await {
                    eprintln!("best-effort probe-prefix cleanup incomplete: {failure}");
                }
            }
            Err(failure) => {
                eprintln!("best-effort probe-prefix cleanup skipped (no live lease): {failure}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Probe-scoped publication store over the real S3 transport
// ---------------------------------------------------------------------------

/// `PublicationStore` for one run's `hfdrive-probe/<run-id>/` namespace, served
/// by the production-bound `S3Transport` exactly like `CapabilityProbe`'s
/// probe namespace. The managed HEAD therefore lives at
/// `hfdrive-probe/<run-id>/HEAD`, and every immutable record at the standard
/// `objects|versions|catalog|commits/…` names beneath it.
pub struct ProbeStore {
    transport: Arc<S3Transport>,
    run_id: uuid::Uuid,
    binding: PublicationBinding,
}

impl ProbeStore {
    fn key(&self, name: &str) -> Result<ProbeKey, PublicationError> {
        ProbeKey::new(self.run_id, name)
    }

    fn record_name(record: &MetadataRecord) -> String {
        match record {
            MetadataRecord::Version(id) => format!("versions/{id}.json"),
            MetadataRecord::Catalog(digest) => format!("catalog/{digest}.json"),
            MetadataRecord::Commit(id) => format!("commits/{id}.json"),
        }
    }

    fn record_max_bytes(record: &MetadataRecord) -> usize {
        match record {
            MetadataRecord::Version(_) => format::MAX_VERSION_BYTES,
            MetadataRecord::Catalog(_) => format::MAX_PAGE_BYTES,
            MetadataRecord::Commit(_) => format::MAX_COMMIT_BYTES,
        }
    }

    fn namespace(&self) -> ProbeNamespace<'_> {
        self.transport.probe(self.run_id)
    }
}

impl PublicationStore for ProbeStore {
    fn binding(&self) -> &PublicationBinding {
        &self.binding
    }

    fn read_head(
        &self,
        lease: &hfdrive_hf::NativeLease,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<HeadVersion, PublicationError>> + Send {
        let namespace = self.namespace();
        let key = self.key("HEAD");
        async move {
            let key = key?;
            let record = namespace.read(lease, &key, format::MAX_HEAD_BYTES, cancel).await?;
            let head = format::from_head_bytes(record.body())
                .map_err(|_| PublicationError::UnsupportedFormat)?;
            Ok(HeadVersion { head, etag: record.etag().clone() })
        }
    }

    fn create_head(
        &self,
        lease: &hfdrive_hf::NativeLease,
        head: &HeadV1,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<PublishOutcome, PublicationError>> + Send {
        let namespace = self.namespace();
        let key = self.key("HEAD");
        let bytes = format::to_head_bytes(head);
        async move {
            let key = key?;
            let bytes = bytes.map_err(|_| PublicationError::UnsupportedFormat)?;
            namespace
                .create(lease, &key, ProbeRecord::new(bytes)?, cancel)
                .await
        }
    }

    fn replace_head(
        &self,
        lease: &hfdrive_hf::NativeLease,
        expected: &OpaqueEtag,
        head: &HeadV1,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<PublishOutcome, PublicationError>> + Send {
        let namespace = self.namespace();
        let key = self.key("HEAD");
        let bytes = format::to_head_bytes(head);
        async move {
            let key = key?;
            let bytes = bytes.map_err(|_| PublicationError::UnsupportedFormat)?;
            namespace
                .replace(lease, &key, expected, ProbeRecord::new(bytes)?, cancel)
                .await
        }
    }

    fn read_metadata(
        &self,
        lease: &hfdrive_hf::NativeLease,
        record: MetadataRecord,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<BoundedRecord, PublicationError>> + Send {
        let namespace = self.namespace();
        let name = Self::record_name(&record);
        let max_bytes = Self::record_max_bytes(&record);
        async move {
            let key = ProbeKey::new(self.run_id, &name)?;
            namespace.read(lease, &key, max_bytes, cancel).await
        }
    }
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

async fn live_run(client_id: &str, run_id: uuid::Uuid, cleanup: &mut Cleanup) -> LiveResult<()> {
    let cancel = CancellationToken::new();

    // ---- 1. real OAuth identity restored by the provider AuthManager ----

    let state_root = hfdrive_windows::ownership::default_state_root()
        .map_err(|failure| err("provider state root unavailable", failure))?;
    let control_state = Arc::new(
        StateStore::open(StatePaths::new(state_root.clone()))
            .await
            .map_err(|failure| err("provider control state failed to open", failure))?,
    );
    let account = control_state
        .selected_account()
        .await
        .map_err(|failure| err("selected account lookup failed", failure))?
        .ok_or_else(|| {
            "no selected account in the provider control state; complete the setup wizard first"
                .to_owned()
        })?;
    let auth = AuthManager::new(
        AuthConfig::with_client_id(Some(client_id.to_owned())),
        state_root.clone(),
        Some(account),
    );
    let profile = auth
        .active_profile()
        .ok_or_else(|| "the restored account has no live profile; sign in first".to_owned())?;
    ensure(
        profile.account_key == account,
        "the restored profile is not the selected account",
    )?;

    // ---- 2. native control over the authorized development fixture ----

    let budget = WireBudget::new(Default::default());
    let xet_cache = std::env::temp_dir().join(format!("hfdrive-live-xet-{run_id}"));
    std::fs::create_dir_all(&xet_cache).map_err(|failure| err("temp Xet cache creation failed", failure))?;
    cleanup.temp_dirs.push(xet_cache.clone());

    let native_config = NativeConfig {
        endpoint: HF_ENDPOINT.to_owned(),
        xet_cache_dir: xet_cache,
        ..Default::default()
    };
    let api = NativeApi::new_with_budget(
        Arc::new(auth.clone()),
        account,
        HF_ENDPOINT.to_owned(),
        budget.clone(),
    )
    .map_err(|failure| err("native API construction failed", failure))?;
    let control = NativeControl::new(api, native_config);
    let lease = control
        .capture_lease()
        .map_err(|failure| err("native lease capture failed", failure))?;

    // Stable identities, never display names, select the fixture.
    let owner_id = OwnerId::new(FIXTURE_OWNER_ID.to_owned())
        .map_err(|failure| err("fixture owner id invalid", failure))?;
    let bucket_id = BucketId::new(FIXTURE_BUCKET_ID.to_owned())
        .map_err(|failure| err("fixture bucket id invalid", failure))?;
    let namespace = Namespace::new(FIXTURE_OWNER.to_owned())
        .map_err(|failure| err("fixture namespace invalid", failure))?;
    let bucket_name = BucketName::new(FIXTURE_BUCKET.to_owned())
        .map_err(|failure| err("fixture bucket name invalid", failure))?;
    let owner = control
        .verify_owner(
            &lease,
            &OwnerLocator {
                owner_id: owner_id.clone(),
                owner_kind: OwnerKind::Personal,
                claimed_namespace: Some(namespace.clone()),
            },
            &cancel,
        )
        .await
        .map_err(|failure| err("native owner verification failed", failure))?;
    ensure(
        owner.owner_id().as_str() == FIXTURE_OWNER_ID
            && owner.owner_namespace().as_str() == FIXTURE_OWNER,
        "verified owner does not match the fixture identities",
    )?;
    let summary = control
        .resolve_bucket(&lease, &owner.owner_ref(), &bucket_name, Some(&bucket_id), &cancel)
        .await
        .map_err(|failure| err("native bucket resolution failed", failure))?
        .ok_or_else(|| "the dev fixture bucket does not exist for this account".to_owned())?;
    let live_bucket: &BucketBinding = &summary.binding;
    ensure(
        live_bucket.bucket_id.as_str() == FIXTURE_BUCKET_ID
            && live_bucket.bucket_name.as_str() == FIXTURE_BUCKET
            && live_bucket.owner_id.as_str() == FIXTURE_OWNER_ID
            && live_bucket.owner_namespace.as_str() == FIXTURE_OWNER,
        "live bucket identity does not match the development fixture",
    )?;

    // ---- 3. SetupRecord + supplemental record, exact production DPAPI load ----

    let setups = control_state
        .list_setups(Some(account))
        .await
        .map_err(|failure| err("setup reservation lookup failed", failure))?;
    let setup = setups
        .into_iter()
        .filter(|record| {
            record.account_key == account
                && record.binding.bucket.bucket_id.as_str() == FIXTURE_BUCKET_ID
                && record.binding.bucket.bucket_name.as_str() == FIXTURE_BUCKET
                && record.credential_ref.is_some()
        })
        .next_back()
        .ok_or_else(|| {
            "no SetupRecord with supplemental credentials for mfuntowicz/drive-dev; \
             run the setup wizard first"
                .to_owned()
        })?;
    let credential_ref = setup
        .credential_ref
        .clone()
        .ok_or_else(|| "the SetupRecord has no credential_ref".to_owned())?;

    // Exact connection-bound DPAPI context/entropy used by production storage
    // (`hfdrive_provider::storage::native_parts` / `setup::set_publication_credentials`):
    // record name `s3-<connection-id>`, entropy over the binding's protection
    // context keyed by the connection id.
    let identity = AccountIdentity {
        issuer: &profile.issuer,
        subject: &profile.subject,
    };
    let setup_publication = PublicationBinding::new(&setup.binding, &identity)
        .map_err(|_| "the SetupRecord binding does not match the signed-in identity".to_owned())?;
    let protection_context = setup_publication.protection_context(*setup.connection_id.as_uuid());
    let entropy = protection_context
        .entropy(*setup.connection_id.as_uuid())
        .map_err(|failure| err("protection entropy derivation failed", failure))?;
    let credential_name =
        RecordName::new(&credential_ref.0).map_err(|failure| err("credential name invalid", failure))?;
    let credential_store = CredentialStore::open(
        StatePaths::new(state_root).account(account).credentials(),
    )
    .map_err(|failure| err("credential store unavailable", failure))?;
    let plaintext = credential_store
        .load_record(&credential_name, Some(&entropy))
        .map_err(|_| {
            "the DPAPI supplemental record did not decrypt with the production \
             connection-bound entropy"
                .to_owned()
        })?;
    let supplemental = SupplementalCredentialRecord::decode(plaintext.expose())
        .map_err(|_| "the decrypted supplemental record is malformed".to_owned())?;
    supplemental
        .validate_context(&protection_context)
        .map_err(|_| "the supplemental record context does not match the production binding".to_owned())?;
    drop(plaintext);

    // ---- probe workspace: fresh owned prefix, one small text file ----

    let workspace = WorkspaceId::new();
    let probe_prefix = cleanup.probe_prefix.clone();
    let binding = DriveBinding {
        account_key: account,
        bucket: live_bucket.clone(),
        prefix: probe_prefix.clone(),
        workspace_id: workspace,
    };
    // `S3Transport::bind` runs the production binding + credential validation
    // against the wizard binding; its probe namespace then serves this run's
    // probe prefix keys (the namespace `CapabilityProbe` uses).
    let transport = S3Transport::bind(&setup.binding, &identity, &supplemental, budget)
        .map_err(|failure| err("supplemental S3 transport binding failed", failure))?;
    let transport = Arc::new(transport);
    let native = control
        .open_store(binding.clone())
        .map_err(|failure| err("native bucket store open failed", failure))?;
    cleanup.native = Some(native.clone());

    let publication_binding = PublicationBinding::new(&binding, &identity)
        .map_err(|_| "the probe workspace binding does not match the signed-in identity".to_owned())?;
    let store = ProbeStore {
        transport,
        run_id,
        binding: publication_binding.clone(),
    };
    let coordinator = PublicationCoordinator::new(publication_binding, native.clone(), store)
        .map_err(|failure| err("publication coordinator construction failed", failure))?;

    // ---- 4. publish the workspace through real native Xet + guarded HEAD ----

    let staging = std::env::temp_dir().join(format!("hfdrive-live-stage-{run_id}"));
    std::fs::create_dir_all(&staging).map_err(|failure| err("staging directory creation failed", failure))?;
    cleanup.temp_dirs.push(staging.clone());
    let capture = staging.join(FILE_NAME);
    tokio::fs::write(&capture, FILE_BYTES)
        .await
        .map_err(|failure| err("payload capture write failed", failure))?;

    let size = FILE_BYTES.len() as u64;
    let sha256 = Sha256Digest::of(FILE_BYTES);
    let snapshot = StableSnapshot {
        snapshot_id: SnapshotId::new(),
        upload_id: UploadId::new(),
        path: capture,
        size,
        sha256,
    };
    // Real native Xet upload: ingestion -> CAS commit -> binding. Payload
    // bytes never use S3.
    let placement = coordinator
        .upload_payload(snapshot, &cancel)
        .await
        .map_err(|failure| err("native Xet payload upload failed", failure))?;
    ensure(
        placement.object.size == size && placement.object.sha256 == sha256,
        "the bound native payload disagrees with the flushed capture",
    )?;

    let root_item = ItemId::new();
    let file_item = ItemId::new();
    let version_id = VersionId::new();
    let init_op = OperationId::new();
    let file_op = OperationId::new();
    let commit_id = CommitId::new();
    let generation = GenerationId::new();
    let device_id = DeviceId::new();

    // `initialize` + `CatalogWriter`: initial empty catalog (live root
    // directory) with the one file added through the copy-on-write B+tree.
    let (empty_root, initial) = hfdrive_core::catalog::initialize(root_item, init_op)
        .map_err(|failure| err("initial catalog construction failed", failure))?;
    let mut pages = InMemoryPageStore::new();
    for (hash, page) in &initial.pages {
        PageSink::store(&mut pages, *hash, page)
            .await
            .map_err(|failure| err("catalog page seeding failed", failure))?;
    }
    let mut writer = CatalogWriter::new(&mut pages, empty_root);
    let file_record = ItemRecord {
        item_id: file_item,
        parent_id: Some(root_item),
        name: FILE_NAME.to_owned(),
        kind: ItemKind::File,
        item_revision: file_op,
        content_version_id: Some(version_id),
        deleted: false,
        content_operation: file_op,
        location_operation: file_op,
        deletion_operation: None,
    };
    writer
        .insert_item(&file_record)
        .await
        .map_err(|failure| err("catalog file insertion failed", failure))?;
    let publish_set = writer
        .commit()
        .map_err(|failure| err("catalog commit failed", failure))?;
    let catalog_root = publish_set.root.digest();

    let version = VersionV1 {
        format: format::FORMAT_NAME.to_owned(),
        schema_version: format::SCHEMA_VERSION,
        workspace_id: workspace,
        version_id,
        object_key: placement.object.key,
        size,
        sha256,
        xet_file_id: Some(placement.object.xet_file_id.clone()),
        display: DisplayMetadata {
            name: FILE_NAME.to_owned(),
            modified_at: FILE_MODIFIED_AT.to_owned(),
        },
    };
    let mut operation_ids = vec![init_op, file_op];
    operation_ids.sort();
    let mut changes = vec![
        ItemChange {
            item_id: root_item,
            change: ChangeKind::Create,
            old_revision: None,
            new_revision: init_op,
        },
        ItemChange {
            item_id: file_item,
            change: ChangeKind::Create,
            old_revision: None,
            new_revision: file_op,
        },
    ];
    changes.sort_by_key(|change| change.item_id);
    let commit = CommitV1 {
        format: format::FORMAT_NAME.to_owned(),
        schema_version: format::SCHEMA_VERSION,
        workspace_id: workspace,
        commit_id,
        parent_commit_id: None,
        catalog_root,
        operation_ids,
        changes,
        device_id,
        created_at: FILE_MODIFIED_AT.to_owned(),
    };
    let head = HeadV1 {
        format: format::FORMAT_NAME.to_owned(),
        schema_version: format::SCHEMA_VERSION,
        workspace_id: workspace,
        root_item_id: root_item,
        commit_id,
        generation,
        required_features: Vec::new(),
    };
    let head_bytes = format::to_head_bytes(&head)
        .map_err(|failure| err("HEAD record encoding failed", failure))?;

    // Record every key this run will create before the first record effect, so
    // cleanup deletes exactly what this run created.
    let payload_key = binding.prefix.immutable_key(placement.object.key.immutable_key());
    let version_key = binding.prefix.immutable_key(ImmutableKey::Version(version_id));
    let commit_key = binding.prefix.immutable_key(ImmutableKey::Commit(commit_id));
    let head_key = binding.prefix.head_key();
    cleanup.created.push(payload_key.clone());
    cleanup.created.push(version_key.clone());
    cleanup.created.push(commit_key.clone());
    for (digest, _) in &publish_set.pages {
        cleanup
            .created
            .push(binding.prefix.immutable_key(ImmutableKey::Catalog(*digest)));
    }
    cleanup.created.push(head_key.clone());

    let candidate = PublicationCandidate {
        head,
        commit,
        versions: vec![version.clone()],
        catalog: publish_set,
        payloads: vec![placement.object.clone()],
    };
    // Immutable payload + metadata through the native Xet path, then exactly
    // one conditional HEAD create (`If-None-Match: *`).
    match coordinator
        .initialize_if_absent(candidate, &cancel)
        .await
        .map_err(|failure| err("guarded workspace initialization failed", failure))?
    {
        InitOutcome::Committed(evidence) => {
            ensure(
                evidence.head_bytes_sha256 == Sha256Digest::of(&head_bytes),
                "published HEAD bytes do not match the constructed HEAD",
            )?;
        }
        InitOutcome::AlreadyInitialized { .. } => {
            return Err(format!(
                "a HEAD already exists under the fresh probe prefix {}; the prefix must be new per run",
                probe_prefix.as_str()
            ));
        }
        InitOutcome::Ambiguous(_) => {
            return Err(
                "the conditional HEAD create was dispatched but its outcome is unknown; \
                 ancestry recovery is required before re-running"
                    .to_owned(),
            );
        }
    }

    // ---- 5. native read-back: HEAD, catalog, commit, version, payload ----

    // Native HEAD: exact bytes first, then decoded identity. Never S3.
    let head_back = read_native_head(&control, &lease, &binding, &cancel).await?;
    ensure(
        head_back.bytes == head_bytes,
        "the native HEAD record bytes differ from the published HEAD record",
    )?;
    let HeadFormat::V1 { workspace_id: head_workspace } = head_back.format else {
        return Err("the native HEAD record carries an unsupported format".to_owned());
    };
    ensure(head_workspace == workspace, "the native HEAD workspace differs")?;
    let head_record = format::from_head_bytes(&head_back.bytes)
        .map_err(|failure| err("native HEAD record does not decode", failure))?;
    ensure(
        head_record.workspace_id == workspace
            && head_record.root_item_id == root_item
            && head_record.commit_id == commit_id
            && head_record.generation == generation,
        "the native HEAD identity differs from the published HEAD",
    )?;

    // Native commit record.
    let commit_bytes =
        read_native_record(&native, &lease, &commit_key, format::MAX_COMMIT_BYTES, &cancel).await?;
    let commit_back = format::from_commit_bytes(&commit_bytes)
        .map_err(|failure| err("native commit record does not decode", failure))?;
    ensure(
        commit_back.workspace_id == workspace
            && commit_back.commit_id == commit_id
            && commit_back.parent_commit_id.is_none()
            && commit_back.catalog_root == catalog_root
            && commit_back.device_id == device_id,
        "the native commit record differs from the published commit",
    )?;
    ensure(
        commit_back.operation_ids.contains(&init_op) && commit_back.operation_ids.contains(&file_op),
        "the native commit record lost the published operations",
    )?;

    // Native catalog page: hash-addressed root page and the exact file item.
    let catalog_key = binding.prefix.immutable_key(ImmutableKey::Catalog(catalog_root));
    let page_bytes =
        read_native_record(&native, &lease, &catalog_key, format::MAX_PAGE_BYTES, &cancel).await?;
    let root_page = format::from_page_bytes(&page_bytes)
        .map_err(|failure| err("native catalog page does not decode", failure))?;
    let (page_hash, _) = hfdrive_core::catalog::encode_and_hash(&root_page)
        .map_err(|failure| err("native catalog page re-hash failed", failure))?;
    ensure(page_hash == catalog_root, "the native catalog page hash mismatch")?;
    let item = match &root_page {
        format::CatalogPage::Leaf(leaf) => leaf
            .entries
            .iter()
            .find_map(|entry| match &entry.value {
                IndexValue::Item(item) if item.item_id == file_item => Some(item.clone()),
                _ => None,
            }),
        format::CatalogPage::Branch(_) => None,
    }
    .ok_or_else(|| "the file item is missing from the native catalog page".to_owned())?;
    ensure(
        item.name == FILE_NAME
            && item.kind == ItemKind::File
            && item.parent_id == Some(root_item)
            && item.content_version_id == Some(version_id)
            && item.item_revision == file_op
            && !item.deleted
            && item.content_operation == file_op
            && item.location_operation == file_op
            && item.deletion_operation.is_none(),
        "the native catalog file item metadata differs from the published item",
    )?;

    // Native version record metadata.
    let version_bytes =
        read_native_record(&native, &lease, &version_key, format::MAX_VERSION_BYTES, &cancel).await?;
    let version_back = format::from_version_bytes(&version_bytes)
        .map_err(|failure| err("native version record does not decode", failure))?;
    ensure(
        version_back.version_id == version_id
            && version_back.object_key == placement.object.key
            && version_back.size == size
            && version_back.sha256 == sha256
            && version_back.xet_file_id == Some(placement.object.xet_file_id.clone())
            && version_back.display.name == FILE_NAME
            && version_back.display.modified_at == FILE_MODIFIED_AT,
        "the native version record metadata differs from the published version",
    )?;

    // Native ranged payload: full object and a boundary slice, byte-exact.
    let full = read_native_range(
        &native,
        &lease,
        &placement.object,
        ByteRange::new(0, size, size).map_err(|failure| err("full range invalid", failure))?,
        &cancel,
    )
    .await?;
    ensure(full == FILE_BYTES, "the full native range read differs from the source bytes")?;
    let (slice_start, slice_end) = (6u64, size.min(20));
    let slice = read_native_range(
        &native,
        &lease,
        &placement.object,
        ByteRange::new(slice_start, slice_end, size)
            .map_err(|failure| err("slice range invalid", failure))?,
        &cancel,
    )
    .await?;
    ensure(
        slice == FILE_BYTES[slice_start as usize..slice_end as usize],
        "the sliced native range read differs from the source bytes",
    )?;

    // Native metadata for every record of the run.
    let report = native
        .paths_info(
            &lease,
            &[
                head_key.clone(),
                payload_key.clone(),
                catalog_key.clone(),
                commit_key.clone(),
                version_key.clone(),
            ],
            &cancel,
        )
        .await
        .map_err(|failure| err("native paths-info failed", failure))?;
    let info_of = |key: &hfdrive_core::storage::RelativeKey| {
        report
            .found
            .iter()
            .find(|info| info.key == *key)
            .ok_or_else(|| format!("native metadata is absent for {}", key.as_str()))
    };
    ensure(
        info_of(&payload_key)?.size == size
            && info_of(&catalog_key)?.size == page_bytes.len() as u64
            && info_of(&commit_key)?.size == commit_bytes.len() as u64
            && info_of(&version_key)?.size == version_bytes.len() as u64,
        "native metadata sizes differ from the published records",
    )?;
    ensure(
        info_of(&payload_key)?.xet_file_id == Some(placement.object.xet_file_id.clone()),
        "the native payload lost its Xet identity (native capability gate)",
    )?;

    // ---- 6. read-only SyncEngine/LiveRemote runtime + real CFAPI hydration ----

    let root = PathBuf::from(LIVE_ROOT);
    std::fs::create_dir_all(&root).map_err(|failure| err("acceptance root creation failed", failure))?;
    let root_empty = std::fs::read_dir(&root)
        .map_err(|failure| err("acceptance root inspection failed", failure))?
        .next()
        .is_none();
    if !root_empty {
        return Err(format!(
            "the acceptance root {} must be empty before the run",
            root.display()
        ));
    }
    cleanup.root_was_empty = true;
    cleanup.root = root.clone();

    // SEAM(parent): user SID of the current Windows user. Derivation from the
    // canonical pipe name avoids a second SID API; swap if `hfdrive_windows`
    // exposes one.
    let pipe = hfdrive_windows::ipc::current_pipe_name()
        .map_err(|failure| err("canonical pipe name unavailable", failure))?;
    let user_sid = pipe
        .strip_prefix(r"\\.\pipe\LOCAL\HFDrive.")
        .and_then(|value| value.strip_suffix(".v1"))
        .ok_or_else(|| "cannot derive the user SID from the canonical pipe name".to_owned())?
        .to_owned();
    cleanup.user_sid = user_sid.clone();

    // Temporary engine state directory: the acceptance run never writes into
    // the provider's durable state.
    let engine_dir = std::env::temp_dir().join(format!("hfdrive-live-engine-{run_id}"));
    std::fs::create_dir_all(engine_dir.join("snapshots"))
        .map_err(|failure| err("engine staging creation failed", failure))?;
    std::fs::create_dir_all(engine_dir.join("recovery"))
        .map_err(|failure| err("engine recovery creation failed", failure))?;
    cleanup.temp_dirs.push(engine_dir.clone());
    let engine_state = Arc::new(
        StateStore::open(StatePaths::new(engine_dir.clone()))
            .await
            .map_err(|failure| err("temporary engine state failed to open", failure))?,
    );

    let engine = Arc::new(SyncEngine::new(
        EngineConfig {
            state_dir: engine_dir.clone(),
            user_sid: user_sid.clone(),
            device_id,
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        engine_state.clone(),
        Arc::new(Scheduler::new(Default::default())),
        cancel.child_token(),
    ));
    let connection = ConnectionId::new();
    let admission = engine
        .admit(connection, &root, &binding)
        .await
        .map_err(|failure| err("root admission refused", failure))?;
    let account_store = engine_state
        .open_account(account)
        .await
        .map_err(|failure| err("temporary account store failed to open", failure))?;

    // Read-only runtime: committed state is rendered through the native
    // bounded record/range paths; no publication credentials reach it.
    let remote = LiveRemote::new(native.clone(), control, None);
    let _runtime = engine
        .connect(
            ConnectionConfig {
                connection_id: connection,
                workspace,
                root_item_id: root_item,
                device_id,
                root: root.clone(),
                staging_dir: engine_dir.join("snapshots"),
                recovery_dir: engine_dir.join("recovery"),
                mode: ConnectionMode::ReadOnly,
                start_paused: false,
            },
            ConnectionServices {
                remote,
                root_item_id: root_item,
            },
            &admission.validated,
            account_store,
        )
        .await
        .map_err(|failure| err("engine connect (CFAPI registration) failed", failure))?;
    cleanup.engine = Some(engine.clone());
    cleanup.connection = Some(connection);

    // Bounded wait for the placeholder, then ordinary file I/O forces real
    // CFAPI hydration through the provider's FETCH_DATA callback.
    let file_path = root.join(FILE_NAME);
    let deadline = tokio::time::Instant::now() + PLACEHOLDER_WAIT;
    let hydrated = loop {
        if let Ok(bytes) = tokio::fs::read(&file_path).await {
            break Some(bytes);
        }
        if tokio::time::Instant::now() >= deadline {
            break None;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    };
    let hydrated = hydrated.ok_or_else(|| {
        format!(
            "{FILE_NAME} did not appear and hydrate under {} within {PLACEHOLDER_WAIT:?}",
            root.display()
        )
    })?;
    ensure(
        hydrated == FILE_BYTES,
        "the CFAPI-hydrated bytes differ from the published bytes",
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Native read helpers
// ---------------------------------------------------------------------------

/// Native HEAD read through `NativeControl`'s bounded managed-record path.
///
async fn read_native_head(
    control: &NativeControl<AuthManager>,
    lease: &hfdrive_hf::NativeLease,
    binding: &DriveBinding,
    cancel: &CancellationToken,
) -> LiveResult<hfdrive_hf::HeadRecord> {
    match control
        .read_head_record(lease, &binding.bucket, &binding.prefix, cancel)
        .await
        .map_err(|failure| err("native HEAD record read failed", failure))?
    {
        HeadRead::Record(record) => Ok(record),
        HeadRead::TooLarge { .. } => Err("the native HEAD record exceeds the format bound".to_owned()),
        HeadRead::Missing => Err("the native HEAD record is absent after publication".to_owned()),
    }
}

/// Native bounded immutable-record read (`NativeBucketStore`).
async fn read_native_record(
    native: &NativeBucketStore<AuthManager>,
    lease: &hfdrive_hf::NativeLease,
    key: &hfdrive_core::storage::RelativeKey,
    max_bytes: usize,
    cancel: &CancellationToken,
) -> LiveResult<Vec<u8>> {
    let bytes = native
        .read_record(lease, key, max_bytes, cancel)
        .await
        .map_err(|failure| err("native record read failed", failure))?
        .ok_or_else(|| format!("native record is absent for {}", key.as_str()))?;
    Ok(bytes.to_vec())
}

/// Native bounded ordered Xet range read. No whole-file fallback exists.
async fn read_native_range(
    native: &NativeBucketStore<AuthManager>,
    lease: &hfdrive_hf::NativeLease,
    object: &ObjectRef,
    range: ByteRange,
    cancel: &CancellationToken,
) -> LiveResult<Vec<u8>> {
    let mut reader = native
        .open_range(lease, object, range, cancel)
        .await
        .map_err(|failure| err("native range open failed", failure))?;
    reader.start();
    let mut out = Vec::with_capacity(range.len() as usize);
    loop {
        match reader.next_chunk(cancel).await {
            Ok(Some(chunk)) => out.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(NativeError::InvalidRange) if out.len() as u64 == range.len() => break,
            Err(failure) => return Err(err("native range read failed", failure)),
        }
    }
    ensure(
        out.len() as u64 == range.len(),
        "native range read returned a different byte count than requested",
    )?;
    Ok(out)
}
