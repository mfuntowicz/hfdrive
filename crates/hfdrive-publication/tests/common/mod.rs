//! Deterministic local fixtures for the publication layer's integration tests.
//!
//! These fixtures implement the production seams ([`PublicationStore`],
//! [`PublicationNative`], [`ProbeTransport`], [`ProbeJournal`]) over an
//! in-memory remote with exact S3 conditional-write semantics and explicit
//! fault injection (applied-but-answered-ambiguously, refused permissions,
//! failed uploads). They exist only for these tests; production wires the
//! real S3 transport and native store.
#![allow(dead_code)]
#![allow(unused_imports)]

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use hfdrive_auth::{
    AuthorizationAuthority, AuthorizationError, AuthorizationLease, SecretAccessToken, TokenSource,
};
use hfdrive_core::catalog::{self, PublishSet};
use hfdrive_core::format::{self, CommitV1, HeadV1, SCHEMA_VERSION};
use hfdrive_core::ids::{
    AccountKey, CommitId, ConnectionId, DeviceId, GenerationId, ItemId, OperationId, SetupId,
    UploadId, VersionId, WorkspaceId,
};
use hfdrive_core::storage::{
    BucketBinding, BucketId, BucketName, ByteRange, DriveBinding, ImmutableKey, Namespace,
    ObjectRef, OwnerId, OwnerKind, PayloadKey, RelativeKey, RemotePrefix, Sha256Digest,
    StableSnapshot, XetFileId,
};
use hfdrive_hf::wire_budget::{BudgetConfig, WireBudget};
use hfdrive_hf::{
    BoundObject, CasCommitCheckpoint, IngestionCheckpoint, NativeApi, NativeError, NativeLease,
    ObjectMetadata, PathInfo, PathKind, PathsInfoReport,
};
use hfdrive_publication::binding::{AccountIdentity, PublicationBinding};
use hfdrive_publication::coordinator::{
    decode_head, HeadVersion, PublicationCandidate, PublicationCoordinator, PublicationNative,
    PublicationStore, RangeSource, UploadEvidence,
};
use hfdrive_publication::probe::{ProbeJournal, ProbeTransport};
use hfdrive_publication::transport::{
    BoundedRecord, MetadataRecord, ProbeKey, ProbeRecord, MAX_PROBE_RECORD_BYTES,
};
use hfdrive_publication::{OpaqueEtag, PublicationError, PublishOutcome};
use hfdrive_state::{ProbeKeyRecord, ProbeKeyState, StateError};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const ISSUER: &str = "https://huggingface.co";
pub const SUBJECT: &str = "fixture-subject";

pub fn account() -> AccountKey {
    AccountKey::from_subject(ISSUER, SUBJECT)
}

/// The in-memory remote: exact bytes per key, strong opaque entity tags,
/// exact conditional semantics, and explicit fault injection.
#[derive(Default)]
pub struct Remote {
    objects: HashMap<String, Vec<u8>>,
    etags: HashMap<String, String>,
    payloads: HashMap<UploadId, Vec<u8>>,
    next_tag: u64,
    /// Apply the next conditional replace but answer `Ambiguous`.
    pub drop_replace_responses: u32,
    /// Apply the next guarded create but answer `Ambiguous`.
    pub drop_create_responses: u32,
    /// Fail the next native upload without applying it.
    pub fail_next_upload: bool,
    /// Refuse fresh native write authorization.
    pub deny_native_write: bool,
    /// Refuse fresh native read authorization.
    pub deny_native_read: bool,
    /// S3 read transactions observed (budget/permission accounting).
    pub s3_reads: u64,
    /// S3 write transactions observed.
    pub s3_writes: u64,
}

impl Remote {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::default()))
    }

    fn tag(&mut self) -> String {
        self.next_tag += 1;
        format!("\"etag-{}\"", self.next_tag)
    }

    /// Seeds exact bytes at a key (test setup and native writes).
    pub fn seed(&mut self, key: &str, bytes: Vec<u8>) {
        let tag = self.tag();
        self.objects.insert(key.to_owned(), bytes);
        self.etags.insert(key.to_owned(), tag);
    }

    pub fn keys_owned(&self) -> impl Iterator<Item = String> + '_ {
        self.objects.keys().cloned()
    }

    pub fn contains(&self, key: &str) -> bool {
        self.objects.contains_key(key)
    }

    pub fn bytes(&self, key: &str) -> Option<Vec<u8>> {
        self.objects.get(key).cloned()
    }

    pub fn etag(&self, key: &str) -> Option<String> {
        self.etags.get(key).cloned()
    }

    /// Exact `If-None-Match: *` create.
    pub fn create(&mut self, key: &str, bytes: Vec<u8>) -> PublishOutcome {
        self.s3_writes += 1;
        if self.objects.contains_key(key) {
            return PublishOutcome::PreconditionFailed;
        }
        self.seed(key, bytes);
        if self.drop_create_responses > 0 {
            self.drop_create_responses -= 1;
            return PublishOutcome::Ambiguous;
        }
        PublishOutcome::Committed
    }

    /// Exact `If-Match` replace.
    pub fn replace(&mut self, key: &str, expected: &str, bytes: Vec<u8>) -> PublishOutcome {
        self.s3_writes += 1;
        match self.etags.get(key) {
            Some(current) if current == expected => {
                self.seed(key, bytes);
                if self.drop_replace_responses > 0 {
                    self.drop_replace_responses -= 1;
                    return PublishOutcome::Ambiguous;
                }
                PublishOutcome::Committed
            }
            _ => PublishOutcome::PreconditionFailed,
        }
    }

    pub fn get(&mut self, key: &str) -> Option<(Vec<u8>, String)> {
        self.s3_reads += 1;
        Some((self.objects.get(key)?.clone(), self.etags.get(key)?.clone()))
    }

    pub fn delete(&mut self, key: &str) -> bool {
        self.s3_writes += 1;
        self.etags.remove(key);
        self.objects.remove(key).is_some()
    }
}

// ---------------------------------------------------------------------------
// Fixture token source: real `NativeLease` values without any network.
// ---------------------------------------------------------------------------

pub struct FixtureTokens {
    authority: AuthorizationAuthority,
}

impl TokenSource for FixtureTokens {
    fn access_token(
        &self,
        account: AccountKey,
    ) -> impl Future<Output = Result<Arc<SecretAccessToken>, AuthorizationError>> + Send {
        async move {
            Ok(Arc::new(SecretAccessToken::new(
                Zeroizing::new("fixture-token".to_owned()),
                account,
                1,
                2_000_000_000,
            )))
        }
    }

    fn refresh_after_unauthorized(
        &self,
        account: AccountKey,
        _rejected_generation: u64,
    ) -> impl Future<Output = Result<Arc<SecretAccessToken>, AuthorizationError>> + Send {
        self.access_token(account)
    }

    fn authorization_lease(
        &self,
        _account: AccountKey,
    ) -> Result<AuthorizationLease, AuthorizationError> {
        self.authority.activate()
    }
}

pub fn lease() -> NativeLease {
    let tokens = Arc::new(FixtureTokens { authority: AuthorizationAuthority::new(account(), 1) });
    NativeApi::new(tokens, account(), "https://huggingface.co".to_owned())
        .unwrap()
        .capture_lease()
        .unwrap()
}

// ---------------------------------------------------------------------------
// Binding builders
// ---------------------------------------------------------------------------

pub fn workspace_id() -> WorkspaceId {
    WorkspaceId::from_uuid(Uuid::from_bytes([3; 16])).unwrap()
}

pub fn drive_binding() -> DriveBinding {
    DriveBinding {
        account_key: account(),
        bucket: BucketBinding {
            bucket_id: BucketId::new("bucket-stable-1".to_owned()).unwrap(),
            bucket_name: BucketName::new("fixture-bucket-1".to_owned()).unwrap(),
            owner_id: OwnerId::new("owner-stable-1".to_owned()).unwrap(),
            owner_kind: OwnerKind::Personal,
            owner_namespace: Namespace::new("alice".to_owned()).unwrap(),
        },
        prefix: RemotePrefix::new("hfdrive/work".to_owned()).unwrap(),
        workspace_id: workspace_id(),
    }
}

pub fn identity() -> (String, String) {
    (ISSUER.to_owned(), SUBJECT.to_owned())
}

pub fn binding() -> PublicationBinding {
    let (issuer, subject) = identity();
    PublicationBinding::new(&drive_binding(), &AccountIdentity { issuer: &issuer, subject: &subject })
        .unwrap()
}

// ---------------------------------------------------------------------------
// Fixture S3 store: the exact conditional `HEAD`/metadata semantics.
// ---------------------------------------------------------------------------

pub struct FixtureStore {
    remote: Arc<Mutex<Remote>>,
    binding: PublicationBinding,
}

impl FixtureStore {
    pub fn new(remote: Arc<Mutex<Remote>>) -> Self {
        Self::with_binding(remote, binding())
    }

    pub fn with_binding(remote: Arc<Mutex<Remote>>, binding: PublicationBinding) -> Self {
        Self { remote, binding }
    }
}

fn metadata_key(binding: &PublicationBinding, record: MetadataRecord) -> String {
    let suffix = match record {
        MetadataRecord::Version(id) => ImmutableKey::Version(id),
        MetadataRecord::Catalog(id) => ImmutableKey::Catalog(id),
        MetadataRecord::Commit(id) => ImmutableKey::Commit(id),
    };
    binding.prefix().immutable_key(suffix).as_str().to_owned()
}

impl PublicationStore for FixtureStore {
    fn binding(&self) -> &PublicationBinding {
        &self.binding
    }

    fn read_head(
        &self,
        _lease: &NativeLease,
        _cancel: &CancellationToken,
    ) -> impl Future<Output = Result<HeadVersion, PublicationError>> + Send {
        async move {
            let key = self.binding.head_key().as_str().to_owned();
            let (body, etag) =
                self.remote.lock().unwrap().get(&key).ok_or(PublicationError::Absent)?;
            let head = decode_head(&body)?;
            Ok(HeadVersion { head, etag: OpaqueEtag::new(etag)? })
        }
    }

    fn create_head(
        &self,
        _lease: &NativeLease,
        head: &HeadV1,
        _cancel: &CancellationToken,
    ) -> impl Future<Output = Result<PublishOutcome, PublicationError>> + Send {
        let body = format::to_head_bytes(head).expect("candidate head is validated");
        async move {
            let key = self.binding.head_key().as_str().to_owned();
            Ok(self.remote.lock().unwrap().create(&key, body))
        }
    }

    fn replace_head(
        &self,
        _lease: &NativeLease,
        expected: &OpaqueEtag,
        head: &HeadV1,
        _cancel: &CancellationToken,
    ) -> impl Future<Output = Result<PublishOutcome, PublicationError>> + Send {
        let body = format::to_head_bytes(head).expect("candidate head is validated");
        let expected = expected.as_str().to_owned();
        async move {
            let key = self.binding.head_key().as_str().to_owned();
            Ok(self.remote.lock().unwrap().replace(&key, &expected, body))
        }
    }

    fn read_metadata(
        &self,
        _lease: &NativeLease,
        record: MetadataRecord,
        _cancel: &CancellationToken,
    ) -> impl Future<Output = Result<BoundedRecord, PublicationError>> + Send {
        async move {
            let key = metadata_key(&self.binding, record);
            let (body, etag) =
                self.remote.lock().unwrap().get(&key).ok_or(PublicationError::Absent)?;
            let etag = OpaqueEtag::new(etag)?;
            Ok(BoundedRecord::from_parts(etag, Bytes::from(body)))
        }
    }
}

// ---------------------------------------------------------------------------
// Fixture native store: immutable record/payload uploads and range reads.
// ---------------------------------------------------------------------------

fn synthetic_xet(sha256: &Sha256Digest) -> XetFileId {
    XetFileId::new(sha256.to_string()).expect("digest hex is a valid Xet identifier spelling")
}

pub struct FixtureRanges {
    bytes: Vec<u8>,
    offset: usize,
}

impl RangeSource for FixtureRanges {
    fn next_chunk(
        &mut self,
        _cancel: &CancellationToken,
    ) -> impl Future<Output = Result<Option<Bytes>, NativeError>> + Send {
        async move {
            if self.offset >= self.bytes.len() {
                return Ok(None);
            }
            let end = (self.offset + 64 * 1024).min(self.bytes.len());
            let chunk = Bytes::copy_from_slice(&self.bytes[self.offset..end]);
            self.offset = end;
            Ok(Some(chunk))
        }
    }
}

pub struct FixtureNative {
    remote: Arc<Mutex<Remote>>,
    drive: DriveBinding,
}

impl FixtureNative {
    pub fn new(remote: Arc<Mutex<Remote>>) -> Self {
        Self::with_drive(remote, drive_binding())
    }

    pub fn with_drive(remote: Arc<Mutex<Remote>>, drive: DriveBinding) -> Self {
        Self { remote, drive }
    }

    fn key(&self, target: ImmutableKey) -> RelativeKey {
        self.drive.prefix.immutable_key(target)
    }

    fn checkpoints(&self, key: &RelativeKey, bytes: &[u8]) -> UploadEvidence {
        let sha256 = Sha256Digest::of(bytes);
        let xet_file_id = synthetic_xet(&sha256);
        UploadEvidence {
            ingestion: IngestionCheckpoint {
                target_key: key.as_str().to_owned(),
                xet_file_id: xet_file_id.clone(),
                size: bytes.len() as u64,
                sha256,
                sdk_task_id: 1,
            },
            cas: CasCommitCheckpoint {
                target_key: key.as_str().to_owned(),
                xet_file_id: xet_file_id.clone(),
                size: bytes.len() as u64,
                sha256,
                sdk_task_id: 1,
            },
            bound: BoundObject {
                key: key.clone(),
                xet_file_id,
                size: bytes.len() as u64,
                sha256,
            },
        }
    }
}

impl PublicationNative for FixtureNative {
    type Ranges = FixtureRanges;

    fn drive(&self) -> &DriveBinding {
        &self.drive
    }

    fn capture_lease(&self) -> Result<NativeLease, NativeError> {
        Ok(lease())
    }

    fn check_read(
        &self,
        _lease: &NativeLease,
        _cancel: &CancellationToken,
    ) -> impl Future<Output = Result<(), NativeError>> + Send {
        async move {
            if self.remote.lock().unwrap().deny_native_read {
                Err(NativeError::PermissionDenied)
            } else {
                Ok(())
            }
        }
    }

    fn check_write(
        &self,
        _lease: &NativeLease,
        _cancel: &CancellationToken,
    ) -> impl Future<Output = Result<(), NativeError>> + Send {
        async move {
            if self.remote.lock().unwrap().deny_native_write {
                Err(NativeError::PermissionDenied)
            } else {
                Ok(())
            }
        }
    }

    fn upload_record(
        &self,
        _lease: &NativeLease,
        target: ImmutableKey,
        bytes: Vec<u8>,
        _cancel: &CancellationToken,
    ) -> impl Future<Output = Result<UploadEvidence, NativeError>> + Send {
        async move {
            let key = self.key(target);
            let mut remote = self.remote.lock().unwrap();
            if remote.fail_next_upload {
                remote.fail_next_upload = false;
                return Err(NativeError::Transport);
            }
            let evidence = self.checkpoints(&key, &bytes);
            remote.seed(key.as_str(), bytes);
            Ok(evidence)
        }
    }

    fn upload_snapshot(
        &self,
        _lease: &NativeLease,
        snapshot: StableSnapshot,
        _cancel: &CancellationToken,
    ) -> impl Future<Output = Result<UploadEvidence, NativeError>> + Send {
        async move {
            let mut remote = self.remote.lock().unwrap();
            if remote.fail_next_upload {
                remote.fail_next_upload = false;
                return Err(NativeError::Transport);
            }
            let bytes = std::fs::read(&snapshot.path).map_err(|_| NativeError::SourceChanged)?;
            if bytes.len() as u64 != snapshot.size || Sha256Digest::of(&bytes) != snapshot.sha256 {
                return Err(NativeError::SourceChanged);
            }
            let key = self.key(ImmutableKey::Payload(snapshot.upload_id));
            let evidence = self.checkpoints(&key, &bytes);
            remote.payloads.insert(snapshot.upload_id, bytes.clone());
            remote.seed(key.as_str(), bytes);
            Ok(evidence)
        }
    }

    fn object_metadata(
        &self,
        _lease: &NativeLease,
        key: &RelativeKey,
        _cancel: &CancellationToken,
    ) -> impl Future<Output = Result<Option<ObjectMetadata>, NativeError>> + Send {
        async move {
            let remote = self.remote.lock().unwrap();
            let Some(bytes) = remote.bytes(key.as_str()) else {
                return Ok(None);
            };
            let xet_file_id = synthetic_xet(&Sha256Digest::of(&bytes));
            Ok(Some(ObjectMetadata {
                key: key.clone(),
                size: bytes.len() as u64,
                xet_file_id: Some(xet_file_id),
            }))
        }
    }

    fn paths_info(
        &self,
        _lease: &NativeLease,
        keys: &[RelativeKey],
        _cancel: &CancellationToken,
    ) -> impl Future<Output = Result<PathsInfoReport, NativeError>> + Send {
        async move {
            let remote = self.remote.lock().unwrap();
            let mut report = PathsInfoReport::default();
            for key in keys {
                match remote.bytes(key.as_str()) {
                    Some(bytes) => report.found.push(PathInfo {
                        key: key.clone(),
                        kind: PathKind::File,
                        size: bytes.len() as u64,
                        xet_file_id: Some(synthetic_xet(&Sha256Digest::of(&bytes))),
                    }),
                    None => report.missing.push(key.clone()),
                }
            }
            Ok(report)
        }
    }

    fn open_range(
        &self,
        _lease: &NativeLease,
        object: &ObjectRef,
        range: ByteRange,
        _cancel: &CancellationToken,
    ) -> impl Future<Output = Result<FixtureRanges, NativeError>> + Send {
        async move {
            let remote = self.remote.lock().unwrap();
            let bytes = remote
                .payloads
                .get(&object.key.upload_id())
                .cloned()
                .ok_or(NativeError::RemoteContentUnavailable)?;
            range.validate_for(bytes.len() as u64).map_err(|_| NativeError::InvalidRange)?;
            let start = range.start() as usize;
            let end = range.end_exclusive() as usize;
            Ok(FixtureRanges { bytes: bytes[start..end].to_vec(), offset: 0 })
        }
    }
}

// ---------------------------------------------------------------------------
// Fixture probe transport and journal.
// ---------------------------------------------------------------------------

pub struct FixtureProbeTransport {
    remote: Arc<Mutex<Remote>>,
    run_id: Uuid,
}

impl FixtureProbeTransport {
    pub fn new(remote: Arc<Mutex<Remote>>, run_id: GenerationId) -> Self {
        Self { remote, run_id: *run_id.as_uuid() }
    }

    fn owned(&self, key: &ProbeKey) -> Result<(), PublicationError> {
        if key.run_id() == self.run_id {
            Ok(())
        } else {
            Err(PublicationError::KeyOutOfScope)
        }
    }
}

impl ProbeTransport for FixtureProbeTransport {
    fn read(
        &self,
        _lease: &NativeLease,
        key: &ProbeKey,
        max_bytes: usize,
        _cancel: &CancellationToken,
    ) -> impl Future<Output = Result<BoundedRecord, PublicationError>> + Send {
        async move {
            self.owned(key)?;
            let (body, etag) = self
                .remote
                .lock()
                .unwrap()
                .get(key.as_str())
                .ok_or(PublicationError::Absent)?;
            if body.len() > max_bytes {
                return Err(PublicationError::RecordTooLarge);
            }
            Ok(BoundedRecord::from_parts(OpaqueEtag::new(etag)?, Bytes::from(body)))
        }
    }

    fn create(
        &self,
        _lease: &NativeLease,
        key: &ProbeKey,
        body: ProbeRecord,
        _cancel: &CancellationToken,
    ) -> impl Future<Output = Result<PublishOutcome, PublicationError>> + Send {
        async move {
            self.owned(key)?;
            Ok(self.remote.lock().unwrap().create(key.as_str(), body.as_bytes().to_vec()))
        }
    }

    fn replace(
        &self,
        _lease: &NativeLease,
        key: &ProbeKey,
        expected: &OpaqueEtag,
        body: ProbeRecord,
        _cancel: &CancellationToken,
    ) -> impl Future<Output = Result<PublishOutcome, PublicationError>> + Send {
        let expected = expected.as_str().to_owned();
        async move {
            self.owned(key)?;
            Ok(self.remote.lock().unwrap().replace(key.as_str(), &expected, body.as_bytes().to_vec()))
        }
    }

    fn delete_owned(
        &self,
        _lease: &NativeLease,
        keys: &[ProbeKey],
        _cancel: &CancellationToken,
    ) -> impl Future<Output = Result<u32, PublicationError>> + Send {
        async move {
            for key in keys {
                self.owned(key)?;
            }
            let mut deleted = 0;
            for key in keys {
                if self.remote.lock().unwrap().delete(key.as_str()) {
                    deleted += 1;
                }
            }
            Ok(deleted)
        }
    }
}

#[derive(Clone, Default)]
pub struct FixtureJournal {
    rows: Arc<Mutex<Vec<ProbeKeyRecord>>>,
}

impl ProbeJournal for FixtureJournal {
    fn reserve(
        &self,
        record: ProbeKeyRecord,
    ) -> impl Future<Output = Result<ProbeKeyRecord, StateError>> + Send {
        async move {
            let mut rows = self.rows.lock().unwrap();
            if !rows.iter().any(|row| row.key == record.key) {
                rows.push(record.clone());
            }
            Ok(record)
        }
    }

    fn set_state(
        &self,
        _connection_id: ConnectionId,
        _run_id: GenerationId,
        key: &str,
        state: ProbeKeyState,
    ) -> impl Future<Output = Result<ProbeKeyRecord, StateError>> + Send {
        let key = key.to_owned();
        async move {
            let mut rows = self.rows.lock().unwrap();
            let row = rows
                .iter_mut()
                .find(|row| row.key == key)
                .expect("state transitions only follow reservations");
            row.state = state;
            Ok(row.clone())
        }
    }

    fn keys(
        &self,
        _connection_id: ConnectionId,
        _run_id: GenerationId,
    ) -> impl Future<Output = Result<Vec<ProbeKeyRecord>, StateError>> + Send {
        async move { Ok(self.rows.lock().unwrap().clone()) }
    }

    fn cleanup_candidates(
        &self,
        _connection_id: ConnectionId,
        _run_id: GenerationId,
    ) -> impl Future<Output = Result<Vec<ProbeKeyRecord>, StateError>> + Send {
        async move {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|row| row.state == ProbeKeyState::Created)
                .cloned()
                .collect())
        }
    }
}

impl FixtureJournal {
    pub fn states(&self) -> Vec<(String, ProbeKeyState)> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .map(|row| (row.key.clone(), row.state))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Candidate builders
// ---------------------------------------------------------------------------

/// The initial publication candidate: empty live-root catalog, one init op.
pub fn initial_candidate(bind: &PublicationBinding) -> PublicationCandidate {
    let root_item_id = ItemId::new();
    let operation = OperationId::new();
    let (catalog_root, publish_set) = catalog::initialize(root_item_id, operation).unwrap();
    let commit = CommitV1 {
        format: format::FORMAT_NAME.to_owned(),
        schema_version: SCHEMA_VERSION,
        workspace_id: bind.workspace_id(),
        commit_id: CommitId::new(),
        parent_commit_id: None,
        catalog_root: catalog_root.digest(),
        operation_ids: vec![operation],
        changes: Vec::new(),
        device_id: DeviceId::new(),
        created_at: "1970-01-01T00:00:00Z".to_owned(),
    };
    let head = HeadV1 {
        format: format::FORMAT_NAME.to_owned(),
        schema_version: SCHEMA_VERSION,
        workspace_id: bind.workspace_id(),
        root_item_id,
        commit_id: commit.commit_id,
        generation: GenerationId::new(),
        required_features: Vec::new(),
    };
    PublicationCandidate { head, commit, versions: Vec::new(), catalog: publish_set, payloads: Vec::new() }
}

/// A candidate advancing `base` with one fresh operation and the unchanged
/// catalog. `catalog_root` is the committed root carried by the base chain.
pub fn next_candidate(
    bind: &PublicationBinding,
    base: &HeadVersion,
    catalog_root: Sha256Digest,
) -> PublicationCandidate {
    let operation = OperationId::new();
    let commit = CommitV1 {
        format: format::FORMAT_NAME.to_owned(),
        schema_version: SCHEMA_VERSION,
        workspace_id: bind.workspace_id(),
        commit_id: CommitId::new(),
        parent_commit_id: Some(base.head.commit_id),
        catalog_root,
        operation_ids: vec![operation],
        changes: Vec::new(),
        device_id: DeviceId::new(),
        created_at: "1970-01-01T00:00:00Z".to_owned(),
    };
    let head = HeadV1 {
        format: format::FORMAT_NAME.to_owned(),
        schema_version: SCHEMA_VERSION,
        workspace_id: bind.workspace_id(),
        root_item_id: base.head.root_item_id,
        commit_id: commit.commit_id,
        generation: GenerationId::new(),
        required_features: Vec::new(),
    };
    let catalog = PublishSet {
        root: catalog::CatalogRoot::from_digest(catalog_root),
        pages: Vec::new(),
        reused_pages: 0,
        loaded_pages: 0,
    };
    PublicationCandidate { head, commit, versions: Vec::new(), catalog, payloads: Vec::new() }
}

pub struct Fixture {
    pub remote: Arc<Mutex<Remote>>,
    pub coordinator: PublicationCoordinator<FixtureNative, FixtureStore>,
}

impl Fixture {
    pub fn new() -> Self {
        let remote = Remote::new();
        let coordinator =
            PublicationCoordinator::new(binding(), FixtureNative::new(remote.clone()), FixtureStore::new(remote.clone()))
                .unwrap();
        Self { remote, coordinator }
    }

    pub fn cancel() -> CancellationToken {
        CancellationToken::new()
    }
}

/// Drives a fresh connection from `initialize_if_absent` to a preserved base
/// `HeadVersion`, returning it and the initial catalog root.
pub async fn initialize_base(fixture: &Fixture) -> (HeadVersion, Sha256Digest) {
    let cancel = CancellationToken::new();
    let bind = binding();
    let candidate = initial_candidate(&bind);
    let catalog_root = candidate.catalog.root.digest();
    let outcome = fixture.coordinator.initialize_if_absent(candidate, &cancel).await.unwrap();
    assert!(matches!(outcome, hfdrive_publication::coordinator::InitOutcome::Committed(_)));
    let base = fixture.coordinator.read_head_with_etag(&cancel).await.unwrap().unwrap();
    (base, catalog_root)
}
