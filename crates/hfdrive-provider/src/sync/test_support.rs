use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

use bytes::Bytes;
use hfdrive_core::ids::{CommitId, OperationId};
use hfdrive_core::storage::{ByteRange, ObjectRef, StableSnapshot};
use hfdrive_hf::{CasCommitCheckpoint, EventCursor, IngestionCheckpoint, NativeError, RangeCache};
use hfdrive_publication::ancestry::AncestryCursor;
use hfdrive_publication::coordinator::{
    InitOutcome, PublicationCandidate, PublishResult, UncertainResolution,
};
use hfdrive_publication::MetadataRecord;
use tokio_util::sync::CancellationToken;

use crate::remote_watch::{EventFeed, RemoteEvents};

use super::remote::{RangeSource, RemoteError, RemoteHead, RemoteOps};

/// A read-only boundary: unexpected effects fail the test, never pretend success.
#[derive(Default)]
pub(crate) struct HeadOnlyRemote {
    pub head: Option<RemoteHead>,
    pub head_reads: Arc<AtomicUsize>,
    pub metadata: Option<Bytes>,
    pub records: Vec<(MetadataRecord, Bytes)>,
    pub metadata_reads: std::sync::Mutex<Vec<MetadataRecord>>,
}

impl HeadOnlyRemote {
    pub fn metadata_read_count(&self, record: MetadataRecord) -> usize {
        self.metadata_reads.lock().unwrap().iter().filter(|read| **read == record).count()
    }

    /// Canonical committed metadata for deterministic planning/cache tests.
    pub async fn catalog(
        workspace: hfdrive_core::ids::WorkspaceId,
        commit: CommitId,
        items: &[hfdrive_core::format::ItemRecord],
    ) -> (Self, hfdrive_core::catalog::CatalogRoot) {
        use hfdrive_core::catalog::{CatalogWriter, InMemoryPageStore, PageSink};
        use hfdrive_core::format::{self, CommitV1, HeadV1};
        use hfdrive_core::ids::{DeviceId, GenerationId};
        let root_item = items.iter().find(|item| item.parent_id.is_none()).unwrap();
        let (root, initial) = hfdrive_core::catalog::initialize(root_item.item_id, root_item.item_revision).unwrap();
        let mut store = InMemoryPageStore::new();
        for (hash, page) in &initial.pages {
            store.store(*hash, page).await.unwrap();
        }
        let mut writer = CatalogWriter::new(&mut store, root);
        for item in items {
            writer.insert_item(item).await.unwrap();
        }
        let catalog = writer.commit().unwrap();
        let mut remote = Self::default();
        for (hash, page) in initial.pages.into_iter().chain(catalog.pages) {
            remote.records.push((MetadataRecord::Catalog(hash), format::to_page_bytes(&page).unwrap().into()));
        }
        for item in items {
            if let Some(version) = item.content_version_id {
                remote.records.push((MetadataRecord::Version(version), version_metadata(workspace, version)));
            }
        }
        let commit_record = CommitV1 {
            format: format::FORMAT_NAME.to_owned(), schema_version: format::SCHEMA_VERSION,
            workspace_id: workspace, commit_id: commit, parent_commit_id: None,
            catalog_root: catalog.root.digest(), operation_ids: vec![root_item.item_revision],
            changes: Vec::new(), device_id: DeviceId::new(),
            created_at: "2026-11-17T00:00:00Z".to_owned(),
        };
        remote.records.push((MetadataRecord::Commit(commit), format::to_commit_bytes(&commit_record).unwrap().into()));
        remote.head = Some(RemoteHead {
            head: HeadV1 {
                format: format::FORMAT_NAME.to_owned(), schema_version: format::SCHEMA_VERSION,
                workspace_id: workspace, root_item_id: root_item.item_id, commit_id: commit,
                generation: GenerationId::new(), required_features: Vec::new(),
            },
            etag: None,
        });
        (remote, catalog.root)
    }
}

pub(crate) fn version_metadata(
    workspace: hfdrive_core::ids::WorkspaceId,
    version: hfdrive_core::ids::VersionId,
) -> Bytes {
    use hfdrive_core::format::{self, DisplayMetadata, VersionV1};
    use hfdrive_core::ids::UploadId;
    use hfdrive_core::storage::{PayloadKey, Sha256Digest, XetFileId};
    format::to_version_bytes(&VersionV1 {
        format: format::FORMAT_NAME.to_owned(), schema_version: format::SCHEMA_VERSION,
        workspace_id: workspace, version_id: version,
        object_key: PayloadKey::new(UploadId::new()), size: 4,
        sha256: Sha256Digest::of(version.as_bytes()),
        xet_file_id: Some(XetFileId::new(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_owned(),
        ).unwrap()),
        display: DisplayMetadata {
            name: "file.bin".to_owned(), modified_at: "2026-11-17T00:00:00Z".to_owned(),
        },
    }).unwrap().into()
}

pub(crate) struct UnusedReader;

impl RangeSource for UnusedReader {
    async fn next_chunk(&mut self, _: &CancellationToken) -> Result<Option<Bytes>, RemoteError> {
        panic!("unexpected range read in a HEAD-only scenario")
    }

    fn cancel(&mut self) {
        panic!("unexpected range cancellation in a HEAD-only scenario")
    }
}

pub(crate) struct UnusedEvents;

impl RemoteEvents for UnusedEvents {
    fn open_events(
        &self,
        _: Option<EventCursor>,
        _: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn EventFeed>, NativeError>> + Send>> {
        Box::pin(async { panic!("unexpected event stream in a HEAD-only scenario") })
    }
}

impl RemoteOps for HeadOnlyRemote {
    type Reader = UnusedReader;
    type Events = UnusedEvents;

    fn event_source(&self) -> Result<Self::Events, RemoteError> {
        Err(RemoteError::Transport)
    }

    async fn read_head(&self, _: &CancellationToken) -> Result<Option<RemoteHead>, RemoteError> {
        self.head_reads.fetch_add(1, Ordering::Relaxed);
        Ok(self.head.clone())
    }

    async fn initialize(
        &self,
        _: PublicationCandidate,
        _: &CancellationToken,
    ) -> Result<InitOutcome, RemoteError> {
        panic!("unexpected initialization in a HEAD-only scenario")
    }

    async fn publish(
        &self,
        _: &RemoteHead,
        _: PublicationCandidate,
        _: &CancellationToken,
    ) -> Result<PublishResult, RemoteError> {
        panic!("unexpected publication in a HEAD-only scenario")
    }

    async fn resolve_uncertain(
        &self,
        _: &PublicationCandidate,
        _: Option<AncestryCursor>,
        _: &CancellationToken,
    ) -> Result<UncertainResolution, RemoteError> {
        panic!("unexpected ancestry resolution in a HEAD-only scenario")
    }

    async fn find_committed_operation(
        &self,
        _: CommitId,
        _: OperationId,
        _: &CancellationToken,
    ) -> Result<Option<CommitId>, RemoteError> {
        panic!("unexpected operation search in a HEAD-only scenario")
    }

    async fn read_metadata(
        &self,
        record: MetadataRecord,
        _: &CancellationToken,
    ) -> Result<Bytes, RemoteError> {
        self.metadata_reads.lock().unwrap().push(record);
        self.records.iter().find(|(key, _)| *key == record).map(|(_, body)| body.clone())
            .or_else(|| self.metadata.clone()).ok_or(RemoteError::RemoteContentUnavailable)
    }

    async fn ingest_payload(
        &self,
        _: &StableSnapshot,
        _: &CancellationToken,
    ) -> Result<IngestionCheckpoint, RemoteError> {
        panic!("unexpected ingestion in a HEAD-only scenario")
    }

    async fn commit_payload_cas(
        &self,
        _: &StableSnapshot,
        _: &IngestionCheckpoint,
        _: &CancellationToken,
    ) -> Result<CasCommitCheckpoint, RemoteError> {
        panic!("unexpected CAS commit in a HEAD-only scenario")
    }

    async fn bind_payload(
        &self,
        _: &StableSnapshot,
        _: &CasCommitCheckpoint,
        _: &CancellationToken,
    ) -> Result<ObjectRef, RemoteError> {
        panic!("unexpected payload binding in a HEAD-only scenario")
    }

    async fn open_range(
        &self,
        _: &ObjectRef,
        _: ByteRange,
        _: &RangeCache,
        _: &CancellationToken,
    ) -> Result<Self::Reader, RemoteError> {
        panic!("unexpected range open in a HEAD-only scenario")
    }

    async fn probe_read(&self, _: &CancellationToken) -> Result<(), RemoteError> {
        panic!("unexpected read probe in a HEAD-only scenario")
    }

    async fn probe_write(&self, _: &CancellationToken) -> Result<(), RemoteError> {
        panic!("unexpected write probe in a HEAD-only scenario")
    }
}

pub(crate) struct TestConnection {
    pub directory: tempfile::TempDir,
    pub root: std::path::PathBuf,
    pub state: hfdrive_state::StateStore,
    pub account: hfdrive_state::AccountStore,
    pub connection: hfdrive_core::ids::ConnectionId,
    pub workspace: hfdrive_core::ids::WorkspaceId,
    pub root_item: hfdrive_core::ids::ItemId,
    pub plan_cache: super::plan::PlanCache,
}

pub(crate) async fn connection_fixture() -> TestConnection {
    use hfdrive_core::ids::{AccountKey, ItemId, WorkspaceId};
    use hfdrive_core::storage::{
        BucketBinding, BucketId, BucketName, DriveBinding, Namespace, OwnerId, OwnerKind, RemotePrefix,
    };
    use hfdrive_state::{AccountRecord, AccountStatus, ConnectionMode, CredentialRef, SetupDraft, StatePaths, StateStore};
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("drive");
    std::fs::create_dir(&root).unwrap();
    let state = StateStore::open(StatePaths::new(directory.path().join("state"))).await.unwrap();
    let key = AccountKey::from_subject("https://huggingface.co", "sync-fixture");
    state.record_account(AccountRecord {
        account_key: key, issuer: "https://huggingface.co".to_owned(), subject: "sync-fixture".to_owned(),
        namespace: "test-user".to_owned(), credential_ref: CredentialRef("oauth.cred".to_owned()),
        auth_epoch: 0, status: AccountStatus::Active,
    }).await.unwrap();
    let workspace = WorkspaceId::new();
    let root_item = ItemId::new();
    let setup = state.reserve_setup(SetupDraft {
        operation_id: OperationId::new(), account_key: key, initialize: false,
        binding: DriveBinding {
            account_key: key, workspace_id: workspace,
            bucket: BucketBinding {
                bucket_id: BucketId::new("test-bucket".to_owned()).unwrap(),
                bucket_name: BucketName::new("test-bucket".to_owned()).unwrap(),
                owner_id: OwnerId::new("test-owner".to_owned()).unwrap(),
                owner_kind: OwnerKind::Personal,
                owner_namespace: Namespace::new("test-user".to_owned()).unwrap(),
            },
            prefix: RemotePrefix::new(format!("hfdrive/{workspace}")).unwrap(),
        },
    }).await.unwrap();
    state.attach_setup_preview(
        setup.setup_id, serde_json::json!({ "root_item_id": root_item.to_string() }),
        root.clone(), ConnectionMode::Writable,
    ).await.unwrap();
    state.finalize_setup(setup.setup_id).await.unwrap();
    let account = state.open_account(key).await.unwrap();
    account.upsert_item(hfdrive_state::ItemRecord {
        connection_id: setup.connection_id, item_id: root_item, parent_id: None,
        name: String::new(), name_key: String::new(), kind: hfdrive_state::ItemKind::Directory,
        revision: OperationId::new(), content_version_id: None, deleted: false,
        metadata_json: serde_json::json!({}),
    }).await.unwrap();
    TestConnection {
        directory, root, state, account, connection: setup.connection_id, workspace, root_item,
        plan_cache: super::plan::PlanCache::default(),
    }
}
