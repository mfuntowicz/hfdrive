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

/// A HEAD-only boundary: unexpected effects fail the test, never pretend success.
#[derive(Default)]
pub(crate) struct HeadOnlyRemote {
    pub head: Option<RemoteHead>,
    pub head_reads: Arc<AtomicUsize>,
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
        _: MetadataRecord,
        _: &CancellationToken,
    ) -> Result<Bytes, RemoteError> {
        panic!("unexpected metadata read in a HEAD-only scenario")
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
    TestConnection { directory, root, state, account, connection: setup.connection_id, workspace, root_item }
}
