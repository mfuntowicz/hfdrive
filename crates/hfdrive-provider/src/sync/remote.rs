//! The remote effect boundary of the synchronization engine.
//!
//! Every network-visible effect of the sync loop goes through [`RemoteOps`]:
//! managed-`HEAD` reads, guarded publication, uncertain-write resolution,
//! staged native-Xet payload upload checkpoints and bounded range reads. The
//! production implementation [`LiveRemote`] composes the delivered
//! `hfdrive-publication` coordinator (guarded conditional `HEAD` CAS over the
//! explicit supplemental S3 pair) with the drive-bound `hfdrive-hf` native
//! bucket store (Xet payloads and metadata). A read-only connection uses the
//! same boundary with publication disabled: native reads always work, every
//! mutation reports [`RemoteError::ReadOnly`].
//!
//! Nothing here invents success. Cancellation and transport failure after a
//! request was dispatched surface as [`RemoteError::Cancelled`] /
//! [`RemoteError::Transport`] and are resolved by ancestry reconciliation,
//! never by blind replay.

use hfdrive_core::format::HeadV1;
use hfdrive_core::ids::{CommitId, OperationId};
use hfdrive_core::storage::{ByteRange, ObjectRef, StableSnapshot};
use hfdrive_hf::{CasCommitCheckpoint, IngestionCheckpoint, NativeError};
use hfdrive_publication::ancestry::AncestryCursor;
use hfdrive_publication::coordinator::{InitOutcome, PublicationCandidate, PublishResult, UncertainResolution};
use hfdrive_publication::{MetadataRecord, OpaqueEtag, PublicationError};
use hfdrive_state::RetryClass;
use tokio_util::sync::CancellationToken;

/// Unified, non-secret remote failure. Retry classification is explicit so
/// the outbox can park work instead of spinning.
#[derive(Debug, thiserror::Error)]
pub enum RemoteError {
    #[error("sign-in is required before remote work")]
    NeedsSignIn,
    #[error("remote access was denied")]
    PermissionDenied,
    #[error("supplemental publication authorization is missing")]
    StorageSetupRequired,
    #[error("the connection is read-only for this operation")]
    ReadOnly,
    #[error("remote format is unsupported")]
    UnsupportedFormat,
    #[error("a referenced immutable remote object is unavailable")]
    RemoteContentUnavailable,
    #[error("remote transport failed")]
    Transport,
    #[error("the committed-ancestry search could not decide; retry")]
    SearchIncomplete,
    #[error("remote service throttled this connection")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("the staged source changed after capture")]
    SourceChanged,
    #[error("remote request was cancelled")]
    Cancelled,
    #[error("remote request was rejected: {detail}")]
    Rejected { detail: String },
    #[error("remote response violated the storage contract")]
    InvalidResponse,
}

impl RemoteError {
    /// Durable retry classification for the outbox.
    pub fn retry_class(&self) -> RetryClass {
        match self {
            RemoteError::NeedsSignIn => RetryClass::NeedsAuth,
            RemoteError::PermissionDenied | RemoteError::ReadOnly => RetryClass::NeedsUser,
            RemoteError::StorageSetupRequired => RetryClass::NeedsUser,
            RemoteError::RateLimited { .. } | RemoteError::Transport | RemoteError::SearchIncomplete => RetryClass::Backoff,
            RemoteError::RemoteContentUnavailable => RetryClass::Backoff,
            RemoteError::Cancelled => RetryClass::None,
            RemoteError::UnsupportedFormat
            | RemoteError::SourceChanged
            | RemoteError::Rejected { .. }
            | RemoteError::InvalidResponse => RetryClass::NeedsUser,
        }
    }

    /// Next attempt hint in milliseconds, when the service supplied one.
    pub fn retry_after_ms(&self) -> Option<u64> {
        match self {
            RemoteError::RateLimited { retry_after_seconds } => {
                retry_after_seconds.map(|s| s.saturating_mul(1000))
            }
            _ => None,
        }
    }
}

impl From<PublicationError> for RemoteError {
    fn from(error: PublicationError) -> Self {
        match error {
            PublicationError::NeedsSignIn => RemoteError::NeedsSignIn,
            PublicationError::PermissionDenied => RemoteError::PermissionDenied,
            PublicationError::StorageSetupRequired => RemoteError::StorageSetupRequired,
            PublicationError::UnsupportedFormat => RemoteError::UnsupportedFormat,
            PublicationError::RemoteContentUnavailable => RemoteError::RemoteContentUnavailable,
            PublicationError::Cancelled => RemoteError::Cancelled,
            PublicationError::Absent | PublicationError::InvalidResponse => {
                RemoteError::InvalidResponse
            }
            PublicationError::Transport => RemoteError::Transport,
            PublicationError::SearchIncomplete => RemoteError::SearchIncomplete,
            PublicationError::XetRequired => RemoteError::Rejected {
                detail: "native Xet capability is required for this object".to_owned(),
            },
            PublicationError::ImmutableRecordConflict => RemoteError::Rejected {
                detail: "an immutable record would be overwritten".to_owned(),
            },
            PublicationError::BindingMismatch => RemoteError::Rejected {
                detail: "publication identity, binding, and credentials do not agree".to_owned(),
            },
            PublicationError::RecordTooLarge | PublicationError::KeyOutOfScope => {
                RemoteError::Rejected { detail: "publication record out of scope".to_owned() }
            }
            PublicationError::InvalidCredentialRecord => RemoteError::StorageSetupRequired,
        }
    }
}

impl From<NativeError> for RemoteError {
    fn from(error: NativeError) -> Self {
        match error {
            NativeError::NeedsSignIn => RemoteError::NeedsSignIn,
            NativeError::PermissionDenied => RemoteError::PermissionDenied,
            NativeError::RemoteContentUnavailable => RemoteError::RemoteContentUnavailable,
            NativeError::RateLimited { retry_after_seconds } => {
                RemoteError::RateLimited { retry_after_seconds }
            }
            NativeError::Transport => RemoteError::Transport,
            NativeError::Cancelled => RemoteError::Cancelled,
            NativeError::SourceChanged => RemoteError::SourceChanged,
            NativeError::XetRequired
            | NativeError::InvalidRange
            | NativeError::IdentityMismatch
            | NativeError::AlreadyExists
            | NativeError::TooManyEntries
            | NativeError::InvalidRequest { .. }
            | NativeError::InvalidResponse => RemoteError::Rejected {
                detail: "native request rejected".to_owned(),
            },
        }
    }
}

/// A committed managed `HEAD`. The strong ETag exists only when the read
/// came from the one GET body+ETag response of the S3 publication transport;
/// a native-only read carries no ETag and therefore can never authorize a
/// conditional write.
#[derive(Debug, Clone)]
pub struct RemoteHead {
    pub head: HeadV1,
    pub etag: Option<OpaqueEtag>,
}

/// Sequential reader over an immutable object's bytes.
pub trait RangeSource: Send + 'static {
    /// Next ordered chunk, `None` at end of the requested range.
    fn next_chunk(
        &mut self,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<Option<Bytes>, RemoteError>> + Send;

    /// Stop reading; the underlying stream is cancelled.
    fn cancel(&mut self);
}

/// The remote effect boundary for one connection.
///
/// The three payload stages are separate calls so the caller can persist each
/// durable Xet checkpoint (`IngestionCheckpoint`, `CasCommitCheckpoint`)
/// **before** dispatching the next external boundary. Stages are idempotent
/// and content-addressed: re-driving an already-completed stage after a crash
/// reproduces the same binding and never rewrites an immutable key.
pub trait RemoteOps: Send + Sync + 'static {
    type Reader: RangeSource;
    type Events: crate::remote_watch::RemoteEvents;

    /// The drive-bound event source for remote invalidations.
    fn event_source(&self) -> Result<Self::Events, RemoteError>;

    /// One bounded read of the managed `HEAD`. `None` means the managed
    /// prefix has no `HEAD` (uninitialized). Read-only connections read
    /// through the native small-record path and never receive an ETag.
    fn read_head(
        &self,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<Option<RemoteHead>, RemoteError>> + Send;

    /// Guarded initialization (`If-None-Match: *`); never overwrites a
    /// racing winner.
    fn initialize(
        &self,
        candidate: PublicationCandidate,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<InitOutcome, RemoteError>> + Send;

    /// Exactly one conditional replacement (`If-Match`) against the preserved
    /// head (`expected` supplies both the base commit identity and its strong
    /// ETag). A native-only head read without an ETag is never a valid base.
    fn publish(
        &self,
        expected: &RemoteHead,
        candidate: PublicationCandidate,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<PublishResult, RemoteError>> + Send;

    /// Resolves a dispatched-but-uncertain publication by walking committed
    /// ancestry. Cancellation-safe at every fetch.
    fn resolve_uncertain(
        &self,
        candidate: &PublicationCandidate,
        cursor: Option<AncestryCursor>,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<UncertainResolution, RemoteError>> + Send;

    /// Bounded committed-ancestry search for one operation identifier.
    fn find_committed_operation(
        &self,
        from: CommitId,
        operation: OperationId,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<Option<CommitId>, RemoteError>> + Send;

    /// Bounded canonical read of one immutable metadata record body. Read-only
    /// connections read through the native bounded record path.
    fn read_metadata(
        &self,
        record: MetadataRecord,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<Bytes, RemoteError>> + Send;

    /// Stage 1: hand the flushed snapshot to native Xet ingestion.
    fn ingest_payload(
        &self,
        snapshot: &StableSnapshot,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<IngestionCheckpoint, RemoteError>> + Send;

    /// Stage 2: CAS-commit previously ingested content.
    fn commit_payload_cas(
        &self,
        snapshot: &StableSnapshot,
        ingested: &IngestionCheckpoint,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<CasCommitCheckpoint, RemoteError>> + Send;

    /// Stage 3: bind the committed content to its exact managed key.
    fn bind_payload(
        &self,
        snapshot: &StableSnapshot,
        committed: &CasCommitCheckpoint,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<ObjectRef, RemoteError>> + Send;

    /// Open one bounded ordered range over an immutable object. There is no
    /// whole-file fallback. `cache` is the provider-wide clean range cache
    /// owned by the shared scheduler.
    fn open_range(
        &self,
        object: &ObjectRef,
        range: ByteRange,
        cache: &hfdrive_hf::RangeCache,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<Self::Reader, RemoteError>> + Send;

    /// Real native read-authorization probe for the bound bucket.
    fn probe_read(
        &self,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<(), RemoteError>> + Send;

    /// Real native write-authorization probe for the bound bucket.
    fn probe_write(
        &self,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<(), RemoteError>> + Send;
}

// ---------------------------------------------------------------------------
// Production implementation
// ---------------------------------------------------------------------------

use bytes::Bytes;
use hfdrive_core::storage::{ImmutableKey, RemotePrefix};
use hfdrive_hf::UploadSource;
use hfdrive_hf::{HeadRead, NativeBucketStore, NativeControl, NativeLease};

/// Live remote boundary: native Xet payloads through the drive-bound
/// [`NativeBucketStore`], guarded publication through the coordinator when
/// the connection has supplemental publication credentials. Read-only
/// connections carry no coordinator: committed state is materialized through
/// the native bounded record reads and range streams.
pub struct LiveRemote<T: hfdrive_auth::TokenSource, S: hfdrive_publication::coordinator::PublicationStore>
{
    native: NativeBucketStore<T>,
    control: NativeControl<T>,
    publication: Option<PublicationCoordinator<NativeBucketStore<T>, S>>,
}

use hfdrive_publication::coordinator::PublicationCoordinator;

impl<T, S> LiveRemote<T, S>
where
    T: hfdrive_auth::TokenSource + 'static,
    S: hfdrive_publication::coordinator::PublicationStore + 'static,
{
    /// `publication` is `None` for read-only connections and for writable
    /// connections whose supplemental authorization is not set up yet: native
    /// reads stay available and mutations report [`RemoteError::ReadOnly`] /
    /// [`RemoteError::StorageSetupRequired`].
    pub fn new(
        native: NativeBucketStore<T>,
        control: NativeControl<T>,
        publication: Option<PublicationCoordinator<NativeBucketStore<T>, S>>,
    ) -> Self {
        Self { native, control, publication }
    }

    /// The drive binding this remote serves.
    pub fn binding(&self) -> &hfdrive_core::storage::DriveBinding {
        self.native.binding()
    }

    /// The drive-bound event source for one remote watch worker.
    pub fn event_source(&self) -> Result<crate::remote_watch::StoreEvents<T>, RemoteError> {
        let lease = self.lease()?;
        Ok(crate::remote_watch::StoreEvents::new(self.native.clone(), lease))
    }

    fn lease(&self) -> Result<NativeLease, RemoteError> {
        self.native.capture_lease().map_err(Into::into)
    }

    fn publication(
        &self,
    ) -> Result<&PublicationCoordinator<NativeBucketStore<T>, S>, RemoteError> {
        self.publication
            .as_ref()
            .ok_or(RemoteError::StorageSetupRequired)
    }

    fn metadata_key(record: MetadataRecord, prefix: &RemotePrefix) -> hfdrive_core::storage::RelativeKey {
        prefix.immutable_key(match record {
            MetadataRecord::Version(id) => ImmutableKey::Version(id),
            MetadataRecord::Catalog(id) => ImmutableKey::Catalog(id),
            MetadataRecord::Commit(id) => ImmutableKey::Commit(id),
        })
    }

    /// Re-derives the staged upload chain for `snapshot` and re-verifies the
    /// durable ingestion checkpoint before returning the ingested stage. The
    /// redo is content-addressed and idempotent.
    async fn reingest_verified(
        &self,
        snapshot: &StableSnapshot,
        expect: Option<&IngestionCheckpoint>,
        cancel: &CancellationToken,
    ) -> Result<(hfdrive_hf::StagedIngested<T>, IngestionCheckpoint), RemoteError> {
        let lease = self.lease()?;
        let staged = self.native.begin_upload(
            &lease,
            ImmutableKey::Payload(snapshot.upload_id),
            UploadSource::Snapshot(snapshot.clone()),
        )?;
        let (ingested, checkpoint) = staged.ingest(cancel).await?;
        if let Some(expect) = expect {
            if expect.target_key != checkpoint.target_key
                || expect.xet_file_id != checkpoint.xet_file_id
                || expect.size != checkpoint.size
                || expect.sha256 != checkpoint.sha256
            {
                return Err(RemoteError::SourceChanged);
            }
        }
        Ok((ingested, checkpoint))
    }
}

/// Reader over `hf-hf`'s bounded ordered range stream.
pub struct NativeRangeReader {
    inner: hfdrive_hf::RangeReader,
}

impl RangeSource for NativeRangeReader {
    async fn next_chunk(
        &mut self,
        cancel: &CancellationToken,
    ) -> Result<Option<Bytes>, RemoteError> {
        self.inner.next_chunk(cancel).await.map_err(Into::into)
    }

    fn cancel(&mut self) {
        self.inner.cancel();
    }
}

impl<T, S> RemoteOps for LiveRemote<T, S>
where
    T: hfdrive_auth::TokenSource + 'static,
    S: hfdrive_publication::coordinator::PublicationStore + 'static,
{
    type Reader = NativeRangeReader;
    type Events = crate::remote_watch::StoreEvents<T>;

    fn event_source(&self) -> Result<Self::Events, RemoteError> {
        LiveRemote::event_source(self)
    }

    async fn read_head(&self, cancel: &CancellationToken) -> Result<Option<RemoteHead>, RemoteError> {
        match self.publication.as_ref() {
            Some(publication) => {
                let head = publication.read_head_with_etag(cancel).await?;
                Ok(head.map(|head| RemoteHead { head: head.head, etag: Some(head.etag) }))
            }
            None => {
                // Native validated small-record read; no ETag exists on this
                // path and none is fabricated.
                let lease = self.lease()?;
                let binding = self.native.binding();
                match self
                    .control
                    .read_head_record(&lease, &binding.bucket, &binding.prefix, cancel)
                    .await?
                {
                    HeadRead::Missing => Ok(None),
                    HeadRead::TooLarge { .. } => Err(RemoteError::UnsupportedFormat),
                    HeadRead::Record(record) => {
                        match record.format {
                            hfdrive_hf::HeadFormat::V1 { .. } => {}
                            hfdrive_hf::HeadFormat::Newer { .. } => {
                                return Err(RemoteError::UnsupportedFormat);
                            }
                            hfdrive_hf::HeadFormat::Foreign => return Err(RemoteError::InvalidResponse),
                        }
                        let head = hfdrive_core::format::from_head_bytes(&record.bytes)
                            .map_err(|_| RemoteError::InvalidResponse)?;
                        Ok(Some(RemoteHead { head, etag: None }))
                    }
                }
            }
        }
    }

    async fn initialize(
        &self,
        candidate: PublicationCandidate,
        cancel: &CancellationToken,
    ) -> Result<InitOutcome, RemoteError> {
        Ok(self.publication()?.initialize_if_absent(candidate, cancel).await?)
    }

    async fn publish(
        &self,
        expected: &RemoteHead,
        candidate: PublicationCandidate,
        cancel: &CancellationToken,
    ) -> Result<PublishResult, RemoteError> {
        // The coordinator validates `candidate.commit.parent` against the
        // preserved base head and refuses any reused immutable identifier
        // before writing anything.
        let etag = expected
            .etag
            .as_ref()
            .ok_or(RemoteError::StorageSetupRequired)?;
        let base = hfdrive_publication::coordinator::HeadVersion {
            head: expected.head.clone(),
            etag: etag.clone(),
        };
        Ok(self.publication()?.publish_if_match(&base, candidate, cancel).await?)
    }

    async fn resolve_uncertain(
        &self,
        candidate: &PublicationCandidate,
        cursor: Option<AncestryCursor>,
        cancel: &CancellationToken,
    ) -> Result<UncertainResolution, RemoteError> {
        Ok(self.publication()?.resolve_uncertain_write(candidate, cursor, cancel).await?)
    }

    async fn find_committed_operation(
        &self,
        from: CommitId,
        operation: OperationId,
        cancel: &CancellationToken,
    ) -> Result<Option<CommitId>, RemoteError> {
        Ok(self
            .publication()?
            .find_committed_operation(from, operation, cancel)
            .await?)
    }

    async fn read_metadata(
        &self,
        record: MetadataRecord,
        cancel: &CancellationToken,
    ) -> Result<Bytes, RemoteError> {
        match self.publication.as_ref() {
            Some(publication) => Ok(publication.read_metadata(record, cancel).await?.into_body()),
            None => {
                let lease = self.lease()?;
                let binding = self.native.binding();
                let key = Self::metadata_key(record, &binding.prefix);
                let body = self
                    .native
                    .read_record(&lease, &key, record.max_bytes(), cancel)
                    .await?;
                body.ok_or(RemoteError::RemoteContentUnavailable)
            }
        }
    }

    async fn ingest_payload(
        &self,
        snapshot: &StableSnapshot,
        cancel: &CancellationToken,
    ) -> Result<IngestionCheckpoint, RemoteError> {
        let (_ingested, checkpoint) = self.reingest_verified(snapshot, None, cancel).await?;
        Ok(checkpoint)
    }

    async fn commit_payload_cas(
        &self,
        snapshot: &StableSnapshot,
        ingested: &IngestionCheckpoint,
        cancel: &CancellationToken,
    ) -> Result<CasCommitCheckpoint, RemoteError> {
        let (ingested_stage, _checkpoint) =
            self.reingest_verified(snapshot, Some(ingested), cancel).await?;
        let (_committed, checkpoint) = ingested_stage.commit_cas(cancel).await?;
        Ok(checkpoint)
    }

    async fn bind_payload(
        &self,
        snapshot: &StableSnapshot,
        committed: &CasCommitCheckpoint,
        cancel: &CancellationToken,
    ) -> Result<ObjectRef, RemoteError> {
        let (ingested_stage, _ingested) = self.reingest_verified(snapshot, None, cancel).await?;
        let (committed_stage, checkpoint) = ingested_stage.commit_cas(cancel).await?;
        if checkpoint.target_key != committed.target_key
            || checkpoint.xet_file_id != committed.xet_file_id
            || checkpoint.size != committed.size
            || checkpoint.sha256 != committed.sha256
        {
            return Err(RemoteError::SourceChanged);
        }
        let bound = committed_stage.bind(cancel).await?;
        bound.payload_ref().map_err(Into::into)
    }

    async fn open_range(
        &self,
        object: &ObjectRef,
        range: ByteRange,
        cache: &hfdrive_hf::RangeCache,
        cancel: &CancellationToken,
    ) -> Result<NativeRangeReader, RemoteError> {
        let lease = self.lease()?;
        let reader = self
            .native
            .open_range_cached(&lease, object, range, cache, cancel)
            .await?;
        Ok(NativeRangeReader { inner: reader })
    }

    async fn probe_read(&self, cancel: &CancellationToken) -> Result<(), RemoteError> {
        let lease = self.lease()?;
        Ok(self.native.check_native_read(&lease, cancel).await?)
    }

    async fn probe_write(&self, cancel: &CancellationToken) -> Result<(), RemoteError> {
        let lease = self.lease()?;
        Ok(self.native.check_native_write(&lease, cancel).await?)
    }
}

/// Reads one immutable version record and returns its payload binding. The
/// record itself is the proof of the binding: workspace agreement and a
/// present Xet identifier are required, and a missing referenced record is
/// retryable `RemoteContentUnavailable`, never deletion.
pub async fn version_object<R: RemoteOps>(
    remote: &R,
    workspace: hfdrive_core::ids::WorkspaceId,
    version: hfdrive_core::ids::VersionId,
    cancel: &CancellationToken,
) -> Result<ObjectRef, RemoteError> {
    let record = version_record(remote, workspace, version, cancel).await?;
    Ok(ObjectRef {
        key: record.object_key,
        sha256: record.sha256,
        size: record.size,
        xet_file_id: record.xet_file_id.ok_or(RemoteError::InvalidResponse)?,
    })
}

/// Reads one immutable version record with its display metadata. Used by
/// history restore: the historical record is the proof of the binding and is
/// never rewritten — a restore publishes a fresh version record that reuses
/// the exact bound payload reference.
pub async fn version_record<R: RemoteOps>(
    remote: &R,
    workspace: hfdrive_core::ids::WorkspaceId,
    version: hfdrive_core::ids::VersionId,
    cancel: &CancellationToken,
) -> Result<hfdrive_core::format::VersionV1, RemoteError> {
    let body = remote
        .read_metadata(MetadataRecord::Version(version), cancel)
        .await?;
    let record = hfdrive_core::format::from_version_bytes(&body)
        .map_err(|_| RemoteError::InvalidResponse)?;
    if record.workspace_id != workspace {
        return Err(RemoteError::InvalidResponse);
    }
    Ok(record)
}

// The coordinator types above are re-exported for callers building candidates.
