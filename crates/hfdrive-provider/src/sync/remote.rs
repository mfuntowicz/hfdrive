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
use hfdrive_core::ids::{CommitId, ItemId, OperationId, WorkspaceId};
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

/// The established identity a committed `HEAD` must match before any round
/// uses it as a baseline: this connection's workspace and its durable root
/// item. A `HEAD` naming either differently is never this drive's baseline —
/// it is a different (or foreign) workspace and requires explicit connection,
/// never a relabel of queued local work.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RemoteIdentity {
    pub workspace: WorkspaceId,
    pub root_item: ItemId,
}

impl RemoteIdentity {
    /// Refuses a `HEAD` that names another workspace or root item before any
    /// round can use it as a baseline: such a record belongs to a different
    /// managed drive (or is foreign) and must never relabel this connection's
    /// baseline or queued local work.
    pub fn check_head(self, head: &HeadV1) -> Result<(), RemoteError> {
        if head.workspace_id != self.workspace || head.root_item_id != self.root_item {
            return Err(RemoteError::InvalidResponse);
        }
        Ok(())
    }
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
    /// A `HEAD` naming another workspace is refused before it can become a
    /// baseline; the root-item half of the identity check is
    /// [`RemoteIdentity::check_head`] at the round level, because the
    /// connection's root item is not part of this boundary.
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

    /// Stage 1: hand the flushed snapshot to native Xet ingestion. Idempotent
    /// per snapshot and target: a retry after a failed durable checkpoint save
    /// finds the compatible live session and returns its checkpoint without
    /// aborting it or ingesting again; check/ingest/park are one critical
    /// section so concurrent retries cannot both miss the same session.
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
    /// Live sessions bridge ordinary ingestion and CAS commit. A cache miss
    /// after restart follows the durable-checkpoint recovery path below.
    pending_ingested: tokio::sync::Mutex<
        std::collections::HashMap<String, hfdrive_hf::StagedIngested<T>>,
    >,
    /// Weak per-target locks serialize check/ingest/insert without blocking
    /// unrelated uploads. Entries disappear when no attempt holds a lock.
    ingest_locks: tokio::sync::Mutex<
        std::collections::HashMap<String, std::sync::Weak<tokio::sync::Mutex<()>>>,
    >,
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
        Self {
            native,
            control,
            publication,
            pending_ingested: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            ingest_locks: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    async fn target_ingest_lock(&self, target: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.ingest_locks.lock().await;
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(target).and_then(std::sync::Weak::upgrade) {
            return lock;
        }
        let lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(target.to_owned(), std::sync::Arc::downgrade(&lock));
        lock
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
    /// redo is content-addressed and idempotent. It runs only when no live
    /// staged session reproduces the durable checkpoint: crash recovery
    /// ([`RemoteOps::commit_payload_cas`] with an empty session cache) and an
    /// [`RemoteOps::ingest_payload`] retry whose first ingestion has no
    /// surviving compatible session — never a retry whose session is already
    /// parked. `expect`'s identity (target key, Xet file id, size, digest)
    /// must be reproduced exactly; the SDK task id is session-local and never
    /// compared.
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
        if let Some(expect) = expect
            && !same_ingestion(expect, &checkpoint)
        {
            // The recovered checkpoint disagrees with what the snapshot
            // produced: release the session (a dropped handle alone does not
            // abort it) and demand recapture, never a bind.
            let _ = ingested.abort();
            return Err(RemoteError::SourceChanged);
        }
        Ok((ingested, checkpoint))
    }
}

/// The two durable ingestion checkpoints describe the same content-addressed
/// ingestion. The SDK task id is session-local and never part of this
/// identity: recovery reproduces the binding evidence, not the task handle.
fn same_ingestion(left: &IngestionCheckpoint, right: &IngestionCheckpoint) -> bool {
    left.target_key == right.target_key
        && left.xet_file_id == right.xet_file_id
        && left.size == right.size
        && left.sha256 == right.sha256
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
        let target_key = self
            .native
            .binding()
            .prefix
            .immutable_key(ImmutableKey::Payload(snapshot.upload_id))
            .to_string();
        let target_lock = self.target_ingest_lock(&target_key).await;
        let _target_guard = target_lock.lock().await;
        {
            let mut pending = self.pending_ingested.lock().await;
            if let Some(stage) = pending.get(&target_key) {
                let checkpoint = stage.checkpoint();
                if checkpoint.size == snapshot.size && checkpoint.sha256 == snapshot.sha256 {
                    // A previous attempt crossed ingestion but failed before
                    // its checkpoint was saved. The live session is already
                    // the required evidence; do not ingest it a second time.
                    return Ok(checkpoint);
                }
                let _ = pending.remove(&target_key).expect("present entry").abort();
            }
        }
        // Ordinary ingestion crosses the boundary once and parks the live
        // StagedIngested for CAS. The per-target guard makes a concurrent
        // retry observe this session instead of performing another ingest.
        let (ingested, checkpoint) = self.reingest_verified(snapshot, None, cancel).await?;
        {
            // Bounded: a session whose commit never runs must not hold SDK
            // resources open forever (dropping a handle alone does not abort
            // it). An evicted session is recovered from its durable checkpoint.
            const MAX_PENDING_INGESTED: usize = 8;
            let mut pending = self.pending_ingested.lock().await;
            while pending.len() >= MAX_PENDING_INGESTED {
                let Some(idle) = pending.keys().next().cloned() else { break };
                if let Some(evicted) = pending.remove(&idle) {
                    let _ = evicted.abort();
                }
            }
            if let Some(previous) = pending.insert(checkpoint.target_key.clone(), ingested) {
                let _ = previous.abort();
            }
        }
        Ok(checkpoint)
    }

    async fn commit_payload_cas(
        &self,
        snapshot: &StableSnapshot,
        ingested: &IngestionCheckpoint,
        cancel: &CancellationToken,
    ) -> Result<CasCommitCheckpoint, RemoteError> {
        // Ordinary path: consume the live session ingest_payload parked under
        // this exact target key — one ingestion, one CAS commit. No live
        // session (crash recovery) or a session that does not reproduce the
        // journal's checkpoint falls back to reingest_verified, which
        // re-ingests once and re-verifies the checkpoint identity before any
        // commit; the SDK task id is session-local and never compared.
        let cached = {
            let mut pending = self.pending_ingested.lock().await;
            let parked = pending.get(&ingested.target_key).map(|stage| stage.checkpoint());
            match parked {
                Some(live) if same_ingestion(&live, ingested) => pending.remove(&ingested.target_key),
                Some(_) => {
                    // Stale session under this key: release it explicitly and
                    // recover from the durable checkpoint below.
                    if let Some(evicted) = pending.remove(&ingested.target_key) {
                        let _ = evicted.abort();
                    }
                    None
                }
                None => None,
            }
        };
        let ingested_stage = match cached {
            Some(stage) => stage,
            None => self.reingest_verified(snapshot, Some(ingested), cancel).await?.0,
        };
        let (_committed, checkpoint) = ingested_stage.commit_cas(cancel).await?;
        Ok(checkpoint)
    }

    async fn bind_payload(
        &self,
        snapshot: &StableSnapshot,
        committed: &CasCommitCheckpoint,
        cancel: &CancellationToken,
    ) -> Result<ObjectRef, RemoteError> {
        let lease = self.lease()?;
        let staged = self.native.resume_committed(&lease, snapshot, committed)?;
        let bound = staged.bind(cancel).await?;
        bound.payload_ref(&self.native.binding().prefix).map_err(Into::into)
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
    if record.workspace_id != workspace || record.version_id != version {
        return Err(RemoteError::InvalidResponse);
    }
    Ok(record)
}

// The coordinator types above are re-exported for callers building candidates.

#[cfg(test)]
mod tests {
    //! Deterministic regressions for the ordinary ingest -> CAS-commit path:
    //! exactly one ingestion per snapshot — the live [`hfdrive_hf::StagedIngested`]
    //! session is reused for the CAS commit, never aborted and re-ingested — and
    //! crash recovery that re-ingests only when no live staged session exists.
    //! The Xet CAS is a local fixture (`local://`) and the only HTTP surface is
    //! the bucket's `xet-write-token` refresh route (one eager refresh per Xet
    //! session), so refresh hits count real ingestions. No external network.

    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use hfdrive_auth::{
        AuthorizationAuthority, AuthorizationError, AuthorizationLease, SecretAccessToken, TokenSource,
    };
    use hfdrive_core::ids::{AccountKey, UploadId, WorkspaceId};
    use hfdrive_core::storage::{
        BucketBinding, BucketId, BucketName, DriveBinding, Namespace, OwnerId, OwnerKind, PayloadKey, Sha256Digest,
    };
    use hfdrive_hf::{NativeApi, NativeConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use zeroize::Zeroizing;

    const SECRET_MARKER: &str = "SECRET_MARKER_HFDRIVE_REMOTE_TEST";

    struct Stub {
        lease: AuthorizationLease,
        account: AccountKey,
    }

    impl TokenSource for Stub {
        fn access_token(
            &self,
            _account: AccountKey,
        ) -> impl Future<Output = Result<Arc<SecretAccessToken>, AuthorizationError>> + Send {
            let account = self.account;
            async move {
                Ok(Arc::new(SecretAccessToken::new(
                    Zeroizing::new(SECRET_MARKER.to_owned()),
                    account,
                    1,
                    u64::MAX,
                )))
            }
        }

        fn refresh_after_unauthorized(
            &self,
            _account: AccountKey,
            _rejected_generation: u64,
        ) -> impl Future<Output = Result<Arc<SecretAccessToken>, AuthorizationError>> + Send {
            let account = self.account;
            async move {
                Ok(Arc::new(SecretAccessToken::new(
                    Zeroizing::new(SECRET_MARKER.to_owned()),
                    account,
                    2,
                    u64::MAX,
                )))
            }
        }

        fn authorization_lease(&self, _account: AccountKey) -> Result<AuthorizationLease, AuthorizationError> {
            Ok(self.lease.clone())
        }
    }

    struct Fixture {
        addr: std::net::SocketAddr,
        token_refreshes: Arc<AtomicUsize>,
        batches: Arc<AtomicUsize>,
        _task: tokio::task::JoinHandle<()>,
    }

    /// Local HTTP fixture: the bucket's `xet-write-token` refresh route (the
    /// only HTTP call one ingestion performs) and the exact-key batch bind.
    async fn fixture(cas_url: String) -> Fixture {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token_refreshes = Arc::new(AtomicUsize::new(0));
        let batches = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn({
            let token_refreshes = token_refreshes.clone();
            let batches = batches.clone();
            async move {
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else {
                        return;
                    };
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let header_end = loop {
                        let Ok(n) = socket.read(&mut chunk).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                    let content_length = head
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    while buf.len() < header_end + 4 + content_length {
                        let Ok(n) = socket.read(&mut chunk).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let mut parts = head.split_whitespace();
                    let method = parts.next().unwrap_or("").to_uppercase();
                    let path = parts.next().unwrap_or("").to_string();
                    let response = if method == "GET" && path.ends_with("/xet-write-token") {
                        token_refreshes.fetch_add(1, Ordering::SeqCst);
                        let body = serde_json::json!({
                            "casUrl": cas_url,
                            "exp": 4_000_000_000u64,
                            "accessToken": "fixture-cas-token",
                        })
                        .to_string();
                        format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len())
                    } else if method == "POST" && path.ends_with("/batch") {
                        batches.fetch_add(1, Ordering::SeqCst);
                        let body = r#"{"success":true,"processed":1,"succeeded":1,"failed":[]}"#;
                        format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len())
                    } else {
                        "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}".to_owned()
                    };
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.flush().await;
                    let _ = socket.shutdown().await;
                }
            }
        });
        Fixture { addr, token_refreshes, batches, _task: task }
    }

    fn drive_binding(account: AccountKey) -> DriveBinding {
        DriveBinding {
            account_key: account,
            bucket: BucketBinding {
                bucket_id: BucketId::new("64b000000000000000000003".to_owned()).unwrap(),
                bucket_name: BucketName::new("single".to_owned()).unwrap(),
                owner_id: OwnerId::new("subject-1".to_owned()).unwrap(),
                owner_kind: OwnerKind::Personal,
                owner_namespace: Namespace::new("ns".to_owned()).unwrap(),
            },
            prefix: RemotePrefix::new("hfdrive/test-workspace".to_owned()).unwrap(),
            workspace_id: WorkspaceId::new(),
        }
    }

    fn live_remote(
        endpoint: String,
        binding: DriveBinding,
        cache_dir: std::path::PathBuf,
    ) -> LiveRemote<Stub, hfdrive_publication::S3Transport> {
        let config = NativeConfig { endpoint: endpoint.clone(), xet_cache_dir: cache_dir, ..NativeConfig::default() };
        let account = binding.account_key;
        let tokens = Arc::new(Stub {
            lease: AuthorizationAuthority::new(account, 1).activate().expect("fresh authority activates"),
            account,
        });
        let api = NativeApi::new(tokens, account, endpoint).unwrap();
        let native = NativeBucketStore::new(api.clone(), binding, config.clone()).unwrap();
        let control = NativeControl::new(api, config);
        LiveRemote::new(native, control, None)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ordinary_upload_ingests_once_and_recovery_reingests_only_without_a_live_session() {
        let temp = tempfile::tempdir().unwrap();
        let payload = b"one ingestion per snapshot, never two".to_vec();
        let source = temp.path().join("source.bin");
        std::fs::write(&source, &payload).unwrap();
        let upload_id = UploadId::new();
        let snapshot = StableSnapshot {
            snapshot_id: hfdrive_core::ids::SnapshotId::new(),
            upload_id,
            path: source,
            size: payload.len() as u64,
            sha256: Sha256Digest::of(&payload),
        };
        let account = AccountKey::from_subject("https://huggingface.co", "remote-single-ingest");
        let cas_url = format!("local://{}", temp.path().join("cas").display());
        let server = fixture(cas_url).await;
        let endpoint = format!("http://{}", server.addr);
        let binding = drive_binding(account);
        let cancel = CancellationToken::new();

        // Ordinary path: ingestion parks the live StagedIngested session and
        // the CAS commit consumes it. One ingestion, no abort-then-re-ingest.
        let live = live_remote(endpoint.clone(), binding.clone(), temp.path().join("cache-live"));
        let checkpoint = live.ingest_payload(&snapshot, &cancel).await.unwrap();
        assert_eq!(server.token_refreshes.load(Ordering::SeqCst), 1, "ingestion crosses its boundary exactly once");
        assert_eq!(checkpoint.target_key, format!("hfdrive/test-workspace/objects/{upload_id}"));
        assert_eq!(checkpoint.size, snapshot.size);
        assert_eq!(checkpoint.sha256, snapshot.sha256);
        let retried = live.ingest_payload(&snapshot, &cancel).await.unwrap();
        assert!(same_ingestion(&checkpoint, &retried));
        assert_eq!(server.token_refreshes.load(Ordering::SeqCst), 1, "a checkpoint-save retry reuses the live ingestion");

        let committed = live.commit_payload_cas(&snapshot, &checkpoint, &cancel).await.unwrap();
        assert_eq!(
            server.token_refreshes.load(Ordering::SeqCst),
            1,
            "the CAS commit reuses the live session and never re-ingests the same snapshot"
        );
        assert_eq!(committed.target_key, checkpoint.target_key);
        assert_eq!(committed.xet_file_id, checkpoint.xet_file_id);
        assert_eq!(committed.size, checkpoint.size);
        assert_eq!(committed.sha256, checkpoint.sha256);

        let object = live.bind_payload(&snapshot, &committed, &cancel).await.unwrap();
        assert_eq!(object.key, PayloadKey::new(upload_id));
        assert_eq!(object.xet_file_id, checkpoint.xet_file_id);
        assert_eq!(object.size, snapshot.size);
        assert_eq!(object.sha256, snapshot.sha256);
        assert_eq!(server.batches.load(Ordering::SeqCst), 1, "binding posts exactly one exact-key batch operation");

        // Crash recovery: a fresh boundary holds no live staged session, so the
        // durable checkpoint is re-ingested exactly once and re-verified before
        // its commit. The SDK task id is session-local and never compared.
        let mut journal = checkpoint.clone();
        journal.sdk_task_id += 1;
        let recovered = live_remote(endpoint.clone(), binding.clone(), temp.path().join("cache-recovered"));
        let resumed = recovered.commit_payload_cas(&snapshot, &journal, &cancel).await.unwrap();
        assert_eq!(
            server.token_refreshes.load(Ordering::SeqCst),
            2,
            "recovery re-ingests exactly once and only when no live staged session exists"
        );
        assert_eq!(resumed.target_key, checkpoint.target_key);
        assert_eq!(resumed.xet_file_id, checkpoint.xet_file_id);
        assert_eq!(resumed.size, checkpoint.size);
        assert_eq!(resumed.sha256, checkpoint.sha256);

        // A checkpoint that does not describe this snapshot is a recapture
        // demand (SourceChanged), never a commit and never a bind.
        let mut foreign = checkpoint.clone();
        foreign.size += 1;
        let error = recovered
            .commit_payload_cas(&snapshot, &foreign, &cancel)
            .await
            .expect_err("a mismatched recovered checkpoint must not commit");
        assert!(matches!(error, RemoteError::SourceChanged));
    }

    #[test]
    fn head_identity_requires_the_established_workspace_and_root() {
        let workspace = WorkspaceId::new();
        let root_item = ItemId::new();
        let identity = RemoteIdentity { workspace, root_item };
        let head = HeadV1 {
            format: "hfdrive".to_owned(),
            schema_version: 1,
            workspace_id: workspace,
            root_item_id: root_item,
            commit_id: CommitId::new(),
            generation: hfdrive_core::ids::GenerationId::new(),
            required_features: Vec::new(),
        };
        identity.check_head(&head).unwrap();
        let mut wrong_workspace = head.clone();
        wrong_workspace.workspace_id = WorkspaceId::new();
        assert!(matches!(identity.check_head(&wrong_workspace), Err(RemoteError::InvalidResponse)));
        let mut wrong_root = head;
        wrong_root.root_item_id = ItemId::new();
        assert!(matches!(identity.check_head(&wrong_root), Err(RemoteError::InvalidResponse)));
    }

    #[tokio::test]
    async fn version_record_must_match_its_requested_immutable_key() {
        let workspace = WorkspaceId::new();
        let requested = hfdrive_core::ids::VersionId::new();
        let record = hfdrive_core::format::VersionV1 {
            format: "hfdrive".to_owned(),
            schema_version: 1,
            workspace_id: workspace,
            version_id: hfdrive_core::ids::VersionId::new(),
            object_key: hfdrive_core::storage::PayloadKey::new(UploadId::new()),
            size: 7,
            sha256: Sha256Digest::of(b"payload"),
            xet_file_id: None,
            display: hfdrive_core::format::DisplayMetadata {
                name: "file.txt".to_owned(),
                modified_at: "2026-01-01T00:00:00Z".to_owned(),
            },
        };
        assert_ne!(record.version_id, requested);
        let bytes = hfdrive_core::format::to_version_bytes(&record).unwrap();
        let remote = crate::sync::test_support::HeadOnlyRemote {
            metadata: Some(bytes::Bytes::from(bytes)),
            ..Default::default()
        };
        assert!(matches!(
            version_record(&remote, workspace, requested, &CancellationToken::new()).await,
            Err(RemoteError::InvalidResponse)
        ));
    }
}
