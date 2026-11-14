//! The guarded publication transaction layer.
//!
//! One publication transaction is ordered and durable:
//!
//! 1. **Validate** the candidate against the exact stable binding (account,
//!    owner, bucket, workspace, prefix) and the preserved base `HEAD`. A
//!    candidate that reuses a commit/generation identity or does not advance
//!    the preserved base is refused before any effect.
//! 2. **Write every dependency before `HEAD`** through the native Xet path
//!    only: version records, hash-addressed catalog pages, then the commit
//!    record. An immutable key that already exists must hold exactly the
//!    candidate bytes (idempotent resume); anything else is
//!    [`PublicationError::ImmutableRecordConflict`] and is never overwritten.
//! 3. **Verify** every referenced payload is bound with its exact size and
//!    native Xet identity. A missing dependency is retryable
//!    [`PublicationError::RemoteContentUnavailable`], never a deletion.
//! 4. **One conditional `HEAD` write**: `If-None-Match: *` for the initial
//!    publication ([`PublicationCoordinator::initialize_if_absent`]) or exactly
//!    one `If-Match` with the preserved strong validator
//!    ([`PublicationCoordinator::publish_if_match`]).
//!
//! Uncertain outcomes (cancelled or unanswered dispatch) are never reported as
//! success or rollback; they resolve through validated bounded committed
//! ancestry ([`PublicationCoordinator::resolve_uncertain_write`]). A
//! precondition conflict re-reads the current `HEAD` and hands it back for
//! fresh reconciliation; the candidate is never replayed wholesale.
//!
//! Authorization: one live [`hfdrive_hf::NativeLease`] is captured per durable
//! operation and threaded through every dispatch. Fresh native resource
//! authorization is verified immediately before **each** S3 transaction; the
//! lease gate at dispatch is an epoch/account check, not resource permission.
//! All metadata and payload bytes are written through the native Xet path;
//! this layer's S3 transport only reads immutable records and conditionally
//! swaps `HEAD` (and the probe namespace during explicit capability probes).
#![forbid(unsafe_code)]

use std::future::Future;

use bytes::Bytes;
use hfdrive_auth::TokenSource;
use hfdrive_core::catalog::{self, PublishSet};
use hfdrive_core::format::{self, CommitV1, FormatError, HeadV1, VersionV1};
use hfdrive_core::ids::{CommitId, GenerationId, OperationId, WorkspaceId};
use hfdrive_core::storage::{
    ByteRange, DriveBinding, ImmutableKey, ObjectRef, PayloadKey, RelativeKey, Sha256Digest,
    StableSnapshot,
};
use hfdrive_hf::{
    BoundObject, CasCommitCheckpoint, IngestionCheckpoint, NativeBucketStore, NativeError,
    NativeLease, ObjectMetadata, PathsInfoReport, RangeReader, UploadSource,
};
use tokio_util::sync::CancellationToken;

use crate::ancestry::{
    self, AncestryCursor, AncestryGoal, AncestryMatch, AncestryProgress, AncestrySource, AncestryStop,
};
use crate::binding::PublicationBinding;
use crate::transport::{BoundedRecord, HeadRecord, MetadataRecord, S3Transport};
use crate::{OpaqueEtag, PublicationError, PublishOutcome};

/// One committed `HEAD` state: validated record bytes plus the strong entity
/// tag preserved from the very GET response that carried them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeadVersion {
    /// The validated `HEAD` record.
    pub head: HeadV1,
    /// The strong validator from the same response; the only value a
    /// conditional replacement may carry in `If-Match`.
    pub etag: OpaqueEtag,
}

/// Bounded ordered byte source over one immutable object (production: the
/// native Xet range reader).
pub trait RangeSource: Send {
    /// Next ordered chunk, `None` at end of the requested range.
    fn next_chunk(
        &mut self,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<Option<Bytes>, NativeError>> + Send;
}

impl RangeSource for RangeReader {
    fn next_chunk(
        &mut self,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<Option<Bytes>, NativeError>> + Send {
        RangeReader::next_chunk(self, cancel)
    }
}

/// Durable checkpoints of one native immutable upload, in boundary order.
/// The caller persists these with outbox evidence before the next external
/// boundary; ingestion -> CAS commit -> path binding are three distinct
/// boundaries, never one opaque success.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadEvidence {
    /// Bytes handed to Xet with digest verified.
    pub ingestion: IngestionCheckpoint,
    /// Metadata committed to the Xet CAS.
    pub cas: CasCommitCheckpoint,
    /// The exact bucket-relative key binding.
    pub bound: BoundObject,
}

/// One payload placed (or verified already placed) at its immutable key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadPlacement {
    /// The immutable payload reference bound into version records.
    pub object: ObjectRef,
    /// Full upload evidence when this run performed the upload; `None` when
    /// the object was already bound at exactly this key (idempotent resume).
    pub upload: Option<UploadEvidence>,
    /// Whether an already-bound object was reused instead of re-uploaded.
    pub reused: bool,
}

/// Evidence of one immutable record written for a candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordEvidence {
    /// The exact bucket-relative key.
    pub key: RelativeKey,
    /// SHA-256 of the canonical record bytes.
    pub sha256: Sha256Digest,
    /// Canonical record length.
    pub size: u64,
}

/// Complete typed evidence of one publication attempt. The caller persists it
/// with the outbox/commit record before acknowledging anything; this layer
/// keeps no public operation ledger of its own.
#[derive(Clone, Debug)]
pub struct PublicationEvidence {
    /// The immutable candidate commit id.
    pub candidate_commit: CommitId,
    /// The fresh generation id of the candidate `HEAD`.
    pub head_generation: GenerationId,
    /// Operation UUIDs included in the candidate commit.
    pub operation_ids: Vec<OperationId>,
    /// SHA-256 of the exact candidate `HEAD` bytes.
    pub head_bytes_sha256: Sha256Digest,
    /// Every immutable metadata record this attempt depends on.
    pub records: Vec<RecordEvidence>,
    /// Native upload evidence in dependency order.
    pub uploads: Vec<UploadEvidence>,
    /// Payload placement evidence (uploaded or verified bound).
    pub payloads: Vec<PayloadPlacement>,
}

/// Native storage seam for publication and probes.
///
/// Production implementation: [`NativeBucketStore`] (see the blanket impl
/// below). The seam exists so the exact production behavior — staged immutable
/// uploads with durable checkpoints, explicit-key metadata, bounded range
/// reads — is deterministically testable; production wires the real native
/// adapter, never a stand-in.
pub trait PublicationNative: Send + Sync {
    /// Byte source produced by [`PublicationNative::open_range`].
    type Ranges: RangeSource + Send;

    /// The exact drive binding this handle writes under. Cross-checked
    /// against the publication binding when a coordinator is constructed.
    fn drive(&self) -> &DriveBinding;

    /// Capture the operation lease; thread it through every dispatch of one
    /// durable operation.
    fn capture_lease(&self) -> Result<NativeLease, NativeError>;

    /// Fresh native read-authorization check against the selected bucket.
    fn check_read(
        &self,
        lease: &NativeLease,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<(), NativeError>> + Send;

    /// Fresh native write-authorization check against the selected bucket.
    fn check_write(
        &self,
        lease: &NativeLease,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<(), NativeError>> + Send;

    /// Staged immutable metadata-record upload
    /// (ingestion -> CAS commit -> binding) with durable checkpoints.
    fn upload_record(
        &self,
        lease: &NativeLease,
        target: ImmutableKey,
        bytes: Vec<u8>,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<UploadEvidence, NativeError>> + Send;

    /// Staged immutable snapshot upload (payload bytes) with durable
    /// checkpoints. The source is a flushed immutable capture, never a live
    /// mutable file.
    fn upload_snapshot(
        &self,
        lease: &NativeLease,
        snapshot: StableSnapshot,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<UploadEvidence, NativeError>> + Send;

    /// Native HEAD metadata for one explicit key (`Ok(None)` when absent).
    fn object_metadata(
        &self,
        lease: &NativeLease,
        key: &RelativeKey,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<Option<ObjectMetadata>, NativeError>> + Send;

    /// Targeted metadata lookup for explicit keys (exact per-key accounting).
    fn paths_info(
        &self,
        lease: &NativeLease,
        keys: &[RelativeKey],
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<PathsInfoReport, NativeError>> + Send;

    /// Bounded ordered native range read over an immutable object.
    fn open_range(
        &self,
        lease: &NativeLease,
        object: &ObjectRef,
        range: ByteRange,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<Self::Ranges, NativeError>> + Send;
}

/// The staged upload chain of the native store, keeping all three durable
/// checkpoints instead of the one-shot convenience.
fn staged_upload<T: TokenSource>(
    store: &NativeBucketStore<T>,
    lease: &NativeLease,
    target: ImmutableKey,
    source: UploadSource,
    cancel: &CancellationToken,
) -> impl Future<Output = Result<UploadEvidence, NativeError>> + Send {
    async move {
        let staged = store.begin_upload(lease, target, source)?;
        let (ingested, ingestion) = staged.ingest(cancel).await?;
        let (committed, cas) = ingested.commit_cas(cancel).await?;
        let bound = committed.bind(cancel).await?;
        Ok(UploadEvidence { ingestion, cas, bound })
    }
}

impl<T: TokenSource> PublicationNative for NativeBucketStore<T> {
    type Ranges = RangeReader;

    fn drive(&self) -> &DriveBinding {
        NativeBucketStore::binding(self)
    }

    fn capture_lease(&self) -> Result<NativeLease, NativeError> {
        NativeBucketStore::capture_lease(self)
    }

    fn check_read(
        &self,
        lease: &NativeLease,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<(), NativeError>> + Send {
        NativeBucketStore::check_native_read(self, lease, cancel)
    }

    fn check_write(
        &self,
        lease: &NativeLease,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<(), NativeError>> + Send {
        NativeBucketStore::check_native_write(self, lease, cancel)
    }

    fn upload_record(
        &self,
        lease: &NativeLease,
        target: ImmutableKey,
        bytes: Vec<u8>,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<UploadEvidence, NativeError>> + Send {
        // Ownership-taking seam: the canonical Vec reaches the SDK upload with
        // no intermediate copy.
        staged_upload(self, lease, target, UploadSource::Record(bytes), cancel)
    }

    fn upload_snapshot(
        &self,
        lease: &NativeLease,
        snapshot: StableSnapshot,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<UploadEvidence, NativeError>> + Send {
        let target = ImmutableKey::Payload(snapshot.upload_id);
        staged_upload(self, lease, target, UploadSource::Snapshot(snapshot), cancel)
    }

    fn object_metadata(
        &self,
        lease: &NativeLease,
        key: &RelativeKey,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<Option<ObjectMetadata>, NativeError>> + Send {
        NativeBucketStore::file_metadata(self, lease, key, cancel)
    }

    fn paths_info(
        &self,
        lease: &NativeLease,
        keys: &[RelativeKey],
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<PathsInfoReport, NativeError>> + Send {
        NativeBucketStore::paths_info(self, lease, keys, cancel)
    }

    fn open_range(
        &self,
        lease: &NativeLease,
        object: &ObjectRef,
        range: ByteRange,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<RangeReader, NativeError>> + Send {
        NativeBucketStore::open_range(self, lease, object, range, cancel)
    }
}

/// Conditional `HEAD` and immutable-record seam over the explicitly
/// credentialed S3 transport.
///
/// Production implementation: [`S3Transport`]. Implementations do no
/// authorization of their own beyond the dispatch-time lease gate; the
/// coordinator verifies fresh native resource permission before every call.
pub trait PublicationStore: Send + Sync {
    /// The immutable binding this store serves; cross-checked when a
    /// coordinator is constructed.
    fn binding(&self) -> &PublicationBinding;

    /// One bounded GET of `HEAD`; body and entity tag come from the same
    /// response. An absent `HEAD` is [`PublicationError::Absent`].
    fn read_head(
        &self,
        lease: &NativeLease,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<HeadVersion, PublicationError>> + Send;

    /// Conditional creation of `HEAD` (`If-None-Match: *`, exactly one attempt).
    fn create_head(
        &self,
        lease: &NativeLease,
        head: &HeadV1,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<PublishOutcome, PublicationError>> + Send;

    /// Conditional replacement of `HEAD` (exactly one `If-Match` attempt with
    /// the preserved strong validator).
    fn replace_head(
        &self,
        lease: &NativeLease,
        expected: &OpaqueEtag,
        head: &HeadV1,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<PublishOutcome, PublicationError>> + Send;

    /// One bounded GET of an immutable metadata record (ancestry/coherence).
    /// An absent record is [`PublicationError::Absent`]; callers that treat
    /// the record as referenced data map it to
    /// [`PublicationError::RemoteContentUnavailable`].
    fn read_metadata(
        &self,
        lease: &NativeLease,
        record: MetadataRecord,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<BoundedRecord, PublicationError>> + Send;
}

impl PublicationStore for S3Transport {
    fn binding(&self) -> &PublicationBinding {
        S3Transport::binding(self)
    }

    fn read_head(
        &self,
        lease: &NativeLease,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<HeadVersion, PublicationError>> + Send {
        async move {
            let record = S3Transport::read_head(self, lease, cancel).await?;
            let head = decode_head(record.body())?;
            Ok(HeadVersion { head, etag: record.etag().clone() })
        }
    }

    fn create_head(
        &self,
        lease: &NativeLease,
        head: &HeadV1,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<PublishOutcome, PublicationError>> + Send {
        async move {
            let body = HeadRecord::new(to_head_bytes(head)?)?;
            S3Transport::create_head(self, lease, body, cancel).await
        }
    }

    fn replace_head(
        &self,
        lease: &NativeLease,
        expected: &OpaqueEtag,
        head: &HeadV1,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<PublishOutcome, PublicationError>> + Send {
        async move {
            let body = HeadRecord::new(to_head_bytes(head)?)?;
            S3Transport::replace_head(self, lease, expected, body, cancel).await
        }
    }

    fn read_metadata(
        &self,
        lease: &NativeLease,
        record: MetadataRecord,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<BoundedRecord, PublicationError>> + Send {
        S3Transport::read_metadata(self, lease, record, cancel)
    }
}

impl<N: PublicationNative, S: PublicationStore> AncestrySource for PublicationCoordinator<N, S> {
    fn read_commit(
        &self,
        _lease: &NativeLease,
        commit: CommitId,
        cancel: &CancellationToken,
    ) -> impl Future<Output = Result<BoundedRecord, PublicationError>> + Send {
        // Refresh and revalidate authorization for each read, not the walk's initial lease.
        self.read_metadata(MetadataRecord::Commit(commit), cancel)
    }
}

/// One fully prepared publication step. Built by the caller's reconciliation
/// from core [`catalog::CatalogWriter`] output; every id is generated and
/// persisted by the caller before this layer performs any external work.
#[derive(Clone, Debug)]
pub struct PublicationCandidate {
    /// The new `HEAD`: same workspace and root, fresh generation UUID, and
    /// `commit_id` equal to [`PublicationCandidate::commit`].
    pub head: HeadV1,
    /// The immutable commit record. `parent_commit_id` is `None` exactly for
    /// the initial publication.
    pub commit: CommitV1,
    /// Immutable version records produced by this publication.
    pub versions: Vec<VersionV1>,
    /// Hash-addressed catalog pages to write (core [`PublishSet`] output).
    pub catalog: PublishSet,
    /// Native-Xet-uploaded payload references bound by `versions`.
    pub payloads: Vec<ObjectRef>,
}

/// Outcome of an initial `HEAD` creation.
#[derive(Clone, Debug)]
pub enum InitOutcome {
    /// `HEAD` created with `If-None-Match: *`.
    Committed(PublicationEvidence),
    /// A `HEAD` already existed (or appeared concurrently). `current` carries
    /// the winning state for explicit identity validation; this layer never
    /// relabels queued work or overwrites the winner. `None` means the `HEAD`
    /// was absent at re-read time (treat as unavailable, never as deletion).
    AlreadyInitialized { current: Option<HeadVersion> },
    /// The conditional create was dispatched but its outcome is unknown;
    /// resolve with [`PublicationCoordinator::resolve_uncertain_write`].
    Ambiguous(PublicationEvidence),
}

/// Outcome of one guarded `HEAD` replacement.
#[derive(Clone, Debug)]
pub enum PublishResult {
    /// Exactly one `If-Match` replacement succeeded.
    Committed(PublicationEvidence),
    /// The preserved validator was stale: the current state was re-read for a
    /// fresh reconciliation. `None` means the `HEAD` was absent at re-read
    /// time (an established connection pauses; never a deletion signal).
    PreconditionFailed { current: Option<HeadVersion> },
    /// The conditional replacement was dispatched but its outcome is unknown;
    /// resolve with [`PublicationCoordinator::resolve_uncertain_write`].
    Ambiguous(PublicationEvidence),
}

/// Resolution of one uncertain conditional write against current committed
/// remote state. Nothing here replays a stale candidate or claims rollback.
#[derive(Clone, Debug)]
pub enum UncertainResolution {
    /// The exact candidate commit is committed at this id.
    Committed {
        /// The committed candidate commit id.
        commit_id: CommitId,
    },
    /// One or more of the candidate's operations were committed by other
    /// commits (an earlier chunk of a multi-commit workflow, or a rebased
    /// publication by another device). The candidate itself was NOT published;
    /// the caller must reconcile the exact intent of each located operation
    /// and never treat the candidate as complete.
    CommittedElsewhere {
        /// Committed locations of the candidate's operations.
        matches: Vec<AncestryMatch>,
    },
    /// Fresh committed ancestry contains neither the candidate nor any of its
    /// operations (the chain was fully consumed within the bound), so a new
    /// candidate with NEW commit/generation ids may be built on `current`.
    NotCommitted {
        /// The current `HEAD`; `None` when absent (pause, never deletion).
        current: Option<HeadVersion>,
    },
    /// The bounded search did not finish; resume with the cursor. Partial
    /// locations are reported but the search is incomplete.
    Unresolved {
        /// Resumable search position.
        cursor: AncestryCursor,
        /// Goal locations found so far.
        matches: Vec<AncestryMatch>,
    },
}

/// The guarded publication coordinator: exact binding, native-only immutable
/// writes, one conditional `HEAD` write, ancestry-based recovery.
pub struct PublicationCoordinator<N, S> {
    binding: PublicationBinding,
    native: N,
    store: S,
}

impl<N: PublicationNative, S: PublicationStore> PublicationCoordinator<N, S> {
    /// Builds a coordinator after cross-validating the exact stable identity:
    /// the store's binding must equal the publication binding, and the native
    /// drive must agree on account, owner, bucket, workspace and prefix.
    /// Display locators never participate in this check.
    pub fn new(
        binding: PublicationBinding,
        native: N,
        store: S,
    ) -> Result<Self, PublicationError> {
        if store.binding() != &binding {
            return Err(PublicationError::BindingMismatch);
        }
        let drive: &DriveBinding = native.drive();
        let agree = drive.account_key == binding.account_key()
            && drive.workspace_id == binding.workspace_id()
            && drive.prefix == *binding.prefix()
            && drive.bucket.owner_id == *binding.owner_id()
            && drive.bucket.bucket_id == *binding.bucket_id()
            && drive.bucket.owner_kind == binding.owner_kind();
        if !agree {
            return Err(PublicationError::BindingMismatch);
        }
        Ok(Self { binding, native, store })
    }

    /// The exact binding this coordinator serves.
    pub fn binding(&self) -> &PublicationBinding {
        &self.binding
    }

    /// One GET of the managed `HEAD`; body and entity tag come from the same
    /// response. `Ok(None)` reports an absent `HEAD` (an established
    /// connection pauses on this; it is never a deletion signal).
    pub async fn read_head_with_etag(
        &self,
        cancel: &CancellationToken,
    ) -> Result<Option<HeadVersion>, PublicationError> {
        let lease = self.capture()?;
        self.before_s3(&lease, false, cancel).await?;
        match self.store.read_head(&lease, cancel).await {
            Ok(version) => Ok(Some(version)),
            Err(PublicationError::Absent) => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Initial publication of the managed prefix: writes every immutable
    /// dependency through the native Xet path, then exactly one `HEAD` create
    /// with `If-None-Match: *`. The candidate must be the initial commit
    /// (`parent_commit_id: null`) for this binding's workspace.
    pub async fn initialize_if_absent(
        &self,
        initial: PublicationCandidate,
        cancel: &CancellationToken,
    ) -> Result<InitOutcome, PublicationError> {
        let lease = self.capture()?;
        let evidence = self.stage(&lease, &initial, None, cancel).await?;
        self.before_s3(&lease, true, cancel).await?;
        match self.store.create_head(&lease, &initial.head, cancel).await? {
            PublishOutcome::Committed => Ok(InitOutcome::Committed(evidence)),
            PublishOutcome::PreconditionFailed => {
                let current = self.read_head_with_etag(cancel).await?;
                Ok(InitOutcome::AlreadyInitialized { current })
            }
            PublishOutcome::Ambiguous => Ok(InitOutcome::Ambiguous(evidence)),
        }
    }

    /// One guarded publication step: writes every immutable dependency through
    /// the native Xet path, verifies payload bindings, then exactly one `HEAD`
    /// replacement with `If-Match` carrying `expected.etag` — the validator
    /// preserved from the reconciliation GET.
    ///
    /// `expected` must be the exact `HeadVersion` the candidate advances: the
    /// candidate's parent must be `expected.head.commit_id`, and commit and
    /// generation identities must be fresh.
    pub async fn publish_if_match(
        &self,
        expected: &HeadVersion,
        candidate: PublicationCandidate,
        cancel: &CancellationToken,
    ) -> Result<PublishResult, PublicationError> {
        if candidate.commit.parent_commit_id != Some(expected.head.commit_id)
            || candidate.head.commit_id == expected.head.commit_id
            || candidate.head.generation == expected.head.generation
        {
            // The candidate does not advance the preserved base, or reuses an
            // immutable identity. Never overwrite under a reused identity.
            return Err(PublicationError::ImmutableRecordConflict);
        }
        let lease = self.capture()?;
        let evidence = self.stage(&lease, &candidate, Some(expected.head.commit_id), cancel).await?;
        self.before_s3(&lease, true, cancel).await?;
        match self.store.replace_head(&lease, &expected.etag, &candidate.head, cancel).await? {
            PublishOutcome::Committed => Ok(PublishResult::Committed(evidence)),
            PublishOutcome::PreconditionFailed => {
                let current = self.read_head_with_etag(cancel).await?;
                Ok(PublishResult::PreconditionFailed { current })
            }
            PublishOutcome::Ambiguous => Ok(PublishResult::Ambiguous(evidence)),
        }
    }

    /// One bounded canonical read of an immutable metadata record. A record
    /// naming a newer schema or unknown feature is
    /// [`PublicationError::UnsupportedFormat`]; a referenced record that is
    /// absent is retryable [`PublicationError::RemoteContentUnavailable`],
    /// never a deletion.
    pub async fn read_metadata(
        &self,
        record: MetadataRecord,
        cancel: &CancellationToken,
    ) -> Result<BoundedRecord, PublicationError> {
        let lease = self.capture()?;
        self.before_s3(&lease, false, cancel).await?;
        self.store.read_metadata(&lease, record, cancel).await.map_err(|err| match err {
            PublicationError::Absent => PublicationError::RemoteContentUnavailable,
            other => other,
        })
    }

    /// Walks validated bounded committed ancestry for the exact operation
    /// UUID. `Ok(Some(id))` reports the commit that records the operation;
    /// `Ok(None)` proves absence (the chain was consumed inside the bound);
    /// [`PublicationError::SearchIncomplete`] means the bound stopped the
    /// search — resume with [`crate::ancestry::walk_ancestry`] and a cursor.
    pub async fn find_committed_operation(
        &self,
        from: CommitId,
        operation: OperationId,
        cancel: &CancellationToken,
    ) -> Result<Option<CommitId>, PublicationError> {
        let lease = self.capture()?;
        let goal = AncestryGoal { candidate: None, operations: vec![operation] };
        let progress = ancestry::walk_ancestry(
            self,
            &lease,
            self.binding.workspace_id(),
            AncestryCursor::begin(from),
            &goal,
            AncestryStop::FirstMatch,
            ancestry::AncestryBounds::default(),
            cancel,
        )
        .await?;
        match progress {
            AncestryProgress::Complete { matches } => {
                Ok(matches.first().map(|found: &AncestryMatch| found.commit_id))
            }
            AncestryProgress::Candidate { commit_id, .. } => Ok(Some(commit_id)),
            AncestryProgress::Paused { .. } => Err(PublicationError::SearchIncomplete),
        }
    }

    /// Resolves one uncertain conditional write by walking current committed
    /// ancestry for the exact candidate commit and all of its operation UUIDs.
    /// Never replays the CAS and never claims rollback; a missing record is
    /// retryable [`PublicationError::RemoteContentUnavailable`].
    ///
    /// `cursor` resumes a previous [`UncertainResolution::Unresolved`].
    pub async fn resolve_uncertain_write(
        &self,
        candidate: &PublicationCandidate,
        cursor: Option<AncestryCursor>,
        cancel: &CancellationToken,
    ) -> Result<UncertainResolution, PublicationError> {
        let start = match cursor {
            Some(cursor) => cursor,
            None => match self.read_head_with_etag(cancel).await? {
                Some(current) => AncestryCursor::begin(current.head.commit_id),
                // No committed chain to search. Nothing can be confirmed as
                // committed; the caller pauses an established connection.
                None => return Ok(UncertainResolution::NotCommitted { current: None }),
            },
        };
        let lease = self.capture()?;
        let goal = AncestryGoal {
            candidate: Some(candidate.commit.commit_id),
            operations: candidate.commit.operation_ids.clone(),
        };
        let progress = ancestry::walk_ancestry(
            self,
            &lease,
            self.binding.workspace_id(),
            start,
            &goal,
            AncestryStop::CandidateOrComplete,
            ancestry::AncestryBounds::default(),
            cancel,
        )
        .await?;
        match progress {
            AncestryProgress::Candidate { commit_id, .. } => {
                Ok(UncertainResolution::Committed { commit_id })
            }
            AncestryProgress::Complete { matches } => {
                if matches.is_empty() {
                    let current = self.read_head_with_etag(cancel).await?;
                    Ok(UncertainResolution::NotCommitted { current })
                } else {
                    Ok(UncertainResolution::CommittedElsewhere { matches })
                }
            }
            AncestryProgress::Paused { cursor, matches } => {
                Ok(UncertainResolution::Unresolved { cursor, matches })
            }
        }
    }

    /// Uploads one flushed immutable payload capture through the native Xet
    /// path (ingestion -> CAS commit -> binding) and returns its immutable
    /// reference. Idempotent across interrupted runs: an object already bound
    /// at exactly `objects/<upload-uuid>` with the capture's size and a native
    /// Xet identity is reused (the upload UUID is generated and persisted
    /// before the first effect, so that key is provably this run's object).
    pub async fn upload_payload(
        &self,
        snapshot: StableSnapshot,
        cancel: &CancellationToken,
    ) -> Result<PayloadPlacement, PublicationError> {
        let lease = self.capture()?;
        let key = self.binding.prefix().immutable_key(ImmutableKey::Payload(snapshot.upload_id));
        if let Some(existing) = self.native.object_metadata(&lease, &key, cancel).await.map_err(map_native_error)?
        {
            let Some(xet_file_id) = existing.xet_file_id.clone() else {
                // The native capability gate: an object without a Xet identity
                // is never served as generic payload.
                return Err(PublicationError::XetRequired);
            };
            if existing.size != snapshot.size {
                return Err(PublicationError::ImmutableRecordConflict);
            }
            return Ok(PayloadPlacement {
                object: ObjectRef {
                    key: PayloadKey::new(snapshot.upload_id),
                    sha256: snapshot.sha256,
                    size: snapshot.size,
                    xet_file_id,
                },
                upload: None,
                reused: true,
            });
        }
        let upload = self
            .native
            .upload_snapshot(&lease, snapshot.clone(), cancel)
            .await
            .map_err(map_native_error)?;
        Ok(PayloadPlacement {
            object: ObjectRef {
                key: PayloadKey::new(snapshot.upload_id),
                sha256: snapshot.sha256,
                size: snapshot.size,
                xet_file_id: upload.bound.xet_file_id.clone(),
            },
            upload: Some(upload),
            reused: false,
        })
    }

    // ---- internals ------------------------------------------------------

    fn capture(&self) -> Result<NativeLease, PublicationError> {
        self.native.capture_lease().map_err(map_native_error)
    }

    /// Fresh native resource-authorization check immediately before one S3
    /// transaction. An epoch check alone is not resource permission.
    async fn before_s3(
        &self,
        lease: &NativeLease,
        write: bool,
        cancel: &CancellationToken,
    ) -> Result<(), PublicationError> {
        let result = if write {
            self.native.check_write(lease, cancel).await
        } else {
            self.native.check_read(lease, cancel).await
        };
        result.map_err(map_native_error)
    }

    /// Validates one candidate against the exact binding and (for a
    /// replacement) the preserved base commit, then writes and verifies every
    /// immutable dependency before the caller writes `HEAD`.
    async fn stage(
        &self,
        lease: &NativeLease,
        candidate: &PublicationCandidate,
        base: Option<CommitId>,
        cancel: &CancellationToken,
    ) -> Result<PublicationEvidence, PublicationError> {
        self.validate_candidate(candidate, base)?;
        let mut uploads = Vec::new();
        let mut records = Vec::new();

        // Dependency order: versions -> catalog pages -> commit; HEAD is
        // written by the caller only after all of these are durable.
        let mut versions = candidate.versions.iter().collect::<Vec<_>>();
        versions.sort_by_key(|version| *version.version_id.as_uuid());
        for version in versions {
            let bytes = format::to_version_bytes(version).map_err(map_format_error)?;
            let target = ImmutableKey::Version(version.version_id);
            let key = self.binding.prefix().immutable_key(target);
            let sha256 = Sha256Digest::of(&bytes);
            let size = bytes.len() as u64;
            self.write_immutable(lease, target, key.clone(), bytes, &mut uploads, cancel).await?;
            records.push(RecordEvidence { key, sha256, size });
        }
        let mut pages = candidate.catalog.pages.clone();
        pages.sort_by_key(|(digest, _)| *digest.as_bytes());
        for (digest, page) in pages {
            let (hash, bytes) = catalog::encode_and_hash(&page).map_err(map_format_error)?;
            if hash != digest {
                return Err(PublicationError::InvalidResponse);
            }
            let target = ImmutableKey::Catalog(hash);
            let key = self.binding.prefix().immutable_key(target);
            let size = bytes.len() as u64;
            self.write_immutable(lease, target, key.clone(), bytes, &mut uploads, cancel).await?;
            records.push(RecordEvidence { key, sha256: hash, size });
        }
        let commit_bytes = format::to_commit_bytes(&candidate.commit).map_err(map_format_error)?;
        let commit_target = ImmutableKey::Commit(candidate.commit.commit_id);
        let commit_key = self.binding.prefix().immutable_key(commit_target);
        let commit_sha = Sha256Digest::of(&commit_bytes);
        let commit_size = commit_bytes.len() as u64;
        self.write_immutable(
            lease,
            commit_target,
            commit_key.clone(),
            commit_bytes,
            &mut uploads,
            cancel,
        )
        .await?;
        records.push(RecordEvidence { key: commit_key, sha256: commit_sha, size: commit_size });

        self.verify_payloads(lease, candidate, cancel).await?;
        let payloads = candidate
            .payloads
            .iter()
            .map(|object| PayloadPlacement { object: object.clone(), upload: None, reused: true })
            .collect();

        Ok(PublicationEvidence {
            candidate_commit: candidate.commit.commit_id,
            head_generation: candidate.head.generation,
            operation_ids: candidate.commit.operation_ids.clone(),
            head_bytes_sha256: Sha256Digest::of(&to_head_bytes(&candidate.head)?),
            records,
            uploads,
            payloads,
        })
    }

    /// Validates candidate shape and exact binding agreement.
    fn validate_candidate(
        &self,
        candidate: &PublicationCandidate,
        base: Option<CommitId>,
    ) -> Result<(), PublicationError> {
        let head = &candidate.head;
        let commit = &candidate.commit;
        if head.workspace_id != self.binding.workspace_id()
            || commit.workspace_id != self.binding.workspace_id()
        {
            return Err(PublicationError::BindingMismatch);
        }
        if head.commit_id != commit.commit_id {
            return Err(PublicationError::InvalidResponse);
        }
        if commit.operation_ids.is_empty() {
            return Err(PublicationError::InvalidResponse);
        }
        match base {
            Some(base) => {
                if commit.parent_commit_id != Some(base) {
                    return Err(PublicationError::ImmutableRecordConflict);
                }
            }
            None => {
                if commit.parent_commit_id.is_some() {
                    // Initial publication must be the root commit.
                    return Err(PublicationError::InvalidResponse);
                }
            }
        }
        if commit.catalog_root != candidate.catalog.root.digest() {
            return Err(PublicationError::InvalidResponse);
        }
        // Canonical bounded records; format/schema/feature failures surface
        // as `UnsupportedFormat`, size violations as `RecordTooLarge`.
        to_head_bytes(head)?;
        format::to_commit_bytes(commit).map_err(map_format_error)?;
        for version in &candidate.versions {
            if version.workspace_id != self.binding.workspace_id() {
                return Err(PublicationError::BindingMismatch);
            }
            format::to_version_bytes(version).map_err(map_format_error)?;
            match candidate.payloads.iter().find(|payload| payload.key == version.object_key) {
                Some(payload) => {
                    if version.xet_file_id.as_ref() != Some(&payload.xet_file_id)
                        || payload.sha256 != version.sha256
                        || payload.size != version.size
                    {
                        return Err(PublicationError::ImmutableRecordConflict);
                    }
                }
                None => {
                    // A version without a payload must be a directory-style
                    // record with no Xet identity.
                    if version.xet_file_id.is_some() {
                        return Err(PublicationError::RemoteContentUnavailable);
                    }
                }
            }
        }
        for payload in &candidate.payloads {
            let referenced = candidate.versions.iter().any(|version| version.object_key == payload.key);
            if !referenced {
                return Err(PublicationError::InvalidResponse);
            }
        }
        Ok(())
    }

    /// Writes one immutable record via the native Xet path. An existing key
    /// must hold exactly these bytes (idempotent resume of an earlier attempt
    /// of this same candidate); any disagreement is
    /// [`PublicationError::ImmutableRecordConflict`] and is never overwritten.
    async fn write_immutable(
        &self,
        lease: &NativeLease,
        target: ImmutableKey,
        key: RelativeKey,
        bytes: Vec<u8>,
        uploads: &mut Vec<UploadEvidence>,
        cancel: &CancellationToken,
    ) -> Result<(), PublicationError> {
        match self.native.object_metadata(lease, &key, cancel).await.map_err(map_native_error)? {
            None => {
                let evidence = self
                    .native
                    .upload_record(lease, target, bytes, cancel)
                    .await
                    .map_err(map_native_error)?;
                uploads.push(evidence);
                Ok(())
            }
            Some(existing) => {
                if existing.size != bytes.len() as u64 {
                    return Err(PublicationError::ImmutableRecordConflict);
                }
                let record = match target {
                    ImmutableKey::Version(id) => MetadataRecord::Version(id),
                    ImmutableKey::Catalog(id) => MetadataRecord::Catalog(id),
                    ImmutableKey::Commit(id) => MetadataRecord::Commit(id),
                    ImmutableKey::Payload(_) => return Err(PublicationError::InvalidResponse),
                };
                // Reuse requires byte equality: a fresh native permission
                // check precedes this S3 transaction like any other.
                self.before_s3(lease, false, cancel).await?;
                let observed = self.store.read_metadata(lease, record, cancel).await.map_err(|err| match err {
                    // The record vanished between the existence check and this
                    // read: retryable evidence, never a deletion.
                    PublicationError::Absent => PublicationError::RemoteContentUnavailable,
                    other => other,
                })?;
                if observed.body() != bytes.as_slice() {
                    return Err(PublicationError::ImmutableRecordConflict);
                }
                Ok(())
            }
        }
    }

    /// Verifies every referenced payload is bound with its exact size and
    /// native Xet identity before `HEAD` may reference it.
    async fn verify_payloads(
        &self,
        lease: &NativeLease,
        candidate: &PublicationCandidate,
        cancel: &CancellationToken,
    ) -> Result<(), PublicationError> {
        if candidate.payloads.is_empty() {
            return Ok(());
        }
        let keys: Vec<RelativeKey> = candidate
            .payloads
            .iter()
            .map(|payload| self.binding.prefix().immutable_key(payload.key.immutable_key()))
            .collect();
        let report = self.native.paths_info(lease, &keys, cancel).await.map_err(map_native_error)?;
        for (payload, key) in candidate.payloads.iter().zip(&keys) {
            let Some(info) = report.found.iter().find(|info| &info.key == key) else {
                // An absent referenced dependency is retryable evidence about
                // transport state, never a deletion.
                return Err(PublicationError::RemoteContentUnavailable);
            };
            if info.size != payload.size || info.xet_file_id.as_ref() != Some(&payload.xet_file_id) {
                return Err(PublicationError::ImmutableRecordConflict);
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Canonical record helpers shared by the publication layer
// ---------------------------------------------------------------------------

/// Maps core format failures onto the publication error surface: newer
/// schemas, unknown required features and foreign records are
/// [`PublicationError::UnsupportedFormat`]; size bounds are
/// [`PublicationError::RecordTooLarge`]; everything else is a violated record
/// contract ([`PublicationError::InvalidResponse`]).
pub fn map_format_error(err: FormatError) -> PublicationError {
    match err {
        FormatError::NewerSchema
        | FormatError::UnsupportedFeature
        | FormatError::NotHFDriveFormat => PublicationError::UnsupportedFormat,
        FormatError::TooLarge => PublicationError::RecordTooLarge,
        _ => PublicationError::InvalidResponse,
    }
}

/// Maps sanitized native failures onto the publication error surface.
pub fn map_native_error(err: NativeError) -> PublicationError {
    match err {
        NativeError::NeedsSignIn => PublicationError::NeedsSignIn,
        NativeError::PermissionDenied => PublicationError::PermissionDenied,
        NativeError::RemoteContentUnavailable => PublicationError::RemoteContentUnavailable,
        NativeError::XetRequired => PublicationError::XetRequired,
        NativeError::Cancelled => PublicationError::Cancelled,
        NativeError::IdentityMismatch => PublicationError::BindingMismatch,
        NativeError::InvalidResponse | NativeError::InvalidRange => PublicationError::InvalidResponse,
        // A staged capture that mutated under the upload violates the
        // immutable-snapshot contract; the closest publication class.
        NativeError::SourceChanged => PublicationError::InvalidResponse,
        // RateLimited, Transport, TooManyEntries, InvalidRequest, AlreadyExists
        // remain retryable transport-class failures.
        _ => PublicationError::Transport,
    }
}

/// Canonical `HEAD` bytes (validated; bounded by the format).
pub fn to_head_bytes(head: &HeadV1) -> Result<Vec<u8>, PublicationError> {
    format::to_head_bytes(head).map_err(map_format_error)
}

/// Parses and validates canonical `HEAD` bytes.
pub fn decode_head(bytes: &[u8]) -> Result<HeadV1, PublicationError> {
    let head = format::from_head_bytes(bytes).map_err(map_format_error)?;
    format::validate_head(&head).map_err(map_format_error)?;
    Ok(head)
}

/// Parses and validates canonical commit bytes with key/body and workspace
/// agreement (the record at `expected` must be that commit, for this workspace).
pub fn decode_commit(
    bytes: &[u8],
    expected: CommitId,
    workspace: WorkspaceId,
) -> Result<CommitV1, PublicationError> {
    if bytes.len() > format::MAX_COMMIT_BYTES {
        return Err(PublicationError::RecordTooLarge);
    }
    let commit = format::from_commit_bytes(bytes).map_err(map_format_error)?;
    if commit.commit_id != expected {
        return Err(PublicationError::InvalidResponse);
    }
    if commit.workspace_id != workspace {
        return Err(PublicationError::BindingMismatch);
    }
    Ok(commit)
}
