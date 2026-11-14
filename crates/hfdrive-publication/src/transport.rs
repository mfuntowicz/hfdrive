//! Explicitly credentialed HF S3 transport for managed `HEAD` CAS and probes.
//!
//! Configuration is fixed: endpoint `https://<canonical-namespace>.s3.hf.co`,
//! bare bucket name, signing region `us-east-1`, path-style addressing, request
//! and response checksums `WhenRequired`, `BehaviorVersion::latest()`, the AWS
//! SDK's supported default connector, and an explicitly supplied credential
//! pair — never ambient credential discovery. Exactly one dispatch attempt runs
//! per call (retries are disabled); signed requests never follow redirects, and
//! any 3xx answer is a contract violation.
//!
//! Key scope: reads cover the managed `HEAD`, the immutable metadata records
//! (ancestry/coherence) and owned probe keys. Writes cover the managed `HEAD`
//! and owned probe records only; immutable metadata and payload bytes are
//! produced through the native Xet path, never through this transport.

use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::operation::get_object::GetObjectOutput;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::{Client, config::{
    BehaviorVersion, Credentials, Region, RequestChecksumCalculation, ResponseChecksumValidation,
    retry::RetryConfig,
}};
use bytes::Bytes;
use hfdrive_hf::wire_budget::{Direction, WireBudget};
use hfdrive_hf::{NativeError, NativeLease};
use hfdrive_core::ids::{CommitId, VersionId};
use hfdrive_core::storage::{
    DriveBinding, ImmutableKey, RelativeKey, RemotePrefix, Sha256Digest,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::binding::{AccountIdentity, PublicationBinding};
use crate::credentials::SupplementalCredentialRecord;
use crate::{OpaqueEtag, PublicationError, PublishOutcome};

/// Managed `HEAD` bound (also used for version records).
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Immutable version record bound.
pub const MAX_VERSION_BYTES: usize = 16 * 1024;
/// Immutable catalog page bound.
pub const MAX_CATALOG_BYTES: usize = 256 * 1024;
/// Immutable commit record bound.
pub const MAX_COMMIT_BYTES: usize = 1024 * 1024;
/// Owned probe record bound ("tiny publication records").
pub const MAX_PROBE_RECORD_BYTES: usize = 16 * 1024;
/// Bound for one probe verification read (covers the deterministic probe file).
pub const MAX_PROBE_READ_BYTES: usize = 64 * 1024 * 1024;

/// Managed `HEAD` body; construction enforces the format bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeadRecord(Bytes);

impl HeadRecord {
    /// Wraps a `HEAD` body, rejecting anything over [`MAX_HEAD_BYTES`].
    pub fn new(bytes: impl Into<Bytes>) -> Result<Self, PublicationError> {
        let bytes = bytes.into();
        if bytes.len() > MAX_HEAD_BYTES {
            return Err(PublicationError::RecordTooLarge);
        }
        Ok(Self(bytes))
    }
    /// The record body.
    pub fn as_bytes(&self) -> &[u8] { &self.0 }
    /// Body length in bytes.
    pub fn len(&self) -> usize { self.0.len() }
    /// Whether the record is empty.
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}

/// Owned probe record body; construction enforces the probe bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeRecord(Bytes);

impl ProbeRecord {
    /// Wraps a probe record body, rejecting anything over [`MAX_PROBE_RECORD_BYTES`].
    pub fn new(bytes: impl Into<Bytes>) -> Result<Self, PublicationError> {
        let bytes = bytes.into();
        if bytes.len() > MAX_PROBE_RECORD_BYTES {
            return Err(PublicationError::RecordTooLarge);
        }
        Ok(Self(bytes))
    }
    /// The record body.
    pub fn as_bytes(&self) -> &[u8] { &self.0 }
    /// Body length in bytes.
    pub fn len(&self) -> usize { self.0.len() }
    /// Whether the record is empty.
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}

/// One bounded GET result: body plus the ETag from the same response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedRecord {
    etag: OpaqueEtag,
    body: Bytes,
}

impl BoundedRecord {
    /// Wraps one already-validated bounded body with the strong validator
    /// preserved from its response. Store implementations (including test
    /// fixtures) construct records through this entry point.
    pub fn from_parts(etag: OpaqueEtag, body: Bytes) -> Self {
        Self { etag, body }
    }
    /// The strong validator preserved from this very response.
    pub fn etag(&self) -> &OpaqueEtag { &self.etag }
    /// The bounded body.
    pub fn body(&self) -> &[u8] { &self.body }
    /// Body length in bytes.
    pub fn len(&self) -> usize { self.body.len() }
    /// Whether the body is empty.
    pub fn is_empty(&self) -> bool { self.body.is_empty() }
    /// Consumes the record into its body bytes.
    pub fn into_body(self) -> Bytes { self.body }
}

/// Immutable metadata record addressable by bounded S3 reads.
///
/// Metadata bytes are written through the native Xet path; this transport only
/// reads them back for ancestry and coherence checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataRecord {
    /// `versions/<id>.json`.
    Version(VersionId),
    /// `catalog/<sha256>.json`.
    Catalog(Sha256Digest),
    /// `commits/<id>.json`.
    Commit(CommitId),
}

impl MetadataRecord {
    /// The format bound for this record kind.
    pub const fn max_bytes(self) -> usize {
        match self {
            Self::Version(_) => MAX_VERSION_BYTES,
            Self::Catalog(_) => MAX_CATALOG_BYTES,
            Self::Commit(_) => MAX_COMMIT_BYTES,
        }
    }

    pub(crate) fn key(self, prefix: &RemotePrefix) -> RelativeKey {
        prefix.immutable_key(match self {
            Self::Version(id) => ImmutableKey::Version(id),
            Self::Catalog(id) => ImmutableKey::Catalog(id),
            Self::Commit(id) => ImmutableKey::Commit(id),
        })
    }
}

/// A key inside one owned probe namespace (`hfdrive-probe/<run-id>/<name>`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeKey {
    run_id: Uuid,
    key: RelativeKey,
}

impl ProbeKey {
    /// Builds and validates `hfdrive-probe/<run-id>/<name>`.
    ///
    /// The name follows canonical bucket-relative key rules (it may address one
    /// nested path such as `objects/<upload-uuid>`); traversal, empty segments
    /// and reserved octets are rejected as out of scope.
    pub fn new(run_id: Uuid, name: &str) -> Result<Self, PublicationError> {
        if run_id.is_nil() {
            return Err(PublicationError::KeyOutOfScope);
        }
        let full = format!("hfdrive-probe/{run_id}/{name}");
        let key = RelativeKey::new(full).map_err(|_| PublicationError::KeyOutOfScope)?;
        Ok(Self { run_id, key })
    }
    /// The owning probe run.
    pub fn run_id(&self) -> Uuid { self.run_id }
    /// The full bucket-relative key.
    pub fn as_str(&self) -> &str { self.key.as_str() }
}

/// The only conditional-write targets: create via `If-None-Match: *`, replace
/// via exactly one `If-Match` with a preserved strong validator.
enum Precondition<'a> {
    Create,
    Replace(&'a OpaqueEtag),
}

/// Explicitly credentialed S3 transport bound to one managed drive prefix.
///
/// Immutable after construction: the supplied [`DriveBinding`] is validated
/// once against the verified issuer/subject and the supplemental credential
/// record, and no mutator exists. Every dispatch revalidates the live
/// [`NativeLease`] (authorization epoch and account identity) and requires its
/// account to match the bound account key. That gate is an epoch check only —
/// the caller must verify current native resource authorization before every
/// publication transaction.
pub struct S3Transport {
    client: Client,
    binding: PublicationBinding,
    budget: WireBudget,
}

impl S3Transport {
    /// Binds the transport after cross-validating binding, identity and credentials.
    ///
    /// Agreement required: binding account key equals
    /// `sha256(issuer || 0x00 || subject)`, and the credential record's context
    /// matches issuer, subject, account key, owner, bucket, workspace and
    /// prefix exactly. `budget` must be the provider's shared wire budget — the
    /// same instance metering the native/Xet boundaries — so S3 request and
    /// response bodies count and pace against the one transfer budget.
    pub fn bind(
        binding: &DriveBinding,
        account: &AccountIdentity<'_>,
        record: &SupplementalCredentialRecord,
        budget: WireBudget,
    ) -> Result<Self, PublicationError> {
        let binding = PublicationBinding::new(binding, account)?;
        binding.matches_record(record)?;
        let credentials = Credentials::new(
            record.key_id(),
            record.secret_key(),
            None,
            None,
            "hfdrive-supplemental",
        );
        let endpoint = format!(
            "https://{}.s3.hf.co",
            binding.address().owner_namespace().as_str()
        );
        let config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .endpoint_url(endpoint)
            .force_path_style(true)
            .credentials_provider(credentials)
            .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
            .response_checksum_validation(ResponseChecksumValidation::WhenRequired)
            .retry_config(RetryConfig::disabled())
            .build();
        Ok(Self { client: Client::from_conf(config), binding, budget })
    }

    /// The immutable binding this transport serves.
    pub fn binding(&self) -> &PublicationBinding { &self.binding }

    /// One bounded GET of the managed `HEAD`; body and ETag come from one response.
    pub async fn read_head(
        &self,
        lease: &NativeLease,
        cancel: &CancellationToken,
    ) -> Result<BoundedRecord, PublicationError> {
        self.get_bounded(lease, self.binding.head_key().as_str(), MAX_HEAD_BYTES, cancel)
            .await
    }

    /// One bounded GET of an immutable metadata record (ancestry/coherence).
    pub async fn read_metadata(
        &self,
        lease: &NativeLease,
        record: MetadataRecord,
        cancel: &CancellationToken,
    ) -> Result<BoundedRecord, PublicationError> {
        let key = record.key(self.binding.prefix());
        self.get_bounded(lease, key.as_str(), record.max_bytes(), cancel).await
    }

    /// Conditional creation of the managed `HEAD` (`If-None-Match: *`, one attempt).
    pub async fn create_head(
        &self,
        lease: &NativeLease,
        body: HeadRecord,
        cancel: &CancellationToken,
    ) -> Result<PublishOutcome, PublicationError> {
        self.put_conditional(
            lease,
            self.binding.head_key().as_str(),
            Precondition::Create,
            body.0,
            MAX_HEAD_BYTES,
            cancel,
        )
        .await
    }

    /// Conditional replacement of the managed `HEAD` (exactly one `If-Match` PUT).
    pub async fn replace_head(
        &self,
        lease: &NativeLease,
        expected: &OpaqueEtag,
        body: HeadRecord,
        cancel: &CancellationToken,
    ) -> Result<PublishOutcome, PublicationError> {
        self.put_conditional(
            lease,
            self.binding.head_key().as_str(),
            Precondition::Replace(expected),
            body.0,
            MAX_HEAD_BYTES,
            cancel,
        )
        .await
    }

    /// The owned probe namespace for one explicit probe run.
    pub fn probe(&self, run_id: Uuid) -> ProbeNamespace<'_> {
        ProbeNamespace { transport: self, run_id }
    }

    /// Per-dispatch gate: live lease (epoch + account identity), binding
    /// agreement, no early cancellation.
    fn begin(
        &self,
        lease: &NativeLease,
        cancel: &CancellationToken,
    ) -> Result<(), PublicationError> {
        lease.check().map_err(|err| match err {
            NativeError::IdentityMismatch => PublicationError::BindingMismatch,
            NativeError::PermissionDenied => PublicationError::PermissionDenied,
            _ => PublicationError::NeedsSignIn,
        })?;
        if lease.account() != self.binding.account_key() {
            return Err(PublicationError::BindingMismatch);
        }
        if cancel.is_cancelled() {
            return Err(PublicationError::Cancelled);
        }
        Ok(())
    }

    async fn get_bounded(
        &self,
        lease: &NativeLease,
        key: &str,
        bound: usize,
        cancel: &CancellationToken,
    ) -> Result<BoundedRecord, PublicationError> {
        self.begin(lease, cancel)?;
        let request = self
            .client
            .get_object()
            .bucket(self.binding.address().bucket_name().as_str())
            .key(key);
        let request = request.send();
        let output = match race_attempt(cancel, async move {
            request.await.map_err(|err| classify_read_verdict(verdict_of(&err)))
        })
        .await?
        {
            Some(output) => output,
            // Reads have no remote effect; a cancelled read is simply cancelled.
            None => return Err(PublicationError::Cancelled),
        };
        let GetObjectOutput { body, content_length, e_tag, .. } = output;
        let etag = OpaqueEtag::new(e_tag.ok_or(PublicationError::InvalidResponse)?)?;
        if content_length.is_some_and(|length| length < 0 || length as usize > bound) {
            return Err(PublicationError::RecordTooLarge);
        }
        let mut body = body;
        let mut collected: Vec<u8> =
            Vec::with_capacity(content_length.unwrap_or(0).clamp(0, bound as i64) as usize);
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|_| PublicationError::Transport)?;
            if collected.len() + chunk.len() > bound {
                return Err(PublicationError::RecordTooLarge);
            }
            // Count and pace the encoded body chunk at the transport boundary
            // against the shared wire budget before buffering it.
            let gate = self.budget.gate(Direction::Download, chunk.len() as u64);
            tokio::select! {
                biased;
                () = gate => {}
                () = cancel.cancelled() => return Err(PublicationError::Cancelled),
            }
            collected.extend_from_slice(&chunk);
            if cancel.is_cancelled() {
                return Err(PublicationError::Cancelled);
            }
        }
        Ok(BoundedRecord { etag, body: Bytes::from(collected) })
    }

    async fn put_conditional(
        &self,
        lease: &NativeLease,
        key: &str,
        precondition: Precondition<'_>,
        body: Bytes,
        bound: usize,
        cancel: &CancellationToken,
    ) -> Result<PublishOutcome, PublicationError> {
        self.begin(lease, cancel)?;
        if body.len() > bound {
            return Err(PublicationError::RecordTooLarge);
        }
        // Count and pace the encoded request body against the shared wire
        // budget before it is dispatched. A cancelled admission means nothing
        // left the process, so `Cancelled` is exact here (uncertainty begins
        // only once the attempt is dispatched).
        let gate = self.budget.gate(Direction::Upload, body.len() as u64);
        tokio::select! {
            biased;
            () = gate => {}
            () = cancel.cancelled() => return Err(PublicationError::Cancelled),
        }
        let mut request = self
            .client
            .put_object()
            .bucket(self.binding.address().bucket_name().as_str())
            .key(key)
            .body(ByteStream::from(body));
        request = match precondition {
            Precondition::Create => request.if_none_match("*"),
            Precondition::Replace(etag) => request.if_match(etag.as_str()),
        };
        let raced = race_attempt(cancel, async move {
            match request.send().await {
                Ok(_) => Ok(PublishOutcome::Committed),
                Err(err) => classify_write_verdict(verdict_of(&err)),
            }
        })
        .await?;
        // Cancellation while the single attempt was in flight leaves an
        // accepted mutation uncertain; never report it as rolled back.
        Ok(raced.unwrap_or(PublishOutcome::Ambiguous))
    }
}

/// Owned probe namespace; all keys live under `hfdrive-probe/<run-id>/`.
///
/// Cleanup deletes exactly the recorded keys of this run — there is no
/// listing, prefix delete or general remote garbage collection.
pub struct ProbeNamespace<'t> {
    transport: &'t S3Transport,
    run_id: Uuid,
}

impl<'t> ProbeNamespace<'t> {
    /// The owning probe run identifier.
    pub fn run_id(&self) -> Uuid { self.run_id }

    /// A key inside this run's namespace.
    pub fn key(&self, name: &str) -> Result<ProbeKey, PublicationError> {
        ProbeKey::new(self.run_id, name)
    }

    fn owned(&self, key: &ProbeKey) -> Result<(), PublicationError> {
        if key.run_id == self.run_id {
            Ok(())
        } else {
            Err(PublicationError::KeyOutOfScope)
        }
    }

    /// One bounded GET of an owned probe key (record or verification read).
    pub async fn read(
        &self,
        lease: &NativeLease,
        key: &ProbeKey,
        max_bytes: usize,
        cancel: &CancellationToken,
    ) -> Result<BoundedRecord, PublicationError> {
        self.owned(key)?;
        if max_bytes > MAX_PROBE_READ_BYTES {
            return Err(PublicationError::RecordTooLarge);
        }
        self.transport
            .get_bounded(lease, key.as_str(), max_bytes, cancel)
            .await
    }

    /// Conditional creation of an owned probe record (`If-None-Match: *`).
    pub async fn create(
        &self,
        lease: &NativeLease,
        key: &ProbeKey,
        body: ProbeRecord,
        cancel: &CancellationToken,
    ) -> Result<PublishOutcome, PublicationError> {
        self.owned(key)?;
        self.transport
            .put_conditional(
                lease,
                key.as_str(),
                Precondition::Create,
                body.0,
                MAX_PROBE_RECORD_BYTES,
                cancel,
            )
            .await
    }

    /// Conditional replacement of an owned probe record (exactly one `If-Match`).
    pub async fn replace(
        &self,
        lease: &NativeLease,
        key: &ProbeKey,
        expected: &OpaqueEtag,
        body: ProbeRecord,
        cancel: &CancellationToken,
    ) -> Result<PublishOutcome, PublicationError> {
        self.owned(key)?;
        self.transport
            .put_conditional(
                lease,
                key.as_str(),
                Precondition::Replace(expected),
                body.0,
                MAX_PROBE_RECORD_BYTES,
                cancel,
            )
            .await
    }

    /// Deletes exactly the listed keys of this run and returns the count.
    ///
    /// Every key must belong to this run. Deletion is idempotent, so a
    /// cancelled half-run converges by re-running the same recorded list.
    pub async fn delete_owned(
        &self,
        lease: &NativeLease,
        keys: &[ProbeKey],
        cancel: &CancellationToken,
    ) -> Result<u32, PublicationError> {
        let mut deleted = 0u32;
        for key in keys {
            self.owned(key)?;
            self.transport.begin(lease, cancel)?;
            let request = self
                .transport
                .client
                .delete_object()
                .bucket(self.transport.binding.address().bucket_name().as_str())
                .key(key.as_str())
                .send();
            match race_attempt(cancel, async move {
                match request.await {
                    Ok(_) => Ok(()),
                    Err(err) => Err(classify_read_verdict(verdict_of(&err))),
                }
            })
            .await?
            {
                Some(()) => deleted += 1,
                None => return Err(PublicationError::Cancelled),
            }
        }
        Ok(deleted)
    }
}

/// Races one already-built network attempt against cancellation.
///
/// The attempt is polled first, so a completed attempt always wins over a
/// simultaneous cancellation (the true outcome is never discarded). `None`
/// means cancellation won while the attempt was in flight: the request may
/// have been accepted.
async fn race_attempt<T, F>(
    cancel: &CancellationToken,
    attempt: F,
) -> Result<Option<T>, PublicationError>
where
    F: Future<Output = Result<T, PublicationError>>,
{
    tokio::pin!(attempt);
    tokio::select! {
        biased;
        result = &mut attempt => result.map(Some),
        () = cancel.cancelled() => Ok(None),
    }
}

/// What the service actually told us about one attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verdict {
    /// The request never reached the wire.
    NotSent,
    /// The request may have been sent; no usable answer came back.
    NoVerdict,
    /// A definite service answer with this status.
    Status(u16),
}

fn verdict_of<E>(err: &SdkError<E>) -> Verdict {
    match err {
        SdkError::ConstructionFailure(_) => Verdict::NotSent,
        SdkError::ServiceError(service) => {
            Verdict::Status(service.raw().status().as_u16())
        }
        // Timeouts, dispatch failures and unparseable responses: the mutation
        // may have been accepted, so there is no verdict.
        _ => Verdict::NoVerdict,
    }
}

/// Classifies one conditional mutation attempt.
///
/// `Ambiguous` covers every dispatched-but-unanswered attempt (including
/// cancellation after dispatch): the caller must search committed ancestry for
/// the persisted operation before deciding on another CAS. Definite answers —
/// absent/403/transport — stay distinct errors, and 3xx answers are contract
/// violations because signed requests never follow redirects.
fn classify_write_verdict(verdict: Verdict) -> Result<PublishOutcome, PublicationError> {
    match verdict {
        Verdict::NotSent => Err(PublicationError::Transport),
        Verdict::NoVerdict => Ok(PublishOutcome::Ambiguous),
        Verdict::Status(412) => Ok(PublishOutcome::PreconditionFailed),
        Verdict::Status(404) => Err(PublicationError::Absent),
        Verdict::Status(401) | Verdict::Status(403) => Err(PublicationError::PermissionDenied),
        Verdict::Status(status) if (300..400).contains(&status) => {
            Err(PublicationError::InvalidResponse)
        }
        Verdict::Status(status) if status >= 500 || status == 429 => {
            Err(PublicationError::Transport)
        }
        Verdict::Status(_) => Err(PublicationError::InvalidResponse),
    }
}

/// Classifies one bounded GET attempt; reads never produce `Ambiguous`.
fn classify_read_verdict(verdict: Verdict) -> PublicationError {
    match verdict {
        Verdict::NotSent | Verdict::NoVerdict => PublicationError::Transport,
        Verdict::Status(404) => PublicationError::Absent,
        Verdict::Status(401) | Verdict::Status(403) => PublicationError::PermissionDenied,
        Verdict::Status(status) if (300..400).contains(&status) => {
            PublicationError::InvalidResponse
        }
        Verdict::Status(_) => PublicationError::Transport,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hfdrive_auth::{AuthorizationAuthority, SecretAccessToken, TokenSource};
    use hfdrive_core::ids::{AccountKey, WorkspaceId};
    use hfdrive_core::storage::{
        BucketBinding, BucketId, BucketName, Namespace, OwnerId, OwnerKind,
    };
    use hfdrive_hf::wire_budget::BudgetConfig;
    use hfdrive_hf::NativeApi;
    use hfdrive_protocol::PublicationProtectionContext;
    use std::future::{pending, ready, Future};
    use std::sync::Arc;
    use zeroize::Zeroizing;

    const ISSUER: &str = "https://huggingface.co";
    const SUBJECT: &str = "subject-fixture";

    fn account() -> AccountKey {
        AccountKey::from_subject(ISSUER, SUBJECT)
    }

    fn workspace_id() -> WorkspaceId {
        WorkspaceId::from_uuid(Uuid::from_bytes([3; 16])).unwrap()
    }

    fn drive_binding() -> DriveBinding {
        DriveBinding {
            account_key: account(),
            bucket: BucketBinding {
                bucket_id: BucketId::new("bucket-stable-1".to_owned()).unwrap(),
                bucket_name: BucketName::new("probe-bucket-1".to_owned()).unwrap(),
                owner_id: OwnerId::new("owner-stable-1".to_owned()).unwrap(),
                owner_kind: OwnerKind::Personal,
                owner_namespace: Namespace::new("alice".to_owned()).unwrap(),
            },
            prefix: RemotePrefix::new("hfdrive/work".to_owned()).unwrap(),
            workspace_id: workspace_id(),
        }
    }

    fn context() -> PublicationProtectionContext {
        PublicationProtectionContext {
            connection_id: Uuid::from_bytes([7; 16]),
            account_key: account().to_string(),
            issuer: ISSUER.to_owned(),
            subject: SUBJECT.to_owned(),
            owner_id: "owner-stable-1".to_owned(),
            owner_kind: hfdrive_protocol::OwnerKind::Personal,
            bucket_id: "bucket-stable-1".to_owned(),
            workspace_id: *workspace_id().as_uuid(),
            prefix: "hfdrive/work".to_owned(),
        }
    }

    fn record() -> SupplementalCredentialRecord {
        SupplementalCredentialRecord::new(
            context(),
            "AKIAEXAMPLEKEYID1234".to_owned(),
            "secret-key-material-0123456789".to_owned(),
        )
        .unwrap()
    }

    fn budget() -> WireBudget {
        WireBudget::new(BudgetConfig::default())
    }

    struct FixtureTokens {
        authority: AuthorizationAuthority,
    }

    impl TokenSource for FixtureTokens {
        fn access_token(
            &self,
            account: AccountKey,
        ) -> impl Future<Output = Result<Arc<SecretAccessToken>, hfdrive_auth::AuthorizationError>> + Send {
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
        ) -> impl Future<Output = Result<Arc<SecretAccessToken>, hfdrive_auth::AuthorizationError>> + Send {
            self.access_token(account)
        }

        fn authorization_lease(
            &self,
            account: AccountKey,
        ) -> Result<hfdrive_auth::AuthorizationLease, hfdrive_auth::AuthorizationError> {
            let _ = account;
            self.authority.activate()
        }
    }

    fn transport() -> S3Transport {
        S3Transport::bind(
            &drive_binding(),
            &AccountIdentity { issuer: ISSUER, subject: SUBJECT },
            &record(),
            budget(),
        )
        .unwrap()
    }

    fn lease() -> NativeLease {
        let tokens = Arc::new(FixtureTokens { authority: AuthorizationAuthority::new(account(), 1) });
        NativeApi::new(tokens, account(), "https://huggingface.co".to_owned())
            .unwrap()
            .capture_lease()
            .unwrap()
    }

    #[tokio::test]
    async fn cancellation_before_dispatch_is_deterministic() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let outcome = transport()
            .create_head(&lease(), HeadRecord::new(b"{}".as_slice()).unwrap(), &cancel)
            .await;
        assert!(matches!(outcome, Err(PublicationError::Cancelled)), "{outcome:?}");
    }

    #[tokio::test]
    async fn probe_operations_reject_foreign_run_keys() {
        let transport = transport();
        let mine = transport.probe(Uuid::from_bytes([1; 16]));
        let foreign = ProbeKey::new(Uuid::from_bytes([2; 16]), "record").unwrap();
        let lease = lease();
        let cancel = CancellationToken::new();
        let body = ProbeRecord::new(b"x".as_slice()).unwrap();
        assert!(matches!(
            mine.create(&lease, &foreign, body.clone(), &cancel).await,
            Err(PublicationError::KeyOutOfScope)
        ));
        assert!(matches!(
            mine.read(&lease, &foreign, 1024, &cancel).await,
            Err(PublicationError::KeyOutOfScope)
        ));
        assert!(matches!(
            mine.delete_owned(&lease, &[foreign.clone()], &cancel).await,
            Err(PublicationError::KeyOutOfScope)
        ));
    }

    #[test]
    fn probe_keys_reject_traversal_and_nil_runs() {
        assert!(ProbeKey::new(Uuid::from_bytes([1; 16]), "../x").is_err());
        assert!(ProbeKey::new(Uuid::from_bytes([1; 16]), "").is_err());
        assert!(ProbeKey::new(Uuid::nil(), "record").is_err());
        let key = ProbeKey::new(Uuid::from_bytes([1; 16]), "objects/abc").unwrap();
        assert!(key.as_str().starts_with("hfdrive-probe/"));
    }

    #[test]
    fn bind_rejects_account_disagreement() {
        let mut binding = drive_binding();
        binding.account_key = AccountKey::from_subject(ISSUER, "someone-else");
        assert!(matches!(
            S3Transport::bind(
                &binding,
                &AccountIdentity { issuer: ISSUER, subject: SUBJECT },
                &record(),
                budget()
            ),
            Err(PublicationError::BindingMismatch)
        ));
    }

    #[test]
    fn bind_rejects_credential_context_disagreement() {
        let mut context = context();
        context.prefix = "hfdrive/other".to_owned();
        let record =
            SupplementalCredentialRecord::new(context, "key".to_owned(), "secret".to_owned())
                .unwrap();
        assert!(matches!(
            S3Transport::bind(
                &drive_binding(),
                &AccountIdentity { issuer: ISSUER, subject: SUBJECT },
                &record,
                budget()
            ),
            Err(PublicationError::BindingMismatch)
        ));
    }

    #[test]
    fn record_bounds_are_enforced_at_construction() {
        assert!(HeadRecord::new(vec![0u8; MAX_HEAD_BYTES]).is_ok());
        assert!(matches!(
            HeadRecord::new(vec![0u8; MAX_HEAD_BYTES + 1]),
            Err(PublicationError::RecordTooLarge)
        ));
        assert!(matches!(
            ProbeRecord::new(vec![0u8; MAX_PROBE_RECORD_BYTES + 1]),
            Err(PublicationError::RecordTooLarge)
        ));
    }

    #[test]
    fn metadata_bounds_follow_the_format() {
        let version = MetadataRecord::Version(VersionId::from_uuid(Uuid::from_bytes([4; 16])).unwrap());
        let catalog = MetadataRecord::Catalog(Sha256Digest::from_bytes([5; 32]));
        let commit = MetadataRecord::Commit(CommitId::from_uuid(Uuid::from_bytes([6; 16])).unwrap());
        assert_eq!(version.max_bytes(), MAX_VERSION_BYTES);
        assert_eq!(catalog.max_bytes(), MAX_CATALOG_BYTES);
        assert_eq!(commit.max_bytes(), MAX_COMMIT_BYTES);
    }

    #[tokio::test]
    async fn race_prefers_a_completed_attempt_even_when_cancelled() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let raced = race_attempt(&cancel, ready(Ok(PublishOutcome::Committed))).await;
        assert_eq!(raced.unwrap(), Some(PublishOutcome::Committed));
    }

    #[tokio::test]
    async fn race_reports_in_flight_cancellation() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let raced: Option<PublishOutcome> = race_attempt(&cancel, pending()).await.unwrap();
        assert_eq!(raced, None);
    }

    #[tokio::test]
    async fn race_returns_the_attempt_without_cancellation() {
        let cancel = CancellationToken::new();
        let raced = race_attempt(&cancel, ready(Ok(PublishOutcome::PreconditionFailed))).await;
        assert_eq!(raced.unwrap(), Some(PublishOutcome::PreconditionFailed));
    }

    #[test]
    fn write_verdict_classifies_conditional_answers() {
        assert!(matches!(classify_write_verdict(Verdict::Status(412)), Ok(PublishOutcome::PreconditionFailed)));
        assert!(matches!(classify_write_verdict(Verdict::Status(404)), Err(PublicationError::Absent)));
        assert!(matches!(classify_write_verdict(Verdict::Status(403)), Err(PublicationError::PermissionDenied)));
        assert!(matches!(classify_write_verdict(Verdict::Status(401)), Err(PublicationError::PermissionDenied)));
        assert!(matches!(classify_write_verdict(Verdict::Status(301)), Err(PublicationError::InvalidResponse)));
        assert!(matches!(classify_write_verdict(Verdict::Status(307)), Err(PublicationError::InvalidResponse)));
        assert!(matches!(classify_write_verdict(Verdict::Status(500)), Err(PublicationError::Transport)));
        assert!(matches!(classify_write_verdict(Verdict::Status(503)), Err(PublicationError::Transport)));
        assert!(matches!(classify_write_verdict(Verdict::Status(429)), Err(PublicationError::Transport)));
        assert!(matches!(classify_write_verdict(Verdict::Status(400)), Err(PublicationError::InvalidResponse)));
        assert!(matches!(classify_write_verdict(Verdict::NoVerdict), Ok(PublishOutcome::Ambiguous)));
        assert!(matches!(classify_write_verdict(Verdict::NotSent), Err(PublicationError::Transport)));
    }

    #[test]
    fn read_verdict_never_reports_ambiguity() {
        assert!(matches!(classify_read_verdict(Verdict::Status(404)), PublicationError::Absent));
        assert!(matches!(classify_read_verdict(Verdict::Status(403)), PublicationError::PermissionDenied));
        assert!(matches!(classify_read_verdict(Verdict::Status(302)), PublicationError::InvalidResponse));
        assert!(matches!(classify_read_verdict(Verdict::Status(500)), PublicationError::Transport));
        assert!(matches!(classify_read_verdict(Verdict::NoVerdict), PublicationError::Transport));
        assert!(matches!(classify_read_verdict(Verdict::NotSent), PublicationError::Transport));
    }

    #[test]
    fn sdk_failures_decompose_into_verdicts() {
        assert_eq!(verdict_of(&SdkError::<()>::construction_failure("bad")), Verdict::NotSent);
        assert_eq!(verdict_of(&SdkError::<()>::timeout_error("slow")), Verdict::NoVerdict);
    }
}
