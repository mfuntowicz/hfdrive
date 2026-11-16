//! Namespace control plane: bucket listing/creation/verification, object
//! metadata, bounded native HEAD-record reads, and prefix inspection.
//!
//! Everything here works from a [`hfdrive_core::storage::BucketBinding`] +
//! [`hfdrive_core::storage::RemotePrefix`] before any workspace identity
//! exists, and never creates a Xet session or cache directory.

use bytes::Bytes;
use hfdrive_core::storage::{
    BucketBinding, BucketId, BucketName, Namespace, OwnerId, OwnerKind, RelativeKey, RemotePrefix, XetFileId,
};
use tokio_util::sync::CancellationToken;

use crate::auth::NativeLease;
use crate::http;
use crate::store::{self, NativeBucketStore, NativeTreeEntry, ObjectMetadata, PageCursor, TreePage};
use crate::wire::{self, BucketSummaryWire, HeadRecord};
use crate::{NativeApi, NativeConfig, NativeError};
use hfdrive_auth::TokenSource;

/// Verified resource owner from the account profile. `owner_namespace` is the
/// **validated endpoint namespace** from the verified profile
/// (`AuthProfile.namespace`); an organization's display `name` is a display
/// hint only and is never used in requests or identity checks. Membership
/// display data never authorizes anything here: every call is authorized by
/// the account token and the service's own resource response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerRef {
    pub owner_id: OwnerId,
    pub owner_kind: OwnerKind,
    pub owner_namespace: Namespace,
}

/// Documented bucket hosting regions. Omitted means the service default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BucketRegion {
    Us,
    Eu,
}

/// Explicit creation options. Creation is always private and is never implied
/// by a login; an existing resource is never adopted.
#[derive(Clone, Debug, Default)]
pub struct CreateBucket {
    pub region: Option<BucketRegion>,
    /// Enterprise resource group id: exactly 24 hex characters when present.
    pub resource_group_id: Option<String>,
    pub description: Option<String>,
}

/// Verified bucket identity plus display metadata. `binding` carries the
/// stable ids that survive display-name changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BucketSummary {
    pub binding: BucketBinding,
    pub private: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub size: u64,
    pub total_files: u64,
}

/// Prefix occupancy, never conflated with absence. An unreadable prefix is an
/// error, not `Empty`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrefixState {
    /// The bucket itself is unavailable (404 on the verified bucket route).
    Missing,
    /// The prefix contains no entry at all.
    Empty,
    /// The prefix contains at least one entry.
    Populated,
}

/// Bounded pre-workspace inspection of one candidate prefix.
#[derive(Clone, Debug)]
pub struct PrefixInspection {
    pub prefix: RemotePrefix,
    pub state: PrefixState,
    /// Bounded sample of entries under the prefix (only when `Populated`).
    pub entries: Vec<NativeTreeEntry>,
}

/// Bounded native read of the mutable managed HEAD record at
/// `<prefix>/HEAD`. Small-record-only: this is never a payload HTTP fallback,
/// and an unsupported or oversized record is never reported as an empty
/// workspace.
#[derive(Clone, Debug)]
pub enum HeadRead {
    /// No HEAD object exists at this prefix.
    Missing,
    /// A HEAD object exists but exceeds the configured bound; it was not read.
    TooLarge { size: u64 },
    /// Bounded record bytes; `HeadRecord::format` classifies compatibility.
    Record(HeadRecord),
}

/// Namespace control plane for one account.
pub struct NativeControl<T: TokenSource> {
    api: NativeApi<T>,
    config: NativeConfig,
}

/// Unverified owner input exactly as the caller selected it: a stable identity
/// plus, optionally, the canonical namespace it claims. Nothing here is proof.
/// Namespace-located mutations require a [`VerifiedOwner`] produced by
/// [`NativeControl::verify_owner`]; there is no fallback from a subject or
/// display name to a namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerLocator {
    pub owner_id: OwnerId,
    pub owner_kind: OwnerKind,
    /// The canonical namespace the caller claims for this identity, when it
    /// selected one. A mismatch with the service's own mapping is rejected.
    pub claimed_namespace: Option<Namespace>,
}

/// Owner identity resolved through `whoami-v2`, with its canonical namespace
/// mapping when the service's reported name is usable as a locator. Produced by
/// [`NativeControl::whoami_owners`] for the parent's owner projection;
/// `namespace: None` means the owner cannot back a namespace-located request
/// and must be projected as unresolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerResolution {
    pub owner_id: OwnerId,
    pub owner_kind: OwnerKind,
    pub namespace: Option<Namespace>,
    /// Display hint only; never used as a locator.
    pub display_name: String,
}

/// Owner identity verified against the authenticated `GET /api/whoami-v2`
/// surface: the stable id and the canonical namespace the **service itself**
/// maps it to. Only [`NativeControl::verify_owner`] constructs this type.
/// Membership, roles and display names never authorize anything; this proves
/// an id -> namespace mapping only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedOwner {
    owner_id: OwnerId,
    owner_kind: OwnerKind,
    owner_namespace: Namespace,
    display_name: String,
}

impl VerifiedOwner {
    /// The stable owner identity.
    pub fn owner_id(&self) -> &OwnerId {
        &self.owner_id
    }

    /// Personal or organization.
    pub fn owner_kind(&self) -> OwnerKind {
        self.owner_kind
    }

    /// The canonical namespace the service maps this identity to.
    pub fn owner_namespace(&self) -> &Namespace {
        &self.owner_namespace
    }

    /// Display hint only; never used as a locator.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// The verified identity projected onto the read surfaces.
    pub fn owner_ref(&self) -> OwnerRef {
        OwnerRef {
            owner_id: self.owner_id.clone(),
            owner_kind: self.owner_kind,
            owner_namespace: self.owner_namespace.clone(),
        }
    }

    /// The locator form of this verification: claimed namespace equals the
    /// verified one. Used to re-resolve immediately before a mutation so a
    /// changed mapping is rejected before any request is posted.
    pub fn locator(&self) -> OwnerLocator {
        OwnerLocator {
            owner_id: self.owner_id.clone(),
            owner_kind: self.owner_kind,
            claimed_namespace: Some(self.owner_namespace.clone()),
        }
    }
}

impl<T: TokenSource> Clone for NativeControl<T> {
    fn clone(&self) -> Self {
        Self { api: self.api.clone(), config: self.config.clone() }
    }
}

impl<T: TokenSource> NativeControl<T> {
    pub fn new(api: NativeApi<T>, config: NativeConfig) -> Self {
        Self { api, config }
    }

    /// Capture the operation lease; thread it through every dispatch of one
    /// durable operation.
    pub fn capture_lease(&self) -> Result<NativeLease, NativeError> {
        self.api.capture_lease()
    }

    /// Resolve the authenticated account's owners through the documented
    /// `GET /api/whoami-v2` route: the personal identity first, then the
    /// organization memberships in service order. Each entry pairs the stable
    /// id with the canonical namespace the service maps it to; display names
    /// are retained as hints and never used as locators. An entry whose
    /// reported name cannot serve as a canonical namespace carries
    /// `namespace: None` and can never back a namespace-located request.
    ///
    /// The pinned SDK's typed `whoami` model omits the stable ids this
    /// verification requires, so the documented raw route is read here with a
    /// bounded parse; the response is classified through the standard dispatch
    /// (lease check and one controlled 401 refresh included).
    pub async fn whoami_owners(
        &self,
        lease: &NativeLease,
        cancel: &CancellationToken,
    ) -> Result<Vec<OwnerResolution>, NativeError> {
        let url =
            reqwest::Url::parse(&format!("{}/api/whoami-v2", self.api.endpoint())).map_err(|_| NativeError::InvalidResponse)?;
        let Some(body) = self.api.get_optional(lease, url, cancel).await? else {
            // The documented route always exists on the service.
            return Err(NativeError::InvalidResponse);
        };
        let owners = wire::parse_whoami_owners(&body)?;
        Ok(owners
            .into_iter()
            .map(|owner| OwnerResolution {
                owner_id: owner.owner_id,
                owner_kind: owner.owner_kind,
                namespace: owner.namespace,
                display_name: owner.display_name,
            })
            .collect())
    }

    /// Resolve one owner by **stable id** through `whoami-v2` and validate the
    /// input locator before any namespace-located mutation:
    /// - the id must be present for the authenticated account (unresolvable
    ///   ids are [`NativeError::InvalidRequest`], never a name-based guess);
    /// - the claimed kind must match the service's own entry type;
    /// - the claimed namespace (when given) must equal the service's id ->
    ///   namespace mapping (a mismatch is [`NativeError::IdentityMismatch`]);
    /// - the mapping must be usable as a canonical namespace locator.
    ///
    /// There is no fallback from a subject or display name to a namespace and
    /// no role-based authorization anywhere in this path.
    pub async fn verify_owner(
        &self,
        lease: &NativeLease,
        locator: &OwnerLocator,
        cancel: &CancellationToken,
    ) -> Result<VerifiedOwner, NativeError> {
        let owners = self.whoami_owners(lease, cancel).await?;
        let entry = owners
            .iter()
            .find(|owner| owner.owner_id == locator.owner_id)
            .ok_or(NativeError::InvalidRequest {
                detail: "requested owner is not resolvable for the authenticated account".to_owned(),
            })?;
        if entry.owner_kind != locator.owner_kind {
            return Err(NativeError::IdentityMismatch);
        }
        let owner_namespace = entry.namespace.clone().ok_or(NativeError::InvalidRequest {
            detail: "owner does not expose a canonical namespace locator".to_owned(),
        })?;
        if let Some(claimed) = &locator.claimed_namespace
            && claimed != &owner_namespace
        {
            return Err(NativeError::IdentityMismatch);
        }
        Ok(VerifiedOwner {
            owner_id: entry.owner_id.clone(),
            owner_kind: entry.owner_kind,
            owner_namespace,
            display_name: entry.display_name.clone(),
        })
    }

    /// Open the storage plane for one connected drive. The binding's account
    /// must match this control plane's account.
    pub fn open_store(&self, binding: hfdrive_core::storage::DriveBinding) -> Result<NativeBucketStore<T>, NativeError> {
        NativeBucketStore::new(self.api.clone(), binding, self.config.clone())
    }

    /// Open the raw account+bucket storage plane used by one-shot imports.
    /// No workspace, managed prefix, or connection exists there; the account
    /// must match this control plane's account.
    pub fn open_raw_store(
        &self,
        account: hfdrive_core::ids::AccountKey,
        bucket: BucketBinding,
    ) -> Result<store::NativeRawStore<T>, NativeError> {
        store::NativeRawStore::new(self.api.clone(), account, bucket, self.config.clone())
    }

    fn summary_binding(&self, owner: &OwnerRef, summary: &BucketSummaryWire) -> Result<BucketBinding, NativeError> {
        let bucket_name = BucketName::new(summary.name.clone()).map_err(|_| NativeError::InvalidResponse)?;
        Ok(BucketBinding {
            bucket_id: summary.bucket_id.clone(),
            bucket_name,
            owner_id: owner.owner_id.clone(),
            owner_kind: owner.owner_kind,
            owner_namespace: wire::wire_namespace(&summary.owner_namespace)?,
        })
    }

    /// List the verified buckets of one owner namespace. Every record is
    /// identity-checked against the requested namespace; pagination stays on
    /// the API origin inside this namespace's bucket API prefix.
    pub async fn list_buckets(
        &self,
        lease: &NativeLease,
        owner: &OwnerRef,
        cancel: &CancellationToken,
    ) -> Result<Vec<BucketSummary>, NativeError> {
        let ns = owner.owner_namespace.as_str();
        let api_prefix = format!("/api/buckets/{ns}");
        // Namespace charset is validated upstream (no URL metacharacters).
        let url =
            reqwest::Url::parse(&format!("{}/api/buckets/{}", self.api.endpoint(), ns)).map_err(|_| NativeError::InvalidResponse)?;

        let mut out = Vec::new();
        let mut next = Some(url);
        let mut pages = 0usize;
        while let Some(page_url) = next {
            pages += 1;
            if pages > 4096 {
                return Err(NativeError::TooManyEntries);
            }
            let (body, next_url) = self.api.get_page(lease, page_url, &api_prefix, cancel).await?;
            next = next_url;
            let values: Vec<serde_json::Value> =
                serde_json::from_slice(&body).map_err(|_| NativeError::InvalidResponse)?;
            for value in &values {
                let summary = BucketSummaryWire::parse(value, ns, None)?;
                out.push(BucketSummary {
                    binding: self.summary_binding(owner, &summary)?,
                    private: summary.private,
                    created_at: summary.created_at,
                    updated_at: summary.updated_at,
                    size: summary.size,
                    total_files: summary.total_files,
                });
            }
            if out.len() > self.config.max_listed_entries {
                return Err(NativeError::TooManyEntries);
            }
        }
        Ok(out)
    }

    /// Resolve and verify one bucket by canonical owner namespace and bare
    /// name. `expected` pins the stable bucket id when the caller already
    /// selected one; a differing live id is [`NativeError::IdentityMismatch`]
    /// (the bucket was renamed or recreated). `Ok(None)` means no such bucket.
    pub async fn resolve_bucket(
        &self,
        lease: &NativeLease,
        owner: &OwnerRef,
        name: &BucketName,
        expected: Option<&BucketId>,
        cancel: &CancellationToken,
    ) -> Result<Option<BucketSummary>, NativeError> {
        let ns = owner.owner_namespace.as_str();
        let url = http::bucket_api_url(self.api.endpoint(), ns, name.as_str(), &[])?;
        let Some(body) = self.api.get_optional(lease, url, cancel).await? else {
            return Ok(None);
        };
        let value: serde_json::Value = serde_json::from_slice(&body).map_err(|_| NativeError::InvalidResponse)?;
        let summary = BucketSummaryWire::parse(&value, ns, Some(name.as_str()))?;
        if let Some(expected) = expected
            && summary.bucket_id != *expected
        {
            return Err(NativeError::IdentityMismatch);
        }
        Ok(Some(BucketSummary {
            binding: self.summary_binding(owner, &summary)?,
            private: summary.private,
            created_at: summary.created_at,
            updated_at: summary.updated_at,
            size: summary.size,
            total_files: summary.total_files,
        }))
    }

    /// Create one explicit private bucket and return its verified identity.
    /// HTTP 409 is [`NativeError::AlreadyExists`] and never adoption of the
    /// existing resource. No storage is created by login itself.
    ///
    /// The owner must be a [`VerifiedOwner`] (produced by
    /// [`NativeControl::verify_owner`]) and the stable id -> namespace mapping
    /// is **re-resolved through whoami-v2 immediately before the POST**: a
    /// changed or mismatched mapping is rejected before any request leaves, so
    /// a display hint can never route creation into the wrong owner.
    pub async fn create_bucket(
        &self,
        lease: &NativeLease,
        owner: &VerifiedOwner,
        name: &BucketName,
        options: &CreateBucket,
        cancel: &CancellationToken,
    ) -> Result<BucketSummary, NativeError> {
        if let Some(group) = &options.resource_group_id
            && (group.len() != 24 || !group.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(NativeError::InvalidRequest {
                detail: "resource group id must be exactly 24 hex characters".to_owned(),
            });
        }
        if let Some(description) = &options.description
            && description.chars().count() > 500
        {
            return Err(NativeError::InvalidRequest { detail: "description exceeds 500 characters".to_owned() });
        }
        // Pre-mutation identity gate: reject mismatched locators BEFORE POST.
        let resolved = self.verify_owner(lease, &owner.locator(), cancel).await?;
        let mut body = serde_json::json!({ "private": true });
        match options.region {
            Some(BucketRegion::Us) => body["region"] = serde_json::json!("us"),
            Some(BucketRegion::Eu) => body["region"] = serde_json::json!("eu"),
            None => {}
        }
        if let Some(group) = &options.resource_group_id {
            body["resourceGroupId"] = serde_json::json!(group);
        }
        if let Some(description) = &options.description {
            body["description"] = serde_json::json!(description);
        }
        let ns = resolved.owner_namespace.as_str();
        let url = http::bucket_api_url(self.api.endpoint(), ns, name.as_str(), &[])?;
        let bytes = Bytes::from(serde_json::to_vec(&body).map_err(|_| NativeError::InvalidResponse)?);
        self.api.post_bytes(lease, url, "application/json", bytes, cancel).await?;

        // The create response carries no stable identity; verify the fresh
        // bucket record before reporting it.
        self.resolve_bucket(lease, &resolved.owner_ref(), name, None, cancel)
            .await?
            .ok_or(NativeError::InvalidRequest { detail: "created bucket is not yet readable".to_owned() })
    }

    /// Object metadata for one key (`Ok(None)` when the object is absent).
    /// Absence here is a lookup result, never a deletion decision.
    pub async fn object_metadata(
        &self,
        lease: &NativeLease,
        bucket: &BucketBinding,
        key: &RelativeKey,
        cancel: &CancellationToken,
    ) -> Result<Option<ObjectMetadata>, NativeError> {
        let Some((size, xet_hash)) = self
            .api
            .hf_file_metadata(
                lease,
                bucket.owner_namespace.as_str(),
                bucket.bucket_name.as_str(),
                key.as_str(),
                cancel,
            )
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(ObjectMetadata {
            key: key.clone(),
            size,
            xet_file_id: XetFileId::new(xet_hash).ok(),
        }))
    }

    /// Real native read-authorization check against the selected bucket.
    pub async fn check_native_read(
        &self,
        lease: &NativeLease,
        bucket: &BucketBinding,
        cancel: &CancellationToken,
    ) -> Result<(), NativeError> {
        let url = http::bucket_api_url(
            self.api.endpoint(),
            bucket.owner_namespace.as_str(),
            bucket.bucket_name.as_str(),
            &[],
        )?;
        self.api.probe(lease, url, cancel).await
    }

    /// Real native write-authorization check against the selected bucket (the
    /// write-token route requires write permission). The token body is never
    /// read or parsed.
    pub async fn check_native_write(
        &self,
        lease: &NativeLease,
        bucket: &BucketBinding,
        cancel: &CancellationToken,
    ) -> Result<(), NativeError> {
        let url = http::bucket_api_url(
            self.api.endpoint(),
            bucket.owner_namespace.as_str(),
            bucket.bucket_name.as_str(),
            &["xet-write-token"],
        )?;
        self.api.probe(lease, url, cancel).await
    }

    /// Pre-workspace prefix inspection: verified bucket identity plus bounded
    /// emptiness. Runs entirely without Xet.
    pub async fn inspect_prefix(
        &self,
        lease: &NativeLease,
        bucket: &BucketBinding,
        prefix: &RemotePrefix,
        cancel: &CancellationToken,
    ) -> Result<PrefixInspection, NativeError> {
        let owner = OwnerRef {
            owner_id: bucket.owner_id.clone(),
            owner_kind: bucket.owner_kind,
            owner_namespace: bucket.owner_namespace.clone(),
        };
        // Identity pin: the live stable id must still match the selected one.
        match self
            .resolve_bucket(lease, &owner, &bucket.bucket_name, Some(&bucket.bucket_id), cancel)
            .await?
        {
            None => {
                return Ok(PrefixInspection {
                    prefix: prefix.clone(),
                    state: PrefixState::Missing,
                    entries: Vec::new(),
                });
            }
            Some(_) => {}
        }

        let mut cursor: Option<PageCursor> = None;
        let mut pages = 0usize;
        loop {
            pages += 1;
            if pages > 4 {
                // The service kept returning empty pages with more links; the
                // bounded walk cannot conclude "empty" and never guesses.
                return Err(NativeError::TooManyEntries);
            }
            let page: TreePage = store::tree_page(
                &self.api,
                lease,
                bucket,
                Some(prefix.as_str()),
                true,
                100,
                cursor,
                cancel,
            )
            .await?;
            if !page.entries.is_empty() {
                return Ok(PrefixInspection {
                    prefix: prefix.clone(),
                    state: PrefixState::Populated,
                    entries: page.entries,
                });
            }
            cursor = page.next;
            if cursor.is_none() {
                return Ok(PrefixInspection {
                    prefix: prefix.clone(),
                    state: PrefixState::Empty,
                    entries: Vec::new(),
                });
            }
        }
    }

    /// Bounded native read of the managed HEAD record at `<prefix>/HEAD`.
    ///
    /// Classification: `Missing` only on a real 404; oversized, foreign, or
    /// newer-format records are `TooLarge`/`Record(..)` and are never treated
    /// as an empty workspace. The v1 format check surfaces the validated
    /// workspace id so the setup coordinator can either bind to it or reserve
    /// an explicit initialization with a fresh UUID.
    pub async fn read_head_record(
        &self,
        lease: &NativeLease,
        bucket: &BucketBinding,
        prefix: &RemotePrefix,
        cancel: &CancellationToken,
    ) -> Result<HeadRead, NativeError> {
        let ns = bucket.owner_namespace.as_str();
        let name = bucket.bucket_name.as_str();
        let head_key = prefix.head_key();
        let Some((size, _)) = self.api.hf_file_metadata(lease, ns, name, head_key.as_str(), cancel).await? else {
            return Ok(HeadRead::Missing);
        };
        if size > self.config.max_head_bytes as u64 {
            return Ok(HeadRead::TooLarge { size });
        }
        let url = http::resolve_url(self.api.endpoint(), ns, name, head_key.as_str())?;
        let bytes = self
            .api
            .resolve_record(lease, url, self.config.max_head_bytes, cancel)
            .await?;
        Ok(HeadRead::Record(wire::parse_head_record(&bytes)))
    }

    /// One bounded listing page under any prefix (setup preview, probe
    /// inspection). Same-origin pagination rules as the storage plane.
    pub async fn list_tree_page(
        &self,
        lease: &NativeLease,
        bucket: &BucketBinding,
        prefix: Option<&str>,
        recursive: bool,
        limit: u32,
        cursor: Option<PageCursor>,
        cancel: &CancellationToken,
    ) -> Result<TreePage, NativeError> {
        store::tree_page(&self.api, lease, bucket, prefix, recursive, limit, cursor, cancel).await
    }
}
