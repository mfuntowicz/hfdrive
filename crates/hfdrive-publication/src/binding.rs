//! Immutable publication identity versus mutable display locators.
//!
//! A publication binding is fixed to one account, owner, bucket, workspace and
//! managed prefix. Display locators (the verified namespace and the bare bucket
//! name) only address the S3 endpoint; they can change across renames and never
//! replace the stable identities.

use crate::credentials::SupplementalCredentialRecord;
use crate::PublicationError;
use hfdrive_core::ids::{AccountKey, WorkspaceId};
use hfdrive_core::storage::{
    BucketId, BucketName, DriveBinding, Namespace, OwnerId, OwnerKind, RelativeKey, RemotePrefix,
};
use hfdrive_protocol::PublicationProtectionContext;

/// Verified OIDC issuer/subject pair; the account key must agree with it.
pub struct AccountIdentity<'a> {
    /// Verified OIDC issuer.
    pub issuer: &'a str,
    /// Verified OIDC subject.
    pub subject: &'a str,
}

impl AccountIdentity<'_> {
    /// The stable credential partition for this issuer/subject pair.
    pub fn account_key(&self) -> AccountKey {
        AccountKey::from_subject(self.issuer, self.subject)
    }
}

/// Mutable addressing locators; never used as identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointAddress {
    owner_namespace: Namespace,
    bucket_name: BucketName,
}

impl EndpointAddress {
    /// Verified canonical owner namespace; the S3 endpoint host label.
    pub fn owner_namespace(&self) -> &Namespace { &self.owner_namespace }
    /// Bare bucket name; path-style addressing uses it as the bucket.
    pub fn bucket_name(&self) -> &BucketName { &self.bucket_name }
}

/// Exact authorization/namespace binding for one managed drive prefix.
///
/// Stable identity is the account key (derived from issuer/subject), the owner
/// and bucket identities, the workspace and the managed prefix. The embedded
/// [`EndpointAddress`] is retained only for wire addressing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationBinding {
    account_key: AccountKey,
    issuer: String,
    subject: String,
    owner_id: OwnerId,
    owner_kind: OwnerKind,
    bucket_id: BucketId,
    workspace_id: WorkspaceId,
    prefix: RemotePrefix,
    head_key: RelativeKey,
    address: EndpointAddress,
}

impl PublicationBinding {
    /// Validates the drive binding against the verified issuer/subject pair.
    ///
    /// The binding's account key must equal `sha256(issuer || 0x00 || subject)`;
    /// display locators are kept separately and never checked as identity.
    pub fn new(
        binding: &DriveBinding,
        account: &AccountIdentity<'_>,
    ) -> Result<Self, PublicationError> {
        if account.issuer.is_empty() || account.subject.is_empty() {
            return Err(PublicationError::BindingMismatch);
        }
        if binding.account_key != account.account_key() {
            return Err(PublicationError::BindingMismatch);
        }
        let head_key = binding.prefix.head_key();
        Ok(Self {
            account_key: binding.account_key,
            issuer: account.issuer.to_owned(),
            subject: account.subject.to_owned(),
            owner_id: binding.bucket.owner_id.clone(),
            owner_kind: binding.bucket.owner_kind,
            bucket_id: binding.bucket.bucket_id.clone(),
            workspace_id: binding.workspace_id,
            prefix: binding.prefix.clone(),
            head_key,
            address: EndpointAddress {
                owner_namespace: binding.bucket.owner_namespace.clone(),
                bucket_name: binding.bucket.bucket_name.clone(),
            },
        })
    }

    /// The bound credential partition.
    pub fn account_key(&self) -> AccountKey { self.account_key }
    /// The bound verified issuer.
    pub fn issuer(&self) -> &str { &self.issuer }
    /// The bound verified subject.
    pub fn subject(&self) -> &str { &self.subject }
    /// The bound stable owner identity.
    pub fn owner_id(&self) -> &OwnerId { &self.owner_id }
    /// The bound owner kind.
    pub fn owner_kind(&self) -> OwnerKind { self.owner_kind }
    /// The bound stable bucket identity.
    pub fn bucket_id(&self) -> &BucketId { &self.bucket_id }
    /// The bound managed workspace.
    pub fn workspace_id(&self) -> WorkspaceId { self.workspace_id }
    /// The bound managed prefix (may be the explicitly selected bucket root).
    pub fn prefix(&self) -> &RemotePrefix { &self.prefix }
    /// The managed `HEAD` key inside the bound prefix.
    pub fn head_key(&self) -> &RelativeKey { &self.head_key }
    /// Addressing locators for the S3 endpoint; not identity.
    pub fn address(&self) -> &EndpointAddress { &self.address }

    /// Requires exact stable-field agreement between binding and credentials.
    ///
    /// Everything except `connection_id` (owned by the provider's setup flow)
    /// and display locators must match: issuer, subject, account key, owner,
    /// bucket, workspace and prefix. On any disagreement the credential record
    /// cannot authorize this binding.
    pub fn matches_record(
        &self,
        record: &SupplementalCredentialRecord,
    ) -> Result<(), PublicationError> {
        let ctx = record.context();
        let agree = ctx.issuer == self.issuer
            && ctx.subject == self.subject
            && ctx.account_key.parse::<AccountKey>().ok() == Some(self.account_key)
            && ctx.owner_id == self.owner_id.as_str()
            && ctx.bucket_id == self.bucket_id.as_str()
            && ctx.workspace_id == *self.workspace_id.as_uuid()
            && ctx.prefix == self.prefix.as_str()
            && wire_owner_kind(ctx.owner_kind) == self.owner_kind;
        if agree {
            Ok(())
        } else {
            Err(PublicationError::BindingMismatch)
        }
    }

    /// The protection context this binding expects inside a credential record.
    ///
    /// The provider composes entropy from this context and the operation UUID
    /// (`hfdrive_protocol::PublicationProtectionContext::entropy`); this crate
    /// never derives entropy itself.
    pub fn protection_context(
        &self,
        connection_id: uuid::Uuid,
    ) -> PublicationProtectionContext {
        PublicationProtectionContext {
            connection_id,
            account_key: self.account_key.to_string(),
            issuer: self.issuer.clone(),
            subject: self.subject.clone(),
            owner_id: self.owner_id.to_string(),
            owner_kind: wire_owner_kind_inverse(self.owner_kind),
            bucket_id: self.bucket_id.to_string(),
            workspace_id: *self.workspace_id.as_uuid(),
            prefix: self.prefix.to_string(),
        }
    }
}

fn wire_owner_kind(kind: hfdrive_protocol::OwnerKind) -> OwnerKind {
    match kind {
        hfdrive_protocol::OwnerKind::Personal => OwnerKind::Personal,
        hfdrive_protocol::OwnerKind::Organization => OwnerKind::Organization,
    }
}

fn wire_owner_kind_inverse(kind: OwnerKind) -> hfdrive_protocol::OwnerKind {
    match kind {
        OwnerKind::Personal => hfdrive_protocol::OwnerKind::Personal,
        OwnerKind::Organization => hfdrive_protocol::OwnerKind::Organization,
    }
}
