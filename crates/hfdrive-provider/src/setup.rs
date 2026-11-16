//! Durable setup reservation and supplemental-credential persistence.
//!
//! Setup never creates a bucket implicitly and never treats a name or an HTTP
//! 409 as ownership. Creation provenance is an exact committed operation
//! receipt; the reserved connection ID binds both the IPC ciphertext and the
//! provider's stable at-rest DPAPI record.

use std::collections::HashMap;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine;
use hfdrive_core::format::{self, ItemKind as FormatItemKind};
use hfdrive_core::ids::{ConnectionId, ItemId, OperationId, SnapshotId};
use hfdrive_core::names;
use hfdrive_core::storage::{BucketBinding, BucketName, DriveBinding, ImmutableKey, Sha256Digest};
use hfdrive_hf::{BucketSummary, HeadFormat, HeadRead, NativeBucketStore, NativeControl, NativeLease, OwnerLocator, PrefixState};
use hfdrive_protocol as wire;
use hfdrive_publication::{AccountIdentity, PublicationBinding, SupplementalCredentialRecord};
use hfdrive_state::{ConnectionMode as StoredMode, CredentialRef, OperationState, SetupDraft, SetupRecord, SetupStatus};
use hfdrive_windows::credentials::{CredentialStore, RecordName};
use hfdrive_windows::filesystem::volume::FileState;
use hfdrive_windows::filesystem::{self, FsError, MetadataEntry, ScanBudget, ScanReport, VisitFlow};
use sha2::{Digest, Sha256};

use crate::{Provider, operations::error, storage::{invalid, native_failure}};

impl Provider {
    pub(crate) async fn begin_setup(
        &self,
        request: wire::BeginSetupRequest,
    ) -> Result<wire::BeginSetupResult, wire::ProtocolError> {
        let profile = self.current_account()?;
        let requested_account = request.account_key.parse::<hfdrive_core::ids::AccountKey>().map_err(|_| invalid("Invalid account key"))?;
        if requested_account != profile.account_key {
            return Err(error(wire::ProtocolErrorCode::PermissionDenied, "The setup account is not the signed-in account"));
        }
        let binding = self.typed_binding(&request.binding)?;
        let creation = request.bucket_creation_operation_id
            .map(|id| OperationId::from_uuid(id).map_err(|_| invalid("A nonzero bucket-creation operation identifier is required")))
            .transpose()?;
        if let Some(creation) = creation {
            self.validate_creation_receipt(creation, &binding, profile.account_key).await?;
        }
        let control = self.native_control(profile.account_key);
        let lease = control.capture_lease().map_err(native_failure)?;
        verify_bucket_location(&control, &lease, &binding.bucket, &self.operations.cancellation).await?;
        let reservation = self.state.reserve_setup(SetupDraft {
            operation_id: OperationId::from_uuid(request.operation_id)
                .map_err(|_| invalid("A nonzero setup operation identifier is required"))?,
            account_key: profile.account_key,
            binding: binding.clone(),
            initialize: request.initialize,
        }).await.map_err(crate::operations::state_error)?;
        let publication = PublicationBinding::new(
            &binding,
            &AccountIdentity { issuer: &profile.issuer, subject: &profile.subject },
        ).map_err(|_| error(wire::ProtocolErrorCode::Conflict, "The setup binding does not match the signed-in identity"))?;
        Ok(wire::BeginSetupResult {
            setup_id: *reservation.setup_id.as_uuid(),
            connection_id: *reservation.connection_id.as_uuid(),
            binding: Self::public_binding(&binding),
            protection_context: publication.protection_context(*reservation.connection_id.as_uuid()),
        })
    }

    async fn validate_creation_receipt(
        &self,
        creation: OperationId,
        binding: &hfdrive_core::storage::DriveBinding,
        account: hfdrive_core::ids::AccountKey,
    ) -> Result<(), wire::ProtocolError> {
        let record = self.state.get_operation(creation).await.map_err(crate::operations::state_error)?
            .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The bucket-creation receipt does not exist"))?;
        if record.state != OperationState::Committed
            || record.kind != "create_bucket"
            || record.account_key != Some(account)
        {
            return Err(error(wire::ProtocolErrorCode::Conflict, "Bucket-creation provenance is not a completed operation for this account"));
        }
        let result: wire::CreateBucketResult = serde_json::from_value(
            record.result_json.ok_or_else(|| error(wire::ProtocolErrorCode::Conflict, "Bucket-creation receipt has no result"))?,
        ).map_err(|_| error(wire::ProtocolErrorCode::Conflict, "Bucket-creation receipt is invalid"))?;
        let bucket = &binding.bucket;
        if !result.completed
            || result.bucket.bucket_id != bucket.bucket_id.as_str()
            || result.bucket.name != bucket.bucket_name.as_str()
            || result.bucket.namespace != bucket.owner_namespace.as_str()
        {
            return Err(error(wire::ProtocolErrorCode::Conflict, "Bucket-creation provenance does not match this setup binding"));
        }
        Ok(())
    }

    pub(crate) async fn set_publication_credentials(
        &self,
        request: wire::SetPublicationCredentialsRequest,
    ) -> Result<wire::SetPublicationCredentialsResult, wire::ProtocolError> {
        let profile = self.current_account()?;
        let connection = ConnectionId::from_uuid(request.connection_id)
            .map_err(|_| invalid("A nonzero connection identifier is required"))?;
        let setup = self.state.get_setup_by_connection(connection).await.map_err(crate::operations::state_error)?
            .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The setup reservation does not exist"))?;
        if setup.account_key != profile.account_key || setup.status != hfdrive_state::SetupStatus::Active {
            return Err(error(wire::ProtocolErrorCode::Conflict, "The setup reservation is not active for this account"));
        }
        let publication = PublicationBinding::new(
            &setup.binding,
            &AccountIdentity { issuer: &profile.issuer, subject: &profile.subject },
        ).map_err(|_| error(wire::ProtocolErrorCode::Conflict, "The credential binding does not match the signed-in identity"))?;
        let context = publication.protection_context(request.connection_id);
        let ipc_entropy = context.entropy(request.operation_id)
            .map_err(|_| invalid("A nonzero credential-operation identifier is required"))?;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(request.protected_credentials.as_bytes())
            .map_err(|_| invalid("The protected credential envelope is not valid base64"))?;
        let plaintext = CredentialStore::unprotect(&ciphertext, Some(&ipc_entropy))
            .map_err(|_| error(wire::ProtocolErrorCode::PermissionDenied, "The credential envelope is not valid for this user and operation"))?;
        let record = SupplementalCredentialRecord::decode(plaintext.expose())
            .map_err(|_| invalid("The protected credential record is invalid"))?;
        record.validate_context(&context)
            .map_err(|_| error(wire::ProtocolErrorCode::Conflict, "The credential record is bound to different storage"))?;
        let encoded = record.encode().map_err(|_| crate::operations::internal())?;
        let stored_entropy = context.entropy(request.connection_id)
            .map_err(|_| invalid("A nonzero connection identifier is required"))?;
        let name_text = format!("s3-{}", request.connection_id);
        let name = RecordName::new(&name_text).map_err(|_| crate::operations::internal())?;
        let store = CredentialStore::open(self.paths.account(profile.account_key).credentials().to_path_buf())
            .map_err(|_| crate::operations::internal())?;
        store.save_record(&name, encoded.as_slice(), Some(&stored_entropy))
            .map_err(|_| crate::operations::internal())?;
        self.state.record_setup_credentials(setup.setup_id, CredentialRef(name_text)).await
            .map_err(crate::operations::state_error)?;
        Ok(wire::SetPublicationCredentialsResult {
            stored: true,
            capability: wire::CapabilityState::StorageSetupRequired,
        })
    }
}

pub(crate) async fn verify_bucket_location<T: hfdrive_auth::TokenSource>(
    control: &NativeControl<T>,
    lease: &NativeLease,
    bucket: &BucketBinding,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<BucketSummary, wire::ProtocolError> {
    let owner = control.verify_owner(lease, &OwnerLocator {
        owner_id: bucket.owner_id.clone(),
        owner_kind: bucket.owner_kind,
        claimed_namespace: Some(bucket.owner_namespace.clone()),
    }, cancel).await.map_err(native_failure)?;
    let name = BucketName::new(bucket.bucket_name.as_str().to_owned()).map_err(|_| invalid("Invalid bucket name"))?;
    let summary = control.resolve_bucket(
        lease,
        &owner.owner_ref(),
        &name,
        Some(&bucket.bucket_id),
        cancel,
    ).await.map_err(native_failure)?
        .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The selected bucket does not exist for this account"))?;
    let live = summary.binding.clone();
    if live.owner_id != bucket.owner_id
        || live.owner_kind != bucket.owner_kind
        || live.owner_namespace != bucket.owner_namespace
        || live.bucket_id != bucket.bucket_id
        || live.bucket_name != bucket.bucket_name
    {
        return Err(error(wire::ProtocolErrorCode::Conflict, "The live bucket identity no longer matches the setup binding"));
    }
    Ok(summary)
}

// ---------------------------------------------------------------------------
// preview_connect
// ---------------------------------------------------------------------------

/// Versioned preview document persisted in the setup journal. `connect`
/// revalidates its inputs against live state before applying anything.
const PREVIEW_SCHEMA: &str = "hfdrive-preview-v1";
/// Representative path/action records are bounded; counts are complete.
const PREVIEW_SAMPLE_LIMIT: usize = 200;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Local,
    Remote,
}

/// One local root entry normalized to a portable relative path.
struct LocalView {
    components: Vec<String>,
    display: String,
    invalid_name: bool,
    is_directory: bool,
    size: u64,
    state: FileState,
    /// Why this source cannot be synchronized as-is, when it cannot.
    unsupported: Option<&'static str>,
}

/// One committed remote item normalized to a portable relative path.
struct RemoteView {
    components: Vec<String>,
    display: String,
    invalid_name: bool,
    item_id: ItemId,
    is_directory: bool,
    size: Option<u64>,
    sha256: Option<Sha256Digest>,
}

/// A coherent staged capture used only as digest proof. The staged file is
/// retained (never deleted here): it is unsynchronized data the user may need,
/// and `connect` can adopt it instead of recapturing.
struct CaptureRecord {
    relative_path: String,
    snapshot_id: SnapshotId,
    staged_path: String,
    size: u64,
    sha256: String,
}

/// One deterministic plan entry: an actionable or colliding path.
struct PlanEntry {
    relative_path: String,
    item_id: Option<uuid::Uuid>,
    action: wire::ProposedAction,
    collision: wire::CollisionKind,
    has_local: bool,
    has_remote: bool,
    local_size: Option<u64>,
    local_sha256: Option<String>,
    remote_size: Option<u64>,
    remote_sha256: Option<String>,
}

impl Provider {
    /// Previews connecting one reserved setup to a local root: fresh remote
    /// identity/HEAD validation, engine root admission, a complete local
    /// metadata scan, digest-proven content comparison, and one durable
    /// versioned preview document. Read-only previews need no supplemental
    /// credentials; writable previews need current credential + probe
    /// evidence. Nothing is registered, uploaded or deleted here.
    pub(crate) async fn preview_connect(
        &self,
        request: wire::PreviewConnectRequest,
    ) -> Result<wire::PreviewConnectResult, wire::ProtocolError> {
        // ---- 1. Active setup for the current account and selected mode ----
        let profile = self.current_account()?;
        let connection = ConnectionId::from_uuid(request.connection_id)
            .map_err(|_| invalid("A nonzero connection identifier is required"))?;
        OperationId::from_uuid(request.operation_id)
            .map_err(|_| invalid("A nonzero preview operation identifier is required"))?;
        let setup = self.state.get_setup_by_connection(connection).await.map_err(crate::operations::state_error)?
            .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The connection has no durable setup reservation"))?;
        if setup.account_key != profile.account_key {
            return Err(error(wire::ProtocolErrorCode::PermissionDenied, "The setup reservation belongs to a different account"));
        }
        if setup.status != SetupStatus::Active {
            return Err(error(wire::ProtocolErrorCode::Conflict, "The setup reservation is not active"));
        }
        let mode = match request.mode {
            wire::ConnectionMode::ReadOnly => StoredMode::ReadOnly,
            wire::ConnectionMode::Writable => StoredMode::Writable,
        };
        let evidence_fingerprint = validate_preview_evidence(&setup, request.mode)?;

        // ---- 2. Local root admission (pure validation, no registration) ----
        let root_path = PathBuf::from(&request.root_path);
        if !root_path.is_absolute() {
            return Err(invalid("The local root path must be absolute"));
        }
        let engine = self.engine.as_ref().ok_or_else(crate::operations::internal)?;
        engine.admit(connection, &root_path, &setup.binding).await.map_err(crate::storage::engine_failure)?;

        // ---- 3. Fresh bucket identity, visibility, HEAD and prefix state ----
        let cancel = &self.operations.cancellation;
        let control = self.native_control(profile.account_key);
        let lease = control.capture_lease().map_err(native_failure)?;
        let summary = verify_bucket_location(&control, &lease, &setup.binding.bucket, cancel).await?;
        let visibility = if summary.private { wire::Visibility::Private } else { wire::Visibility::Public };

        enum RemoteState {
            Managed { head: format::HeadV1 },
            Initialize,
        }
        let remote_state = match control.read_head_record(&lease, &setup.binding.bucket, &setup.binding.prefix, cancel)
            .await.map_err(native_failure)?
        {
            HeadRead::Record(record) => {
                if !matches!(record.format, HeadFormat::V1 { .. }) {
                    return Err(error(wire::ProtocolErrorCode::UnsupportedFormat, "The managed HEAD uses an unsupported format"));
                }
                let head = format::from_head_bytes(&record.bytes)
                    .map_err(|_| error(wire::ProtocolErrorCode::UnsupportedFormat, "The managed HEAD is invalid"))?;
                if head.workspace_id != setup.binding.workspace_id {
                    return Err(error(wire::ProtocolErrorCode::Conflict,
                        "The prefix holds a different managed workspace; ordinary drives are never imported or relabeled"));
                }
                RemoteState::Managed { head }
            }
            HeadRead::TooLarge { .. } => {
                return Err(error(wire::ProtocolErrorCode::UnsupportedFormat, "The managed HEAD exceeds its format bound"));
            }
            HeadRead::Missing => {
                if !setup.initialize {
                    return Err(error(wire::ProtocolErrorCode::Conflict,
                        "The prefix has no managed HEAD and this setup does not authorize initialization"));
                }
                let inspection = control.inspect_prefix(&lease, &setup.binding.bucket, &setup.binding.prefix, cancel)
                    .await.map_err(native_failure)?;
                match inspection.state {
                    PrefixState::Empty => RemoteState::Initialize,
                    PrefixState::Populated => {
                        return Err(error(wire::ProtocolErrorCode::Conflict,
                            "A populated ordinary prefix is not imported; select a managed drive or a genuinely empty prefix"));
                    }
                    PrefixState::Missing => {
                        return Err(error(wire::ProtocolErrorCode::NotFound, "The selected bucket no longer exists"));
                    }
                }
            }
        };

        // ---- 4. Commit/catalog load and validation; stable root identity ----
        let (root_item_id, head_generation, head_commit_id, remotes) = match &remote_state {
            RemoteState::Managed { head } => {
                let binding = DriveBinding {
                    account_key: profile.account_key,
                    workspace_id: head.workspace_id,
                    bucket: setup.binding.bucket.clone(),
                    prefix: setup.binding.prefix.clone(),
                };
                let native = control.open_store(binding.clone()).map_err(native_failure)?;
                let items = crate::inspect::load_catalog_items(&native, &lease, &binding, head.commit_id, cancel).await?;
                if !items.iter().any(|item| {
                    item.item_id == head.root_item_id && item.parent_id.is_none() && !item.deleted
                }) {
                    return Err(error(wire::ProtocolErrorCode::UnsupportedFormat, "The catalog root does not match HEAD"));
                }
                let remote_views = remote_plan_entries(&native, &lease, &binding, &items, cancel).await?;
                (head.root_item_id, Some(head.generation), Some(head.commit_id), remote_views)
            }
            RemoteState::Initialize => {
                (prior_root_item_id(&setup).unwrap_or_else(ItemId::new), None, None, Vec::new())
            }
        };

        // ---- 5. Complete local metadata scan (cancellation-aware) ----
        let (scan_entries, scan_report) = run_local_scan(&root_path, cancel).await?;
        if !scan_report.denied.is_empty() || scan_report.overflow {
            return Err(error(wire::ProtocolErrorCode::LocalRootInvalid,
                "The local root could not be enumerated completely; the preview would not have complete counts"));
        }
        if scan_entries.iter().any(|entry| entry.is_directory && component_invalid(entry)) {
            return Err(error(wire::ProtocolErrorCode::LocalRootInvalid,
                "A directory with an unsupported name hides part of the local root from a complete preview"));
        }
        let locals: Vec<LocalView> = scan_entries.iter().map(local_view).collect();
        let (local_fingerprint, local_scan_generation) = local_fingerprint(&scan_entries, scan_report.complete);
        drop(scan_entries);

        // ---- 6. Deterministic reconciliation plan with digest proof ----
        let staging_dir = self.paths.account(profile.account_key)
            .drive(setup.binding.workspace_id)
            .snapshots();
        let mut entries: Vec<PlanEntry> = Vec::new();
        let mut captures: Vec<CaptureRecord> = Vec::new();
        let mut parent_groups: HashMap<Vec<u8>, Vec<(Side, usize)>> = HashMap::new();
        for (index, view) in locals.iter().enumerate() {
            parent_groups.entry(match_key(&view.components[..view.components.len().saturating_sub(1)]))
                .or_default().push((Side::Local, index));
        }
        for (index, view) in remotes.iter().enumerate() {
            parent_groups.entry(match_key(&view.components[..view.components.len().saturating_sub(1)]))
                .or_default().push((Side::Remote, index));
        }
        let mut group_keys: Vec<Vec<u8>> = parent_groups.keys().cloned().collect();
        group_keys.sort();
        for key in group_keys {
            let mut members = parent_groups.remove(&key).unwrap_or_default();
            members.sort_by(|a, b| {
                let (display_a, display_b) = (member_display(&locals, &remotes, *a), member_display(&locals, &remotes, *b));
                utf16_cmp(display_a, display_b)
                    .then_with(|| u8::from(a.0 == Side::Remote).cmp(&u8::from(b.0 == Side::Remote)))
                    .then_with(|| a.1.cmp(&b.1))
            });
            let last_names: Vec<String> = members.iter()
                .map(|member| member_last_name(&locals, &remotes, *member).to_owned())
                .collect();
            for cluster in cluster_case_equivalent(&last_names) {
                let cluster_members: Vec<(Side, usize)> = cluster.iter().map(|position| members[*position]).collect();
                let invalid_cluster = cluster_members.iter().any(|&(side, index)| match side {
                    Side::Local => locals[index].invalid_name,
                    Side::Remote => remotes[index].invalid_name,
                });
                let local_members: Vec<usize> = cluster_members.iter()
                    .filter(|(side, _)| *side == Side::Local).map(|(_, index)| *index).collect();
                let remote_members: Vec<usize> = cluster_members.iter()
                    .filter(|(side, _)| *side == Side::Remote).map(|(_, index)| *index).collect();
                let exact_pair = cluster_members.len() == 2
                    && local_members.len() == 1
                    && remote_members.len() == 1
                    && locals[local_members[0]].components == remotes[remote_members[0]].components;

                if invalid_cluster {
                    // Unportable names never match, adopt, or upload; every
                    // affected entry is surfaced for review with complete counts.
                    for &(side, index) in &cluster_members {
                        let (display, item_id, _is_directory, local, remote, size, sha) = match side {
                            Side::Local => {
                                let view = &locals[index];
                                (view.display.clone(), None, view.is_directory, true, false, Some(view.size), None)
                            }
                            Side::Remote => {
                                let view = &remotes[index];
                                (view.display.clone(), Some(*view.item_id.as_uuid()), view.is_directory, false, true,
                                    view.size, view.sha256.map(|digest| digest.to_string()))
                            }
                        };
                        entries.push(PlanEntry {
                            relative_path: display,
                            item_id,
                            action: wire::ProposedAction::RequiresReview,
                            collision: wire::CollisionKind::NameInvalid,
                            has_local: local,
                            has_remote: remote,
                            local_size: if local { size } else { None },
                            local_sha256: if local { sha.clone() } else { None },
                            remote_size: if remote { size } else { None },
                            remote_sha256: if remote { sha } else { None },
                        });
                    }
                    continue;
                }

                if exact_pair {
                    let local = &locals[local_members[0]];
                    let remote = &remotes[remote_members[0]];
                    // Directory/file mismatch or content difference keeps both
                    // sides; only a coherent digest proof adopts identical bytes.
                    let local_digest = if local.is_directory {
                        None
                    } else {
                        match self.capture_digest_proof(
                            &root_path, local, &staging_dir, *setup.binding.workspace_id.as_uuid(), cancel,
                        ).await? {
                            Some(record) => {
                                let digest = record.sha256.clone();
                                captures.push(record);
                                Some(digest)
                            }
                            None => None,
                        }
                    };
                    let remote_digest = remote.sha256.map(|digest| digest.to_string());
                    if let Some((collision, action)) = classify_both_present(
                        local.is_directory,
                        remote.is_directory,
                        local.size,
                        remote.size.unwrap_or(u64::MAX),
                        local_digest.as_deref(),
                        remote_digest.as_deref(),
                    ) {
                        entries.push(PlanEntry {
                            relative_path: local.display.clone(),
                            item_id: Some(*remote.item_id.as_uuid()),
                            action,
                            collision,
                            has_local: true,
                            has_remote: true,
                            local_size: Some(local.size),
                            local_sha256: local_digest,
                            remote_size: remote.size,
                            remote_sha256: remote_digest,
                        });
                    }
                    continue;
                }

                if cluster_members.len() == 1 {
                    match cluster_members[0] {
                        (Side::Local, index) => {
                            let view = &locals[index];
                            let (action, collision, reason) = match view.unsupported {
                                Some(reason) => (wire::ProposedAction::RequiresReview, wire::CollisionKind::LocalOnly, Some(reason)),
                                None => (wire::ProposedAction::QueueLocal, wire::CollisionKind::LocalOnly, None),
                            };
                            entries.push(PlanEntry {
                                relative_path: match reason {
                                    Some(reason) => format!("{} ({reason})", view.display),
                                    None => view.display.clone(),
                                },
                                item_id: None,
                                action,
                                collision,
                                has_local: true,
                                has_remote: false,
                                local_size: Some(view.size),
                                local_sha256: None,
                                remote_size: None,
                                remote_sha256: None,
                            });
                        }
                        (Side::Remote, index) => {
                            let view = &remotes[index];
                            entries.push(PlanEntry {
                                relative_path: view.display.clone(),
                                item_id: Some(*view.item_id.as_uuid()),
                                action: wire::ProposedAction::DownloadRemote,
                                collision: wire::CollisionKind::RemoteOnly,
                                has_local: false,
                                has_remote: true,
                                local_size: None,
                                local_sha256: None,
                                remote_size: view.size,
                                remote_sha256: view.sha256.map(|digest| digest.to_string()),
                            });
                        }
                    }
                    continue;
                }

                // Windows case-equivalent spellings cannot share one directory
                // on the case-insensitive root; keep every spelling for review.
                for &(side, index) in &cluster_members {
                    let (display, item_id, local, remote, size, sha) = match side {
                        Side::Local => {
                            let view = &locals[index];
                            (view.display.clone(), None, true, false, Some(view.size), None)
                        }
                        Side::Remote => {
                            let view = &remotes[index];
                            (view.display.clone(), Some(*view.item_id.as_uuid()), false, true,
                                view.size, view.sha256.map(|digest| digest.to_string()))
                        }
                    };
                    entries.push(PlanEntry {
                        relative_path: display,
                        item_id,
                        action: wire::ProposedAction::RequiresReview,
                        collision: wire::CollisionKind::CaseCollision,
                        has_local: local,
                        has_remote: remote,
                        local_size: if local { size } else { None },
                        local_sha256: if local { sha.clone() } else { None },
                        remote_size: if remote { size } else { None },
                        remote_sha256: if remote { sha } else { None },
                    });
                }
            }
        }
        entries.sort_by(|a, b| utf16_cmp(&a.relative_path, &b.relative_path));
        captures.sort_by(|a, b| utf16_cmp(&a.relative_path, &b.relative_path));

        // ---- 7. Complete counts, bounded samples, review requirement ----
        let mut counts = [0u64; 6];
        for entry in &entries {
            counts[collision_slot(entry.collision)] += 1;
        }
        let collision_summary: Vec<wire::CollisionCategorySummary> = [
            wire::CollisionKind::IdenticalContent,
            wire::CollisionKind::DifferentContent,
            wire::CollisionKind::LocalOnly,
            wire::CollisionKind::RemoteOnly,
            wire::CollisionKind::CaseCollision,
            wire::CollisionKind::NameInvalid,
        ].iter().copied().map(|kind| wire::CollisionCategorySummary {
            kind,
            count: counts[collision_slot(kind)],
        }).collect();
        let requires_review = entries.iter().any(|entry| entry_needs_review(entry.action, entry.collision));
        let collisions: Vec<wire::Collision> = entries.iter()
            .filter(|entry| entry_needs_review(entry.action, entry.collision))
            .take(PREVIEW_SAMPLE_LIMIT)
            .map(|entry| wire::Collision {
                kind: entry.collision,
                relative_path: entry.relative_path.clone(),
                item_id: entry.item_id,
                proposed_action: entry.action,
            })
            .collect();
        let proposed_actions: Vec<wire::ProposedActionRecord> = entries.iter()
            .take(PREVIEW_SAMPLE_LIMIT)
            .map(|entry| wire::ProposedActionRecord {
                item_id: entry.item_id,
                action: entry.action,
                description: action_description(entry.action, &entry.relative_path),
            })
            .collect();

        // ---- 8. One durable versioned preview document ----
        let preview_id = uuid::Uuid::new_v4();
        let preview_json = serde_json::json!({
            "schema": PREVIEW_SCHEMA,
            "preview_id": preview_id.to_string(),
            "operation_id": request.operation_id.to_string(),
            "setup_id": setup.setup_id.to_string(),
            "connection_id": connection.to_string(),
            "evidence_generation": setup.evidence_generation,
            "evidence_fingerprint": evidence_fingerprint,
            "binding": Self::public_binding(&setup.binding),
            "mode": match request.mode {
                wire::ConnectionMode::ReadOnly => "read_only",
                wire::ConnectionMode::Writable => "writable",
            },
            "visibility": match visibility {
                wire::Visibility::Private => "private",
                wire::Visibility::Public => "public",
            },
            "initialize": matches!(remote_state, RemoteState::Initialize),
            "root_item_id": root_item_id.to_string(),
            "head_generation": head_generation.map(|generation| generation.to_string()),
            "head_commit_id": head_commit_id.map(|commit| commit.to_string()),
            "local_scan_generation": local_scan_generation,
            "local_fingerprint": local_fingerprint.to_string(),
            "local_scan_complete": scan_report.complete,
            "entries": entries.iter().map(|entry| serde_json::json!({
                "relative_path": entry.relative_path,
                "local": entry.has_local.then(|| serde_json::json!({
                    "size": entry.local_size,
                    "sha256": entry.local_sha256,
                })),
                "remote": entry.has_remote.then(|| serde_json::json!({
                    "size": entry.remote_size,
                    "sha256": entry.remote_sha256,
                })),
                "action": entry.action,
                "collision_kind": entry.collision,
                "item_id": entry.item_id,
            })).collect::<Vec<_>>(),
            "collision_summary": &collision_summary,
            "collisions": &collisions,
            "proposed_action_count": entries.len() as u64,
            "proposed_actions": &proposed_actions,
            "requires_review": requires_review,
            "evidence": {
                "local_paths": true,
                "captures": captures.iter().map(|capture| serde_json::json!({
                    "relative_path": capture.relative_path,
                    "snapshot_id": capture.snapshot_id.to_string(),
                    "staged_path": capture.staged_path,
                    "size": capture.size,
                    "sha256": capture.sha256,
                })).collect::<Vec<_>>(),
            },
        });
        self.state.attach_setup_preview(setup.setup_id, preview_json, root_path, mode)
            .await.map_err(crate::operations::state_error)?;

        Ok(wire::PreviewConnectResult {
            preview_id,
            connection_id: request.connection_id,
            binding: Self::public_binding(&setup.binding),
            visibility,
            head_generation: head_generation.map(|generation| *generation.as_uuid()),
            local_scan_generation,
            collision_summary,
            collisions,
            proposed_action_count: entries.len() as u64,
            proposed_actions,
            requires_review,
        })
    }

    /// Captures one coherent staged snapshot of a both-present local file to
    /// prove its digest. The staged file is retained (never deleted here) and
    /// recorded in the preview document. `None` means the digest proof was not
    /// obtainable (unsupported source, staging admission, drift, sharing): the
    /// caller must never treat those bytes as identical or different.
    async fn capture_digest_proof(
        &self,
        root: &Path,
        local: &LocalView,
        staging_dir: &Path,
        drive: uuid::Uuid,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<Option<CaptureRecord>, wire::ProtocolError> {
        if local.unsupported.is_some() {
            return Ok(None);
        }
        if cancel.is_cancelled() {
            return Err(error(wire::ProtocolErrorCode::Cancelled, "The preview was cancelled"));
        }
        let mut source = root.to_path_buf();
        for component in &local.components {
            source.push(component);
        }
        let reservation = self.scheduler.reserve_staging(
            crate::scheduler::WorkClass::LocalEdit,
            drive,
            root,
            local.size,
            cancel,
        ).await;
        let Ok(_reservation) = reservation else {
            // Staging admission refused: no proof, no deletion, no claim.
            return Ok(None);
        };
        let snapshot_id = SnapshotId::new();
        let staging = staging_dir.to_path_buf();
        let expected = local.state.clone();
        let captured = tokio::task::spawn_blocking(move || {
            filesystem::capture_snapshot(&source, &staging, snapshot_id, Some(&expected))
        }).await.map_err(|_| crate::operations::internal())?;
        match captured {
            Ok(captured) => Ok(Some(CaptureRecord {
                relative_path: local.display.clone(),
                snapshot_id: captured.snapshot_id,
                staged_path: captured.staged_path.to_string_lossy().into_owned(),
                size: captured.size,
                sha256: captured.sha256.to_string(),
            })),
            Err(FsError::Cancelled) => Err(error(wire::ProtocolErrorCode::Cancelled, "The preview was cancelled")),
            Err(_) => Ok(None),
        }
    }
}

/// Writable previews require stored supplemental credentials plus current
/// capability-probe evidence proving full write capability. Read-only
/// previews need neither. Returns the evidence fingerprint `connect` must
/// re-verify against live state.
fn validate_preview_evidence(setup: &SetupRecord, mode: wire::ConnectionMode) -> Result<String, wire::ProtocolError> {
    let mut hasher = Sha256::new();
    hasher.update(setup.credential_ref.as_ref().map(|reference| reference.0.as_str()).unwrap_or("").as_bytes());
    hasher.update([0]);
    let probe_json = setup.probe_evidence_json.as_ref().map(|value| value.to_string()).unwrap_or_default();
    hasher.update(probe_json.as_bytes());
    let fingerprint = hex::encode(hasher.finalize());
    if mode == wire::ConnectionMode::ReadOnly {
        return Ok(fingerprint);
    }
    if setup.credential_ref.is_none() {
        return Err(error(wire::ProtocolErrorCode::StorageSetupRequired,
            "A writable preview requires stored supplemental publication credentials"));
    }
    let evidence = setup.probe_evidence_json.as_ref().ok_or_else(|| error(wire::ProtocolErrorCode::StorageSetupRequired,
        "A writable preview requires current capability-probe evidence"))?;
    if !probe_proves_writable(evidence, setup.connection_id) {
        return Err(error(wire::ProtocolErrorCode::StorageSetupRequired,
            "The recorded capability evidence does not prove full writable access; run the storage probe again"));
    }
    Ok(fingerprint)
}

/// Structural validation of the persisted probe report for a writable
/// preview or repair commit: full mode, every measured check passed, and full
/// write/Xet/S3/conditional-publication capability flags.
pub(crate) fn probe_proves_writable(evidence: &serde_json::Value, connection: ConnectionId) -> bool {
    if evidence.get("connection_id").and_then(serde_json::Value::as_str) != Some(connection.to_string().as_str()) {
        return false;
    }
    if evidence.get("mode").and_then(serde_json::Value::as_str) != Some("full") {
        return false;
    }
    let Some(capabilities) = evidence.get("capabilities") else { return false; };
    for flag in [
        "native_write", "xet_upload", "xet_range", "s3_read",
        "conditional_create", "conditional_replace", "strong_etag",
    ] {
        if capabilities.get(flag).and_then(serde_json::Value::as_bool) != Some(true) {
            return false;
        }
    }
    if capabilities.get("read_only").and_then(serde_json::Value::as_bool) != Some(false) {
        return false;
    }
    let Some(checks) = evidence.get("checks").and_then(serde_json::Value::as_array) else { return false; };
    !checks.is_empty() && checks.iter().all(|check| {
        check.get("outcome").and_then(serde_json::Value::as_str) == Some("passed")
    })
}

/// The root identity a previous explicit initialization preview fixed for
/// this setup, if any. Fresh identities are never invented while a prior
/// preview already committed one to the journal.
fn prior_root_item_id(setup: &SetupRecord) -> Option<ItemId> {
    let preview = setup.preview_json.as_ref()?;
    if preview.get("initialize").and_then(serde_json::Value::as_bool) != Some(true) {
        return None;
    }
    preview.get("root_item_id").and_then(serde_json::Value::as_str)?
        .parse::<ItemId>().ok()
}

/// Loads every live committed item as a relative path plus its immutable
/// version record (size and application SHA-256). A missing or mismatched
/// version record is `RemoteContentUnavailable`/`UnsupportedFormat`, never an
/// invented digest.
async fn remote_plan_entries<T: hfdrive_auth::TokenSource>(
    native: &NativeBucketStore<T>,
    lease: &NativeLease,
    binding: &DriveBinding,
    items: &[format::ItemRecord],
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<Vec<RemoteView>, wire::ProtocolError> {
    let mut by_id: HashMap<ItemId, &format::ItemRecord> = HashMap::new();
    for item in items {
        by_id.insert(item.item_id, item);
    }
    let mut views = Vec::new();
    for item in items {
        if cancel.is_cancelled() {
            return Err(error(wire::ProtocolErrorCode::Cancelled, "The preview was cancelled"));
        }
        if item.deleted || item.parent_id.is_none() {
            continue;
        }
        let mut components = Vec::new();
        let mut cursor = Some(item.item_id);
        let mut depth = 0usize;
        while let Some(id) = cursor {
            let entry = by_id.get(&id).ok_or_else(|| error(wire::ProtocolErrorCode::UnsupportedFormat, "The managed catalog is invalid"))?;
            let Some(parent) = entry.parent_id else { break; };
            components.push(entry.name.clone());
            cursor = Some(parent);
            depth += 1;
            if depth > 1024 {
                return Err(error(wire::ProtocolErrorCode::UnsupportedFormat, "The managed catalog is invalid"));
            }
        }
        components.reverse();
        let invalid_name = components.iter().any(|name| names::validate_name(name).is_err());
        let is_directory = item.kind == FormatItemKind::Directory;
        let (size, sha256) = match item.content_version_id {
            Some(version_id) => {
                let key = binding.prefix.immutable_key(ImmutableKey::Version(version_id));
                let bytes = native.read_record(lease, &key, format::MAX_VERSION_BYTES, cancel).await.map_err(native_failure)?
                    .ok_or_else(|| error(wire::ProtocolErrorCode::RemoteContentUnavailable,
                        "A referenced immutable version record is not yet available; no deletion is inferred"))?;
                let version = format::from_version_bytes(&bytes)
                    .map_err(|_| error(wire::ProtocolErrorCode::UnsupportedFormat, "A managed version record is invalid"))?;
                if version.version_id != version_id || version.workspace_id != binding.workspace_id {
                    return Err(error(wire::ProtocolErrorCode::UnsupportedFormat,
                        "A managed version record does not match its workspace binding"));
                }
                (Some(version.size), Some(version.sha256))
            }
            None => (None, None),
        };
        views.push(RemoteView {
            display: components.join("\\"),
            invalid_name,
            item_id: item.item_id,
            is_directory,
            size,
            sha256,
            components,
        });
    }
    Ok(views)
}

/// One complete metadata enumeration pass (no content reads). Synchronous
/// core; the caller drives it through `spawn_blocking`. `connect` reuses this
/// exact scan for preview freshness.
pub(crate) fn scan_local_metadata(
    root: &Path,
    cancel: &AtomicBool,
) -> Result<(Vec<MetadataEntry>, ScanReport), FsError> {
    let mut entries = Vec::new();
    let budget = ScanBudget { max_entries: 1_000_000, max_depth: 512 };
    let report = filesystem::scan_metadata(root, &budget, cancel, &mut |entry| {
        entries.push(entry.clone());
        VisitFlow::Continue
    })?;
    Ok((entries, report))
}

async fn run_local_scan(
    root: &Path,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<(Vec<MetadataEntry>, ScanReport), wire::ProtocolError> {
    let flag = Arc::new(AtomicBool::new(false));
    let watcher = {
        let token = cancel.clone();
        let flag = Arc::clone(&flag);
        tokio::spawn(async move {
            token.cancelled().await;
            flag.store(true, Ordering::SeqCst);
        })
    };
    let root_path = root.to_path_buf();
    let scan_flag = Arc::clone(&flag);
    let outcome = tokio::task::spawn_blocking(move || scan_local_metadata(&root_path, &scan_flag)).await;
    watcher.abort();
    match outcome {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(error_value)) => Err(scan_failure(error_value)),
        Err(_) => Err(error(wire::ProtocolErrorCode::Cancelled, "The preview scan was cancelled")),
    }
}

fn scan_failure(error_value: FsError) -> wire::ProtocolError {
    match error_value {
        FsError::Cancelled => error(wire::ProtocolErrorCode::Cancelled, "The preview scan was cancelled"),
        FsError::NotFound { .. } => error(wire::ProtocolErrorCode::LocalRootInvalid, "The local root does not exist"),
        FsError::DiskFull => error(wire::ProtocolErrorCode::DiskFull, "The local volume is out of disk space"),
        _ => error(wire::ProtocolErrorCode::LocalRootInvalid, "The local root could not be enumerated"),
    }
}

/// Deterministic local scan fingerprint: SHA-256 over every entry sorted by
/// (relative path UTF-16, kind), each hashed as path, NUL, kind flag, size,
/// modification time, volume serial and file id, plus the scan-completeness
/// flag. The derived generation is the first 8 fingerprint bytes as
/// little-endian u64; identical trees always produce identical generations.
/// `connect` recomputes the full fingerprint and requires equality.
pub(crate) fn local_fingerprint(entries: &[MetadataEntry], complete: bool) -> (Sha256Digest, u64) {
    let mut sorted: Vec<&MetadataEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| path_units(&a.relative_path).cmp(&path_units(&b.relative_path))
        .then_with(|| a.is_directory.cmp(&b.is_directory)));
    let mut hasher = Sha256::new();
    for entry in sorted {
        for unit in entry.relative_path.as_os_str().encode_wide() {
            hasher.update(unit.to_le_bytes());
        }
        hasher.update([0]);
        hasher.update([if entry.is_directory { b'd' } else { b'f' }]);
        hasher.update([0]);
        hasher.update(entry.size.to_string().as_bytes());
        hasher.update([0]);
        hasher.update(entry.last_write_time_100ns.to_string().as_bytes());
        hasher.update([0]);
        hasher.update(entry.identity.volume_serial_number.to_string().as_bytes());
        hasher.update([0]);
        hasher.update(hex::encode(entry.identity.file_id).as_bytes());
        hasher.update([0]);
    }
    hasher.update(format!("incomplete:{}", if complete { 0 } else { 1 }).as_bytes());
    let digest = Sha256Digest::from_bytes(hasher.finalize().into());
    let generation = u64::from_le_bytes(digest.as_bytes()[..8].try_into().unwrap_or([0; 8]));
    (digest, generation)
}

fn path_units(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().collect()
}

fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Portable match key of a relative path: per-component NFC + full default
/// case folding. Equal keys identify the same portable namespace entry.
fn match_key(components: &[String]) -> Vec<u8> {
    let mut key = Vec::new();
    for name in components {
        key.extend_from_slice(&names::collision_key(name));
        key.push(0);
    }
    key
}

fn component_invalid(entry: &MetadataEntry) -> bool {
    entry.name.is_empty() || names::validate_name(&entry.name).is_err()
}

/// Normalizes one scanned entry; invalid names are retained lossily so they
/// can be counted and reviewed, never silently dropped.
fn local_view(entry: &MetadataEntry) -> LocalView {
    let components: Vec<String> = entry.relative_path.components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    let invalid_name = components.iter().any(|name| names::validate_name(name).is_err());
    let unsupported = if entry.identity.is_reparse_point() {
        Some("reparse point")
    } else if entry.identity.is_encrypted() {
        Some("EFS-encrypted")
    } else if entry.identity.has_multiple_links() {
        Some("multiply linked")
    } else if entry.identity.may_not_be_materialized() {
        Some("not fully materialized")
    } else {
        None
    };
    LocalView {
        display: components.join("\\"),
        invalid_name,
        is_directory: entry.is_directory,
        size: entry.size,
        state: FileState {
            identity: entry.identity.clone(),
            size: entry.size,
            last_write_time_100ns: entry.last_write_time_100ns,
            usn: None,
        },
        components,
        unsupported,
    }
}

fn member_display<'a>(locals: &'a [LocalView], remotes: &'a [RemoteView], member: (Side, usize)) -> &'a str {
    match member {
        (Side::Local, index) => &locals[index].display,
        (Side::Remote, index) => &remotes[index].display,
    }
}

fn member_last_name<'a>(locals: &'a [LocalView], remotes: &'a [RemoteView], member: (Side, usize)) -> &'a str {
    let components = match member {
        (Side::Local, index) => &locals[index].components,
        (Side::Remote, index) => &remotes[index].components,
    };
    components.last().map(String::as_str).unwrap_or("")
}

/// Groups name indices whose spellings are Windows case-equivalent
/// (`CompareStringOrdinal(..., TRUE)`). Groups follow the order of their first
/// member and keep ascending index order, so grouping is deterministic.
fn cluster_case_equivalent(names: &[String]) -> Vec<Vec<usize>> {
    let mut buckets: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, name) in names.iter().enumerate() {
        buckets.entry(name.to_uppercase()).or_default().push(index);
    }
    let mut bucket_keys: Vec<String> = buckets.keys().cloned().collect();
    bucket_keys.sort();
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for key in bucket_keys {
        let members = buckets.get(&key).cloned().unwrap_or_default();
        let mut parent: Vec<usize> = (0..members.len()).collect();
        for i in 0..members.len() {
            for j in (i + 1)..members.len() {
                if filesystem::windows_case_equivalent(&names[members[i]], &names[members[j]]) {
                    let (root_i, root_j) = (find_root(&mut parent, i), find_root(&mut parent, j));
                    if root_i != root_j {
                        parent[root_j] = root_i;
                    }
                }
            }
        }
        let mut grouped: HashMap<usize, Vec<usize>> = HashMap::new();
        for (position, &member) in members.iter().enumerate() {
            grouped.entry(find_root(&mut parent, position)).or_default().push(member);
        }
        let mut roots: Vec<usize> = grouped.keys().copied().collect();
        roots.sort();
        for root in roots {
            let mut group = grouped.remove(&root).unwrap_or_default();
            group.sort_unstable();
            groups.push(group);
        }
    }
    groups.sort_by_key(|group| group.first().copied().unwrap_or(0));
    groups
}

fn find_root(parent: &mut [usize], mut node: usize) -> usize {
    while parent[node] != node {
        parent[node] = parent[parent[node]];
        node = parent[node];
    }
    node
}

/// Pure both-present classification. `None` means both sides are matching
/// directories needing no action. Identical content is claimed only with
/// proof (empty files, or equal coherent digests); unproven bytes are never
/// silently adopted or declared different.
fn classify_both_present(
    local_is_directory: bool,
    remote_is_directory: bool,
    local_size: u64,
    remote_size: u64,
    local_digest: Option<&str>,
    remote_digest: Option<&str>,
) -> Option<(wire::CollisionKind, wire::ProposedAction)> {
    if local_is_directory && remote_is_directory {
        return None;
    }
    if local_is_directory != remote_is_directory {
        return Some((wire::CollisionKind::DifferentContent, wire::ProposedAction::RequiresReview));
    }
    if local_size != remote_size {
        return Some((wire::CollisionKind::DifferentContent, wire::ProposedAction::KeepBoth));
    }
    if local_size == 0 {
        // Two empty files are byte-identical by size alone.
        return Some((wire::CollisionKind::IdenticalContent, wire::ProposedAction::AdoptIdentical));
    }
    match (local_digest, remote_digest) {
        (Some(local), Some(remote)) => if local == remote {
            Some((wire::CollisionKind::IdenticalContent, wire::ProposedAction::AdoptIdentical))
        } else {
            Some((wire::CollisionKind::DifferentContent, wire::ProposedAction::KeepBoth))
        },
        _ => Some((wire::CollisionKind::DifferentContent, wire::ProposedAction::RequiresReview)),
    }
}

/// Review requirement: any unresolvable entry, and every category that
/// changes what the user sees (differing content, case collisions, invalid
/// names) must be reviewed before registration.
fn entry_needs_review(action: wire::ProposedAction, collision: wire::CollisionKind) -> bool {
    action == wire::ProposedAction::RequiresReview
        || matches!(
            collision,
            wire::CollisionKind::DifferentContent
                | wire::CollisionKind::CaseCollision
                | wire::CollisionKind::NameInvalid
        )
}

fn collision_slot(kind: wire::CollisionKind) -> usize {
    match kind {
        wire::CollisionKind::IdenticalContent => 0,
        wire::CollisionKind::DifferentContent => 1,
        wire::CollisionKind::LocalOnly => 2,
        wire::CollisionKind::RemoteOnly => 3,
        wire::CollisionKind::CaseCollision => 4,
        wire::CollisionKind::NameInvalid => 5,
    }
}

fn action_description(action: wire::ProposedAction, path: &str) -> String {
    match action {
        wire::ProposedAction::AdoptIdentical => format!("Adopt \"{path}\" after digest verification"),
        wire::ProposedAction::KeepBoth => format!("Keep both sides of \"{path}\""),
        wire::ProposedAction::QueueLocal => format!("Queue \"{path}\" as local-only work"),
        wire::ProposedAction::DownloadRemote => format!("Download \"{path}\" from the managed drive"),
        wire::ProposedAction::RequiresReview => format!("Review \"{path}\" before connecting"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_adoption_requires_proof() {
        let digest = "ab".repeat(32);
        assert_eq!(classify_both_present(false, false, 0, 0, None, None),
            Some((wire::CollisionKind::IdenticalContent, wire::ProposedAction::AdoptIdentical)));
        assert_eq!(classify_both_present(false, false, 4, 4, Some(&digest), Some(&digest)),
            Some((wire::CollisionKind::IdenticalContent, wire::ProposedAction::AdoptIdentical)));
        assert_eq!(classify_both_present(false, false, 4, 4, Some(&digest), Some(&"cd".repeat(32))),
            Some((wire::CollisionKind::DifferentContent, wire::ProposedAction::KeepBoth)));
        assert_eq!(classify_both_present(false, false, 4, 4, None, Some(&digest)),
            Some((wire::CollisionKind::DifferentContent, wire::ProposedAction::RequiresReview)));
        assert_eq!(classify_both_present(false, false, 3, 4, Some(&digest), Some(&digest)),
            Some((wire::CollisionKind::DifferentContent, wire::ProposedAction::KeepBoth)));
    }

    #[test]
    fn local_fingerprint_is_order_independent_and_identity_sensitive() {
        let a = metadata_entry("a.txt", 4, 10);
        let b = metadata_entry("b.txt", 5, 20);
        assert_eq!(local_fingerprint(&[a.clone(), b.clone()], true), local_fingerprint(&[b.clone(), a.clone()], true));
        assert_ne!(local_fingerprint(&[a.clone()], true), local_fingerprint(&[b], true));
        assert_ne!(local_fingerprint(&[a.clone()], true), local_fingerprint(&[a], false));
    }

    fn metadata_entry(name: &str, size: u64, mtime: i64) -> MetadataEntry {
        MetadataEntry {
            relative_path: PathBuf::from(name),
            name: name.to_owned(),
            is_directory: false,
            identity: hfdrive_windows::filesystem::volume::FileIdentity {
                volume_serial_number: 7,
                file_id: [2; 16],
                link_count: 1,
                attributes: 0,
                reparse_tag: 0,
            },
            size,
            creation_time_100ns: 0,
            last_write_time_100ns: mtime,
            placeholder: hfdrive_windows::filesystem::volume::PlaceholderState(0),
        }
    }
}
