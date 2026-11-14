//! Read-only discovery of a managed prefix: verified bucket identity, bounded
//! native HEAD/metadata reads, full catalog verification, and generation-bound
//! pagination. An unbound location never receives an invented workspace ID.

use std::collections::HashMap;

use hfdrive_core::catalog::{CatalogError, CatalogReader, CatalogRoot, PageSource, verify};
use hfdrive_core::format::{self, CatalogPage, IndexValue};
use hfdrive_core::ids::ConnectionId;
use hfdrive_core::storage::{
    BucketBinding, BucketId, BucketName, DriveBinding, ImmutableKey, Namespace, OwnerId, OwnerKind,
    RemotePrefix, Sha256Digest,
};
use hfdrive_hf::{HeadFormat, HeadRead, NativeBucketStore, NativeError, NativeLease, PrefixState};
use hfdrive_protocol as wire;

use crate::{Provider, operations::error, setup::verify_bucket_location, storage::{invalid, native_failure}};

impl Provider {
    pub(crate) async fn inspect_drive(
        &self,
        request: wire::InspectDriveRequest,
    ) -> Result<wire::InspectDriveResult, wire::ProtocolError> {
        if !(1..=200).contains(&request.limit) {
            return Err(invalid("Inspection page size must be between 1 and 200"));
        }
        let profile = self.current_account()?;
        let (bucket, prefix, expected_workspace) = match request.connection_id {
            Some(id) => {
                if request.location.is_some() {
                    return Err(invalid("Select either a connection or a remote location, not both"));
                }
                let connection = ConnectionId::from_uuid(id)
                    .map_err(|_| invalid("A nonzero connection identifier is required"))?;
                let record = self.state.reconcile_connections().await.map_err(crate::operations::state_error)?
                    .into_iter()
                    .find(|record| record.connection_id == connection && record.account_key == profile.account_key)
                    .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The connection does not exist for this account"))?;
                (record.binding.bucket, record.binding.prefix, Some(record.binding.workspace_id))
            }
            None => {
                let location = request.location.ok_or_else(|| invalid("A remote location is required when no connection is selected"))?;
                let bucket = BucketBinding {
                    owner_namespace: Namespace::new(location.owner_namespace).map_err(|_| invalid("Invalid canonical owner namespace"))?,
                    owner_id: OwnerId::new(location.owner_id).map_err(|_| invalid("Invalid stable owner identifier"))?,
                    owner_kind: match location.owner_kind {
                        wire::OwnerKind::Personal => OwnerKind::Personal,
                        wire::OwnerKind::Organization => OwnerKind::Organization,
                    },
                    bucket_name: BucketName::new(location.bucket).map_err(|_| invalid("Invalid bucket name"))?,
                    bucket_id: BucketId::new(location.bucket_id).map_err(|_| invalid("Invalid stable bucket identifier"))?,
                };
                let prefix = RemotePrefix::new(location.prefix).map_err(|_| invalid("Invalid managed storage prefix"))?;
                (bucket, prefix, None)
            }
        };
        let control = self.native_control(profile.account_key);
        let lease = control.capture_lease().map_err(native_failure)?;
        let cancel = &self.operations.cancellation;
        verify_bucket_location(&control, &lease, &bucket, cancel).await?;
        let record = match control.read_head_record(&lease, &bucket, &prefix, cancel).await.map_err(native_failure)? {
            HeadRead::Missing => {
                let inspection = control.inspect_prefix(&lease, &bucket, &prefix, cancel).await.map_err(native_failure)?;
                let prefix_empty = match inspection.state {
                    PrefixState::Empty => true,
                    PrefixState::Populated => false,
                    PrefixState::Missing => {
                        return Err(error(wire::ProtocolErrorCode::NotFound, "The selected bucket no longer exists"));
                    }
                };
                return Ok(wire::InspectDriveResult {
                    binding: None,
                    head_generation: None,
                    is_managed_drive: false,
                    prefix_empty,
                    items: Vec::new(),
                    next_cursor: None,
                });
            }
            HeadRead::TooLarge { .. } => {
                return Err(error(wire::ProtocolErrorCode::UnsupportedFormat, "The managed HEAD exceeds its format bound"));
            }
            HeadRead::Record(record) => record,
        };
        if !matches!(record.format, HeadFormat::V1 { .. }) {
            return Err(error(wire::ProtocolErrorCode::UnsupportedFormat, "The managed HEAD uses an unsupported format"));
        }
        let head = format::from_head_bytes(&record.bytes)
            .map_err(|_| error(wire::ProtocolErrorCode::UnsupportedFormat, "The managed HEAD is invalid"))?;
        if expected_workspace.is_some_and(|workspace| workspace != head.workspace_id) {
            return Err(error(wire::ProtocolErrorCode::Conflict, "The managed workspace identity changed"));
        }
        let binding = DriveBinding {
            account_key: profile.account_key,
            workspace_id: head.workspace_id,
            bucket,
            prefix,
        };
        let native = control.open_store(binding.clone()).map_err(native_failure)?;
        let items = load_catalog_items(&native, &lease, &binding, head.commit_id, cancel).await?;
        if !items.iter().any(|item| {
            item.item_id == head.root_item_id && item.parent_id.is_none() && !item.deleted
        }) {
            return Err(error(wire::ProtocolErrorCode::UnsupportedFormat, "The catalog root does not match HEAD"));
        }
        let start = inspection_cursor(&request.cursor, head.generation, items.len())?;
        let end = start.saturating_add(request.limit as usize).min(items.len());
        let page = items.get(start..end).ok_or_else(|| invalid("Invalid inspection continuation cursor"))?;
        let next_cursor = (end < items.len()).then(|| {
            format!("inspect-v1:{}:{end}", head.generation)
        });
        Ok(wire::InspectDriveResult {
            binding: Some(wire::RemoteBinding {
                owner_namespace: binding.bucket.owner_namespace.as_str().to_owned(),
                owner_id: binding.bucket.owner_id.as_str().to_owned(),
                owner_kind: match binding.bucket.owner_kind {
                    OwnerKind::Personal => wire::OwnerKind::Personal,
                    OwnerKind::Organization => wire::OwnerKind::Organization,
                },
                bucket: binding.bucket.bucket_name.as_str().to_owned(),
                bucket_id: binding.bucket.bucket_id.as_str().to_owned(),
                prefix: binding.prefix.as_str().to_owned(),
                workspace_id: *binding.workspace_id.as_uuid(),
            }),
            head_generation: Some(*head.generation.as_uuid()),
            is_managed_drive: true,
            prefix_empty: false,
            items: page.iter().map(|item| wire::InspectItem {
                item_id: *item.item_id.as_uuid(),
                parent_id: item.parent_id.map(|id| *id.as_uuid()),
                name: item.name.clone(),
                kind: match item.kind {
                    format::ItemKind::File => wire::ItemKind::File,
                    format::ItemKind::Directory => wire::ItemKind::Directory,
                },
                item_revision: *item.item_revision.as_uuid(),
                content_version_id: item.content_version_id.map(|id| *id.as_uuid()),
            }).collect(),
            next_cursor,
        })
    }
}

pub(crate) async fn load_catalog_items<T: hfdrive_auth::TokenSource>(
    native: &NativeBucketStore<T>,
    lease: &NativeLease,
    binding: &DriveBinding,
    commit_id: hfdrive_core::ids::CommitId,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<Vec<format::ItemRecord>, wire::ProtocolError> {
    let key = binding.prefix.immutable_key(ImmutableKey::Commit(commit_id));
    let bytes = native.read_record(lease, &key, format::MAX_COMMIT_BYTES, cancel).await.map_err(native_failure)?
        .ok_or_else(|| error(wire::ProtocolErrorCode::RemoteContentUnavailable, "The HEAD commit is not yet available"))?;
    let commit = format::from_commit_bytes(&bytes)
        .map_err(|_| error(wire::ProtocolErrorCode::UnsupportedFormat, "The HEAD commit is invalid"))?;
    if commit.commit_id != commit_id || commit.workspace_id != binding.workspace_id {
        return Err(error(wire::ProtocolErrorCode::UnsupportedFormat, "The HEAD commit identity does not match its binding"));
    }
    let mut pages = NativePages {
        native,
        lease,
        prefix: &binding.prefix,
        cancel,
        cache: HashMap::new(),
    };
    let catalog_root = CatalogRoot::from_digest(commit.catalog_root);
    verify(&mut pages, catalog_root).await.map_err(catalog_failure)?;
    let mut reader = CatalogReader::new(&mut pages, catalog_root);
    let mut items = Vec::new();
    reader.scan_prefix("i/", &mut |_, value| {
        let IndexValue::Item(item) = value else {
            return Err(CatalogError::Invariant("item index contains a non-item value"));
        };
        items.push(item);
        Ok(())
    }).await.map_err(catalog_failure)?;
    Ok(items)
}

struct NativePages<'a, T: hfdrive_auth::TokenSource> {
    native: &'a NativeBucketStore<T>,
    lease: &'a NativeLease,
    prefix: &'a RemotePrefix,
    cancel: &'a tokio_util::sync::CancellationToken,
    cache: HashMap<Sha256Digest, Option<CatalogPage>>,
}

impl<T: hfdrive_auth::TokenSource> PageSource for NativePages<'_, T> {
    type Error = NativeError;

    fn load(
        &mut self,
        page_id: Sha256Digest,
    ) -> impl Future<Output = Result<Option<CatalogPage>, Self::Error>> + Send {
        async move {
            if let Some(page) = self.cache.get(&page_id) {
                return Ok(page.clone());
            }
            let key = self.prefix.immutable_key(ImmutableKey::Catalog(page_id));
            let Some(bytes) = self.native.read_record(self.lease, &key, format::MAX_PAGE_BYTES, self.cancel).await? else {
                self.cache.insert(page_id, None);
                return Ok(None);
            };
            let page = format::from_page_bytes(&bytes).map_err(|_| NativeError::InvalidResponse)?;
            let (hash, _) = hfdrive_core::catalog::encode_and_hash(&page).map_err(|_| NativeError::InvalidResponse)?;
            if hash != page_id {
                return Err(NativeError::InvalidResponse);
            }
            self.cache.insert(page_id, Some(page.clone()));
            Ok(Some(page))
        }
    }
}

fn catalog_failure(error_value: CatalogError<NativeError>) -> wire::ProtocolError {
    match error_value {
        CatalogError::Storage(error) => native_failure(error),
        _ => error(wire::ProtocolErrorCode::UnsupportedFormat, "The managed catalog is invalid"),
    }
}

fn inspection_cursor(
    cursor: &Option<String>,
    generation: hfdrive_core::ids::GenerationId,
    total: usize,
) -> Result<usize, wire::ProtocolError> {
    let Some(cursor) = cursor else { return Ok(0); };
    let mut parts = cursor.split(':');
    let valid_shape = parts.next() == Some("inspect-v1")
        && parts.next() == Some(generation.to_string().as_str())
        && parts.next().is_some()
        && parts.next().is_none();
    if !valid_shape {
        return Err(error(wire::ProtocolErrorCode::Conflict, "Inspection changed; reload the first page"));
    }
    // The shape was checked above; reparsing only the final component avoids
    // accepting a cursor from another HEAD generation.
    let offset = cursor.rsplit(':').next().and_then(|value| value.parse::<usize>().ok())
        .ok_or_else(|| invalid("Invalid inspection continuation cursor"))?;
    if offset > total {
        return Err(error(wire::ProtocolErrorCode::Conflict, "Inspection changed; reload the first page"));
    }
    Ok(offset)
}
