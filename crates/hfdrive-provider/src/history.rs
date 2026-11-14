//! Bounded committed-ancestry history. Commit bodies and the item records
//! behind each change are read from immutable remote metadata; display names
//! and parents come from that commit's catalog, never today's catalog.

use std::collections::{BTreeSet, HashMap};

use hfdrive_core::catalog::{CatalogError, CatalogReader, CatalogRoot, PageSource};
use hfdrive_core::format::{self, ChangeKind, CommitV1};
use hfdrive_core::history::{CommitSource, HistoryCursor, HistoryError, HistoryOptions, history_page};
use hfdrive_core::ids::{CommitId, ConnectionId, GenerationId, ItemId, OperationId, WorkspaceId};
use hfdrive_protocol as wire;

use crate::{Provider, operations::error, storage::{invalid, remote_failure}};
use crate::sync::plan::RemotePages;
use crate::sync::remote::{RemoteError, RemoteOps};

impl Provider {
    pub(crate) async fn restore(
        &self,
        request: wire::RestoreRequest,
    ) -> Result<wire::RestoreResult, wire::ProtocolError> {
        let connection = ConnectionId::from_uuid(request.connection_id)
            .map_err(|_| invalid("A nonzero connection identifier is required"))?;
        let item = ItemId::from_uuid(request.item_id)
            .map_err(|_| invalid("A nonzero restore item identifier is required"))?;
        let version = hfdrive_core::ids::VersionId::from_uuid(request.version_id)
            .map_err(|_| invalid("A nonzero restore version identifier is required"))?;
        let operation = OperationId::from_uuid(request.operation_id)
            .map_err(|_| invalid("A nonzero restore operation identifier is required"))?;
        let engine = self.engine.as_ref().ok_or_else(crate::operations::internal)?;
        engine.restore_item(connection, item, version, operation).await.map_err(crate::storage::engine_failure)?;
        let status = self.connection_status(connection).await?;
        Ok(wire::RestoreResult { operation_id: request.operation_id, status })
    }

    pub(crate) async fn list_history(
        &self,
        request: wire::ListHistoryRequest,
    ) -> Result<wire::ListHistoryResult, wire::ProtocolError> {
        if !(1..=200).contains(&request.limit) {
            return Err(invalid("History page size must be between 1 and 200"));
        }
        let profile = self.current_account()?;
        let connection = ConnectionId::from_uuid(request.connection_id)
            .map_err(|_| invalid("A nonzero connection identifier is required"))?;
        let record = self.state.reconcile_connections().await.map_err(crate::operations::state_error)?
            .into_iter()
            .find(|record| record.connection_id == connection && record.account_key == profile.account_key)
            .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The connection does not exist for this account"))?;
        let filter = request.item_id
            .map(|id| ItemId::from_uuid(id).map_err(|_| invalid("A nonzero history item identifier is required")))
            .transpose()?;
        let remote = self.remote_for(&record, &profile)?;
        let cancel = &self.operations.cancellation;
        let head = remote.read_head(cancel).await.map_err(remote_failure)?
            .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The managed workspace has no committed HEAD"))?;
        let cursor = request.cursor.as_deref().map(HistoryCursor::decode)
            .transpose().map_err(|_| invalid("Invalid history continuation cursor"))?;
        let filter = match filter {
            Some(item) => Some(load_subtree(&remote, record.binding.workspace_id, head.head.commit_id, item, cancel).await?),
            None => None,
        };
        let mut commits = RemoteCommits {
            remote: &remote,
            workspace: record.binding.workspace_id,
            cancel,
        };
        let page = history_page(
            &mut commits,
            Some(head.head.commit_id),
            cursor,
            &HistoryOptions { filter: None, page_limit: request.limit as usize, max_loads_per_page: 1024 },
        ).await.map_err(history_failure)?;
        let account = self.state.open_account(profile.account_key).await.map_err(crate::operations::state_error)?;
        let mut pages = RemotePages::new(&remote, cancel);
        let mut items = Vec::new();
        for commit in &page.entries {
            if filter.as_ref().is_some_and(|items| !commit.changes.iter().any(|change| items.contains(&change.item_id))) {
                continue;
            }
            let generation = generation_evidence(&account, connection, commit, &head.head).await?;
            items.push(project_history_record(&mut pages, commit, generation).await.map_err(catalog_failure)?);
        }
        Ok(wire::ListHistoryResult {
            items,
            next_cursor: page.next_cursor.map(|cursor| cursor.encode()),
        })
    }
}

struct RemoteCommits<'a, R: RemoteOps> {
    remote: &'a R,
    workspace: WorkspaceId,
    cancel: &'a tokio_util::sync::CancellationToken,
}

impl<R: RemoteOps> CommitSource for RemoteCommits<'_, R> {
    type Error = RemoteError;

    fn load_commit(
        &mut self,
        commit_id: CommitId,
    ) -> impl Future<Output = Result<Option<CommitV1>, Self::Error>> + Send {
        async move { read_remote_commit(self.remote, self.workspace, commit_id, self.cancel).await }
    }
}

async fn read_remote_commit<R: RemoteOps>(
    remote: &R,
    workspace: WorkspaceId,
    commit_id: CommitId,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<Option<CommitV1>, RemoteError> {
    let body = match remote.read_metadata(hfdrive_publication::MetadataRecord::Commit(commit_id), cancel).await {
        Ok(body) => body,
        Err(RemoteError::RemoteContentUnavailable) => return Ok(None),
        Err(error) => return Err(error),
    };
    let commit = format::from_commit_bytes(&body).map_err(|_| RemoteError::InvalidResponse)?;
    if commit.commit_id != commit_id || commit.workspace_id != workspace {
        return Err(RemoteError::InvalidResponse);
    }
    Ok(Some(commit))
}

async fn load_subtree<R: RemoteOps>(
    remote: &R,
    workspace: WorkspaceId,
    head: CommitId,
    root: ItemId,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<BTreeSet<ItemId>, wire::ProtocolError> {
    let commit = read_remote_commit(remote, workspace, head, cancel).await.map_err(remote_failure)?
        .ok_or_else(|| error(wire::ProtocolErrorCode::RemoteContentUnavailable, "The HEAD commit is unavailable"))?;
    let mut pages = RemotePages::new(remote, cancel);
    let mut reader = CatalogReader::new(&mut pages, CatalogRoot::from_digest(commit.catalog_root));
    let mut parents = HashMap::new();
    reader.scan_prefix("i/", &mut |_, value| {
        let format::IndexValue::Item(item) = value else {
            return Err(CatalogError::Invariant("item index contains a non-item value"));
        };
        parents.insert(item.item_id, item.parent_id);
        Ok(())
    }).await.map_err(catalog_failure)?;
    if !parents.contains_key(&root) {
        return Ok(BTreeSet::new());
    }
    let mut subtree = BTreeSet::from([root]);
    loop {
        let before = subtree.len();
        for (item, parent) in &parents {
            if parent.as_ref().is_some_and(|parent| subtree.contains(parent)) {
                subtree.insert(*item);
            }
        }
        if subtree.len() == before {
            break;
        }
    }
    Ok(subtree)
}

async fn generation_evidence(
    account: &hfdrive_state::AccountStore,
    connection: ConnectionId,
    commit: &CommitV1,
    current: &format::HeadV1,
) -> Result<Option<GenerationId>, wire::ProtocolError> {
    if current.commit_id == commit.commit_id {
        return Ok(Some(current.generation));
    }
    for operation in &commit.operation_ids {
        let entry = account.outbox_entry(connection, *operation).await.map_err(crate::operations::state_error)?;
        let Some(entry) = entry else { continue; };
        if entry.candidate_commit != Some(commit.commit_id) {
            continue;
        }
        let Some(bundle) = entry.candidate_head_json else { continue; };
        let head = bundle.get("head").unwrap_or(&bundle);
        if let Some(generation) = head.get("generation").and_then(serde_json::Value::as_str)
            .and_then(|value| value.parse::<GenerationId>().ok())
        {
            return Ok(Some(generation));
        }
    }
    Ok(None)
}

async fn project_history_record<S: PageSource>(
    source: &mut S,
    commit: &CommitV1,
    generation: Option<GenerationId>,
) -> Result<wire::HistoryRecord, CatalogError<S::Error>> {
    let mut reader = CatalogReader::new(source, CatalogRoot::from_digest(commit.catalog_root));
    let mut changes = Vec::with_capacity(commit.changes.len());
    for change in &commit.changes {
        let item = reader.get_item(change.item_id).await?;
        changes.push(wire::HistoryChange {
            item_id: *change.item_id.as_uuid(),
            kind: match change.change {
                ChangeKind::Create => wire::HistoryChangeKind::Create,
                ChangeKind::Content | ChangeKind::Undelete => wire::HistoryChangeKind::Content,
                ChangeKind::Location => wire::HistoryChangeKind::Location,
                ChangeKind::Deletion => wire::HistoryChangeKind::Delete,
            },
            name: item.name,
            parent_id: item.parent_id.map(|id| *id.as_uuid()),
        });
    }
    Ok(wire::HistoryRecord {
        commit_id: *commit.commit_id.as_uuid(),
        parent_commit_id: commit.parent_commit_id.map(|id| *id.as_uuid()),
        generation: generation.map(|id| *id.as_uuid()),
        device_id: *commit.device_id.as_uuid(),
        created_at: commit.created_at.clone(),
        changes,
    })
}

fn history_failure(error_value: HistoryError<RemoteError>) -> wire::ProtocolError {
    match error_value {
        HistoryError::Storage(error) => remote_failure(error),
        HistoryError::InvalidCursor | HistoryError::InvalidOption => invalid("Invalid history options or cursor"),
        HistoryError::MissingCommit(_) => error(wire::ProtocolErrorCode::RemoteContentUnavailable, "Committed ancestry is incomplete"),
        HistoryError::CorruptAncestry(_) | HistoryError::Reconcile(_) => {
            error(wire::ProtocolErrorCode::UnsupportedFormat, "Committed ancestry is invalid")
        }
    }
}

fn catalog_failure(error_value: CatalogError<RemoteError>) -> wire::ProtocolError {
    match error_value {
        CatalogError::Storage(error) => remote_failure(error),
        _ => error(wire::ProtocolErrorCode::UnsupportedFormat, "An immutable commit catalog is invalid"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hfdrive_core::catalog::{InMemoryPageStore, PageSink, initialize};
    use hfdrive_core::format::ItemChange;
    use hfdrive_core::ids::{DeviceId, OperationId};

    #[tokio::test]
    async fn history_projection_uses_the_commits_catalog_and_optional_generation() {
        let root = ItemId::new();
        let operation = OperationId::new();
        let workspace = WorkspaceId::new();
        let (root_page, set) = initialize(root, operation).unwrap();
        let mut store = InMemoryPageStore::new();
        for (hash, page) in &set.pages {
            store.store(*hash, page).await.unwrap();
        }
        let commit = CommitV1 {
            format: format::FORMAT_NAME.to_owned(),
            schema_version: format::SCHEMA_VERSION,
            workspace_id: workspace,
            commit_id: CommitId::new(),
            parent_commit_id: None,
            catalog_root: root_page.digest(),
            operation_ids: vec![operation],
            changes: vec![ItemChange {
                item_id: root,
                change: ChangeKind::Create,
                old_revision: None,
                new_revision: operation,
            }],
            device_id: DeviceId::new(),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
        };
        let projected = project_history_record(&mut store, &commit, None).await.unwrap();
        assert_eq!(projected.generation, None);
        assert_eq!(projected.changes.len(), 1);
        assert_eq!(projected.changes[0].kind, wire::HistoryChangeKind::Create);
        assert_eq!(projected.changes[0].name, "");
        assert_eq!(projected.changes[0].parent_id, None);
    }
}
