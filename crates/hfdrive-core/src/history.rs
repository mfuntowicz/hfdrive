//! Bounded paginated history traversal and restore-as-new-mutation planning.
//!
//! History is the retained committed ancestry of one managed drive: commits
//! are immutable and their parents are never rewritten. [`history_page`]
//! walks that ancestry newest-first with strict per-call bounds, so listing
//! history can never turn into an unbounded scan. [`plan_restore`] plans a
//! restore as a NEW committed mutation against the latest state: historical
//! commits, HEAD and old payloads are never rewritten or deleted.
//!
//! The module is pure apart from the caller-supplied [`CommitSource`]; all
//! identifiers it emits are either caller-supplied or deterministic conflict
//! identities from `crate::reconcile`.

use crate::format::{self, ChangeKind, CommitV1, DisplayMetadata, ItemChange, ItemKind};
use crate::ids::{CommitId, ItemId, OperationId, VersionId, WorkspaceId};
use crate::names;
use crate::reconcile::{
    conflict_identity, conflict_name, CatalogView, ConflictKind, ConflictNames, ConflictOutcome,
    ConflictRecord, ConflictSide, IdSource, IntentOutcome, IntentOutcomeKind, ItemState,
    LocalAction, LocalActionKind, MissingRef, ReconcileError, ReconcileMode, ReconcilePlan,
    RemoteOp,
};
use crate::storage::ObjectRef;
use std::collections::BTreeSet;
use std::future::Future;

// ---------------------------------------------------------------------------
// Commit source
// ---------------------------------------------------------------------------

/// Source of retained immutable commit records. The provider adapts its
/// durable state store or the remote `commits/<uuid>.json` objects.
pub trait CommitSource {
    type Error;
    /// Loads one commit record, or `None` when it is absent.
    fn load_commit(
        &mut self,
        commit_id: CommitId,
    ) -> impl Future<Output = Result<Option<CommitV1>, Self::Error>> + Send;
}

#[derive(Debug, thiserror::Error)]
pub enum HistoryError<E> {
    #[error("commit storage failed: {0}")]
    Storage(E),
    #[error("history cursor is not valid")]
    InvalidCursor,
    #[error("history options are invalid")]
    InvalidOption,
    #[error("committed ancestry is missing commit {0}")]
    MissingCommit(CommitId),
    #[error("committed ancestry is corrupt: {0}")]
    CorruptAncestry(&'static str),
    #[error("reconciliation failed: {0}")]
    Reconcile(#[from] ReconcileError),
}

// ---------------------------------------------------------------------------
// Cursors and options
// ---------------------------------------------------------------------------

/// An opaque, strictly validated traversal cursor: the next commit to visit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryCursor {
    next: CommitId,
}

impl HistoryCursor {
    /// Canonical cursor spelling: `h1-` plus the lowercase hyphenated commit
    /// UUID.
    pub fn encode(&self) -> String {
        format!("h1-{}", self.next)
    }

    /// Strict decode; anything but the canonical spelling is rejected.
    pub fn decode(value: &str) -> Result<Self, InvalidCursor> {
        let rest = value.strip_prefix("h1-").ok_or(InvalidCursor)?;
        let next = rest.parse::<CommitId>().map_err(|_| InvalidCursor)?;
        Ok(Self { next })
    }

    pub fn next_commit(&self) -> CommitId {
        self.next
    }
}

/// Returned when a cursor does not decode to one canonical spelling.
#[derive(Debug, thiserror::Error)]
#[error("history cursor is not valid")]
pub struct InvalidCursor;

/// Bounds and filter for one history page.
#[derive(Clone, Copy, Debug)]
pub struct HistoryOptions {
    /// When set, only commits whose `changes` mention this item are returned.
    pub filter: Option<ItemId>,
    /// Maximum entries in one page.
    pub page_limit: usize,
    /// Maximum commit loads in one call. When the budget is exhausted the
    /// walk returns a resumable cursor even if the page is not full.
    pub max_loads_per_page: usize,
}

impl Default for HistoryOptions {
    fn default() -> Self {
        Self { filter: None, page_limit: 200, max_loads_per_page: 1024 }
    }
}

/// One page of history, newest commit first.
#[derive(Clone, Debug)]
pub struct HistoryPage {
    pub entries: Vec<CommitV1>,
    /// `Some` when more history remains; resume with [`history_page`].
    pub next_cursor: Option<HistoryCursor>,
    /// Commits loaded during this call (bounded by `max_loads_per_page`).
    pub commits_loaded: u64,
}

/// Walks the retained committed ancestry newest-first.
///
/// `head` is the current committed commit (`None` for an empty history);
/// `cursor` from a previous page resumes the walk and takes precedence. Each
/// call loads at most `max_loads_per_page` commits and returns at most
/// `page_limit` entries. A missing intermediate commit is an error, and a
/// cycle in the parent chain is detected rather than walked forever.
pub async fn history_page<S: CommitSource>(
    source: &mut S,
    head: Option<CommitId>,
    cursor: Option<HistoryCursor>,
    options: &HistoryOptions,
) -> Result<HistoryPage, HistoryError<S::Error>> {
    if options.page_limit == 0 || options.max_loads_per_page == 0 {
        return Err(HistoryError::InvalidOption);
    }
    let mut next = match cursor {
        Some(cursor) => Some(cursor.next),
        None => head,
    };
    let mut entries: Vec<CommitV1> = Vec::new();
    let mut seen: BTreeSet<CommitId> = BTreeSet::new();
    let mut commits_loaded = 0u64;
    while let Some(commit_id) = next {
        if entries.len() >= options.page_limit {
            return Ok(HistoryPage {
                entries,
                next_cursor: Some(HistoryCursor { next: commit_id }),
                commits_loaded,
            });
        }
        if commits_loaded >= options.max_loads_per_page as u64 {
            return Ok(HistoryPage {
                entries,
                next_cursor: Some(HistoryCursor { next: commit_id }),
                commits_loaded,
            });
        }
        if !seen.insert(commit_id) {
            return Err(HistoryError::CorruptAncestry("parent cycle in committed ancestry"));
        }
        let commit = source
            .load_commit(commit_id)
            .await
            .map_err(HistoryError::Storage)?
            .ok_or(HistoryError::MissingCommit(commit_id))?;
        if commit.commit_id != commit_id {
            return Err(HistoryError::CorruptAncestry("commit record id mismatch"));
        }
        commits_loaded += 1;
        next = commit.parent_commit_id;
        let matches = match options.filter {
            None => true,
            Some(item) => commit.changes.iter().any(|c| c.item_id == item),
        };
        if matches {
            entries.push(commit);
        }
    }
    Ok(HistoryPage { entries, next_cursor: None, commits_loaded })
}

// ---------------------------------------------------------------------------
// Restore planning
// ---------------------------------------------------------------------------

/// One restore request. The version record must already exist (it is
/// historical and immutable); the payload is never re-uploaded and no blob is
/// ever deleted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreSpec {
    /// Caller-supplied durable operation id for this restore mutation.
    pub operation_id: OperationId,
    /// The item whose content is restored.
    pub item_id: ItemId,
    /// The historical version to rebind.
    pub version_id: VersionId,
    /// Payload identity of that version, verified against its version record
    /// by the caller before planning.
    pub object: ObjectRef,
    /// Display metadata carried by the historical version record.
    pub display: DisplayMetadata,
}

/// Plans a restore as a new committed mutation against the latest state.
///
/// The restored item keeps (or reclaims) its retained location, is revived if
/// it is currently a tombstone, and binds `content_version_id` to the
/// historical version. Historical commits, HEAD and old payloads are never
/// rewritten or deleted; the plan emits one new item mutation (plus a
/// deterministic recovered directory when the retained parent is gone) and a
/// guarded local action to materialize the restored bytes. Read-only
/// connections get no mutation: the restore is deferred and nothing claims a
/// successful remote restore.
pub fn plan_restore(
    workspace_id: WorkspaceId,
    mode: ReconcileMode,
    current: &CatalogView,
    spec: &RestoreSpec,
    ids: &mut dyn IdSource,
) -> Result<ReconcilePlan, ReconcileError> {
    let cur = current
        .get(spec.item_id)
        .ok_or(ReconcileError::MissingContext(vec![MissingRef::Item {
            item_id: spec.item_id,
        }]))?
        .clone();
    if cur.kind != ItemKind::File {
        return Err(ReconcileError::InconsistentIntent(
            "restore targets a directory; only file versions restore",
        ));
    }

    let mut conflicts: Vec<ConflictRecord> = Vec::new();
    let mut remote_ops: Vec<RemoteOp> = Vec::new();
    let mut recovered_dirs: Vec<ItemState> = Vec::new();

    // Retained location: the tombstone keeps its parent and name.
    let mut parent_id = cur.parent_id.ok_or(ReconcileError::InvalidView("file without parent"))?;
    let mut name = cur.name.clone();

    // Parent liveness: a retained parent that is gone gets its deterministic
    // recovered directory (same policy as reconciliation).
    if let Some(parent) = current.get(parent_id) {
        if parent.deleted || parent.kind != ItemKind::Directory {
            let del_ops: Vec<OperationId> = parent.deletion_operation.into_iter().collect();
            if del_ops.is_empty() {
                return Err(ReconcileError::InvalidView("restore parent state is inconsistent"));
            }
            let ident = conflict_identity(
                workspace_id,
                ConflictKind::DirectoryDeleteRecovery,
                &[parent_id],
                &del_ops,
            );
            let place = nearest_live_directory(current, parent_id)
                .unwrap_or_else(|| current.root_id().expect("validated view has a root"));
            let dir = ItemState {
                item_id: ident.recovered_dir_id,
                parent_id: Some(place),
                name: conflict_name("Recovered", ident.conflict_id),
                kind: ItemKind::Directory,
                deleted: false,
                item_revision: del_ops[0],
                content_version_id: None,
                content_operation: del_ops[0],
                location_operation: del_ops[0],
                deletion_operation: None,
                content_sha256: None,
                content_size: None,
            };
            conflicts.push(ConflictRecord {
                conflict_id: ident.conflict_id,
                kind: ConflictKind::DirectoryDeleteRecovery,
                item_id: parent_id,
                competing_operations: del_ops.clone(),
                sides: vec![ConflictSide {
                    operation_id: del_ops[0],
                    parent_id: parent.parent_id,
                    name: parent.name.clone(),
                    content_version_id: parent.content_version_id,
                }],
                outcome: ConflictOutcome::RecoveredDirectory,
                preserved_item_id: Some(ident.recovered_dir_id),
                preserved_version_id: None,
                preserved_name: Some(dir.name.clone()),
                preserved_parent_id: dir.parent_id,
            });
            parent_id = ident.recovered_dir_id;
            recovered_dirs.push(dir);
        }
    } else {
        return Err(ReconcileError::MissingContext(vec![
            MissingRef::Ancestor { item_id: spec.item_id, missing: parent_id },
        ]));
    }

    // The retained name slot may now belong to another live item (a tombstone
    // frees its slot). The occupant is never overwritten: the restored item
    // takes the deterministic conflict name instead.
    let occupant = current
        .iter()
        .find(|s| {
            !s.deleted
                && s.item_id != spec.item_id
                && s.parent_id == Some(parent_id)
                && names::collision_key(&s.name) == names::collision_key(&name)
        })
        .map(|s| s.clone());
    if let Some(occupant) = &occupant {
        let ident = conflict_identity(
            workspace_id,
            ConflictKind::NameCollision,
            &[occupant.item_id, spec.item_id],
            &[occupant.location_operation, spec.operation_id],
        );
        let mut chosen: Option<String> = None;
        let taken: BTreeSet<Vec<u8>> = current
            .iter()
            .filter(|s| !s.deleted && s.parent_id == Some(parent_id))
            .map(|s| names::collision_key(&s.name))
            .collect();
        for candidate in ConflictNames::new(&name, ident.conflict_id) {
            if names::validate_name(&candidate).is_err() {
                continue;
            }
            let key = names::collision_key(&candidate);
            if !taken.contains(&key) {
                chosen = Some(candidate);
                break;
            }
        }
        name = chosen.ok_or(ReconcileError::NotConverged)?;
        conflicts.push(ConflictRecord {
            conflict_id: ident.conflict_id,
            kind: ConflictKind::NameCollision,
            item_id: spec.item_id,
            competing_operations: {
                let mut ops = vec![occupant.location_operation, spec.operation_id];
                ops.sort();
                ops.dedup();
                ops
            },
            sides: {
                let mut sides = vec![
                    ConflictSide {
                        operation_id: occupant.location_operation,
                        parent_id: occupant.parent_id,
                        name: occupant.name.clone(),
                        content_version_id: occupant.content_version_id,
                    },
                    ConflictSide {
                        operation_id: spec.operation_id,
                        parent_id: Some(parent_id),
                        name: name.clone(),
                        content_version_id: Some(spec.version_id),
                    },
                ];
                sides.sort_by_key(|s| s.operation_id);
                sides
            },
            outcome: ConflictOutcome::KeepBoth,
            preserved_item_id: Some(spec.item_id),
            preserved_version_id: Some(spec.version_id),
            preserved_name: Some(name.clone()),
            preserved_parent_id: Some(parent_id),
        });
    }

    // Already restored: converge without a mutation.
    if !cur.deleted && cur.content_version_id == Some(spec.version_id) {
        return Ok(ReconcilePlan {
            workspace_id,
            mode,
            remote_ops: Vec::new(),
            versions: Vec::new(),
            changes: Vec::new(),
            operation_ids: Vec::new(),
            local_actions: Vec::new(),
            conflicts,
            aliases: Vec::new(),
            intents: vec![IntentOutcome {
                operation_id: spec.operation_id,
                item_id: spec.item_id,
                outcome: IntentOutcomeKind::Converged,
                conflict_id: None,
            }],
        });
    }

    let restored = ItemState {
        item_id: spec.item_id,
        parent_id: Some(parent_id),
        name,
        kind: ItemKind::File,
        deleted: false,
        item_revision: spec.operation_id,
        content_version_id: Some(spec.version_id),
        content_operation: spec.operation_id,
        location_operation: cur.location_operation,
        deletion_operation: None,
        content_sha256: Some(spec.object.sha256),
        content_size: Some(spec.object.size),
    };

    if mode == ReconcileMode::ReadOnly {
        return Ok(ReconcilePlan {
            workspace_id,
            mode,
            remote_ops: Vec::new(),
            versions: Vec::new(),
            changes: Vec::new(),
            operation_ids: Vec::new(),
            local_actions: Vec::new(),
            conflicts,
            aliases: Vec::new(),
            intents: vec![IntentOutcome {
                operation_id: spec.operation_id,
                item_id: spec.item_id,
                outcome: IntentOutcomeKind::Deferred,
                conflict_id: None,
            }],
        });
    }

    // Recovered directories first, then the restored item.
    let mut changes: Vec<ItemChange> = Vec::new();
    let mut operation_ids: BTreeSet<OperationId> = BTreeSet::new();
    for dir in &recovered_dirs {
        let record = dir.to_record();
        format::validate_item_record(&record)
            .map_err(|_| ReconcileError::InvalidRecord("recovered directory is not canonical"))?;
        for op in [
            record.item_revision,
            record.content_operation,
            record.location_operation,
        ] {
            operation_ids.insert(op);
        }
        changes.push(ItemChange {
            item_id: record.item_id,
            change: ChangeKind::Create,
            old_revision: None,
            new_revision: record.item_revision,
        });
        remote_ops.push(RemoteOp {
            record,
            change: ChangeKind::Create,
            old_revision: None,
        });
    }
    let change = if cur.deleted {
        ChangeKind::Undelete
    } else {
        ChangeKind::Content
    };
    let record = restored.to_record();
    format::validate_item_record(&record)
        .map_err(|_| ReconcileError::InvalidRecord("restored record is not canonical"))?;
    for op in [
        record.item_revision,
        record.content_operation,
        record.location_operation,
    ] {
        operation_ids.insert(op);
    }
    changes.push(ItemChange {
        item_id: record.item_id,
        change,
        old_revision: Some(cur.item_revision),
        new_revision: record.item_revision,
    });
    remote_ops.push(RemoteOp { record, change, old_revision: Some(cur.item_revision) });
    changes.sort_by_key(|c| c.item_id);

    // The historical version record already exists; nothing is re-uploaded
    // and nothing is deleted. The local file materializes the restored bytes.
    let local_actions = vec![LocalAction {
        action_id: ids.action_id(),
        item_id: spec.item_id,
        action: if cur.deleted {
            LocalActionKind::CreatePlaceholder
        } else {
            LocalActionKind::UpdatePlaceholder
        },
        expected: Some(cur),
        target: Some(restored),
        local_alias: None,
    }];

    Ok(ReconcilePlan {
        workspace_id,
        mode,
        remote_ops,
        versions: Vec::new(),
        changes,
        operation_ids: operation_ids.into_iter().collect(),
        local_actions,
        conflicts,
        aliases: Vec::new(),
        intents: vec![IntentOutcome {
            operation_id: spec.operation_id,
            item_id: spec.item_id,
            outcome: IntentOutcomeKind::Published,
            conflict_id: None,
        }],
    })
}

/// The nearest live directory at or above `start` in `view`.
fn nearest_live_directory(view: &CatalogView, start: ItemId) -> Option<ItemId> {
    let mut seen: BTreeSet<ItemId> = BTreeSet::new();
    let mut cur = start;
    loop {
        if !seen.insert(cur) {
            return None;
        }
        match view.get(cur) {
            Some(state) if !state.deleted && state.kind == ItemKind::Directory => return Some(cur),
            Some(state) => cur = state.parent_id?,
            None => return None,
        }
    }
}
