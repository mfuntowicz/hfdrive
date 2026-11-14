//! Conflict projection from durable reconciliation evidence. Missing legacy
//! evidence fails closed: kind and detection time are never guessed.

use hfdrive_core::ids::{ConnectionId, OperationId};
use hfdrive_protocol as wire;

use crate::{Provider, operations::error, storage::invalid};

impl Provider {
    pub(crate) async fn resolve_conflict(
        &self,
        request: wire::ResolveConflictRequest,
    ) -> Result<wire::ResolveConflictResult, wire::ProtocolError> {
        let resolution = match request.resolution {
            wire::ConflictResolution::KeepLocal => hfdrive_state::ConflictResolution::KeepLocal,
            wire::ConflictResolution::KeepRemote => hfdrive_state::ConflictResolution::KeepRemote,
            wire::ConflictResolution::KeepBoth => hfdrive_state::ConflictResolution::KeepBoth,
            _ => return Err(invalid("Choose keep_local, keep_remote or keep_both")),
        };
        let connection = ConnectionId::from_uuid(request.connection_id)
            .map_err(|_| invalid("A nonzero connection identifier is required"))?;
        let conflict = hfdrive_core::ids::ConflictId::from_uuid(request.conflict_id)
            .map_err(|_| invalid("A nonzero conflict identifier is required"))?;
        let operation = OperationId::from_uuid(request.operation_id)
            .map_err(|_| invalid("A nonzero resolution operation identifier is required"))?;
        let engine = self.engine.as_ref().ok_or_else(crate::operations::internal)?;
        let record = engine.resolve_conflict(connection, conflict, resolution, operation).await
            .map_err(crate::storage::engine_failure)?;
        let projected = project_conflict(&record)?;
        Ok(wire::ResolveConflictResult {
            conflict_id: projected.conflict_id,
            resolution_state: projected.resolution_state,
        })
    }

    pub(crate) async fn list_conflicts(
        &self,
        request: wire::ListConflictsRequest,
    ) -> Result<wire::ListConflictsResult, wire::ProtocolError> {
        if !(1..=200).contains(&request.limit) {
            return Err(invalid("Conflict page size must be between 1 and 200"));
        }
        let profile = self.current_account()?;
        let connection = ConnectionId::from_uuid(request.connection_id)
            .map_err(|_| invalid("A nonzero connection identifier is required"))?;
        self.state.reconcile_connections().await.map_err(crate::operations::state_error)?
            .into_iter()
            .find(|record| record.connection_id == connection && record.account_key == profile.account_key)
            .ok_or_else(|| error(wire::ProtocolErrorCode::NotFound, "The connection does not exist for this account"))?;
        let account = self.state.open_account(profile.account_key).await.map_err(crate::operations::state_error)?;
        let records = account.list_conflicts(connection).await.map_err(crate::operations::state_error)?;
        let start = conflict_cursor(&request.cursor, connection, records.len())?;
        let end = start.saturating_add(request.limit as usize).min(records.len());
        let page = records.get(start..end).ok_or_else(|| invalid("Invalid conflict continuation cursor"))?;
        let items = page.iter().map(project_conflict).collect::<Result<Vec<_>, _>>()?;
        Ok(wire::ListConflictsResult {
            items,
            next_cursor: (end < records.len()).then(|| format!("conflicts-v1:{connection}:{end}")),
        })
    }
}

fn project_conflict(
    record: &hfdrive_state::ConflictRecord,
) -> Result<wire::ConflictRecord, wire::ProtocolError> {
    let kind = record.revisions_json.get("kind").and_then(serde_json::Value::as_str)
        .ok_or_else(|| unsupported_conflict())?;
    let kind = match kind {
        "content_divergence" | "content_and_location" => wire::ConflictKind::Content,
        "rename_race" => wire::ConflictKind::Rename,
        "delete_vs_change" | "directory_delete_recovery" => wire::ConflictKind::DeleteEdit,
        "name_collision" | "ntfs_alias" => wire::ConflictKind::CaseCollision,
        "cycle_move" => wire::ConflictKind::MoveCycle,
        _ => return Err(unsupported_conflict()),
    };
    let sides = record.revisions_json.get("sides").and_then(serde_json::Value::as_array)
        .ok_or_else(|| unsupported_conflict())?;
    let revisions = sides.iter().map(|side| {
        side.get("operation_id").and_then(serde_json::Value::as_str)
            .and_then(|value| value.parse::<OperationId>().ok())
            .map(|id| *id.as_uuid())
            .ok_or_else(|| unsupported_conflict())
    }).collect::<Result<Vec<_>, _>>()?;
    if revisions.len() != 2 {
        return Err(unsupported_conflict());
    }
    let mut competing_operation_ids = record.competing_ops.iter().map(|id| *id.as_uuid()).collect::<Vec<_>>();
    competing_operation_ids.sort();
    let resolution_state = match record.resolution_state {
        hfdrive_state::ConflictResolution::Unresolved => wire::ConflictResolution::Unresolved,
        hfdrive_state::ConflictResolution::KeepLocal => wire::ConflictResolution::KeepLocal,
        hfdrive_state::ConflictResolution::KeepRemote => wire::ConflictResolution::KeepRemote,
        hfdrive_state::ConflictResolution::KeepBoth => wire::ConflictResolution::KeepBoth,
        hfdrive_state::ConflictResolution::Recovered => wire::ConflictResolution::Recovered,
    };
    Ok(wire::ConflictRecord {
        conflict_id: *record.conflict_id.as_uuid(),
        item_id: *record.item_id.as_uuid(),
        kind,
        competing_operation_ids,
        revisions,
        original_names: record.original_names.clone(),
        detected_at: conflict_timestamp(record.detected_at_ms.ok_or_else(|| unsupported_conflict())?)?,
        resolution_state,
    })
}

fn conflict_timestamp(milliseconds: u64) -> Result<String, wire::ProtocolError> {
    const WINDOWS_EPOCH_OFFSET_MS: i64 = 11_644_473_600_000;
    let milliseconds = i64::try_from(milliseconds).map_err(|_| unsupported_conflict())?;
    let windows_100ns = WINDOWS_EPOCH_OFFSET_MS
        .checked_add(milliseconds)
        .and_then(|value| value.checked_mul(10_000))
        .ok_or_else(|| unsupported_conflict())?;
    Ok(crate::sync::outbox::display_timestamp(windows_100ns))
}

fn unsupported_conflict() -> wire::ProtocolError {
    error(wire::ProtocolErrorCode::UnsupportedFormat, "A persisted conflict lacks required kind or revision evidence")
}

fn conflict_cursor(
    cursor: &Option<String>,
    connection: ConnectionId,
    total: usize,
) -> Result<usize, wire::ProtocolError> {
    let Some(cursor) = cursor else { return Ok(0); };
    let mut parts = cursor.split(':');
    if parts.next() != Some("conflicts-v1")
        || parts.next() != Some(connection.to_string().as_str())
    {
        return Err(invalid("Conflict cursor belongs to a different connection"));
    }
    let offset = parts.next().and_then(|value| value.parse::<usize>().ok())
        .filter(|_| parts.next().is_none())
        .ok_or_else(|| invalid("Invalid conflict continuation cursor"))?;
    if offset > total {
        return Err(error(wire::ProtocolErrorCode::Conflict, "Conflict listing changed; reload the first page"));
    }
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_is_connection_bound_and_checks_offset() {
        let connection = ConnectionId::new();
        let other = ConnectionId::new();
        assert_eq!(conflict_cursor(&None, connection, 2).unwrap(), 0);
        assert_eq!(conflict_cursor(&Some(format!("conflicts-v1:{connection}:1")), connection, 2).unwrap(), 1);
        assert!(conflict_cursor(&Some(format!("conflicts-v1:{other}:1")), connection, 2).is_err());
        assert!(conflict_cursor(&Some(format!("conflicts-v1:{connection}:3")), connection, 2).is_err());
    }

    #[test]
    fn projection_preserves_kind_revisions_and_unresolved_state() {
        let left = OperationId::new();
        let right = OperationId::new();
        let record = hfdrive_state::ConflictRecord {
            connection_id: ConnectionId::new(),
            conflict_id: hfdrive_core::ids::ConflictId::new(),
            item_id: hfdrive_core::ids::ItemId::new(),
            competing_ops: vec![right, left],
            revisions_json: serde_json::json!({
                "kind": "content_divergence",
                "sides": [
                    {"operation_id": left.to_string(), "parent_id": null, "name": "a", "content_version_id": null},
                    {"operation_id": right.to_string(), "parent_id": null, "name": "b", "content_version_id": null}
                ]
            }),
            original_names: vec!["a".to_owned(), "b".to_owned()],
            resolution_state: hfdrive_state::ConflictResolution::Unresolved,
            detected_at_ms: Some(0),
        };
        let projected = project_conflict(&record).unwrap();
        assert_eq!(projected.kind, wire::ConflictKind::Content);
        assert_eq!(projected.revisions, vec![*left.as_uuid(), *right.as_uuid()]);
        assert_eq!(projected.resolution_state, wire::ConflictResolution::Unresolved);
        assert_eq!(projected.detected_at, "1970-01-01T00:00:00Z");
        assert!(projected.competing_operation_ids.is_sorted());
    }
}
