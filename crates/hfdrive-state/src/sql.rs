//! Typed row readers. Every column is read strictly: a shape mismatch is
//! reported as corruption, never coerced.

use crate::convert as c;
use crate::error::StateError;
use crate::model::*;
use hfdrive_core::storage::{BucketBinding, DriveBinding, RemotePrefix};
use rusqlite::Row;

type SResult<T> = Result<T, StateError>;

pub(crate) fn read_account(row: &Row<'_>) -> SResult<AccountRecord> {
    Ok(AccountRecord {
        account_key: c::account_key(row.get_ref(0)?)?,
        issuer: c::text(row.get_ref(1)?, "issuer")?,
        subject: c::text(row.get_ref(2)?, "subject")?,
        namespace: c::text(row.get_ref(3)?, "namespace")?,
        credential_ref: CredentialRef(c::text(row.get_ref(4)?, "credential_ref")?),
        auth_epoch: c::unsigned(row.get_ref(5)?, "auth_epoch")?,
        status: parse_account_status(&c::text(row.get_ref(6)?, "status")?)?,
    })
}

/// Reads the exact resource binding from the typed registry columns
/// (account_key, workspace_id, owner_kind, owner_id, owner_namespace,
/// bucket_id, bucket_name, prefix).
pub(crate) fn read_binding(row: &Row<'_>, offset: usize) -> SResult<DriveBinding> {
    Ok(DriveBinding {
        account_key: c::account_key(row.get_ref(offset)?)?,
        workspace_id: c::workspace_id(row.get_ref(offset + 1)?)?,
        bucket: BucketBinding {
            owner_kind: parse_owner_kind(&c::text(row.get_ref(offset + 2)?, "owner_kind")?)?,
            owner_id: c::text(row.get_ref(offset + 3)?, "owner_id")?.parse().map_err(|_| StateError::InvalidId { entity: "OwnerId" })?,
            owner_namespace: c::text(row.get_ref(offset + 4)?, "owner_namespace")?.parse().map_err(|_| StateError::InvalidId { entity: "Namespace" })?,
            bucket_id: c::text(row.get_ref(offset + 5)?, "bucket_id")?.parse().map_err(|_| StateError::InvalidId { entity: "BucketId" })?,
            bucket_name: c::text(row.get_ref(offset + 6)?, "bucket_name")?.parse().map_err(|_| StateError::InvalidId { entity: "BucketName" })?,
        },
        prefix: c::text(row.get_ref(offset + 7)?, "prefix")?.parse::<RemotePrefix>().map_err(|_| StateError::InvalidId { entity: "RemotePrefix" })?,
    })
}

/// Control registry row. Columns: connection_id, then the eight binding
/// columns, root_path, mode, registered, volume_guid, volume_serial,
/// sync_root_id, oauth_ref, s3_ref, config_json.
pub(crate) fn read_control_connection(row: &Row<'_>) -> SResult<ConnectionRecord> {
    Ok(ConnectionRecord {
        connection_id: c::connection_id(row.get_ref(0)?)?,
        account_key: c::account_key(row.get_ref(1)?)?,
        binding: read_binding(row, 1)?,
        root_path: c::path(row.get_ref(9)?, "root_path")?,
        mode: parse_mode(&c::text(row.get_ref(10)?, "mode")?)?,
        registered: c::boolean(row.get_ref(11)?, "registered")?,
        volume_guid: c::text_opt(row.get_ref(12)?, "volume_guid")?,
        volume_serial: c::unsigned_opt(row.get_ref(13)?, "volume_serial")?,
        sync_root_id: c::text_opt(row.get_ref(14)?, "sync_root_id")?,
        oauth_ref: c::text_opt(row.get_ref(15)?, "oauth_ref")?.map(CredentialRef),
        s3_ref: c::text_opt(row.get_ref(16)?, "s3_ref")?.map(CredentialRef),
        schema_version: 1,
        config_json: c::json(row.get_ref(17)?, "config_json")?,
    })
}

/// Account-local connection row. Columns: connection_id, the eight binding
/// columns, root_path, volume_guid, volume_serial, sync_root_id, oauth_ref,
/// s3_ref, schema_version, mode, observed/published/applied, config_json.
pub(crate) fn read_account_connection(row: &Row<'_>) -> SResult<ConnectionRecord> {
    Ok(ConnectionRecord {
        connection_id: c::connection_id(row.get_ref(0)?)?,
        account_key: c::account_key(row.get_ref(1)?)?,
        binding: read_binding(row, 1)?,
        root_path: c::path(row.get_ref(9)?, "root_path")?,
        volume_guid: c::text_opt(row.get_ref(10)?, "volume_guid")?,
        volume_serial: c::unsigned_opt(row.get_ref(11)?, "volume_serial")?,
        sync_root_id: c::text_opt(row.get_ref(12)?, "sync_root_id")?,
        oauth_ref: c::text_opt(row.get_ref(13)?, "oauth_ref")?.map(CredentialRef),
        s3_ref: c::text_opt(row.get_ref(14)?, "s3_ref")?.map(CredentialRef),
        schema_version: c::unsigned(row.get_ref(15)?, "schema_version")? as u32,
        mode: parse_mode(&c::text(row.get_ref(16)?, "mode")?)?,
        config_json: c::json(row.get_ref(17)?, "config_json")?,
        registered: true,
    })
}

pub(crate) fn read_baseline(row: &Row<'_>) -> SResult<PublicationBaseline> {
    Ok(PublicationBaseline {
        observed_commit: c::commit_id_opt(row.get_ref(0)?)?,
        published_commit: c::commit_id_opt(row.get_ref(1)?)?,
        applied_commit: c::commit_id_opt(row.get_ref(2)?)?,
    })
}

/// Setup journal row (identical column order in both databases).
pub(crate) fn read_setup(row: &Row<'_>) -> SResult<SetupRecord> {
    let binding: DriveBinding = c::from_json("binding_json", &c::text(row.get_ref(4)?, "binding_json")?)?;
    let created_resources_raw = c::text(row.get_ref(10)?, "created_resources_json")?;
    let created_resources: Vec<CreatedResource> = c::from_json("created_resources_json", &created_resources_raw)?;
    Ok(SetupRecord {
        setup_id: c::setup_id(row.get_ref(0)?)?,
        connection_id: c::connection_id(row.get_ref(1)?)?,
        operation_id: c::operation_id(row.get_ref(2)?)?,
        account_key: c::account_key(row.get_ref(3)?)?,
        binding,
        initialize: c::boolean(row.get_ref(5)?, "initialize")?,
        bucket_creation_operation_id: c::operation_id_opt(row.get_ref(6)?)?,
        request_fingerprint: c::digest_from(row.get_ref(7)?, "request_fingerprint")?,
        phase: parse_phase(&c::text(row.get_ref(8)?, "phase")?)?,
        status: parse_setup_status(&c::text(row.get_ref(9)?, "status")?)?,
        created_resources,
        preview_json: c::json_opt(row.get_ref(11)?, "preview_json")?,
        root_path: c::path_opt(row.get_ref(12)?, "root_path")?,
        mode: c::text_opt(row.get_ref(13)?, "mode")?
            .map(|text| parse_mode(&text))
            .transpose()?,
        credential_ref: c::text_opt(row.get_ref(14)?, "credential_ref")?.map(CredentialRef),
        probe_evidence_json: c::json_opt(row.get_ref(15)?, "probe_evidence_json")?,
        failure_reason: c::text_opt(row.get_ref(16)?, "failure_reason")?,
        evidence_generation: c::unsigned(row.get_ref(17)?, "evidence_generation")?,
        account_committed: c::boolean(row.get_ref(18)?, "account_committed")?,
        control_committed: c::boolean(row.get_ref(19)?, "control_committed")?,
    })
}

pub(crate) fn read_operation(row: &Row<'_>) -> SResult<OperationRecord> {
    Ok(OperationRecord {
        operation_id: c::operation_id(row.get_ref(0)?)?,
        kind: c::text(row.get_ref(1)?, "kind")?,
        request_digest: c::digest_from(row.get_ref(2)?, "request_digest")?,
        effect_class: parse_effect_class(&c::text(row.get_ref(3)?, "effect_class")?)?,
        state: parse_operation_state(&c::text(row.get_ref(4)?, "state")?)?,
        account_key: c::account_key_opt(row.get_ref(5)?)?,
        connection_id: c::connection_id_opt(row.get_ref(6)?)?,
        result_json: c::json_opt(row.get_ref(7)?, "result_json")?,
        error_code: c::text_opt(row.get_ref(8)?, "error_code")?,
        bucket_creation_operation_id: c::operation_id_opt(row.get_ref(9)?)?,
    })
}

pub(crate) fn read_outbox(row: &Row<'_>) -> SResult<OutboxEntry> {
    Ok(OutboxEntry {
        connection_id: c::connection_id(row.get_ref(0)?)?,
        operation_id: c::operation_id(row.get_ref(1)?)?,
        item_id: c::item_id_opt(row.get_ref(2)?)?,
        base_commit: c::commit_id_opt(row.get_ref(3)?)?,
        // Canonical format bytes are stored verbatim, never re-serialized.
        base_json: c::text_opt(row.get_ref(4)?, "base_json")?,
        observed_generation: c::unsigned(row.get_ref(5)?, "observed_generation")?,
        intent_json: c::json(row.get_ref(6)?, "intent_json")?,
        state: parse_outbox_state(&c::text(row.get_ref(7)?, "state")?)?,
        snapshot_id: c::snapshot_id_opt(row.get_ref(8)?)?,
        object_ref: match c::json_opt(row.get_ref(9)?, "object_ref_json")? {
            None => None,
            Some(value) => Some(c::from_json("object_ref_json", &value.to_string())?),
        },
        candidate_commit: c::commit_id_opt(row.get_ref(10)?)?,
        candidate_head_json: c::json_opt(row.get_ref(11)?, "candidate_head_json")?,
        expected_etag: c::text_opt(row.get_ref(12)?, "expected_etag")?,
        retry_class: parse_retry_class(&c::text(row.get_ref(13)?, "retry_class")?)?,
        next_attempt_at_ms: c::unsigned_opt(row.get_ref(14)?, "next_attempt_at_ms")?,
    })
}

pub(crate) fn read_common_base(row: &Row<'_>) -> SResult<CommonBaseRecord> {
    Ok(CommonBaseRecord {
        connection_id: c::connection_id(row.get_ref(0)?)?,
        item_id: c::item_id(row.get_ref(1)?)?,
        commit_id: c::commit_id(row.get_ref(2)?)?,
        item_json: c::text(row.get_ref(3)?, "item_json")?,
    })
}

pub(crate) fn read_snapshot(row: &Row<'_>) -> SResult<SnapshotRecord> {
    Ok(SnapshotRecord {
        connection_id: c::connection_id(row.get_ref(0)?)?,
        snapshot_id: c::snapshot_id(row.get_ref(1)?)?,
        path: c::path(row.get_ref(2)?, "path")?,
        size: c::unsigned_opt(row.get_ref(3)?, "size")?,
        sha256: c::digest_opt(row.get_ref(4)?, "sha256")?,
        status: parse_snapshot_status(&c::text(row.get_ref(5)?, "status")?)?,
    })
}

pub(crate) fn read_transfer(row: &Row<'_>) -> SResult<TransferRecord> {
    Ok(TransferRecord {
        connection_id: c::connection_id(row.get_ref(0)?)?,
        transfer_id: c::transfer_id(row.get_ref(1)?)?,
        operation_id: c::operation_id_opt(row.get_ref(2)?)?,
        direction: parse_direction(&c::text(row.get_ref(3)?, "direction")?)?,
        version_id: c::version_id_opt(row.get_ref(4)?)?,
        range_start: c::unsigned_opt(row.get_ref(5)?, "range_start")?,
        range_end: c::unsigned_opt(row.get_ref(6)?, "range_end")?,
        state: parse_transfer_state(&c::text(row.get_ref(7)?, "state")?)?,
        sdk_resume_json: c::json_opt(row.get_ref(8)?, "sdk_resume_json")?,
        logical_bytes: c::unsigned(row.get_ref(9)?, "logical_bytes")?,
        wire_bytes: c::unsigned(row.get_ref(10)?, "wire_bytes")?,
    })
}

pub(crate) fn read_commit(row: &Row<'_>) -> SResult<CommitRecord> {
    let operation_ids_raw = c::text(row.get_ref(4)?, "operation_ids_json")?;
    Ok(CommitRecord {
        connection_id: c::connection_id(row.get_ref(0)?)?,
        commit_id: c::commit_id(row.get_ref(1)?)?,
        parent_id: c::commit_id_opt(row.get_ref(2)?)?,
        catalog_root: c::digest_opt(row.get_ref(3)?, "catalog_root")?,
        operation_ids: c::from_json("operation_ids_json", &operation_ids_raw)?,
        status: parse_commit_status(&c::text(row.get_ref(5)?, "status")?)?,
    })
}

pub(crate) fn read_local_action(row: &Row<'_>) -> SResult<LocalAction> {
    Ok(LocalAction {
        connection_id: c::connection_id(row.get_ref(0)?)?,
        action_id: c::action_id(row.get_ref(1)?)?,
        item_id: c::item_id_opt(row.get_ref(2)?)?,
        kind: parse_action_kind(&c::text(row.get_ref(3)?, "kind")?)?,
        expected_file_id: c::text_opt(row.get_ref(4)?, "expected_file_id")?,
        expected_generation: c::unsigned_opt(row.get_ref(5)?, "expected_generation")?,
        expected_usn: c::unsigned_opt(row.get_ref(6)?, "expected_usn")?,
        old_version: c::version_id_opt(row.get_ref(7)?)?,
        new_version: c::version_id_opt(row.get_ref(8)?)?,
        source_path: c::path_opt(row.get_ref(9)?, "source_path")?,
        target_path: c::path_opt(row.get_ref(10)?, "target_path")?,
        recovery_path: c::path_opt(row.get_ref(11)?, "recovery_path")?,
        state: parse_action_state(&c::text(row.get_ref(12)?, "state")?)?,
    })
}

pub(crate) fn read_conflict(row: &Row<'_>) -> SResult<ConflictRecord> {
    let competing = c::text(row.get_ref(3)?, "competing_ops_json")?;
    let names = c::text(row.get_ref(5)?, "original_names_json")?;
    Ok(ConflictRecord {
        connection_id: c::connection_id(row.get_ref(0)?)?,
        conflict_id: c::conflict_id(row.get_ref(1)?)?,
        item_id: c::item_id(row.get_ref(2)?)?,
        competing_ops: c::from_json("competing_ops_json", &competing)?,
        revisions_json: c::json(row.get_ref(4)?, "revisions_json")?,
        original_names: c::from_json("original_names_json", &names)?,
        resolution_state: parse_resolution(&c::text(row.get_ref(6)?, "resolution_state")?)?,
        detected_at_ms: Some(c::unsigned(row.get_ref(7)?, "conflict.created_at_ms")?),
    })
}

pub(crate) fn read_observation(row: &Row<'_>) -> SResult<LocalObservation> {
    Ok(LocalObservation {
        connection_id: c::connection_id(row.get_ref(0)?)?,
        item_id: c::item_id(row.get_ref(1)?)?,
        generation: c::unsigned(row.get_ref(2)?, "generation")?,
        observed_usn: c::unsigned_opt(row.get_ref(3)?, "observed_usn")?,
        dirty: c::boolean(row.get_ref(4)?, "dirty")?,
        pin_requested: c::boolean(row.get_ref(5)?, "pin_requested")?,
        pin_complete: c::boolean(row.get_ref(6)?, "pin_complete")?,
        excluded: c::boolean(row.get_ref(7)?, "excluded")?,
        scan_epoch: c::unsigned(row.get_ref(8)?, "scan_epoch")?,
    })
}

pub(crate) fn read_scan(row: &Row<'_>) -> SResult<ScanState> {
    Ok(ScanState {
        connection_id: c::connection_id(row.get_ref(0)?)?,
        cursor: c::text_opt(row.get_ref(1)?, "cursor")?,
        pending_head_refresh: c::boolean(row.get_ref(2)?, "pending_head_refresh")?,
        volume_id: c::text(row.get_ref(3)?, "volume_id")?,
        journal_id: c::text(row.get_ref(4)?, "journal_id")?,
        usn_cursor: c::unsigned_opt(row.get_ref(5)?, "usn_cursor")?,
        scan_epoch: c::unsigned(row.get_ref(6)?, "scan_epoch")?,
        scan_complete: c::boolean(row.get_ref(7)?, "scan_complete")?,
        scan_invalidated: c::boolean(row.get_ref(8)?, "scan_invalidated")?,
    })
}

pub(crate) fn read_settings(row: &Row<'_>) -> SResult<SettingsRow> {
    Ok(SettingsRow {
        scope_id: c::text(row.get_ref(0)?, "scope_id")?,
        revision: c::unsigned(row.get_ref(1)?, "revision")?,
        value_json: c::json(row.get_ref(2)?, "value_json")?,
    })
}

pub(crate) fn read_probe_key(row: &Row<'_>) -> SResult<ProbeKeyRecord> {
    Ok(ProbeKeyRecord {
        run_id: c::generation_id(row.get_ref(0)?)?,
        connection_id: c::connection_id(row.get_ref(1)?)?,
        setup_id: c::setup_id_opt(row.get_ref(2)?)?,
        key: c::text(row.get_ref(3)?, "key")?,
        state: parse_probe_key_state(&c::text(row.get_ref(4)?, "state")?)?,
    })
}

pub(crate) fn read_item(row: &Row<'_>) -> SResult<ItemRecord> {
    Ok(ItemRecord {
        connection_id: c::connection_id(row.get_ref(0)?)?,
        item_id: c::item_id(row.get_ref(1)?)?,
        parent_id: c::item_id_opt(row.get_ref(2)?)?,
        name: c::text(row.get_ref(3)?, "name")?,
        name_key: c::text(row.get_ref(4)?, "name_key")?,
        kind: parse_item_kind(&c::text(row.get_ref(5)?, "kind")?)?,
        revision: c::operation_id(row.get_ref(6)?)?,
        content_version_id: c::version_id_opt(row.get_ref(7)?)?,
        deleted: c::boolean(row.get_ref(8)?, "deleted")?,
        metadata_json: c::json(row.get_ref(9)?, "metadata_json")?,
    })
}

macro_rules! parse_enum {
    ($fn:ident, $ty:ty, $entity:literal, $(($variant:ident, $text:literal)),+ $(,)?) => {
        pub(crate) fn $fn(value: &str) -> SResult<$ty> {
            match value {
                $($text => Ok(<$ty>::$variant),)+
                other => Err(StateError::invalid_state($entity, other, "unknown enum value")),
            }
        }
    };
}

parse_enum!(parse_account_status, AccountStatus, "AccountStatus",
    (Active, "active"), (NeedsSignIn, "needs_sign_in"), (SignedOut, "signed_out"));

pub(crate) fn account_status_text(value: AccountStatus) -> &'static str {
    match value {
        AccountStatus::Active => "active",
        AccountStatus::NeedsSignIn => "needs_sign_in",
        AccountStatus::SignedOut => "signed_out",
    }
}
parse_enum!(parse_owner_kind, OwnerKind, "OwnerKind",
    (Personal, "personal"), (Organization, "organization"));
parse_enum!(parse_mode, ConnectionMode, "ConnectionMode",
    (ReadOnly, "read_only"), (Writable, "writable"));
parse_enum!(parse_phase, SetupPhase, "SetupPhase",
    (Reserved, "reserved"), (CredentialsRecorded, "credentials_recorded"), (Probed, "probed"),
    (PreviewReady, "preview_ready"), (Registering, "registering"), (Connected, "connected"));
parse_enum!(parse_setup_status, SetupStatus, "SetupStatus",
    (Active, "active"), (Failed, "failed"), (Connected, "connected"), (Abandoned, "abandoned"));
parse_enum!(parse_effect_class, EffectClass, "EffectClass",
    (None, "none"), (Local, "local"), (External, "external"));
parse_enum!(parse_operation_state, OperationState, "OperationState",
    (Pending, "pending"), (ExternalPending, "external_pending"), (Committed, "committed"),
    (Failed, "failed"), (Abandoned, "abandoned"));
parse_enum!(parse_outbox_state, OutboxState, "OutboxState",
    (Observed, "observed"), (SnapshotReady, "snapshot_ready"), (PayloadReady, "payload_ready"),
    (MetadataReady, "metadata_ready"), (PublishUnknown, "publish_unknown"), (Published, "published"),
    (LocalApplyPending, "local_apply_pending"), (Complete, "complete"));
parse_enum!(parse_retry_class, RetryClass, "RetryClass",
    (None, "none"), (Backoff, "backoff"), (NeedsUser, "needs_user"), (NeedsAuth, "needs_auth"));
parse_enum!(parse_snapshot_status, SnapshotStatus, "SnapshotStatus",
    (Capturing, "capturing"), (Ready, "ready"), (Consumed, "consumed"), (Released, "released"));
parse_enum!(parse_direction, TransferDirection, "TransferDirection",
    (Upload, "upload"), (Download, "download"));
parse_enum!(parse_transfer_state, TransferState, "TransferState",
    (Pending, "pending"), (InProgress, "in_progress"), (Succeeded, "succeeded"),
    (Failed, "failed"), (Cancelled, "cancelled"));
parse_enum!(parse_commit_status, CommitStatus, "CommitStatus",
    (Candidate, "candidate"), (Committed, "committed"), (Applied, "applied"));
parse_enum!(parse_action_kind, LocalActionKind, "LocalActionKind",
    (CreatePlaceholder, "create_placeholder"), (UpdatePlaceholder, "update_placeholder"),
    (Rename, "rename"), (DeletePlaceholder, "delete_placeholder"), (Hydrate, "hydrate"),
    (Dehydrate, "dehydrate"), (SetPin, "set_pin"), (ConvertToNormal, "convert_to_normal"),
    (Other, "other"));
parse_enum!(parse_action_state, LocalActionState, "LocalActionState",
    (Pending, "pending"), (InProgress, "in_progress"), (Applied, "applied"), (Failed, "failed"),
    (Requeued, "requeued"), (Recovered, "recovered"));
parse_enum!(parse_resolution, ConflictResolution, "ConflictResolution",
    (Unresolved, "unresolved"), (KeepLocal, "keep_local"), (KeepRemote, "keep_remote"),
    (KeepBoth, "keep_both"), (Recovered, "recovered"));
parse_enum!(parse_probe_key_state, ProbeKeyState, "ProbeKeyState",
    (Reserved, "reserved"), (CreateInFlight, "create_in_flight"), (Created, "created"),
    (NotCreated, "not_created"), (Deleted, "deleted"));
parse_enum!(parse_item_kind, ItemKind, "ItemKind",
    (File, "file"), (Directory, "directory"));

pub(crate) fn owner_kind_text(value: OwnerKind) -> &'static str {
    match value {
        OwnerKind::Personal => "personal",
        OwnerKind::Organization => "organization",
    }
}

pub(crate) fn mode_text(value: ConnectionMode) -> &'static str {
    match value {
        ConnectionMode::ReadOnly => "read_only",
        ConnectionMode::Writable => "writable",
    }
}

pub(crate) fn phase_text(value: SetupPhase) -> &'static str {
    match value {
        SetupPhase::Reserved => "reserved",
        SetupPhase::CredentialsRecorded => "credentials_recorded",
        SetupPhase::Probed => "probed",
        SetupPhase::PreviewReady => "preview_ready",
        SetupPhase::Registering => "registering",
        SetupPhase::Connected => "connected",
    }
}

pub(crate) fn setup_status_text(value: SetupStatus) -> &'static str {
    match value {
        SetupStatus::Active => "active",
        SetupStatus::Failed => "failed",
        SetupStatus::Connected => "connected",
        SetupStatus::Abandoned => "abandoned",
    }
}

pub(crate) fn effect_class_text(value: EffectClass) -> &'static str {
    match value {
        EffectClass::None => "none",
        EffectClass::Local => "local",
        EffectClass::External => "external",
    }
}

pub(crate) fn operation_state_text(value: OperationState) -> &'static str {
    match value {
        OperationState::Pending => "pending",
        OperationState::ExternalPending => "external_pending",
        OperationState::Committed => "committed",
        OperationState::Failed => "failed",
        OperationState::Abandoned => "abandoned",
    }
}

pub(crate) fn outbox_state_text(value: OutboxState) -> &'static str {
    match value {
        OutboxState::Observed => "observed",
        OutboxState::SnapshotReady => "snapshot_ready",
        OutboxState::PayloadReady => "payload_ready",
        OutboxState::MetadataReady => "metadata_ready",
        OutboxState::PublishUnknown => "publish_unknown",
        OutboxState::Published => "published",
        OutboxState::LocalApplyPending => "local_apply_pending",
        OutboxState::Complete => "complete",
    }
}

pub(crate) fn retry_class_text(value: RetryClass) -> &'static str {
    match value {
        RetryClass::None => "none",
        RetryClass::Backoff => "backoff",
        RetryClass::NeedsUser => "needs_user",
        RetryClass::NeedsAuth => "needs_auth",
    }
}

pub(crate) fn snapshot_status_text(value: SnapshotStatus) -> &'static str {
    match value {
        SnapshotStatus::Capturing => "capturing",
        SnapshotStatus::Ready => "ready",
        SnapshotStatus::Consumed => "consumed",
        SnapshotStatus::Released => "released",
    }
}

pub(crate) fn direction_text(value: TransferDirection) -> &'static str {
    match value {
        TransferDirection::Upload => "upload",
        TransferDirection::Download => "download",
    }
}

pub(crate) fn transfer_state_text(value: TransferState) -> &'static str {
    match value {
        TransferState::Pending => "pending",
        TransferState::InProgress => "in_progress",
        TransferState::Succeeded => "succeeded",
        TransferState::Failed => "failed",
        TransferState::Cancelled => "cancelled",
    }
}

pub(crate) fn commit_status_text(value: CommitStatus) -> &'static str {
    match value {
        CommitStatus::Candidate => "candidate",
        CommitStatus::Committed => "committed",
        CommitStatus::Applied => "applied",
    }
}

pub(crate) fn action_kind_text(value: LocalActionKind) -> &'static str {
    match value {
        LocalActionKind::CreatePlaceholder => "create_placeholder",
        LocalActionKind::UpdatePlaceholder => "update_placeholder",
        LocalActionKind::Rename => "rename",
        LocalActionKind::DeletePlaceholder => "delete_placeholder",
        LocalActionKind::Hydrate => "hydrate",
        LocalActionKind::Dehydrate => "dehydrate",
        LocalActionKind::SetPin => "set_pin",
        LocalActionKind::ConvertToNormal => "convert_to_normal",
        LocalActionKind::Other => "other",
    }
}

pub(crate) fn action_state_text(value: LocalActionState) -> &'static str {
    match value {
        LocalActionState::Pending => "pending",
        LocalActionState::InProgress => "in_progress",
        LocalActionState::Applied => "applied",
        LocalActionState::Failed => "failed",
        LocalActionState::Requeued => "requeued",
        LocalActionState::Recovered => "recovered",
    }
}

pub(crate) fn resolution_text(value: ConflictResolution) -> &'static str {
    match value {
        ConflictResolution::Unresolved => "unresolved",
        ConflictResolution::KeepLocal => "keep_local",
        ConflictResolution::KeepRemote => "keep_remote",
        ConflictResolution::KeepBoth => "keep_both",
        ConflictResolution::Recovered => "recovered",
    }
}

pub(crate) fn probe_key_state_text(value: ProbeKeyState) -> &'static str {
    match value {
        ProbeKeyState::Reserved => "reserved",
        ProbeKeyState::CreateInFlight => "create_in_flight",
        ProbeKeyState::Created => "created",
        ProbeKeyState::NotCreated => "not_created",
        ProbeKeyState::Deleted => "deleted",
    }
}

pub(crate) fn item_kind_text(value: ItemKind) -> &'static str {
    match value {
        ItemKind::File => "file",
        ItemKind::Directory => "directory",
    }
}
