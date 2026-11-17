//! Connection registry: root admission, Windows registration and the
//! connect/restore lifecycle.
//!
//! * **admission** validates the local root through handles (fixed writable
//!   NTFS, no reparse ancestors, no case-sensitive directories, no overlap
//!   with other roots or with application state) and checks the managed
//!   remote prefix for overlap with other configured connections;
//! * **registration** goes through `StorageProviderSyncRootManager` only
//!   (never `CfRegisterSyncRoot`), with the stable identity
//!   `HFDrive!<user-SID>!<connection-uuid>`, and is idempotent on restore;
//! * **connect** registers (or adopts the existing registration), connects
//!   the CFAPI callback pipeline and starts the runtime; a moved or missing
//!   volume pauses the binding instead of attaching to a different volume
//!   under the same drive letter.
//!
//! Registration identity is persisted in the account settings scope
//! `connection/<id>/registration` so restore can prove ownership of the root
//! before reconnecting.

use std::path::{Path, PathBuf};

use hfdrive_core::ids::{ConnectionId, ItemId, WorkspaceId};
use hfdrive_core::storage::DriveBinding;
use hfdrive_state::AccountStore;
use hfdrive_windows::cfapi::registration::{
    self, RegistrationInfo, RegisteredRoot, sync_root_id,
};
use hfdrive_windows::cfapi::{CfConnection, ConnectConfig, QueueCapacity};
use hfdrive_windows::filesystem::validate::{
    RootContext, ValidatedRoot, validate_sync_root,
};
use hfdrive_windows::filesystem::volume::VolumeIdentity;

/// Why a candidate root or binding was refused.
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error("the local root is invalid: {0}")]
    LocalRoot(String),
    #[error("the local root overlaps an existing HF Drive path")]
    Overlap,
    #[error("the remote prefix overlaps another configured connection")]
    RemoteOverlap,
    #[error("the volume identity changed; the binding is paused")]
    VolumeChanged,
    #[error("windows registration failed")]
    Registration,
    #[error("durable state failed: {0}")]
    State(#[from] hfdrive_state::StateError),
}

/// Admission evidence for one candidate connection.
#[derive(Debug, Clone)]
pub struct AdmissionEvidence {
    pub validated: ValidatedRoot,
    pub sync_root_id: String,
}

/// Validates a candidate local root and remote binding against every other
/// configured connection. Nothing is registered or mutated here.
pub fn admit_root(
    connection: ConnectionId,
    root: &Path,
    binding: &DriveBinding,
    state_dir: &Path,
    configured: &[(PathBuf, DriveBinding)],
    user_sid: &str,
) -> Result<AdmissionEvidence, AdmissionError> {
    admit_root_internal(connection, root, binding, state_dir, configured, user_sid, None)
}

fn admit_root_internal(
    connection: ConnectionId,
    root: &Path,
    binding: &DriveBinding,
    state_dir: &Path,
    configured: &[(PathBuf, DriveBinding)],
    user_sid: &str,
    existing_sync_root_id: Option<String>,
) -> Result<AdmissionEvidence, AdmissionError> {
    let context = RootContext {
        state_dir: state_dir.to_path_buf(),
        configured_roots: configured.iter().map(|(path, _)| path.clone()).collect(),
        existing_sync_root_id,
    };
    let validated = validate_sync_root(root, &context)
        .map_err(|error| AdmissionError::LocalRoot(error.to_string()))?;

    // Remote prefix overlap for the same canonical bucket, by path-segment
    // containment.
    for (_, other) in configured {
        if other.bucket.bucket_id == binding.bucket.bucket_id
            && binding.prefix.overlaps(&other.prefix)
        {
            return Err(AdmissionError::RemoteOverlap);
        }
    }
    let id = match context.existing_sync_root_id {
        Some(id) => id,
        None => sync_root_id(user_sid, connection).map_err(|_| AdmissionError::Registration)?,
    };
    Ok(AdmissionEvidence { validated, sync_root_id: id })
}

/// Durable registration identity for one connection.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationRecord {
    pub sync_root_id: String,
    pub volume_guid: String,
    pub volume_serial: u32,
    pub registered: bool,
}

/// Persists the registration identity in the account settings scope.
pub async fn persist_registration(
    state: &AccountStore,
    connection: ConnectionId,
    record: &RegistrationRecord,
) -> Result<(), AdmissionError> {
    let scope = format!("connection/{connection}/registration");
    let value = serde_json::to_value(record).map_err(|_| AdmissionError::Registration)?;
    state.set_settings(scope, value, None).await?;
    Ok(())
}

/// Loads the persisted registration identity.
pub async fn load_registration(
    state: &AccountStore,
    connection: ConnectionId,
) -> Result<Option<RegistrationRecord>, AdmissionError> {
    let scope = format!("connection/{connection}/registration");
    let row = state.settings(scope).await?;
    Ok(row.and_then(|row| serde_json::from_value(row.value_json).ok()))
}

/// Registers (or idempotently adopts) the sync root for one validated
/// connection and persists the identity evidence.
pub async fn register_connection(
    state: &AccountStore,
    connection: ConnectionId,
    validated: &ValidatedRoot,
    user_sid: &str,
    display_name: &str,
    version: &str,
) -> Result<RegistrationRecord, AdmissionError> {
    let id = sync_root_id(user_sid, connection).map_err(|_| AdmissionError::Registration)?;
    let info = RegistrationInfo {
        connection,
        display_name: display_name.to_owned(),
        icon_resource: std::env::current_exe()
            .map(|path| format!("@{{{}}},-101", path.display()))
            .unwrap_or_else(|_| "@{hfdrive-provider.exe},-101".to_owned()),
        version: version.to_owned(),
    };
    registration::register_sync_root(validated, user_sid, &info)
        .map_err(|_| AdmissionError::Registration)?;
    let record = RegistrationRecord {
        sync_root_id: id,
        volume_guid: validated.volume.guid_path.clone(),
        volume_serial: validated.volume.serial_number,
        registered: true,
    };
    persist_registration(state, connection, &record).await?;
    Ok(record)
}

/// Unregisters one connection's sync root. Idempotent.
pub fn unregister_connection(user_sid: &str, connection: ConnectionId) -> Result<(), AdmissionError> {
    registration::unregister_sync_root(user_sid, connection)
        .map_err(|_| AdmissionError::Registration)
}

/// Checks one registration by stable ID without resolving a deleted folder.
pub fn registration_present(user_sid: &str, connection: ConnectionId) -> Result<bool, AdmissionError> {
    registration::sync_root_registered(user_sid, connection)
        .map_err(|_| AdmissionError::Registration)
}

/// Every HF Drive root registered with Windows (any provider), used for
/// overlap checks and restore reconciliation.
pub fn registered_roots() -> Result<Vec<RegisteredRoot>, AdmissionError> {
    registration::registered_sync_roots().map_err(|_| AdmissionError::Registration)
}

/// Verifies the volume recorded at registration still backs the root. A
/// moved/missing volume pauses the binding; it never rebinds to whatever
/// volume now answers at the same path.
pub fn verify_volume(record: &RegistrationRecord, current: &VolumeIdentity) -> Result<(), AdmissionError> {
    if current.guid_path == record.volume_guid && current.serial_number == record.volume_serial {
        Ok(())
    } else {
        Err(AdmissionError::VolumeChanged)
    }
}

/// The connected CFAPI callback pipeline of one running connection.
pub struct ConnectedRoot {
    pub connection: CfConnection,
    pub streams: hfdrive_windows::cfapi::ProviderStreams,
}

/// Connects the CFAPI callback pipeline to a registered, validated root.
pub fn connect_root(
    validated: &ValidatedRoot,
    workspace: WorkspaceId,
) -> Result<ConnectedRoot, AdmissionError> {
    let config = ConnectConfig {
        workspace,
        queues: QueueCapacity::default(),
    };
    let (connection, streams) =
        CfConnection::connect(&validated.final_path, config).map_err(|_| AdmissionError::Registration)?;
    Ok(ConnectedRoot { connection, streams })
}

/// Shuts one connection down cleanly: stop scheduling first (caller), then
/// disconnect the runtime callbacks while the context is valid. Registration,
/// state and data are retained.
pub fn disconnect_root(connected: ConnectedRoot) -> Result<(), AdmissionError> {
    connected
        .connection
        .shutdown()
        .map_err(|_| AdmissionError::Registration)
}

/// A restored connection's identity proof used at reconnect time.
#[derive(Debug, Clone)]
pub struct RestoredConnection {
    pub record: hfdrive_state::ConnectionRecord,
    pub root_item_id: ItemId,
    pub validated: ValidatedRoot,
    pub registration: Option<RegistrationRecord>,
}

/// Reconciles persisted connections with the registrations Windows still
/// reports. Connections whose registration is missing are re-registered from
/// their validated root (idempotent reconnect); foreign registrations are
/// never touched.
pub async fn restore_connections(
    state: &AccountStore,
    connections: &[hfdrive_state::ConnectionRecord],
    state_dir: &Path,
    user_sid: &str,
) -> Result<Vec<RestoredConnection>, AdmissionError> {
    let mut restored = Vec::with_capacity(connections.len());
    let all = state.list_connections().await?;
    for record in connections {
        let root_item_id = record
            .config_json
            .get("root_item_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| value.parse::<ItemId>().ok())
            .ok_or_else(|| AdmissionError::LocalRoot("durable root item identity is missing".to_owned()))?;
        // A deleted folder or disconnected volume pauses the binding; it does
        // not invalidate every other connection or turn into a generic
        // identity conflict. Other admission failures remain fatal because
        // they could attach the wrong root or registration.
        if matches!(std::fs::symlink_metadata(&record.root_path), Err(error) if error.kind() == std::io::ErrorKind::NotFound) {
            continue;
        }
        let configured = all
            .iter()
            .filter(|other| other.connection_id != record.connection_id)
            .map(|other| (other.root_path.clone(), other.binding.clone()))
            .collect::<Vec<_>>();
        let registration = load_registration(state, record.connection_id).await?;
        let expected = sync_root_id(user_sid, record.connection_id)
            .map_err(|_| AdmissionError::Registration)?;
        if registration.as_ref().is_some_and(|registration| registration.sync_root_id != expected) {
            return Err(AdmissionError::Registration);
        }
        let evidence = admit_root_internal(
            record.connection_id,
            &record.root_path,
            &record.binding,
            state_dir,
            &configured,
            user_sid,
            Some(expected),
        )?;
        if let Some(registration) = &registration {
            verify_volume(registration, &evidence.validated.volume)?;
        }
        restored.push(RestoredConnection {
            record: record.clone(),
            root_item_id,
            validated: evidence.validated,
            registration,
        });
    }
    Ok(restored)
}

/// Reconciles persisted connections across every recorded account with the
/// registrations Windows still reports. Connections whose registration is
/// missing are re-registered from their validated root (idempotent
/// reconnect); foreign registrations are never touched.
pub async fn restore_all_account_connections(
    state: &hfdrive_state::StateStore,
    connections: &[hfdrive_state::ConnectionRecord],
    state_dir: &Path,
    user_sid: &str,
) -> Result<Vec<RestoredConnection>, AdmissionError> {
    let mut restored = Vec::with_capacity(connections.len());
    for record in connections {
        let account = state.open_account(record.account_key).await?;
        restored.extend(
            restore_connections(&account, std::slice::from_ref(record), state_dir, user_sid).await?,
        );
    }
    Ok(restored)
}

/// Snapshot of one root's validation facts for status reporting.
#[derive(Debug, Clone)]
pub struct RootFacts {
    pub volume: VolumeIdentity,
    pub sync_root_id: String,
}

impl RootFacts {
    pub fn of(validated: &ValidatedRoot, sync_root_id: String) -> Self {
        Self {
            volume: validated.volume.clone(),
            sync_root_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn absent_root_is_skipped_without_a_generic_restore_conflict() {
        let fixture = crate::sync::test_support::connection_fixture().await;
        let record = fixture.account.get_connection(fixture.connection).await.unwrap().unwrap();
        std::fs::remove_dir(&fixture.root).unwrap();
        let restored = restore_connections(
            &fixture.account,
            std::slice::from_ref(&record),
            &fixture.directory.path().join("state"),
            "S-1-5-21-fixture",
        )
        .await
        .unwrap();
        assert!(restored.is_empty(), "an absent root stays recoverable but inactive");
        fixture.state.close().await.unwrap();
    }
}
