//! Failure modes surfaced to provider callers.
//!
//! Every variant is a state-layer condition the caller can act on; SQLite and
//! filesystem causes are carried but never swallowed.

use crate::model::{OperationState, OutboxState, SetupPhase};
use hfdrive_core::ids::{AccountKey, ConnectionId, OperationId, SetupId};
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("state storage i/o failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("state database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("the state database worker has stopped")]
    WorkerStopped,

    #[error("{path} exists but is not an HF Drive state database")]
    NotAnHfDriveDatabase { path: PathBuf },

    #[error("state database schema {found} is newer than the supported schema {supported}; refusing to open")]
    SchemaTooNew { found: u32, supported: u32 },

    #[error("state database schema {found} cannot reach the supported schema {supported}")]
    SchemaUnsupported { found: u32, supported: u32 },

    #[error("state database is corrupt or unreadable: {detail}")]
    Corrupt { detail: String },

    #[error("operation {operation_id} was already recorded with a different request")]
    OperationConflict { operation_id: OperationId },

    #[error("operation {operation_id} is {state:?}; its uncertain external effect must be reconciled, not replayed")]
    OperationNotReplayable {
        operation_id: OperationId,
        state: OperationState,
    },

    #[error("operation {operation_id} is {state:?} and cannot change further")]
    OperationNotMutable {
        operation_id: OperationId,
        state: OperationState,
    },

    #[error("no {entity} record for {id}")]
    NotFound {
        entity: &'static str,
        id: String,
    },

    #[error("illegal outbox transition {from:?} -> {to:?}")]
    IllegalOutboxTransition { from: OutboxState, to: OutboxState },

    #[error("illegal setup transition {from:?} -> {to:?}")]
    IllegalSetupTransition { from: SetupPhase, to: SetupPhase },

    #[error("invalid state for {entity} {id}: {detail}")]
    InvalidState {
        entity: &'static str,
        id: String,
        detail: String,
    },

    #[error("settings revision mismatch: expected {expected}, found {actual}")]
    RevisionMismatch { expected: u64, actual: u64 },

    #[error("evidence is stale: recorded under generation {found}, current generation is {expected}")]
    StaleEvidence { expected: u64, found: u64 },

    #[error("value {value} does not fit the signed 64-bit SQLite column")]
    IntegerOutOfRange { value: u64 },

    #[error("{entity} column holds {found} bytes where {expected} are required")]
    InvalidBlob {
        entity: &'static str,
        expected: usize,
        found: usize,
    },

    #[error("{entity} column holds an invalid identifier")]
    InvalidId { entity: &'static str },

    #[error("the account {0} is not recorded")]
    UnknownAccount(AccountKey),

    #[error("the connection {0} is not registered")]
    UnknownConnection(ConnectionId),

    #[error("the setup {0} is not reserved")]
    UnknownSetup(SetupId),

    #[error("path is not valid UTF-8 and cannot be persisted in state: {0}")]
    NonUtf8Path(PathBuf),
}

impl StateError {
    pub(crate) fn not_found(entity: &'static str, id: impl std::fmt::Display) -> Self {
        Self::NotFound { entity, id: id.to_string() }
    }

    pub(crate) fn invalid_state(
        entity: &'static str,
        id: impl std::fmt::Display,
        detail: impl Into<String>,
    ) -> Self {
        Self::InvalidState {
            entity,
            id: id.to_string(),
            detail: detail.into(),
        }
    }
}
