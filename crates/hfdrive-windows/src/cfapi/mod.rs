//! Safe CFAPI synchronization-provider layer: registration, connection
//! lifecycle, callback events, transfer completion and guarded placeholder
//! operations.
//!
//! The unsafe ABI glue lives in [`crate::ffi::cfapi`] and
//! [`crate::ffi::syncroot`]; this module composes it into the concrete safe
//! APIs a real provider needs. It deliberately provides **no fake provider**:
//! remote bytes, durable journaling and scheduling belong to the composing
//! crates (`hfdrive-provider`/`hfdrive-state`/`hfdrive-hf`).
//!
//! Frozen product identities (stable across builds and releases):
//!
//! * Provider GUID: `f727443d-0db5-4746-a08f-16afb2d2f289`.
//! * Sync root ID: `HFDrive!<windows-user-sid>!<connection-uuid>`, at most
//!   174 characters (overlong IDs are rejected, never truncated).
//! * Registration: `StorageProviderSyncRootManager.Register` only — never
//!   `CfRegisterSyncRoot` — with hydration `PARTIAL` (no streaming,
//!   auto-dehydration or validation-required modifiers), population `FULL`,
//!   hard links `NONE`, and `CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH` on
//!   connect.

pub mod callbacks;
pub mod events;
pub mod identity;
pub mod ops;
pub mod registration;
pub mod transfers;

mod connection;

pub use connection::{CfConnection, ConnectConfig};
pub use events::{
    AckToken, CancelRanges, CancelTarget, CompletionEvent, DeleteCompletion, DeleteNotification,
    FetchFailure, FetchRequest, PlaceholdersRequest, ProviderEvent, RenameCompletion,
    RenameNotification, TransferStatus,
};
pub use identity::{IdentityError, PlaceholderIdentity, IDENTITY_LEN};
pub use ops::{
    convert_published, create_placeholders, dehydrate, hydrate_range, revert_to_normal,
    set_in_sync, set_pin_state, update_placeholder, FreeSpaceEvidence, GuardMismatch, GuardOutcome,
    MetadataSpec, PinOutcome, PinRequest, PlaceholderCreate, PlaceholderOutcome,
    PlaceholderRequestOutcome, UpdateSpec,
};
pub use registration::{
    register_sync_root, registered_sync_roots, sync_root_id, unregister_sync_root,
    HardlinkPolicy, HydrationModifiers, HydrationPolicy, PopulationPolicy, RegisteredRoot,
    RegistrationInfo, RegistrationOutcome, SyncPolicy, HFDRIVE_PROVIDER_GUID,
    SYNC_POLICY, SYNC_ROOT_ID_MAX_LEN,
};
pub use transfers::{
    plan_chunks, validate_chunk, TransferChunk, TransferCompletion, MAX_OPTIONAL_READAHEAD,
    MAX_TRANSFER_BUFFER, TRANSFER_ALIGNMENT,
};

pub use callbacks::{ProviderStreams, QueueCapacity};

/// Structured, non-secret CFAPI/registration error.
#[derive(Debug, thiserror::Error)]
pub enum CfError {
    /// A Windows/CFAPI call failed during `operation`; `code` is the Win32 or
    /// HRESULT code.
    #[error("windows api failure during {operation} (code={code})")]
    Win32 { operation: &'static str, code: u32 },
    /// The sync root ID would exceed the 174-character registration limit.
    /// IDs are never truncated or asserted away.
    #[error("sync root id exceeds {max} characters")]
    SyncRootIdTooLong { max: usize },
    /// A placeholder identity record failed validation.
    #[error("invalid placeholder identity: {0}")]
    Identity(#[from] IdentityError),
    /// The operation needs a connected sync root.
    #[error("no active sync root connection")]
    NotConnected,
    /// The connection is shutting down; the request failed truthfully
    /// instead of being silently dropped.
    #[error("connection is shutting down")]
    ShuttingDown,
    /// Transfer buffer/alignment contract violation (<= 1 MiB, 4096-aligned
    /// unless EOF).
    #[error("transfer chunk violates the size/alignment contract")]
    InvalidChunk,
    /// A guarded operation refused because its preconditions are not all
    /// true. Content is preserved; nothing was fabricated.
    #[error("guard preconditions not satisfied: {0}")]
    Precondition(&'static str),
    /// A placeholder identity embedded in a placeholder does not match the
    /// expected item/workspace.
    #[error("placeholder identity mismatch")]
    IdentityMismatch,
}

pub type CfResult<T> = Result<T, CfError>;
