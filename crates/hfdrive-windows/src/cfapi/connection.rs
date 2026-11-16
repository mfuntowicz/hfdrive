//! The provider's CFAPI connection: lifecycle, request completion and
//! shutdown.
//!
//! The connection owns the callback context and the bounded queues. Its
//! `shutdown` implements the required lifetime order: stop scheduling, mark
//! cancellation, `CfDisconnectSyncRoot` **while the context is still valid**,
//! join in-flight callbacks, then free the context. OS callback transfer keys
//! are never released by the provider.

use std::path::Path;
use std::sync::Arc;

use hfdrive_core::ids::WorkspaceId;
use hfdrive_core::storage::ByteRange;

use crate::ffi::cfapi::EventSink;

use super::callbacks::{CallbackHub, ProviderStreams};
use super::events::{
    AckToken, CancelRanges, DeleteCompletion, DeleteNotification, FetchFailure, FetchRequest,
    PlaceholdersRequest, RenameCompletion, RenameNotification, TransferStatus,
};
use super::transfers::{validate_chunk, TransferCompletion};
use super::{CfError, CfResult};

/// Connection configuration.
#[derive(Clone, Copy, Debug)]
pub struct ConnectConfig {
    /// The connection's workspace identity; placeholder identities from
    /// other workspaces are rejected at decode time.
    pub workspace: WorkspaceId,
    /// Bounded capacities for the per-kind callback queues.
    pub queues: QueueCapacity,
}

/// Delegating sink so the context can hold a `Box<dyn EventSink>` while the
/// connection keeps its own `Arc<CallbackHub>`.
struct SinkHandle(Arc<CallbackHub>);

impl EventSink for SinkHandle {
    fn on_fetch_data(&self, request: FetchRequest) {
        self.0.on_fetch_data(request)
    }
    fn on_cancel_fetch_data(&self, cancel: CancelRanges) {
        self.0.on_cancel_fetch_data(cancel)
    }
    fn on_fetch_placeholders(&self, request: PlaceholdersRequest) {
        self.0.on_fetch_placeholders(request)
    }
    fn on_cancel_fetch_placeholders(&self, cancel: CancelRanges) {
        self.0.on_cancel_fetch_placeholders(cancel)
    }
    fn on_rename(&self, notification: RenameNotification) {
        self.0.on_rename(notification)
    }
    fn on_delete(&self, notification: DeleteNotification) {
        self.0.on_delete(notification)
    }
    fn on_rename_completion(&self, completion: RenameCompletion) {
        self.0.on_rename_completion(completion)
    }
    fn on_delete_completion(&self, completion: DeleteCompletion) {
        self.0.on_delete_completion(completion)
    }
}

/// One connected sync root.
pub struct CfConnection {
    key: i64,
    connected: Option<crate::ffi::cfapi::Connected>,
    hub: Arc<CallbackHub>,
}

impl CfConnection {
    /// Connect the callback pipeline to the sync root at `root`.
    ///
    /// The root must already be registered
    /// ([`super::registration::register_sync_root`]); this call performs
    /// `CfConnectSyncRoot` with `CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH`.
    /// Returns the connection and the typed callback streams.
    pub fn connect(
        root: &Path,
        config: ConnectConfig,
    ) -> CfResult<(Self, ProviderStreams)> {
        let (hub, streams) = CallbackHub::new(config.queues);
        let sink: Box<dyn EventSink> = Box::new(SinkHandle(hub.clone()));
        let connected = crate::ffi::cfapi::connect(root, config.workspace, sink).map_err(
            |code| CfError::Win32 {
                operation: "CfConnectSyncRoot",
                code,
            },
        )?;
        let key = connected.key;
        Ok((
            CfConnection {
                key,
                connected: Some(connected),
                hub,
            },
            streams,
        ))
    }

    pub fn connection_key(&self) -> i64 {
        self.key
    }

    /// Complete one planned chunk of a `FETCH_DATA` request. `bytes` must
    /// exactly match the chunk (`len` bytes) and stay alive until this call
    /// returns; the 1 MiB / 4096-alignment / EOF contract is re-validated
    /// here before `CfExecute(TRANSFER_DATA)`.
    pub fn complete_transfer(
        &self,
        completion: TransferCompletion,
        bytes: &[u8],
    ) -> CfResult<()> {
        validate_chunk(&completion.chunk, completion.file_size)?;
        if bytes.len() as u64 != completion.chunk.len {
            return Err(CfError::InvalidChunk);
        }
        let offset = i64::try_from(completion.chunk.offset).map_err(|_| CfError::InvalidChunk)?;
        crate::ffi::cfapi::transfer_data(
            completion.ack,
            TransferStatus::Success,
            offset,
            bytes,
        )
        .map_err(|code| CfError::Win32 {
            operation: "CfExecute(TRANSFER_DATA)",
            code,
        })
    }

    /// Fail one request with a truthful terminal status (auth/offline/
    /// missing/cancel/...). Cleans the request's range interests.
    pub fn fail_fetch(&self, ack: AckToken, required: ByteRange, failure: FetchFailure) -> CfResult<()> {
        let offset = i64::try_from(required.start()).map_err(|_| CfError::InvalidChunk)?;
        let length = i64::try_from(required.end_exclusive().saturating_sub(required.start()))
            .map_err(|_| CfError::InvalidChunk)?;
        let result = crate::ffi::cfapi::fail_transfer(ack, failure, offset, length);
        self.hub.finish_request(ack.request_key);
        result.map_err(|code| CfError::Win32 {
            operation: "CfExecute(TRANSFER_DATA)",
            code,
        })
    }

    /// Report genuine transfer progress to the OS (before the CFAPI
    /// deadline). Progress must reflect actually transferred bytes.
    pub fn report_progress(
        &self,
        transfer_key: i64,
        total: u64,
        completed: u64,
    ) -> CfResult<()> {
        let total = i64::try_from(total).map_err(|_| CfError::InvalidChunk)?;
        let completed = i64::try_from(completed).map_err(|_| CfError::InvalidChunk)?;
        crate::ffi::cfapi::report_progress(self.key, transfer_key, total, completed).map_err(
            |code| CfError::Win32 {
                operation: "CfReportProviderProgress",
                code,
            },
        )
    }

    /// Deliver the directory listing in bounded calls, then finish the request.
    ///
    /// Set `complete_directory` only for an authoritative whole-directory
    /// listing. The terminal call disables on-demand population only when all
    /// entries were processed and left present; subsets and failures stay
    /// unpopulated. Occupied names are preserved, never overwritten.
    /// Returns every per-entry result, including unprocessed failures.
    pub fn complete_placeholders(
        &self,
        ack: AckToken,
        entries: &[super::ops::PlaceholderCreate],
        complete_directory: bool,
    ) -> CfResult<Vec<super::ops::PlaceholderOutcome>> {
        let pending = super::ops::to_pending(entries)?;
        let total = i64::try_from(entries.len()).unwrap_or(i64::MAX);
        let mut results = Vec::with_capacity(entries.len());
        for range in crate::ffi::cfapi::population_calls(entries.len()) {
            let mark_populated = range.is_empty()
                && crate::ffi::cfapi::directory_populated_mark(complete_directory, &results);
            let batch = crate::ffi::cfapi::transfer_placeholders(
                ack,
                TransferStatus::Success,
                total,
                &pending[range],
                mark_populated,
            );
            let batch = batch.map_err(|code| CfError::Win32 {
                operation: "CfExecute(TRANSFER_PLACEHOLDERS)",
                code,
            })?;
            results.extend(batch);
        }
        Ok(super::ops::from_entry_results(entries, results))
    }

    /// Fail one `FETCH_PLACEHOLDERS` request truthfully. A failed request is
    /// never marked fully populated.
    pub fn fail_placeholders(
        &self,
        ack: AckToken,
        failure: FetchFailure,
    ) -> CfResult<()> {
        crate::ffi::cfapi::transfer_placeholders(
            ack,
            TransferStatus::Failed(failure),
            0,
            &[],
            false,
        )
        .map(|_| ())
        .map_err(|code| CfError::Win32 {
            operation: "CfExecute(TRANSFER_PLACEHOLDERS)",
            code,
        })
    }

    /// Acknowledge a rename notification after the observation is durably
    /// queued/persisted by the provider.
    pub fn ack_rename(&self, ack: AckToken, status: TransferStatus) -> CfResult<()> {
        crate::ffi::cfapi::ack_rename(ack, status).map_err(|code| CfError::Win32 {
            operation: "CfExecute(ACK_RENAME)",
            code,
        })
    }

    /// Acknowledge a delete notification after the observation is durably
    /// queued/persisted by the provider.
    pub fn ack_delete(&self, ack: AckToken, status: TransferStatus) -> CfResult<()> {
        crate::ffi::cfapi::ack_delete(ack, status).map_err(|code| CfError::Win32 {
            operation: "CfExecute(ACK_DELETE)",
            code,
        })
    }

    /// Cancel the range interests of one request that overlap `ranges`
    /// (`None` = all of that request). Interests of other requests — e.g.
    /// shared overlapping ranges — stay alive. Returns how many interests
    /// were cancelled.
    pub fn cancel_matching(&self, request_key: i64, ranges: Option<&[ByteRange]>) -> usize {
        self.hub.cancel_matching(request_key, ranges)
    }

    /// Drop a request's interest bookkeeping once its required range is
    /// fully covered (or it failed).
    pub fn finish_fetch(&self, request_key: i64) {
        self.hub.finish_request(request_key);
    }

    /// Completion notifications dropped because a queue was full; a nonzero
    /// count means observations were lost and a rescan is required.
    pub fn dropped_completions(&self) -> u64 {
        self.hub.dropped_completions()
    }

    /// Disconnects with the callback context still registered and joins
    /// callbacks that already acquired it. On failure the registry retains
    /// the context so process-lifetime safety does not depend on a successful
    /// best-effort teardown.
    pub fn shutdown(mut self) -> CfResult<()> {
        let connected = self.connected.as_ref().ok_or(CfError::NotConnected)?;
        crate::ffi::cfapi::disconnect(connected).map_err(|code| CfError::Win32 {
            operation: "CfDisconnectSyncRoot",
            code,
        })?;
        self.connected.take();
        Ok(())
    }
}

impl Drop for CfConnection {
    fn drop(&mut self) {
        if let Some(connected) = self.connected.take() {
            // Best-effort disconnect when the owner forgot `shutdown`.
            let _ = crate::ffi::cfapi::disconnect(&connected);
        }
    }
}

/// Re-exported for callers that configure the connection.
pub use super::callbacks::QueueCapacity;
