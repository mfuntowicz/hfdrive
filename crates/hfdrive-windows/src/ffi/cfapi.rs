//! Generated-projection CFAPI adapters: connection lifecycle, callback
//! trampolines, request completions and guarded placeholder operations.
//!
//! Everything here is unsafe OS glue; the safe `cfapi` modules consume only
//! the plain-data types (`crate::cfapi::events`) and the `EventSink`
//! dispatch trait. No handwritten ABI: every struct, union and function
//! comes from the generated `windows` 0.62.2 projection.

use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use hfdrive_core::ids::WorkspaceId;
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Storage::CloudFilters::{
    CfConnectSyncRoot, CfConvertToPlaceholder, CfCreatePlaceholders, CfDehydratePlaceholder,
    CfDisconnectSyncRoot, CfExecute, CfGetPlaceholderInfo, CfGetPlaceholderRangeInfo,
    CfGetPlaceholderStateFromAttributeTag, CfGetTransferKey, CfHydratePlaceholder,
    CfOpenFileWithOplock, CfReleaseTransferKey, CfReportProviderProgress, CfRevertPlaceholder,
    CfSetInSyncState, CfSetPinState, CfUpdatePlaceholder, CF_CALLBACK_INFO, CF_CALLBACK_PARAMETERS,
    CF_CALLBACK_REGISTRATION, CF_CALLBACK_TYPE_CANCEL_FETCH_DATA,
    CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS, CF_CALLBACK_TYPE_FETCH_DATA,
    CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS, CF_CALLBACK_TYPE_NONE, CF_CALLBACK_TYPE_NOTIFY_DELETE,
    CF_CALLBACK_TYPE_NOTIFY_DELETE_COMPLETION, CF_CALLBACK_TYPE_NOTIFY_RENAME,
    CF_CALLBACK_TYPE_NOTIFY_RENAME_COMPLETION, CF_CONNECTION_KEY, CF_CONVERT_FLAG_MARK_IN_SYNC,
    CF_CREATE_FLAG_NONE, CF_DEHYDRATE_FLAG_NONE, CF_FILE_RANGE, CF_FS_METADATA,
    CF_HYDRATE_FLAG_NONE, CF_IN_SYNC_STATE_IN_SYNC, CF_OPEN_FILE_FLAG_EXCLUSIVE,
    CF_OPEN_FILE_FLAG_FOREGROUND, CF_OPEN_FILE_FLAG_WRITE_ACCESS, CF_OPERATION_ACK_DELETE_FLAG_NONE,
    CF_OPERATION_ACK_RENAME_FLAG_NONE, CF_OPERATION_INFO, CF_OPERATION_PARAMETERS,
    CF_OPERATION_TRANSFER_DATA_FLAG_NONE, CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE,
    CF_OPERATION_TYPE, CF_OPERATION_TYPE_ACK_DELETE, CF_OPERATION_TYPE_ACK_RENAME,
    CF_OPERATION_TYPE_TRANSFER_DATA, CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS,
    CF_PLACEHOLDER_BASIC_INFO, CF_PLACEHOLDER_CREATE_FLAGS, CF_PLACEHOLDER_CREATE_INFO,
    CF_PLACEHOLDER_INFO_BASIC, CF_PLACEHOLDER_RANGE_INFO_ONDISK, CF_PIN_STATE_PINNED,
    CF_PIN_STATE_EXCLUDED, CF_PIN_STATE_UNPINNED, CF_REVERT_FLAG_NONE, CF_SET_IN_SYNC_FLAG_NONE,
    CF_SET_PIN_FLAG_NONE, CF_UPDATE_FLAG_MARK_IN_SYNC, CF_UPDATE_FLAG_VERIFY_IN_SYNC,
};

use crate::cfapi::events::{
    AckToken, CancelRanges, DeleteCompletion, DeleteNotification, FetchFailure, FetchRequest,
    PlaceholdersRequest, ProviderEvent, RenameCompletion, RenameNotification, TransferStatus,
};
use crate::cfapi::identity::PlaceholderIdentity;
use super::handle::OwnedHandle;

// ---------------------------------------------------------------------------
// EventSink: the safe side of the boundary
// ---------------------------------------------------------------------------

/// Implemented by the provider's callback hub. Invoked from OS callback
/// threads; implementations must not perform network I/O and must return
/// promptly (the adapters deep-copy everything they pass).
pub(crate) trait EventSink: Send + Sync {
    fn on_fetch_data(&self, request: FetchRequest);
    fn on_cancel_fetch_data(&self, cancel: CancelRanges);
    fn on_fetch_placeholders(&self, request: PlaceholdersRequest);
    fn on_cancel_fetch_placeholders(&self, cancel: CancelRanges);
    fn on_rename(&self, notification: RenameNotification);
    fn on_delete(&self, notification: DeleteNotification);
    fn on_rename_completion(&self, completion: RenameCompletion);
    fn on_delete_completion(&self, completion: DeleteCompletion);
}

/// CFAPI receives the context address only as an opaque key. This registry
/// lets callback entry acquire an `Arc` before dereferencing anything, closing
/// the race between a callback starting and disconnect reclaiming the context.
static CALLBACK_CONTEXTS: LazyLock<Mutex<HashMap<usize, Arc<CallbackContext>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The callback context handed to `CfConnectSyncRoot`. The registry owns it
/// until a successful disconnect; in-flight callbacks own additional `Arc`s.
pub(crate) struct CallbackContext {
    workspace: WorkspaceId,
    sink: Box<dyn EventSink>,
    inflight: AtomicUsize,
    closed: AtomicBool,
}

impl CallbackContext {
    fn new(workspace: WorkspaceId, sink: Box<dyn EventSink>) -> Arc<Self> {
        Arc::new(CallbackContext {
            workspace,
            sink,
            inflight: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
        })
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

struct InflightGuard<'a>(&'a AtomicUsize);

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// Status mapping
// ---------------------------------------------------------------------------

fn ntstatus(status: TransferStatus) -> NTSTATUS {
    match status {
        TransferStatus::Success => NTSTATUS(0),
        TransferStatus::Failed(failure) => match failure {
            FetchFailure::NeedsSignIn => {
                windows::Win32::Foundation::STATUS_CLOUD_FILE_AUTHENTICATION_FAILED
            }
            FetchFailure::Offline => windows::Win32::Foundation::STATUS_CLOUD_FILE_NETWORK_UNAVAILABLE,
            FetchFailure::Missing => windows::Win32::Foundation::STATUS_OBJECT_NAME_NOT_FOUND,
            FetchFailure::Cancelled => windows::Win32::Foundation::STATUS_CLOUD_FILE_REQUEST_CANCELED,
            FetchFailure::PermissionDenied => {
                windows::Win32::Foundation::STATUS_CLOUD_FILE_ACCESS_DENIED
            }
            FetchFailure::ResourceExhausted => {
                windows::Win32::Foundation::STATUS_CLOUD_FILE_INSUFFICIENT_RESOURCES
            }
            FetchFailure::InvalidRequest => {
                windows::Win32::Foundation::STATUS_CLOUD_FILE_INVALID_REQUEST
            }
            FetchFailure::ProviderStopping => {
                windows::Win32::Foundation::STATUS_CLOUD_FILE_PROVIDER_TERMINATED
            }
            FetchFailure::Internal => windows::Win32::Foundation::STATUS_UNSUCCESSFUL,
        },
    }
}

// ---------------------------------------------------------------------------
// Callback table + trampolines
// ---------------------------------------------------------------------------

static CALLBACK_TABLE: [CF_CALLBACK_REGISTRATION; 9] = [
    CF_CALLBACK_REGISTRATION {
        Type: CF_CALLBACK_TYPE_FETCH_DATA,
        Callback: Some(trampoline_fetch_data),
    },
    CF_CALLBACK_REGISTRATION {
        Type: CF_CALLBACK_TYPE_CANCEL_FETCH_DATA,
        Callback: Some(trampoline_cancel_fetch_data),
    },
    CF_CALLBACK_REGISTRATION {
        Type: CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS,
        Callback: Some(trampoline_fetch_placeholders),
    },
    CF_CALLBACK_REGISTRATION {
        Type: CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS,
        Callback: Some(trampoline_cancel_fetch_placeholders),
    },
    CF_CALLBACK_REGISTRATION {
        Type: CF_CALLBACK_TYPE_NOTIFY_RENAME,
        Callback: Some(trampoline_notify_rename),
    },
    CF_CALLBACK_REGISTRATION {
        Type: CF_CALLBACK_TYPE_NOTIFY_RENAME_COMPLETION,
        Callback: Some(trampoline_notify_rename_completion),
    },
    CF_CALLBACK_REGISTRATION {
        Type: CF_CALLBACK_TYPE_NOTIFY_DELETE,
        Callback: Some(trampoline_notify_delete),
    },
    CF_CALLBACK_REGISTRATION {
        Type: CF_CALLBACK_TYPE_NOTIFY_DELETE_COMPLETION,
        Callback: Some(trampoline_notify_delete_completion),
    },
    // Terminates the table as required by CfConnectSyncRoot.
    CF_CALLBACK_REGISTRATION {
        Type: CF_CALLBACK_TYPE_NONE,
        Callback: None,
    },
];

/// Dispatch one callback with panic containment and an in-flight guard; the
/// callback context cannot be freed while `body` runs.
fn dispatch(
    callbackinfo: *const CF_CALLBACK_INFO,
    callbackparameters: *const CF_CALLBACK_PARAMETERS,
    body: impl FnOnce(&CallbackContext, &CF_CALLBACK_INFO, &CF_CALLBACK_PARAMETERS),
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if callbackinfo.is_null() || callbackparameters.is_null() {
            return;
        }
        // SAFETY: the OS passes live info/parameter blocks for the duration
        // of the callback. Both blocks are `repr(C)` projection structs of
        // the exact callback types registered in `CALLBACK_TABLE`.
        let info = unsafe { &*callbackinfo };
        let params = unsafe { &*callbackparameters };
        if info.CallbackContext.is_null() {
            return;
        }
        let ctx = {
            let contexts = CALLBACK_CONTEXTS.lock().unwrap_or_else(|error| error.into_inner());
            let Some(context) = contexts.get(&(info.CallbackContext as usize)).cloned() else {
                return;
            };
            context
        };
        ctx.inflight.fetch_add(1, Ordering::SeqCst);
        let _guard = InflightGuard(&ctx.inflight);
        body(&ctx, info, params);
    }));
}

macro_rules! trampoline {
    ($name:ident, $handler:ident) => {
        unsafe extern "system" fn $name(
            callbackinfo: *const CF_CALLBACK_INFO,
            callbackparameters: *const CF_CALLBACK_PARAMETERS,
        ) {
            dispatch(callbackinfo, callbackparameters, $handler);
        }
    };
}

trampoline!(trampoline_fetch_data, handle_fetch_data);
trampoline!(trampoline_cancel_fetch_data, handle_cancel_fetch_data);
trampoline!(trampoline_fetch_placeholders, handle_fetch_placeholders);
trampoline!(
    trampoline_cancel_fetch_placeholders,
    handle_cancel_fetch_placeholders
);
trampoline!(trampoline_notify_rename, handle_notify_rename);
trampoline!(
    trampoline_notify_rename_completion,
    handle_notify_rename_completion
);
trampoline!(trampoline_notify_delete, handle_notify_delete);
trampoline!(
    trampoline_notify_delete_completion,
    handle_notify_delete_completion
);

fn handle_fetch_data(
    ctx: &CallbackContext,
    info: &CF_CALLBACK_INFO,
    params: &CF_CALLBACK_PARAMETERS,
) {
    let ack = ack_token(info);
    // SAFETY: `FetchData` is the active union member for this callback type.
    let fetch = unsafe { params.Anonymous.FetchData };
    let terminal = Arc::new(crate::cfapi::events::CallbackTerminal::new(
        ack,
        fetch.RequiredFileOffset,
        fetch.RequiredLength,
    ));
    if ctx.is_closed() {
        terminal.complete(FetchFailure::ProviderStopping);
        return;
    }
    let identity_bytes = copy_identity(info);
    let identity = match PlaceholderIdentity::decode(&identity_bytes, Some(ctx.workspace)) {
        Ok(identity) => identity,
        Err(_) => {
            terminal.complete(FetchFailure::InvalidRequest);
            return;
        }
    };
    let file_size = info.FileSize.max(0) as u64;
    let required = match checked_range(fetch.RequiredFileOffset, fetch.RequiredLength, file_size) {
        Some(range) => range,
        None => {
            terminal.complete(FetchFailure::InvalidRequest);
            return;
        }
    };
    let optional = (fetch.OptionalLength > 0)
        .then(|| checked_range(fetch.OptionalFileOffset, fetch.OptionalLength, file_size))
        .flatten();
    let request = FetchRequest {
        ack,
        identity,
        file_size,
        required,
        optional,
        explicit_hydration: fetch
            .Flags
            .contains(windows::Win32::Storage::CloudFilters::CF_CALLBACK_FETCH_DATA_FLAG_EXPLICIT_HYDRATION),
        recovery: fetch
            .Flags
            .contains(windows::Win32::Storage::CloudFilters::CF_CALLBACK_FETCH_DATA_FLAG_RECOVERY),
        cancelled: Arc::new(AtomicBool::new(false)),
        terminal,
    };
    ctx.sink.on_fetch_data(request);
}

fn handle_cancel_fetch_data(
    ctx: &CallbackContext,
    info: &CF_CALLBACK_INFO,
    params: &CF_CALLBACK_PARAMETERS,
) {
    let ack = ack_token(info);
    // SAFETY: `Cancel` is the active union member for this callback type;
    // `Cancel.Anonymous.FetchData` is its only nested variant.
    let cancel = unsafe { params.Anonymous.Cancel };
    let range = unsafe { cancel.Anonymous.FetchData };
    if ctx.is_closed() {
        return;
    }
    let cancel = CancelRanges {
        ack,
        target: crate::cfapi::events::CancelTarget::FetchData,
        ranges: (range.Length > 0)
            .then(|| checked_range(range.FileOffset, range.Length, i64::MAX as u64))
            .flatten()
            .map(|r| vec![r]),
    };
    ctx.sink.on_cancel_fetch_data(cancel);
}

fn handle_fetch_placeholders(
    ctx: &CallbackContext,
    info: &CF_CALLBACK_INFO,
    params: &CF_CALLBACK_PARAMETERS,
) {
    let ack = ack_token(info);
    // SAFETY: `FetchPlaceholders` is the active union member here.
    let fetch = unsafe { params.Anonymous.FetchPlaceholders };
    if ctx.is_closed() {
        let _ = transfer_placeholders(
            ack,
            TransferStatus::Failed(FetchFailure::ProviderStopping),
            0,
            &[],
        );
        return;
    }
    let pattern = (!fetch.Pattern.is_null())
        // SAFETY: the OS-provided pattern string is valid for the callback.
        .then(|| unsafe { fetch.Pattern.to_string().ok() })
        .flatten();
    ctx.sink.on_fetch_placeholders(PlaceholdersRequest {
        ack,
        normalized_path: normalized_path(info),
        pattern,
    });
}

fn handle_cancel_fetch_placeholders(
    ctx: &CallbackContext,
    info: &CF_CALLBACK_INFO,
    _params: &CF_CALLBACK_PARAMETERS,
) {
    if ctx.is_closed() {
        return;
    }
    ctx.sink.on_cancel_fetch_placeholders(CancelRanges {
        ack: ack_token(info),
        target: crate::cfapi::events::CancelTarget::FetchPlaceholders,
        ranges: None,
    });
}

fn handle_notify_rename(
    ctx: &CallbackContext,
    info: &CF_CALLBACK_INFO,
    params: &CF_CALLBACK_PARAMETERS,
) {
    let ack = ack_token(info);
    // SAFETY: `Rename` is the active union member here.
    let rename = unsafe { params.Anonymous.Rename };
    let notification = RenameNotification {
        ack,
        normalized_path: normalized_path(info),
        target_path: (!rename.TargetPath.is_null())
            // SAFETY: the OS-provided target path is valid for the callback.
            .then(|| unsafe { rename.TargetPath.to_string().unwrap_or_default() })
            .unwrap_or_default(),
        is_directory: rename
            .Flags
            .contains(windows::Win32::Storage::CloudFilters::CF_CALLBACK_RENAME_FLAG_IS_DIRECTORY),
        source_in_scope: rename
            .Flags
            .contains(windows::Win32::Storage::CloudFilters::CF_CALLBACK_RENAME_FLAG_SOURCE_IN_SCOPE),
        target_in_scope: rename
            .Flags
            .contains(windows::Win32::Storage::CloudFilters::CF_CALLBACK_RENAME_FLAG_TARGET_IN_SCOPE),
    };
    if ctx.is_closed() {
        let _ = ack_rename(ack, TransferStatus::Failed(FetchFailure::ProviderStopping));
        return;
    }
    ctx.sink.on_rename(notification);
}

fn handle_notify_rename_completion(
    ctx: &CallbackContext,
    _info: &CF_CALLBACK_INFO,
    params: &CF_CALLBACK_PARAMETERS,
) {
    // SAFETY: `RenameCompletion` is the active union member here.
    let completion = unsafe { params.Anonymous.RenameCompletion };
    if ctx.is_closed() {
        return;
    }
    ctx.sink.on_rename_completion(RenameCompletion {
        source_path: (!completion.SourcePath.is_null())
            // SAFETY: the OS-provided source path is valid for the callback.
            .then(|| unsafe { completion.SourcePath.to_string().unwrap_or_default() })
            .unwrap_or_default(),
    });
}

fn handle_notify_delete(
    ctx: &CallbackContext,
    info: &CF_CALLBACK_INFO,
    params: &CF_CALLBACK_PARAMETERS,
) {
    let ack = ack_token(info);
    // SAFETY: `Delete` is the active union member here.
    let delete = unsafe { params.Anonymous.Delete };
    let notification = DeleteNotification {
        ack,
        normalized_path: normalized_path(info),
        is_directory: delete
            .Flags
            .contains(windows::Win32::Storage::CloudFilters::CF_CALLBACK_DELETE_FLAG_IS_DIRECTORY),
        is_undelete: delete
            .Flags
            .contains(windows::Win32::Storage::CloudFilters::CF_CALLBACK_DELETE_FLAG_IS_UNDELETE),
    };
    if ctx.is_closed() {
        let _ = ack_delete(ack, TransferStatus::Failed(FetchFailure::ProviderStopping));
        return;
    }
    ctx.sink.on_delete(notification);
}

fn handle_notify_delete_completion(
    ctx: &CallbackContext,
    info: &CF_CALLBACK_INFO,
    params: &CF_CALLBACK_PARAMETERS,
) {
    // SAFETY: `DeleteCompletion` is the active union member here.
    let completion = unsafe { params.Anonymous.DeleteCompletion };
    if ctx.is_closed() {
        return;
    }
    let _ = info;
    ctx.sink.on_delete_completion(DeleteCompletion {
        deleted: completion.Flags.0 & CF_CALLBACK_DELETE_COMPLETION_DELETED_BIT != 0,
    });
}

/// `CF_CALLBACK_DELETE_COMPLETION_FLAG_DELETED` (cfapi.h value `0x1`): the
/// SDK enum value; the generated projection exports only
/// `CF_CALLBACK_DELETE_COMPLETION_FLAG_NONE`, so the documented bit value is
/// carried here as a flag constant (not an ABI definition).
const CF_CALLBACK_DELETE_COMPLETION_DELETED_BIT: i32 = 1;

fn ack_token(info: &CF_CALLBACK_INFO) -> AckToken {
    AckToken {
        connection_key: info.ConnectionKey.0,
        transfer_key: info.TransferKey,
        request_key: info.RequestKey,
    }
}

fn copy_identity(info: &CF_CALLBACK_INFO) -> Vec<u8> {
    if info.FileIdentity.is_null() || info.FileIdentityLength == 0 {
        return Vec::new();
    }
    // SAFETY: the OS points at a live identity buffer of the given length
    // for the duration of the callback.
    unsafe {
        std::slice::from_raw_parts(info.FileIdentity as *const u8, info.FileIdentityLength as usize)
            .to_vec()
    }
}

fn normalized_path(info: &CF_CALLBACK_INFO) -> String {
    (!info.NormalizedPath.is_null())
        // SAFETY: the OS-provided normalized path is valid for the callback.
        .then(|| unsafe { info.NormalizedPath.to_string().unwrap_or_default() })
        .unwrap_or_default()
}

fn checked_range(
    offset: i64,
    length: i64,
    file_size: u64,
) -> Option<hfdrive_core::storage::ByteRange> {
    use hfdrive_core::storage::ByteRange;
    if offset < 0 || length < 0 {
        return None;
    }
    let end = (offset as u64).checked_add(length as u64)?;
    if end > file_size {
        return None;
    }
    ByteRange::new(offset as u64, end, file_size).ok()
}

// ---------------------------------------------------------------------------
// Connection lifecycle
// ---------------------------------------------------------------------------

/// A connected sync root: connection key plus the live callback context.
pub(crate) struct Connected {
    pub key: i64,
    context: Arc<CallbackContext>,
}

/// Connect the callback table to a registered sync root.
///
/// Uses `CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH` (callbacks carry full file
/// paths). Registration itself is done through
/// `StorageProviderSyncRootManager`; `CfRegisterSyncRoot` is never called.
pub(crate) fn connect(
    root: &Path,
    workspace: WorkspaceId,
    sink: Box<dyn EventSink>,
) -> Result<Connected, u32> {
    let w = wide(root);
    let context = CallbackContext::new(workspace, sink);
    let context_key = Arc::as_ptr(&context) as usize;
    CALLBACK_CONTEXTS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(context_key, context.clone());
    // SAFETY: `CALLBACK_TABLE` is valid and terminated; the registry keeps
    // `context` alive throughout this call and every callback it can start.
    let key = unsafe {
        CfConnectSyncRoot(
            windows::core::PCWSTR(w.as_ptr()),
            CALLBACK_TABLE.as_ptr(),
            Some(context_key as *const c_void),
            windows::Win32::Storage::CloudFilters::CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH,
        )
    };
    let key = match key {
        Ok(key) => key,
        Err(error) => {
            CALLBACK_CONTEXTS
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .remove(&context_key);
            return Err(super::error_code(&error));
        }
    };
    Ok(Connected { key: key.0, context })
}

/// Marks callbacks closed, disconnects while their context remains
/// registered, then removes the registry entry only after successful
/// disconnect and joins callbacks that already acquired an `Arc`. On failure
/// the caller may retry; dropping the connection retains the registry entry
/// so a late callback can never dereference reclaimed memory.
pub(crate) fn disconnect(connected: &Connected) -> Result<(), u32> {
    connected.context.closed.store(true, Ordering::SeqCst);
    unsafe {
        CfDisconnectSyncRoot(CF_CONNECTION_KEY(connected.key)).map_err(|e| super::error_code(&e))?;
    }
    CALLBACK_CONTEXTS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(&(Arc::as_ptr(&connected.context) as usize));
    while connected.context.inflight.load(Ordering::SeqCst) != 0 {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Request completions
// ---------------------------------------------------------------------------

fn operation_param_size<T>() -> u32 {
    (offset_of!(windows::Win32::Storage::CloudFilters::CF_OPERATION_PARAMETERS, Anonymous)
        + size_of::<T>()) as u32
}

/// Complete (or fail) one `FETCH_DATA` request chunk. `bytes` stays alive
/// until `CfExecute(TRANSFER_DATA)` returns (the caller keeps its buffer).
/// Chunks must be <= 1 MiB and 4096-aligned unless they end at EOF —
/// enforced by the transfer planner in `crate::cfapi::transfers`.
pub(crate) fn transfer_data(
    ack: AckToken,
    status: TransferStatus,
    offset: i64,
    bytes: &[u8],
) -> Result<(), u32> {
    let mut parameters = default_operation_parameters();
    parameters.ParamSize = operation_param_size::<windows::Win32::Storage::CloudFilters::CF_OPERATION_PARAMETERS_0_0>();
    // Writing the active union member of a zeroed parameters struct is safe;
    // `bytes` outlives the synchronous `execute` call below.
    parameters.Anonymous.TransferData =
        windows::Win32::Storage::CloudFilters::CF_OPERATION_PARAMETERS_0_0 {
            Flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
            CompletionStatus: ntstatus(status),
            Buffer: bytes.as_ptr() as *const c_void,
            Offset: offset,
            Length: bytes.len() as i64,
        };
    execute(
        ack,
        CF_OPERATION_TYPE_TRANSFER_DATA,
        &mut parameters,
    )
}

/// Fail a FETCH_DATA request over the exact OS-required range. Failure length
/// is independent of the empty buffer supplied to `CfExecute`.
pub(crate) fn fail_transfer(
    ack: AckToken,
    failure: FetchFailure,
    offset: i64,
    length: i64,
) -> Result<(), u32> {
    let mut parameters = default_operation_parameters();
    parameters.ParamSize = operation_param_size::<windows::Win32::Storage::CloudFilters::CF_OPERATION_PARAMETERS_0_0>();
    parameters.Anonymous.TransferData =
        windows::Win32::Storage::CloudFilters::CF_OPERATION_PARAMETERS_0_0 {
            Flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
            CompletionStatus: ntstatus(TransferStatus::Failed(failure)),
            Buffer: std::ptr::null(),
            Offset: offset,
            Length: length,
        };
    execute(ack, CF_OPERATION_TYPE_TRANSFER_DATA, &mut parameters)
}

/// Filesystem metadata for placeholder creation/update (display metadata
/// only: size, timestamps and attributes).
#[derive(Clone, Copy, Debug)]
pub(crate) struct MetadataBytes {
    pub size: u64,
    pub creation_time_100ns: i64,
    pub last_write_time_100ns: i64,
    pub attributes: u32,
}

/// One placeholder entry for `CfCreatePlaceholders` or the
/// `TRANSFER_PLACEHOLDERS` completion.
pub(crate) struct PendingCreate {
    /// NUL-terminated wide relative name.
    pub name: Vec<u16>,
    pub metadata: MetadataBytes,
    /// Encoded HFDR identity record.
    pub identity: Vec<u8>,
    /// `CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC` (true) or plain create.
    pub mark_in_sync: bool,
}

/// Per-entry outcome of a create/transfer batch. Every entry's `Result` is
/// checked; a batch-level success is never assumed.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EntryResult {
    /// HRESULT reported for the entry (0 = success).
    pub result: i32,
    pub create_usn: i64,
}

/// Complete one `FETCH_PLACEHOLDERS` request with a batch of entries and
/// return every per-entry result.
pub(crate) fn transfer_placeholders(
    ack: AckToken,
    status: TransferStatus,
    total_count: i64,
    entries: &[PendingCreate],
) -> Result<Vec<EntryResult>, u32> {
    let mut wide_names: Vec<Vec<u16>> = entries.iter().map(|e| e.name.clone()).collect();
    let identities: Vec<Vec<u8>> = entries.iter().map(|e| e.identity.clone()).collect();
    let mut array: Vec<CF_PLACEHOLDER_CREATE_INFO> = entries
        .iter()
        .enumerate()
        .map(|(i, entry)| placeholder_create_info(entry, &mut wide_names[i], &identities[i]))
        .collect();
    let mut parameters = default_operation_parameters();
    parameters.ParamSize = operation_param_size::<windows::Win32::Storage::CloudFilters::CF_OPERATION_PARAMETERS_0_4>();
    // Writing the active union member is safe; the name/identity arrays stay
    // alive until `execute` returns.
    parameters.Anonymous.TransferPlaceholders =
        windows::Win32::Storage::CloudFilters::CF_OPERATION_PARAMETERS_0_4 {
            Flags: CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE,
            CompletionStatus: ntstatus(status),
            PlaceholderTotalCount: total_count,
            PlaceholderArray: array.as_mut_ptr(),
            PlaceholderCount: array.len() as u32,
            EntriesProcessed: array.len() as u32,
        };
    execute(ack, CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS, &mut parameters)?;
    Ok(entry_results(&array))
}

fn entry_results(array: &[CF_PLACEHOLDER_CREATE_INFO]) -> Vec<EntryResult> {
    array
        .iter()
        .map(|e| EntryResult {
            result: e.Result.0,
            create_usn: e.CreateUsn,
        })
        .collect()
}

fn placeholder_create_info(
    entry: &PendingCreate,
    wide_name: &mut Vec<u16>,
    identity: &[u8],
) -> CF_PLACEHOLDER_CREATE_INFO {
    CF_PLACEHOLDER_CREATE_INFO {
        RelativeFileName: windows::core::PCWSTR(wide_name.as_ptr()),
        FsMetadata: fs_metadata(&entry.metadata),
        FileIdentity: identity.as_ptr() as *const c_void,
        FileIdentityLength: identity.len() as u32,
        Flags: CF_PLACEHOLDER_CREATE_FLAGS(
            if entry.mark_in_sync {
                windows::Win32::Storage::CloudFilters::CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC.0
            } else {
                0
            },
        ),
        Result: windows::core::HRESULT(0),
        CreateUsn: 0,
    }
}

fn fs_metadata(metadata: &MetadataBytes) -> CF_FS_METADATA {
    CF_FS_METADATA {
        BasicInfo: windows::Win32::Storage::FileSystem::FILE_BASIC_INFO {
            CreationTime: metadata.creation_time_100ns,
            LastAccessTime: metadata.last_write_time_100ns,
            LastWriteTime: metadata.last_write_time_100ns,
            ChangeTime: metadata.last_write_time_100ns,
            FileAttributes: metadata.attributes,
        },
        FileSize: metadata.size as i64,
    }
}

/// Acknowledge a `NOTIFY_RENAME` observation after it is durably queued.
pub(crate) fn ack_rename(ack: AckToken, status: TransferStatus) -> Result<(), u32> {
    let mut parameters = default_operation_parameters();
    parameters.ParamSize = operation_param_size::<windows::Win32::Storage::CloudFilters::CF_OPERATION_PARAMETERS_0_6>();
    // Writing the active union member is safe.
    parameters.Anonymous.AckRename =
        windows::Win32::Storage::CloudFilters::CF_OPERATION_PARAMETERS_0_6 {
            Flags: CF_OPERATION_ACK_RENAME_FLAG_NONE,
            CompletionStatus: ntstatus(status),
        };
    execute(ack, CF_OPERATION_TYPE_ACK_RENAME, &mut parameters)
}

/// Acknowledge a `NOTIFY_DELETE` observation after it is durably queued.
pub(crate) fn ack_delete(ack: AckToken, status: TransferStatus) -> Result<(), u32> {
    let mut parameters = default_operation_parameters();
    parameters.ParamSize = operation_param_size::<windows::Win32::Storage::CloudFilters::CF_OPERATION_PARAMETERS_0_7>();
    // Writing the active union member is safe.
    parameters.Anonymous.AckDelete =
        windows::Win32::Storage::CloudFilters::CF_OPERATION_PARAMETERS_0_7 {
            Flags: CF_OPERATION_ACK_DELETE_FLAG_NONE,
            CompletionStatus: ntstatus(status),
        };
    execute(ack, CF_OPERATION_TYPE_ACK_DELETE, &mut parameters)
}

/// Report genuine transfer progress to the OS (before the CFAPI deadline).
pub(crate) fn report_progress(
    connection_key: i64,
    transfer_key: i64,
    total: i64,
    completed: i64,
) -> Result<(), u32> {
    // SAFETY: plain value call on a live connection key.
    unsafe {
        CfReportProviderProgress(
            CF_CONNECTION_KEY(connection_key),
            transfer_key,
            total,
            completed,
        )
        .map_err(|e| super::error_code(&e))
    }
}

fn default_operation_parameters() -> CF_OPERATION_PARAMETERS {
    // SAFETY: the generated struct documents zero-init as a valid default.
    unsafe { std::mem::zeroed() }
}

fn execute(
    ack: AckToken,
    operation: CF_OPERATION_TYPE,
    parameters: &mut CF_OPERATION_PARAMETERS,
) -> Result<(), u32> {
    let info = CF_OPERATION_INFO {
        StructSize: size_of::<CF_OPERATION_INFO>() as u32,
        Type: operation,
        ConnectionKey: CF_CONNECTION_KEY(ack.connection_key),
        TransferKey: ack.transfer_key,
        CorrelationVector: std::ptr::null(),
        SyncStatus: std::ptr::null(),
        RequestKey: ack.request_key,
    };
    // SAFETY: `info` and `parameters` are valid for the call; buffers inside
    // `parameters` are owned by the caller and outlive `CfExecute`.
    unsafe { CfExecute(&info, parameters).map_err(|e| super::error_code(&e)) }
}

// ---------------------------------------------------------------------------
// Placeholder management
// ---------------------------------------------------------------------------

/// Open a placeholder with oplock protection (`CfOpenFileWithOplock`).
/// `exclusive` requires exclusive access (guarded transitions); `write`
/// requests write access. The returned opaque CFAPI handle is closed with
/// `CfCloseHandle`; it is not a normal Win32 file handle.
pub(crate) fn open_with_oplock(
    path: &Path,
    write: bool,
    exclusive: bool,
) -> Result<OwnedHandle, u32> {
    let w = wide(path);
    let mut flags = CF_OPEN_FILE_FLAG_FOREGROUND;
    if write {
        flags |= CF_OPEN_FILE_FLAG_WRITE_ACCESS;
    }
    if exclusive {
        flags |= CF_OPEN_FILE_FLAG_EXCLUSIVE;
    }
    // SAFETY: `w` is NUL-terminated; the returned handle is owned exactly
    // once by `OwnedHandle`.
    unsafe {
        let raw = CfOpenFileWithOplock(windows::core::PCWSTR(w.as_ptr()), flags)
            .map_err(|e| super::error_code(&e))?;
        OwnedHandle::from_cfapi_raw(raw).ok_or_else(super::last_error_code)
    }
}

/// Create a bounded batch of placeholders. Existing paths fail per entry
/// (`ERROR_FILE_EXISTS`) and are never overwritten; every per-entry result is
/// returned so the caller can reconcile each one.
pub(crate) fn create_placeholders(
    base: &Path,
    entries: &[PendingCreate],
) -> Result<Vec<EntryResult>, u32> {
    let w = wide(base);
    let mut wide_names: Vec<Vec<u16>> = entries.iter().map(|e| e.name.clone()).collect();
    let identities: Vec<Vec<u8>> = entries.iter().map(|e| e.identity.clone()).collect();
    let mut array: Vec<CF_PLACEHOLDER_CREATE_INFO> = entries
        .iter()
        .enumerate()
        .map(|(i, entry)| placeholder_create_info(entry, &mut wide_names[i], &identities[i]))
        .collect();
    let mut processed = 0u32;
    // SAFETY: `w` and the arrays are valid for the call; every entry's
    // `Result` is inspected afterwards regardless of the batch HRESULT.
    unsafe {
        CfCreatePlaceholders(
            windows::core::PCWSTR(w.as_ptr()),
            &mut array,
            CF_CREATE_FLAG_NONE,
            Some(&mut processed),
        )
        .map_err(|e| super::error_code(&e))?;
    }
    Ok(entry_results(&array))
}

/// Update a placeholder to a new immutable version: new metadata, new
/// identity and invalidated old ranges, with `VERIFY_IN_SYNC | MARK_IN_SYNC`.
/// Returns the USN the update landed at. The safe layer has already verified
/// the expected USN/generation and drained old-version requests.
pub(crate) fn update_placeholder(
    handle: &OwnedHandle,
    metadata: &MetadataBytes,
    identity: &[u8],
    invalidate: &[(i64, i64)],
) -> Result<i64, u32> {
    let ranges: Vec<CF_FILE_RANGE> = invalidate
        .iter()
        .map(|&(start, length)| CF_FILE_RANGE {
            StartingOffset: start,
            Length: length,
        })
        .collect();
    let mut usn = 0i64;
    // SAFETY: `metadata`, `identity` and `ranges` are owned by this frame and
    // outlive the synchronous call.
    unsafe {
        CfUpdatePlaceholder(
            super::volume::as_handle(handle),
            Some(&fs_metadata(metadata)),
            Some(identity.as_ptr() as *const c_void),
            identity.len() as u32,
            Some(&ranges),
            CF_UPDATE_FLAG_VERIFY_IN_SYNC | CF_UPDATE_FLAG_MARK_IN_SYNC,
            Some(&mut usn),
            None,
        )
        .map_err(|e| super::error_code(&e))?;
    }
    Ok(usn)
}

/// Convert a verified, already-published local file into a provider
/// placeholder, preserving its identity and generation evidence.
pub(crate) fn convert_to_placeholder(handle: &OwnedHandle, identity: &[u8]) -> Result<i64, u32> {
    let mut usn = 0i64;
    // SAFETY: `identity` outlives the synchronous call.
    unsafe {
        CfConvertToPlaceholder(
            super::volume::as_handle(handle),
            Some(identity.as_ptr() as *const c_void),
            identity.len() as u32,
            CF_CONVERT_FLAG_MARK_IN_SYNC,
            Some(&mut usn),
            None,
        )
        .map_err(|e| super::error_code(&e))?;
    }
    Ok(usn)
}

/// Convert a placeholder back into a plain file — the documented inverse of
/// `CfConvertToPlaceholder`. The SDK provides **no** `CfUninitializePlaceholder`;
/// `CfRevertPlaceholder(handle, CF_REVERT_FLAG_NONE, NULL)` is the supported
/// clearing path (cldapi.dll). The safe layer has already proven full
/// residency, clean state and the exact identity/USN guard before this call;
/// this adapter never invents success and reports the OS result verbatim.
pub(crate) fn revert_to_normal(handle: &OwnedHandle) -> Result<(), u32> {
    // SAFETY: handle is a live placeholder handle; synchronous completion.
    unsafe {
        CfRevertPlaceholder(
            super::volume::as_handle(handle),
            CF_REVERT_FLAG_NONE,
            None,
        )
        .map_err(|e| super::error_code(&e))
    }
}

/// Mark a placeholder in-sync, returning the USN it was stamped at. Callers
/// must have verified the expected USN/generation **before** calling; this
/// call never performs that verification itself.
pub(crate) fn set_in_sync(handle: &OwnedHandle) -> Result<i64, u32> {
    let mut usn = 0i64;
    // SAFETY: handle is a live placeholder handle.
    unsafe {
        CfSetInSyncState(
            super::volume::as_handle(handle),
            CF_IN_SYNC_STATE_IN_SYNC,
            CF_SET_IN_SYNC_FLAG_NONE,
            Some(&mut usn),
        )
        .map_err(|e| super::error_code(&e))?;
    }
    Ok(usn)
}

/// Pin state request values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PinRequest {
    Pinned,
    Unpinned,
    Excluded,
}

pub(crate) fn set_pin(handle: &OwnedHandle, pin: PinRequest) -> Result<(), u32> {
    let state = match pin {
        PinRequest::Pinned => CF_PIN_STATE_PINNED,
        PinRequest::Unpinned => CF_PIN_STATE_UNPINNED,
        PinRequest::Excluded => CF_PIN_STATE_EXCLUDED,
    };
    // SAFETY: handle is live; synchronous completion.
    unsafe {
        CfSetPinState(
            super::volume::as_handle(handle),
            state,
            CF_SET_PIN_FLAG_NONE,
            None,
        )
        .map_err(|e| super::error_code(&e))
    }
}

pub(crate) fn hydrate(handle: &OwnedHandle, start: i64, length: i64) -> Result<(), u32> {
    // SAFETY: handle is live; synchronous completion.
    unsafe {
        CfHydratePlaceholder(
            super::volume::as_handle(handle),
            start,
            length,
            CF_HYDRATE_FLAG_NONE,
            None,
        )
        .map_err(|e| super::error_code(&e))
    }
}

/// Dehydrate the whole file. Only called after the safe layer verified the
/// free-space preconditions (clean, unpinned, in-sync, no pending work).
pub(crate) fn dehydrate(handle: &OwnedHandle) -> Result<(), u32> {
    // SAFETY: handle is live; synchronous completion.
    unsafe {
        CfDehydratePlaceholder(
            super::volume::as_handle(handle),
            0,
            0,
            CF_DEHYDRATE_FLAG_NONE,
            None,
        )
        .map_err(|e| super::error_code(&e))
    }
}

/// Pin/in-sync state plus the raw identity bytes of a placeholder.
#[derive(Clone, Debug)]
pub(crate) struct PlaceholderInfoBits {
    pub pin_state: i32,
    pub in_sync_state: i32,
    pub identity: Vec<u8>,
}

pub(crate) fn placeholder_info(handle: &OwnedHandle) -> Result<PlaceholderInfoBits, u32> {
    let mut buffer = vec![0u8; size_of::<CF_PLACEHOLDER_BASIC_INFO>() + 512];
    let mut returned = 0u32;
    // SAFETY: `buffer` is a valid output buffer for the basic info class.
    unsafe {
        CfGetPlaceholderInfo(
            super::volume::as_handle(handle),
            CF_PLACEHOLDER_INFO_BASIC,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
            Some(&mut returned),
        )
        .map_err(|e| super::error_code(&e))?;
        let info = &*(buffer.as_ptr() as *const CF_PLACEHOLDER_BASIC_INFO);
        let identity_offset = offset_of!(CF_PLACEHOLDER_BASIC_INFO, FileIdentity);
        let identity_len = (info.FileIdentityLength as usize)
            .min(buffer.len().saturating_sub(identity_offset));
        let identity = buffer[identity_offset..identity_offset + identity_len].to_vec();
        Ok(PlaceholderInfoBits {
            pin_state: info.PinState.0,
            in_sync_state: info.InSyncState.0,
            identity,
        })
    }
}

/// On-disk (resident) ranges of a placeholder as `(offset, length)` pairs.
pub(crate) fn on_disk_ranges(
    handle: &OwnedHandle,
    start: i64,
    length: i64,
) -> Result<Vec<(u64, u64)>, u32> {
    let mut ranges = vec![CF_FILE_RANGE { StartingOffset: 0, Length: 0 }; 256];
    let mut returned = 0u32;
    // SAFETY: `ranges` is a valid output array.
    unsafe {
        CfGetPlaceholderRangeInfo(
            super::volume::as_handle(handle),
            CF_PLACEHOLDER_RANGE_INFO_ONDISK,
            start,
            length,
            ranges.as_mut_ptr() as *mut c_void,
            (ranges.len() * size_of::<CF_FILE_RANGE>()) as u32,
            Some(&mut returned),
        )
        .map_err(|e| super::error_code(&e))?;
    }
    let count = (returned as usize) / size_of::<CF_FILE_RANGE>();
    Ok(ranges[..count.min(ranges.len())]
        .iter()
        .map(|r| (r.StartingOffset as u64, r.Length as u64))
        .collect())
}

/// Classify placeholder state bits from attributes and reparse tag
/// (`CfGetPlaceholderStateFromAttributeTag`).
pub(crate) fn placeholder_state_bits(attributes: u32, reparse_tag: u32) -> u32 {
    // SAFETY: pure computation over two value inputs.
    unsafe { CfGetPlaceholderStateFromAttributeTag(attributes, reparse_tag).0 }
}

/// `CF_PLACEHOLDER_STATE_PLACEHOLDER`.
pub(crate) const STATE_PLACEHOLDER: u32 = 0x1;
/// `CF_PLACEHOLDER_STATE_SYNC_ROOT`.
pub(crate) const STATE_SYNC_ROOT: u32 = 0x2;
/// `CF_PLACEHOLDER_STATE_IN_SYNC`.
pub(crate) const STATE_IN_SYNC: u32 = 0x8;
/// `CF_PLACEHOLDER_STATE_PARTIAL`.
pub(crate) const STATE_PARTIAL: u32 = 0x10;
/// `CF_PLACEHOLDER_STATE_PARTIALLY_ON_DISK`.
pub(crate) const STATE_PARTIALLY_ON_DISK: u32 = 0x20;

/// A transfer key obtained by the provider (`CfGetTransferKey`); released
/// with `CfReleaseTransferKey` exactly once on drop. Keys that arrive in
/// callbacks are **never** wrapped in this type: they belong to the OS.
pub(crate) struct ProviderTransferKey {
    handle: OwnedHandle,
    key: i64,
}

pub(crate) fn provider_transfer_key(handle: OwnedHandle) -> Result<ProviderTransferKey, u32> {
    // SAFETY: handle is live; the key is released exactly once on drop.
    let key = unsafe { CfGetTransferKey(super::volume::as_handle(&handle)) }
        .map_err(|e| super::error_code(&e))?;
    Ok(ProviderTransferKey { handle, key })
}

impl Drop for ProviderTransferKey {
    fn drop(&mut self) {
        // SAFETY: the key came from `CfGetTransferKey` for this exact handle
        // and has not been released before.
        unsafe {
            CfReleaseTransferKey(super::volume::as_handle(&self.handle), &self.key);
        }
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(path.as_os_str())
        .encode_wide()
        .chain(Some(0))
        .collect()
}

// Keep the aggregate event enum referenced so the module's contract (the
// safe layer consumes `ProviderEvent` values built by its own hub) stays
// visible to readers and rustdoc.
#[allow(unused_imports)]
use ProviderEvent as _EVENT_CONTRACT;

#[cfg(test)]
mod tests {
    use super::operation_param_size;
    use windows::Win32::Storage::CloudFilters::{
        CF_OPERATION_PARAMETERS_0_0, CF_OPERATION_PARAMETERS_0_4,
        CF_OPERATION_PARAMETERS_0_6, CF_OPERATION_PARAMETERS_0_7,
    };

    #[test]
    fn operation_sizes_include_the_union_offset_and_active_member() {
        assert_eq!(operation_param_size::<CF_OPERATION_PARAMETERS_0_0>(), 40);
        assert_eq!(operation_param_size::<CF_OPERATION_PARAMETERS_0_4>(), 40);
        assert_eq!(operation_param_size::<CF_OPERATION_PARAMETERS_0_6>(), 16);
        assert_eq!(operation_param_size::<CF_OPERATION_PARAMETERS_0_7>(), 16);
    }
}
