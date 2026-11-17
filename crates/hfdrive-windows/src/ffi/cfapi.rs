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
    CfGetPlaceholderStateFromAttributeTag, CfHydratePlaceholder,
    CfOpenFileWithOplock, CfReportProviderProgress, CfRevertPlaceholder,
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
    CF_OPERATION_TRANSFER_DATA_FLAG_NONE, CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_DISABLE_ON_DEMAND_POPULATION,
    CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE,
    CF_OPERATION_TYPE, CF_OPERATION_TYPE_ACK_DELETE, CF_OPERATION_TYPE_ACK_RENAME,
    CF_OPERATION_TYPE_TRANSFER_DATA, CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS,
    CF_PLACEHOLDER_BASIC_INFO, CF_PLACEHOLDER_CREATE_FLAGS, CF_PLACEHOLDER_CREATE_INFO,
    CF_PLACEHOLDER_INFO_BASIC, CF_PLACEHOLDER_MAX_FILE_IDENTITY_LENGTH,
    CF_PLACEHOLDER_RANGE_INFO_ONDISK, CF_PIN_STATE_PINNED,
    CF_PIN_STATE_EXCLUDED, CF_PIN_STATE_UNPINNED, CF_REVERT_FLAG_NONE, CF_SET_IN_SYNC_FLAG_NONE,
    CF_SET_PIN_FLAG_NONE, CF_UPDATE_FLAG_MARK_IN_SYNC, CF_UPDATE_FLAG_VERIFY_IN_SYNC,
};

use crate::cfapi::events::{
    AckToken, CancelRanges, DeleteCompletion, DeleteNotification, FetchFailure, FetchRequest,
    PlaceholdersRequest, ProviderEvent, RenameCompletion, RenameNotification, TransferStatus,
};
use crate::cfapi::identity::PlaceholderIdentity;
use super::handle::{CfaHandle, ProtectedHandle};

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
    /// The sync root's volume-relative prefix, captured once at connect;
    /// every callback path (absolute from the volume root) is converted
    /// against it before it becomes a typed event.
    root: RootPrefix,
    sink: Box<dyn EventSink>,
    inflight: AtomicUsize,
    closed: AtomicBool,
}

impl CallbackContext {
    fn new(workspace: WorkspaceId, root: RootPrefix, sink: Box<dyn EventSink>) -> Arc<Self> {
        Arc::new(CallbackContext {
            workspace,
            root,
            sink,
            inflight: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
        })
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// The callback path as its sync-root-relative event spelling (`""` is
    /// the sync root directory itself), or `None` when the path is not under
    /// this root or is not a well-formed absolute path. Foreign and
    /// malformed spellings are never reinterpreted as root-relative.
    fn owned_path(&self, path: windows::core::PCWSTR) -> Option<String> {
        if path.is_null() {
            return None;
        }
        // SAFETY: the OS-provided path is valid for the callback.
        owned_relative(&self.root, unsafe { path.as_wide() })
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
            false,
        );
        return;
    }
    let pattern = (!fetch.Pattern.is_null())
        // SAFETY: the OS-provided pattern string is valid for the callback.
        .then(|| unsafe { fetch.Pattern.to_string().ok() })
        .flatten();
    let normalized_path = match ctx.owned_path(info.NormalizedPath) {
        Some(path) => path,
        None => {
            // The subject is not under this sync root (or is malformed):
            // fail the population request truthfully instead of resolving a
            // foreign spelling as a root-relative path.
            let _ = transfer_placeholders(
                ack,
                TransferStatus::Failed(FetchFailure::InvalidRequest),
                0,
                &[],
                false,
            );
            return;
        }
    };
    ctx.sink.on_fetch_placeholders(PlaceholdersRequest {
        ack,
        normalized_path,
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
    if ctx.is_closed() {
        let _ = ack_rename(ack, TransferStatus::Failed(FetchFailure::ProviderStopping));
        return;
    }
    let source_in_scope = rename
        .Flags
        .contains(windows::Win32::Storage::CloudFilters::CF_CALLBACK_RENAME_FLAG_SOURCE_IN_SCOPE);
    let target_in_scope = rename
        .Flags
        .contains(windows::Win32::Storage::CloudFilters::CF_CALLBACK_RENAME_FLAG_TARGET_IN_SCOPE);
    let spellings = rename_spellings(
        ctx.owned_path(info.NormalizedPath),
        os_path_string(info.NormalizedPath),
        source_in_scope,
        ctx.owned_path(rename.TargetPath),
        os_path_string(rename.TargetPath),
        target_in_scope,
    );
    let Some((normalized_path, target_path)) = spellings else {
        // A side the OS reports in scope is not under this root (or has no
        // usable spelling): veto the rename instead of reinterpreting or
        // truncating a foreign path.
        let _ = ack_rename(ack, TransferStatus::Failed(FetchFailure::InvalidRequest));
        return;
    };
    let notification = RenameNotification {
        ack,
        normalized_path,
        target_path,
        is_directory: rename
            .Flags
            .contains(windows::Win32::Storage::CloudFilters::CF_CALLBACK_RENAME_FLAG_IS_DIRECTORY),
        source_in_scope,
        target_in_scope,
    };
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
        // Post-facto outcome: an in-root source becomes sync-root-relative,
        // a source that moved in from outside keeps its OS spelling.
        source_path: ctx
            .owned_path(completion.SourcePath)
            .unwrap_or_else(|| os_path_string(completion.SourcePath)),
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
    if ctx.is_closed() {
        let _ = ack_delete(ack, TransferStatus::Failed(FetchFailure::ProviderStopping));
        return;
    }
    let normalized_path = match ctx.owned_path(info.NormalizedPath) {
        Some(path) => path,
        None => {
            // Not under this sync root (or malformed): veto instead of
            // acknowledging a deletion that cannot be observed.
            let _ = ack_delete(ack, TransferStatus::Failed(FetchFailure::InvalidRequest));
            return;
        }
    };
    let notification = DeleteNotification {
        ack,
        normalized_path,
        is_directory: delete
            .Flags
            .contains(windows::Win32::Storage::CloudFilters::CF_CALLBACK_DELETE_FLAG_IS_DIRECTORY),
        is_undelete: delete
            .Flags
            .contains(windows::Win32::Storage::CloudFilters::CF_CALLBACK_DELETE_FLAG_IS_UNDELETE),
    };
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

/// The OS's raw spelling of a callback path, kept unchanged for sides that
/// live outside the sync root; empty when the pointer is null or the text is
/// not valid UTF-16.
fn os_path_string(path: windows::core::PCWSTR) -> String {
    (!path.is_null())
        // SAFETY: the OS-provided path is valid for the callback.
        .then(|| unsafe { path.to_string().ok() })
        .flatten()
        .unwrap_or_default()
}

/// Decide a rename notification's event spellings from the converted paths:
/// owned sides become sync-root-relative (`""` is the sync root itself),
/// outside sides keep the OS spelling so moves into/out of the root stay
/// meaningful. `None` vetoes the notification — a side the OS reports in
/// scope must actually be owned by this root and is never reinterpreted.
fn rename_spellings(
    source_owned: Option<String>,
    source_raw: String,
    source_in_scope: bool,
    target_owned: Option<String>,
    target_raw: String,
    target_in_scope: bool,
) -> Option<(String, String)> {
    if (source_in_scope && source_owned.is_none()) || (target_in_scope && target_owned.is_none()) {
        return None;
    }
    Some((
        source_owned.unwrap_or(source_raw),
        target_owned.unwrap_or(target_raw),
    ))
}

// ---------------------------------------------------------------------------
// Sync-root-relative callback paths
// ---------------------------------------------------------------------------
//
// `CF_CALLBACK_INFO.NormalizedPath` is the callback subject's ABSOLUTE path
// on its volume ("It starts from the root directory of the volume") — never
// sync-root relative. Every in-scope path crossing into the typed events is
// converted here against the root prefix captured at connect: the sync root
// directory itself becomes the empty spelling, descendants keep their
// spelling below the root. Matching is per path component with
// case-insensitive component boundaries — never a string-prefix strip — so a
// sibling like `drive-dev2` can never borrow `drive-dev`'s root. Traversal
// (`.`/`..`), empty and otherwise malformed components are never resolved or
// reinterpreted (a mount point/junction subject arrives already resolved by
// the OS to its real location and simply fails the match if it is foreign).

/// The separator the OS uses inside normalized callback paths.
const PATH_SEPARATOR: u16 = b'\\' as u16;

/// How a path spelling names its volume. Same-shape designators are compared
/// case-insensitively; different namespaces (drive letter vs NT device name
/// vs volume GUID) are not comparable as strings and defer to the OS
/// connection binding, while an unmarked (`\...`) spelling carries none.
#[derive(Clone, Copy)]
enum VolumeDesignator<'a> {
    Unmarked,
    /// Drive designator (`C:`, also inside `\\?\C:\...`).
    Dos(&'a [u16]),
    /// `Volume{GUID}` designator (inside `\\?\Volume{...}`).
    VolumeGuid(&'a [u16]),
    /// NT device designator (`\Device\HarddiskVolumeN`).
    Device(&'a [u16]),
}

impl<'a> VolumeDesignator<'a> {
    /// `other` borrows an independent spelling, so it never shares `'a`;
    /// the explicit variant paths keep the two borrows decoupled.
    fn compatible<'b>(self, other: VolumeDesignator<'b>) -> bool {
        match (self, other) {
            (Self::Unmarked, _) | (_, VolumeDesignator::Unmarked) => true,
            (Self::Dos(a), VolumeDesignator::Dos(b))
            | (Self::VolumeGuid(a), VolumeDesignator::VolumeGuid(b))
            | (Self::Device(a), VolumeDesignator::Device(b)) => {
                super::nls::equal_ordinal_ignore_case(a, b)
            }
            _ => true,
        }
    }

    fn kind(self) -> DesignatorKind {
        match self {
            Self::Unmarked => DesignatorKind::Unmarked,
            Self::Dos(_) => DesignatorKind::Dos,
            Self::VolumeGuid(_) => DesignatorKind::VolumeGuid,
            Self::Device(_) => DesignatorKind::Device,
        }
    }

    fn span(self) -> &'a [u16] {
        match self {
            Self::Unmarked => &[],
            Self::Dos(span) | Self::VolumeGuid(span) | Self::Device(span) => span,
        }
    }
}

#[derive(Clone, Copy)]
enum DesignatorKind {
    Unmarked,
    Dos,
    VolumeGuid,
    Device,
}

/// The connected sync root's volume-relative prefix, parsed once from the
/// validated absolute root and reused (borrowed) by every callback.
struct RootPrefix {
    kind: DesignatorKind,
    designator: Vec<u16>,
    /// Volume-root-relative components, wide and NUL-free.
    segments: Vec<Vec<u16>>,
}

impl RootPrefix {
    /// Parse a validated absolute local root (`C:\a\b`, `\\?\C:\a\b`, ...)
    /// into its volume-relative segments. `None` means unparseable; such a
    /// root must never connect, because its paths could only be fabricated.
    fn parse(path: &Path) -> Option<RootPrefix> {
        let wide = wide(path);
        let spelling = wide.strip_suffix(&[0]).unwrap_or(&wide);
        for candidate in candidate_starts(spelling) {
            let Some((designator, start)) = candidate else {
                continue;
            };
            if let Some(segments) = validate_segments(spelling, start) {
                return Some(RootPrefix {
                    kind: designator.kind(),
                    designator: designator.span().to_vec(),
                    segments: segments.iter().map(|segment| segment.to_vec()).collect(),
                });
            }
        }
        None
    }

    fn designator(&self) -> VolumeDesignator<'_> {
        match self.kind {
            DesignatorKind::Unmarked => VolumeDesignator::Unmarked,
            DesignatorKind::Dos => VolumeDesignator::Dos(&self.designator),
            DesignatorKind::VolumeGuid => VolumeDesignator::VolumeGuid(&self.designator),
            DesignatorKind::Device => VolumeDesignator::Device(&self.designator),
        }
    }
}

/// Convert one OS callback path to its sync-root-relative event spelling:
/// `""` for the sync root directory itself, the child spelling below it, and
/// `None` for anything outside this root or not a well-formed absolute path
/// (never reinterpreted, never the root).
fn owned_relative(root: &RootPrefix, path: &[u16]) -> Option<String> {
    for candidate in candidate_starts(path) {
        let Some((designator, start)) = candidate else {
            continue;
        };
        if !root.designator().compatible(designator) {
            continue;
        }
        if let Some((rel_start, rel_end)) = match_candidate(root, path, start) {
            if let Ok(relative) = String::from_utf16(&path[rel_start..rel_end]) {
                return Some(relative);
            }
            // Not valid UTF-16: this spelling is unusable; try the next
            // interpretation instead of fabricating replacement text.
        }
    }
    None
}

/// The interpretation candidates for one absolute path spelling, in
/// preference order: extended device namespace + designator, drive
/// designator, NT `\Device\HarddiskVolumeN` designator, then bare
/// volume-root relative. Each yields where the volume-relative segments
/// begin together with the designator it stripped.
fn candidate_starts(path: &[u16]) -> [Option<(VolumeDesignator<'_>, usize)>; 4] {
    [
        extended_designator(path),
        drive_designator(path),
        device_designator(path),
        bare_volume_relative(path),
    ]
}

/// `\\?\`, `\\.\` or `\??\` namespace prefix length.
fn extended_namespace(path: &[u16]) -> Option<usize> {
    const FORMS: [[u16; 4]; 3] = [
        [b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16],
        [b'\\' as u16, b'\\' as u16, b'.' as u16, b'\\' as u16],
        [b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16],
    ];
    (path.len() >= 4 && FORMS.iter().any(|form| &path[..4] == &form[..])).then_some(4)
}

/// The region right after one volume designator (its end and the path end).
fn designator_start(path: &[u16], end: usize) -> Option<usize> {
    if end == path.len() {
        // `\\?\C:` / `\\?\Volume{...}` name the volume root absolutely.
        Some(end)
    } else if path[end] == PATH_SEPARATOR {
        Some(end + 1)
    } else {
        None
    }
}

fn extended_designator(path: &[u16]) -> Option<(VolumeDesignator<'_>, usize)> {
    let after_namespace = extended_namespace(path)?;
    let end = path[after_namespace..]
        .iter()
        .position(|&unit| unit == PATH_SEPARATOR)
        .map(|position| after_namespace + position)
        .unwrap_or(path.len());
    let designator = classify_designator(&path[after_namespace..end])?;
    Some((designator, designator_start(path, end)?))
}

/// ASCII letter in a wide path component (`u16` carries no `is_ascii_*`
/// predicates; ranges are spelled directly).
fn is_ascii_letter(unit: u16) -> bool {
    matches!(unit, 0x41..=0x5A | 0x61..=0x7A)
}

fn is_ascii_digit(unit: u16) -> bool {
    matches!(unit, 0x30..=0x39)
}

fn drive_designator(path: &[u16]) -> Option<(VolumeDesignator<'_>, usize)> {
    // `X:\...`: a bare `X:` is drive-relative (the drive's current
    // directory), not an absolute volume path, so it is never accepted here;
    // the extended `\\?\X:` form is absolute and handled above.
    if path.len() < 3
        || !is_ascii_letter(path[0])
        || path[1] != b':' as u16
        || path[2] != PATH_SEPARATOR
    {
        return None;
    }
    Some((VolumeDesignator::Dos(&path[0..2]), 3))
}

fn device_designator(path: &[u16]) -> Option<(VolumeDesignator<'_>, usize)> {
    const PREFIX: [u16; 8] = [
        b'\\' as u16,
        b'D' as u16,
        b'e' as u16,
        b'v' as u16,
        b'i' as u16,
        b'c' as u16,
        b'e' as u16,
        b'\\' as u16,
    ];
    if path.len() < PREFIX.len()
        || !super::nls::equal_ordinal_ignore_case(&path[..PREFIX.len()], &PREFIX)
    {
        return None;
    }
    let end = path[PREFIX.len()..]
        .iter()
        .position(|&unit| unit == PATH_SEPARATOR)
        .map(|position| PREFIX.len() + position)
        .unwrap_or(path.len());
    let volume = &path[PREFIX.len()..end];
    if !is_harddisk_volume(volume) {
        return None;
    }
    Some((VolumeDesignator::Device(volume), designator_start(path, end)?))
}

fn bare_volume_relative(path: &[u16]) -> Option<(VolumeDesignator<'_>, usize)> {
    (path.first() == Some(&PATH_SEPARATOR)).then_some((VolumeDesignator::Unmarked, 1))
}

fn classify_designator(span: &[u16]) -> Option<VolumeDesignator<'_>> {
    if span.len() == 2 && is_ascii_letter(span[0]) && span[1] == b':' as u16 {
        return Some(VolumeDesignator::Dos(span));
    }
    const VOLUME: [u16; 7] = [
        b'V' as u16,
        b'o' as u16,
        b'l' as u16,
        b'u' as u16,
        b'm' as u16,
        b'e' as u16,
        b'{' as u16,
    ];
    if span.len() > VOLUME.len() + 1
        && super::nls::equal_ordinal_ignore_case(&span[..VOLUME.len()], &VOLUME)
        && span.last() == Some(&(b'}' as u16))
    {
        return Some(VolumeDesignator::VolumeGuid(span));
    }
    None
}

fn is_harddisk_volume(span: &[u16]) -> bool {
    const VOLUME: [u16; 14] = [
        b'H' as u16,
        b'a' as u16,
        b'r' as u16,
        b'd' as u16,
        b'd' as u16,
        b'i' as u16,
        b's' as u16,
        b'k' as u16,
        b'V' as u16,
        b'o' as u16,
        b'l' as u16,
        b'u' as u16,
        b'm' as u16,
        b'e' as u16,
    ];
    span.len() > VOLUME.len()
        && super::nls::equal_ordinal_ignore_case(&span[..VOLUME.len()], &VOLUME)
        && span[VOLUME.len()..].iter().all(|&unit| is_ascii_digit(unit))
}

/// A component is a real name: non-empty, not `.`/`..`, and free of the
/// separators/ADS/NUL that cannot occur in an owned namespace spelling.
fn valid_segment(segment: &[u16]) -> bool {
    const DOT: &[u16] = &[b'.' as u16];
    const DOTDOT: &[u16] = &[b'.' as u16, b'.' as u16];
    !segment.is_empty()
        && segment != DOT
        && segment != DOTDOT
        && !segment
            .iter()
            .any(|&unit| unit == 0 || unit == b'/' as u16 || unit == b':' as u16)
}

/// Component spans of the volume-relative region, or `None` when it is
/// malformed (empty components, traversal). One optional trailing separator
/// terminates the last component and changes nothing.
fn validate_segments(path: &[u16], start: usize) -> Option<Vec<&[u16]>> {
    let mut segments = Vec::new();
    let mut at = start;
    while at < path.len() {
        if path[at] == PATH_SEPARATOR {
            return None;
        }
        let end = path[at..]
            .iter()
            .position(|&unit| unit == PATH_SEPARATOR)
            .map(|position| at + position)
            .unwrap_or(path.len());
        if !valid_segment(&path[at..end]) {
            return None;
        }
        segments.push(&path[at..end]);
        at = end;
        if at < path.len() {
            at += 1; // the component's terminating separator
        }
    }
    Some(segments)
}

/// Match one interpretation's segments against the root prefix. Returns the
/// span of the sync-root-relative remainder (empty span = the root itself).
/// `None` = shorter than the root, a case-insensitive component mismatch or
/// a malformed component — never the root.
fn match_candidate(root: &RootPrefix, path: &[u16], start: usize) -> Option<(usize, usize)> {
    let mut at = start;
    let mut matched = 0;
    let mut rel_start = start;
    while at < path.len() {
        if path[at] == PATH_SEPARATOR {
            return None;
        }
        let end = path[at..]
            .iter()
            .position(|&unit| unit == PATH_SEPARATOR)
            .map(|position| at + position)
            .unwrap_or(path.len());
        if !valid_segment(&path[at..end]) {
            return None;
        }
        if matched < root.segments.len() {
            if !super::nls::equal_ordinal_ignore_case(&path[at..end], &root.segments[matched]) {
                return None;
            }
            matched += 1;
            if matched == root.segments.len() {
                // The remainder starts after the separator following the
                // last root component — never mid-component.
                rel_start = if end < path.len() { end + 1 } else { end };
            }
        }
        at = end;
        if at < path.len() {
            at += 1;
        }
    }
    if matched < root.segments.len() {
        return None;
    }
    let rel_end = if path.last() == Some(&PATH_SEPARATOR) {
        path.len() - 1
    } else {
        path.len()
    };
    Some((rel_start, rel_end.max(rel_start)))
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
    // Capture the root's volume-relative prefix once: every callback path is
    // absolute from the volume root and is converted against it at this
    // boundary. A root that cannot be parsed never connects — its callback
    // paths could only be fabricated, never converted.
    let Some(root_prefix) = RootPrefix::parse(root) else {
        return Err(windows::Win32::Foundation::ERROR_INVALID_NAME.0);
    };
    let w = wide(root);
    let context = CallbackContext::new(workspace, root_prefix, sink);
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

/// `E_FAIL` for an entry the OS did not process: reported as a failure, never
/// as a fabricated success.
const UNPROCESSED_ENTRY_HRESULT: i32 = 0x8000_4005u32 as i32;

/// Transfer a bounded batch for one `FETCH_PLACEHOLDERS` request.
///
/// `total_count` covers the whole request; `EntriesProcessed` is per call.
/// Only the terminal call may mark a complete authoritative listing populated,
/// after every prior entry was processed and left present. Windows otherwise
/// repeats on-demand population, including for empty directories.
///
/// Contract: https://learn.microsoft.com/windows/win32/api/cfapi/ne-cfapi-cf_operation_transfer_placeholders_flags
/// Every per-entry result is returned; unprocessed entries remain failures.
pub(crate) fn transfer_placeholders(
    ack: AckToken,
    status: TransferStatus,
    total_count: i64,
    entries: &[PendingCreate],
    mark_populated: bool,
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
    // alive until `execute` returns. `PlaceholderArray` is NULL for an empty
    // batch (a dangling non-null pointer is not a valid buffer) and
    // `EntriesProcessed` is an `CfExecute` OUTPUT: it starts at 0 and is
    // filled by the OS.
    parameters.Anonymous.TransferPlaceholders =
        windows::Win32::Storage::CloudFilters::CF_OPERATION_PARAMETERS_0_4 {
            Flags: if mark_populated {
                CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_DISABLE_ON_DEMAND_POPULATION
            } else {
                CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE
            },
            CompletionStatus: ntstatus(status),
            PlaceholderTotalCount: total_count,
            PlaceholderArray: if array.is_empty() {
                std::ptr::null_mut()
            } else {
                array.as_mut_ptr()
            },
            PlaceholderCount: array.len() as u32,
            EntriesProcessed: 0,
        };
    execute(ack, CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS, &mut parameters)?;
    // SAFETY: reading the output member back after `CfExecute` returned.
    let processed = unsafe { parameters.Anonymous.TransferPlaceholders.EntriesProcessed };
    Ok(entry_results(&array, processed))
}

/// The completion calls of one `FETCH_PLACEHOLDERS` request: bounded data
/// calls (every planned entry lands in exactly one of them — a directory
/// larger than [`POPULATION_BATCH_MAX`] completes across several calls of the
/// same request, never truncated) followed by the request's **terminal**
/// call, the always-empty last range. A genuinely empty directory therefore
/// completes with exactly one empty call. Every call reports the same true
/// `PlaceholderTotalCount`; only the terminal call may carry the
/// fully-populated mark, decided from the observed per-entry outcomes by
/// [`directory_populated_mark`].
pub(crate) fn population_calls(
    entry_count: usize,
) -> impl Iterator<Item = std::ops::Range<usize>> {
    (0..entry_count)
        .step_by(POPULATION_BATCH_MAX)
        .map(move |start| start..entry_count.min(start + POPULATION_BATCH_MAX))
        .chain(std::iter::once(entry_count..entry_count))
}

/// Entries per `TRANSFER_PLACEHOLDERS` data call: the same bound as
/// `CfCreatePlaceholders` batches, so one call stays bounded no matter how
/// large the directory is.
pub(crate) const POPULATION_BATCH_MAX: usize = 1000;

/// Per-entry failure codes that still mean the name is **present** in the
/// directory: `HRESULT_FROM_WIN32(ERROR_FILE_EXISTS)`,
/// `HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)` and
/// `STATUS_OBJECT_NAME_COLLISION`. The platform leaves an occupied name
/// untouched (never overwritten) and the provider reconciles that local
/// file/placeholder separately.
const ENTRY_OCCUPIED_HRESULTS: [i32; 3] = [
    0x8007_0050u32 as i32,
    0x8007_00B7u32 as i32,
    0xC000_0035u32 as i32,
];

/// True when one entry's outcome means its name is present in the directory:
/// freshly created (success, including the `STATUS_OBJECT_NAME_EXISTS`
/// success warning) or already occupied by an untouched local entry. Anything
/// else — including [`UNPROCESSED_ENTRY_HRESULT`] for entries the OS never
/// processed — means the name is missing.
pub(crate) fn entry_present(result: i32) -> bool {
    result >= 0 || ENTRY_OCCUPIED_HRESULTS.contains(&result)
}

/// Decide the request's fully-populated mark: only a **complete
/// authoritative** delivery (`complete_directory`) that left **every** entry
/// present. The empty-directory case falls out naturally: zero entries are
/// all present, so a genuinely empty directory is marked complete, while an
/// empty *subset* delivery (`complete_directory == false`, e.g. children that
/// cannot become placeholders) is not. A missing name must never be declared
/// part of a full listing — that is what leaves it unresolvable — and an
/// honestly partial delivery stays unmarked so the platform may re-fetch.
pub(crate) fn directory_populated_mark(complete_directory: bool, results: &[EntryResult]) -> bool {
    complete_directory && results.iter().all(|result| entry_present(result.result))
}

/// Per-entry outcomes of a create/transfer batch. `processed` is the count
/// the OS actually processed (its output); entries past it never became
/// placeholders and are reported as failures instead of fabricated successes
/// left over from the pre-call initialization.
fn entry_results(array: &[CF_PLACEHOLDER_CREATE_INFO], processed: u32) -> Vec<EntryResult> {
    array
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let handled = (i as u32) < processed;
            EntryResult {
                result: if handled {
                    entry.Result.0
                } else {
                    UNPROCESSED_ENTRY_HRESULT
                },
                create_usn: if handled { entry.CreateUsn } else { 0 },
            }
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
/// requests write access. The returned opaque protected handle is closed
/// exactly once with `CfCloseHandle`; Win32 metadata/USN queries on the same
/// open go through `ProtectedHandle::win32` (borrowed, never closed).
pub(crate) fn open_with_oplock(
    path: &Path,
    write: bool,
    exclusive: bool,
) -> Result<ProtectedHandle, u32> {
    let w = wide(path);
    let mut flags = CF_OPEN_FILE_FLAG_FOREGROUND;
    if write {
        flags |= CF_OPEN_FILE_FLAG_WRITE_ACCESS;
    }
    if exclusive {
        flags |= CF_OPEN_FILE_FLAG_EXCLUSIVE;
    }
    // SAFETY: `w` is NUL-terminated; the returned opaque handle is owned
    // exactly once by `ProtectedHandle`.
    unsafe {
        let raw = CfOpenFileWithOplock(windows::core::PCWSTR(w.as_ptr()), flags)
            .map_err(|e| super::error_code(&e))?;
        ProtectedHandle::from_raw_with(raw, super::handle::CfaProtectedOps)
            .ok_or_else(super::last_error_code)
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
    // `processed` is the API's output count of handled entries.
    unsafe {
        CfCreatePlaceholders(
            windows::core::PCWSTR(w.as_ptr()),
            &mut array,
            CF_CREATE_FLAG_NONE,
            Some(&mut processed),
        )
        .map_err(|e| super::error_code(&e))?;
    }
    Ok(entry_results(&array, processed))
}

/// Update placeholder identity and optional metadata/ranges atomically against
/// the caller's expected USN. Remote replacement verifies in-sync state;
/// publication of captured local bytes marks in-sync without invalidating data.
pub(crate) fn update_placeholder(
    handle: &impl CfaHandle,
    metadata: Option<&MetadataBytes>,
    identity: &[u8],
    invalidate: &[(i64, i64)],
    expected_usn: i64,
    verify_in_sync: bool,
) -> Result<i64, u32> {
    let ranges: Vec<CF_FILE_RANGE> = invalidate
        .iter()
        .map(|&(start, length)| CF_FILE_RANGE {
            StartingOffset: start,
            Length: length,
        })
        .collect();
    let metadata = metadata.map(fs_metadata);
    let mut usn = expected_usn;
    // SAFETY: `metadata`, `identity` and `ranges` are owned by this frame and
    // outlive the synchronous call.
    unsafe {
        CfUpdatePlaceholder(
            handle.as_cfa(),
            metadata.as_ref().map(|metadata| metadata as *const CF_FS_METADATA),
            Some(identity.as_ptr() as *const c_void),
            identity.len() as u32,
            if ranges.is_empty() { None } else { Some(ranges.as_slice()) },
            if verify_in_sync {
                CF_UPDATE_FLAG_VERIFY_IN_SYNC | CF_UPDATE_FLAG_MARK_IN_SYNC
            } else {
                CF_UPDATE_FLAG_MARK_IN_SYNC
            },
            Some(&mut usn),
            None,
        )
        .map_err(|e| super::error_code(&e))?;
    }
    Ok(usn)
}

/// Convert a verified, already-published local file into a provider
/// placeholder, preserving its identity and generation evidence.
pub(crate) fn convert_to_placeholder(handle: &impl CfaHandle, identity: &[u8]) -> Result<i64, u32> {
    let mut usn = 0i64;
    // SAFETY: `identity` outlives the synchronous call.
    unsafe {
        CfConvertToPlaceholder(
            handle.as_cfa(),
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
pub(crate) fn revert_to_normal(handle: &impl CfaHandle) -> Result<(), u32> {
    // SAFETY: handle is a live placeholder handle; synchronous completion.
    unsafe {
        CfRevertPlaceholder(
            handle.as_cfa(),
            CF_REVERT_FLAG_NONE,
            None,
        )
        .map_err(|e| super::error_code(&e))
    }
}

/// Mark a placeholder in-sync, returning the USN it was stamped at. Callers
/// must have verified the expected USN/generation **before** calling; this
/// call never performs that verification itself.
pub(crate) fn set_in_sync(handle: &impl CfaHandle) -> Result<i64, u32> {
    let mut usn = 0i64;
    // SAFETY: handle is a live placeholder handle.
    unsafe {
        CfSetInSyncState(
            handle.as_cfa(),
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

pub(crate) fn set_pin(handle: &impl CfaHandle, pin: PinRequest) -> Result<(), u32> {
    let state = match pin {
        PinRequest::Pinned => CF_PIN_STATE_PINNED,
        PinRequest::Unpinned => CF_PIN_STATE_UNPINNED,
        PinRequest::Excluded => CF_PIN_STATE_EXCLUDED,
    };
    // SAFETY: handle is live; synchronous completion.
    unsafe {
        CfSetPinState(
            handle.as_cfa(),
            state,
            CF_SET_PIN_FLAG_NONE,
            None,
        )
        .map_err(|e| super::error_code(&e))
    }
}

pub(crate) fn hydrate(handle: &impl CfaHandle, start: i64, length: i64) -> Result<(), u32> {
    // SAFETY: handle is live; synchronous completion.
    unsafe {
        CfHydratePlaceholder(
            handle.as_cfa(),
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
pub(crate) fn dehydrate(handle: &impl CfaHandle) -> Result<(), u32> {
    // SAFETY: handle is live; synchronous completion.
    unsafe {
        CfDehydratePlaceholder(
            handle.as_cfa(),
            0,
            0,
            CF_DEHYDRATE_FLAG_NONE,
            None,
        )
        .map_err(|e| super::error_code(&e))
    }
}

/// Pin/in-sync state of a placeholder.
#[derive(Clone, Debug)]
pub(crate) struct PlaceholderInfoBits {
    pub pin_state: i32,
    pub in_sync_state: i32,
}

pub(crate) fn placeholder_info(handle: &impl CfaHandle) -> Result<PlaceholderInfoBits, u32> {
    let mut buffer = vec![0u8; size_of::<CF_PLACEHOLDER_BASIC_INFO>() + 512];
    let mut returned = 0u32;
    // SAFETY: `buffer` is a valid output buffer for the basic info class.
    unsafe {
        CfGetPlaceholderInfo(
            handle.as_cfa(),
            CF_PLACEHOLDER_INFO_BASIC,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
            Some(&mut returned),
        )
        .map_err(|e| super::error_code(&e))?;
        let info = &*(buffer.as_ptr() as *const CF_PLACEHOLDER_BASIC_INFO);
        Ok(PlaceholderInfoBits {
            pin_state: info.PinState.0,
            in_sync_state: info.InSyncState.0,
        })
    }
}

/// `ERROR_INVALID_DATA` (13): the placeholder metadata the OS returned is
/// not a well-formed `CF_PLACEHOLDER_BASIC_INFO` buffer.
const ERROR_INVALID_DATA: u32 = 13;

/// Byte offset of the inline `FileIdentity` flexible array inside the
/// generated `CF_PLACEHOLDER_BASIC_INFO`: the fixed prefix the OS writes
/// before the identity bytes. Derived from the generated struct, never from
/// a handwritten layout.
const IDENTITY_INFO_OFFSET: usize = offset_of!(CF_PLACEHOLDER_BASIC_INFO, FileIdentity);

/// `ERROR_NOT_A_CLOUD_FILE` (376): the path is not a cloud placeholder at
/// all — a plain file, a foreign provider's item, or no placeholder.
pub(crate) const ERROR_NOT_A_CLOUD_FILE: u32 = 376;

/// Read a placeholder's inline identity bytes through
/// `CfGetPlaceholderInfo(CF_PLACEHOLDER_BASIC_INFO)`.
///
/// The result is exactly the `FileIdentityLength` bytes the OS stored with
/// the placeholder; a placeholder without an identity yields an empty
/// vector. The output buffer is sized from `IDENTITY_INFO_OFFSET` plus the
/// generated `CF_PLACEHOLDER_MAX_FILE_IDENTITY_LENGTH`, so any identity the
/// API can hold fits in one call, and a reported length that overruns the
/// buffer is `ERROR_INVALID_DATA`, never an over-read.
pub(crate) fn placeholder_identity(handle: &impl CfaHandle) -> Result<Vec<u8>, u32> {
    let mut buffer =
        vec![0u8; IDENTITY_INFO_OFFSET + CF_PLACEHOLDER_MAX_FILE_IDENTITY_LENGTH as usize];
    let mut returned = 0u32;
    // SAFETY: `buffer` is a valid output buffer for the basic info class and
    // is large enough for the fixed prefix plus the maximum identity length
    // the generated API defines.
    unsafe {
        CfGetPlaceholderInfo(
            handle.as_cfa(),
            CF_PLACEHOLDER_INFO_BASIC,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
            Some(&mut returned),
        )
        .map_err(|e| super::error_code(&e))?;
    }
    // `FileIdentityLength` is the authoritative identity bound; `returned`
    // is only the API's byte count and never widens the buffer.
    identity_from_info_buffer(&buffer)
}

/// Extract the inline identity from one `CF_PLACEHOLDER_BASIC_INFO` output
/// buffer. Pure and deterministic — no OS call — so the exact-length and
/// bounds contract is testable without a registered sync root.
fn identity_from_info_buffer(buffer: &[u8]) -> Result<Vec<u8>, u32> {
    if buffer.len() < IDENTITY_INFO_OFFSET {
        return Err(ERROR_INVALID_DATA);
    }
    let mut info = CF_PLACEHOLDER_BASIC_INFO::default();
    // SAFETY: `info` is a valid `CF_PLACEHOLDER_BASIC_INFO` whose fixed
    // prefix (everything before the inline `FileIdentity` array) is exactly
    // `IDENTITY_INFO_OFFSET` bytes; copying that prefix out of a buffer of
    // at least that length is in bounds on both sides.
    unsafe {
        std::ptr::copy_nonoverlapping(
            buffer.as_ptr(),
            &mut info as *mut CF_PLACEHOLDER_BASIC_INFO as *mut u8,
            IDENTITY_INFO_OFFSET,
        );
    }
    let identity_len = info.FileIdentityLength as usize;
    if identity_len > CF_PLACEHOLDER_MAX_FILE_IDENTITY_LENGTH as usize {
        return Err(ERROR_INVALID_DATA);
    }
    let end = IDENTITY_INFO_OFFSET
        .checked_add(identity_len)
        .ok_or(ERROR_INVALID_DATA)?;
    buffer
        .get(IDENTITY_INFO_OFFSET..end)
        .map(|identity| identity.to_vec())
        .ok_or(ERROR_INVALID_DATA)
}

/// On-disk (resident) ranges of a placeholder as `(offset, length)` pairs.
pub(crate) fn on_disk_ranges(
    handle: &impl CfaHandle,
    start: i64,
    length: i64,
) -> Result<Vec<(u64, u64)>, u32> {
    let mut ranges = vec![CF_FILE_RANGE { StartingOffset: 0, Length: 0 }; 256];
    let mut returned = 0u32;
    // SAFETY: `ranges` is a valid output array.
    unsafe {
        CfGetPlaceholderRangeInfo(
            handle.as_cfa(),
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
    use super::{
        entry_results, handle_fetch_placeholders, handle_notify_rename, operation_param_size,
        owned_relative, rename_spellings, CallbackContext, EventSink, RootPrefix,
        UNPROCESSED_ENTRY_HRESULT,
    };
    use std::sync::{Arc, Mutex};
    use windows::core::PCWSTR;
    use windows::Win32::Storage::CloudFilters::{
        CF_CALLBACK_INFO, CF_CALLBACK_PARAMETERS, CF_CALLBACK_PARAMETERS_0,
        CF_CALLBACK_PARAMETERS_0_10, CF_CALLBACK_PARAMETERS_0_3,
        CF_CALLBACK_RENAME_FLAG_IS_DIRECTORY, CF_CALLBACK_RENAME_FLAG_TARGET_IN_SCOPE,
        CF_OPERATION_PARAMETERS_0_0, CF_OPERATION_PARAMETERS_0_4, CF_OPERATION_PARAMETERS_0_6,
        CF_OPERATION_PARAMETERS_0_7, CF_PLACEHOLDER_BASIC_INFO, CF_PLACEHOLDER_CREATE_INFO,
    };
    use windows::core::HRESULT;

    /// The live sync root of the acceptance drive.
    const ROOT: &str = "C:\\Users\\momo-\\HF Drive\\drive-dev";
    /// The same directory as the OS spells it in `NormalizedPath`.
    const ROOT_CALLBACK: &str = "\\Users\\momo-\\HF Drive\\drive-dev";

    fn root(path: &str) -> RootPrefix {
        RootPrefix::parse(std::path::Path::new(path)).expect("root parses")
    }

    /// PCWSTR-contract buffer: NUL-terminated wide spelling, exactly like
    /// the production `wide` helper and the OS. `PCWSTR::as_wide`/`to_string`
    /// scan to the first NUL, so an unterminated fixture buffer over-reads
    /// into adjacent heap instead of producing its spelling.
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    fn owned(root_path: &str, callback: &str) -> Option<String> {
        // Hand the converter the spelling exactly as `as_wide()` yields it:
        // the NUL-terminated buffer's data without the trailing 0.
        let spelling = wide(callback);
        owned_relative(&root(root_path), &spelling[..spelling.len() - 1])
    }

    #[test]
    fn operation_sizes_include_the_union_offset_and_active_member() {
        assert_eq!(operation_param_size::<CF_OPERATION_PARAMETERS_0_0>(), 40);
        assert_eq!(operation_param_size::<CF_OPERATION_PARAMETERS_0_4>(), 40);
        assert_eq!(operation_param_size::<CF_OPERATION_PARAMETERS_0_6>(), 16);
        assert_eq!(operation_param_size::<CF_OPERATION_PARAMETERS_0_7>(), 16);
    }

    // -- production path conversion -------------------------------------

    #[test]
    fn volume_root_callback_path_is_the_empty_spelling() {
        assert_eq!(owned(ROOT, ROOT_CALLBACK), Some(String::new()));
    }

    #[test]
    fn nested_child_is_sync_root_relative() {
        assert_eq!(
            owned(ROOT, "\\Users\\momo-\\HF Drive\\drive-dev\\docs\\a.txt"),
            Some("docs\\a.txt".to_owned())
        );
    }

    #[test]
    fn case_equivalent_prefix_keeps_the_child_spelling() {
        assert_eq!(
            owned(ROOT, "\\users\\MOMO-\\hf drive\\DRIVE-DEV\\Docs\\A.TXT"),
            Some("Docs\\A.TXT".to_owned())
        );
    }

    #[test]
    fn sibling_prefix_and_ancestors_are_not_owned() {
        // String-prefix neighbours of the root never borrow its ownership.
        assert_eq!(owned(ROOT, "\\Users\\momo-\\HF Drive\\drive-dev2\\x"), None);
        assert_eq!(owned(ROOT, "\\Users\\momo-\\HF Drive\\drive-dev-old\\x"), None);
        assert_eq!(owned(ROOT, "\\Users\\momo-\\HF Drive\\drive-dev2"), None);
        // The root's ancestors are outside the root.
        assert_eq!(owned(ROOT, "\\Users\\momo-\\HF Drive"), None);
    }

    #[test]
    fn other_volume_with_the_same_tail_is_not_owned() {
        assert_eq!(owned(ROOT, "D:\\Users\\momo-\\HF Drive\\drive-dev\\x"), None);
    }

    #[test]
    fn extended_and_device_spellings_convert_to_the_same_relative_path() {
        assert_eq!(
            owned(ROOT, "\\\\?\\C:\\Users\\momo-\\HF Drive\\drive-dev\\a"),
            Some("a".to_owned())
        );
        assert_eq!(
            owned(ROOT, "\\Device\\HarddiskVolume7\\Users\\momo-\\HF Drive\\drive-dev\\a"),
            Some("a".to_owned())
        );
        // The root itself may be spelled extended while the callback is not.
        assert_eq!(
            owned("\\\\?\\C:\\Users\\momo-\\HF Drive\\drive-dev", "C:\\Users\\momo-\\HF Drive\\drive-dev\\a"),
            Some("a".to_owned())
        );
    }

    #[test]
    fn same_shape_volume_guid_mismatch_is_not_owned() {
        let guid_root = "\\\\?\\Volume{1234}\\Users\\momo-\\HF Drive\\drive-dev";
        assert_eq!(
            owned(guid_root, "\\\\?\\Volume{1234}\\Users\\momo-\\HF Drive\\drive-dev\\a"),
            Some("a".to_owned())
        );
        assert_eq!(
            owned(guid_root, "\\\\?\\Volume{9999}\\Users\\momo-\\HF Drive\\drive-dev\\a"),
            None
        );
    }

    #[test]
    fn same_shape_device_mismatch_is_not_owned() {
        let device_root = "\\Device\\HarddiskVolume1\\Users\\momo-\\HF Drive\\drive-dev";
        assert_eq!(
            owned(device_root, "\\Device\\HarddiskVolume1\\Users\\momo-\\HF Drive\\drive-dev\\a"),
            Some("a".to_owned())
        );
        assert_eq!(
            owned(device_root, "\\Device\\HarddiskVolume2\\Users\\momo-\\HF Drive\\drive-dev\\a"),
            None
        );
    }

    #[test]
    fn traversal_and_malformed_paths_never_become_root_or_child() {
        assert_eq!(owned(ROOT, "\\Users\\momo-\\HF Drive\\drive-dev\\..\\..\\secret"), None);
        assert_eq!(owned(ROOT, "\\Users\\momo-\\HF Drive\\drive-dev\\.\\x"), None);
        assert_eq!(owned(ROOT, "\\..\\Users\\momo-\\HF Drive\\drive-dev"), None);
        assert_eq!(owned(ROOT, ""), None);
        assert_eq!(owned(ROOT, "\\"), None);
        assert_eq!(owned(ROOT, "\\Users\\momo-\\HF Drive\\drive-dev\\a:b"), None);
        assert_eq!(owned(ROOT, "\\\\server\\share\\x"), None);
        assert_eq!(owned(ROOT, "\\Users\\\\momo-"), None);
    }

    #[test]
    fn one_trailing_separator_is_the_same_subject() {
        assert_eq!(owned(ROOT, "\\Users\\momo-\\HF Drive\\drive-dev\\"), Some(String::new()));
        assert_eq!(
            owned(ROOT, "\\Users\\momo-\\HF Drive\\drive-dev\\docs\\"),
            Some("docs".to_owned())
        );
    }

    #[test]
    fn a_sync_root_on_the_volume_root_maps_only_absolute_children() {
        assert_eq!(owned("C:\\", "\\"), Some(String::new()));
        assert_eq!(owned("C:\\", "\\x\\y"), Some("x\\y".to_owned()));
        assert_eq!(owned("C:\\", ""), None);
        assert_eq!(owned("C:\\", "\\\\"), None);
    }

    // -- rename spelling decision --------------------------------------

    #[test]
    fn rename_outside_source_and_inside_target_keep_both_meaningful() {
        assert_eq!(
            rename_spellings(
                None,
                "E:\\other\\old".to_owned(),
                false,
                Some("new".to_owned()),
                "E:\\other\\new".to_owned(),
                true,
            ),
            Some(("E:\\other\\old".to_owned(), "new".to_owned()))
        );
    }

    #[test]
    fn rename_move_out_keeps_the_outside_target() {
        assert_eq!(
            rename_spellings(
                Some("old".to_owned()),
                "C:\\Users\\momo-\\HF Drive\\drive-dev\\old".to_owned(),
                true,
                None,
                "E:\\other\\new".to_owned(),
                false,
            ),
            Some(("old".to_owned(), "E:\\other\\new".to_owned()))
        );
    }

    #[test]
    fn rename_an_in_scope_side_must_be_owned() {
        assert_eq!(
            rename_spellings(
                None,
                "E:\\other\\old".to_owned(),
                true,
                Some("new".to_owned()),
                String::new(),
                true,
            ),
            None
        );
        assert_eq!(
            rename_spellings(
                Some("old".to_owned()),
                String::new(),
                true,
                None,
                "E:\\other\\new".to_owned(),
                true,
            ),
            None
        );
    }

    #[test]
    fn rename_of_the_root_itself_uses_the_empty_spelling() {
        assert_eq!(
            rename_spellings(
                Some(String::new()),
                String::new(),
                true,
                Some("renamed".to_owned()),
                String::new(),
                true,
            ),
            Some((String::new(), "renamed".to_owned()))
        );
    }

    // -- native completion ABI edges ------------------------------------

    #[test]
    fn unprocessed_entries_are_reported_as_failures() {
        let entries = [
            CF_PLACEHOLDER_CREATE_INFO {
                Result: HRESULT(0),
                CreateUsn: 7,
                ..Default::default()
            },
            CF_PLACEHOLDER_CREATE_INFO {
                Result: HRESULT(0),
                CreateUsn: 9,
                ..Default::default()
            },
        ];
        let results = entry_results(&entries, 1);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].result, 0);
        assert_eq!(results[0].create_usn, 7);
        assert_eq!(results[1].result, UNPROCESSED_ENTRY_HRESULT);
        assert_eq!(results[1].create_usn, 0);
        let results = entry_results(&entries, 2);
        assert_eq!(results[0].create_usn, 7);
        assert_eq!(results[1].create_usn, 9);
        assert!(entry_results(&[], 0).is_empty());
    }

    // -- population completion contract --------------------------------

    fn entry(result: i32) -> super::EntryResult {
        super::EntryResult {
            result,
            create_usn: 0,
        }
    }

    #[test]
    fn population_calls_are_bounded_and_never_truncate() {
        let calls: Vec<_> = super::population_calls(2500).collect();
        assert_eq!(calls, vec![0..1000, 1000..2000, 2000..2500, 2500..2500]);
        assert_eq!(super::population_calls(1).collect::<Vec<_>>(), vec![0..1, 1..1]);
        assert_eq!(
            super::population_calls(1000).collect::<Vec<_>>(),
            vec![0..1000, 1000..1000]
        );
        assert!(calls.iter().all(|call| call.len() <= super::POPULATION_BATCH_MAX));
    }

    #[test]
    fn empty_directory_completes_but_empty_subset_never_claims_complete() {
        // The empty delivery shape: the terminal call with zero entries.
        assert_eq!(super::population_calls(0).collect::<Vec<_>>(), vec![0..0]);
        // A genuinely empty directory IS fully populated (all zero of its
        // entries are present) — the old always-`FLAG_NONE` completion left
        // this directory endlessly re-fetching.
        assert!(super::directory_populated_mark(true, &[]));
        // An empty delivery that is NOT the complete listing (children that
        // cannot become placeholders were dropped) must never claim to be.
        assert!(!super::directory_populated_mark(false, &[]));
    }

    #[test]
    fn only_complete_deliveries_with_every_entry_present_are_marked() {
        let all_created = [entry(0), entry(0)];
        assert!(super::directory_populated_mark(true, &all_created));
        // The OS not processing an entry (batch tail) is a missing name.
        assert!(!super::directory_populated_mark(true, &[
            entry(0),
            entry(UNPROCESSED_ENTRY_HRESULT),
        ]));
        // A real per-entry failure is a missing name too.
        assert!(!super::directory_populated_mark(true, &[
            entry(0),
            entry(0x8007_0070u32 as i32), // HRESULT_FROM_WIN32(ERROR_DISK_FULL)
        ]));
        // A subset delivery is never complete, however clean its entries.
        assert!(!super::directory_populated_mark(false, &all_created));
    }

    #[test]
    fn occupied_names_count_as_present_and_missing_names_do_not() {
        // Created (0 and the STATUS_OBJECT_NAME_EXISTS success warning) and
        // the untouched-occupied name codes mean the name is resolvable.
        assert!(super::entry_present(0));
        assert!(super::entry_present(0x4000_0000u32 as i32));
        assert!(super::entry_present(0x8007_0050u32 as i32)); // ERROR_FILE_EXISTS
        assert!(super::entry_present(0x8007_00B7u32 as i32)); // ERROR_ALREADY_EXISTS
        assert!(super::entry_present(0xC000_0035u32 as i32)); // STATUS_OBJECT_NAME_COLLISION
        // Anything else leaves the name missing.
        assert!(!super::entry_present(UNPROCESSED_ENTRY_HRESULT));
        assert!(!super::entry_present(0x8007_0781u32 as i32)); // ERROR_CANT_RESOLVE_FILENAME
        assert!(!super::entry_present(0x8007_0005u32 as i32)); // E_ACCESSDENIED
        // A complete delivery whose entries are all occupied names is still
        // a complete listing (occupied names are preserved, never overwritten).
        assert!(super::directory_populated_mark(true, &[
            entry(0),
            entry(0xC000_0035u32 as i32),
        ]));
    }

    // -- placeholder identity buffer contract --------------------------

    /// Build a synthetic `CF_PLACEHOLDER_BASIC_INFO` output buffer: the
    /// generated fixed prefix carrying `claimed_length`, followed by exactly
    /// `identity` bytes (they may disagree, as a corrupt OS report would).
    fn info_buffer(claimed_length: u32, identity: &[u8]) -> Vec<u8> {
        let info = CF_PLACEHOLDER_BASIC_INFO {
            FileIdentityLength: claimed_length,
            ..Default::default()
        };
        let mut buffer = vec![0u8; super::IDENTITY_INFO_OFFSET + identity.len()];
        // SAFETY: the fixed prefix occupies exactly `IDENTITY_INFO_OFFSET`
        // bytes at the front of `info`, which is larger than that prefix.
        unsafe {
            std::ptr::copy_nonoverlapping(
                &info as *const CF_PLACEHOLDER_BASIC_INFO as *const u8,
                buffer.as_mut_ptr(),
                super::IDENTITY_INFO_OFFSET,
            );
        }
        buffer[super::IDENTITY_INFO_OFFSET..].copy_from_slice(identity);
        buffer
    }

    #[test]
    fn identity_buffer_extracts_exactly_the_reported_bytes() {
        let identity = [0xABu8; 53];
        assert_eq!(
            super::identity_from_info_buffer(&info_buffer(53, &identity)),
            Ok(identity.to_vec())
        );
        // A placeholder with no stored identity is an empty vector, not an
        // error: it is simply not an HFDR placeholder.
        assert_eq!(
            super::identity_from_info_buffer(&info_buffer(0, &[])),
            Ok(Vec::new())
        );
    }

    #[test]
    fn identity_buffer_rejects_truncated_fixed_prefix() {
        let identity = [1u8; 53];
        let buffer = info_buffer(53, &identity);
        for len in 0..super::IDENTITY_INFO_OFFSET {
            assert_eq!(
                super::identity_from_info_buffer(&buffer[..len]),
                Err(super::ERROR_INVALID_DATA),
                "prefix truncated to {len} bytes must be rejected"
            );
        }
    }

    #[test]
    fn identity_buffer_rejects_length_overruns_without_overreading() {
        let identity = [2u8; 53];
        // Claimed identity longer than the bytes present after the prefix:
        // rejected, never over-read.
        assert_eq!(
            super::identity_from_info_buffer(&info_buffer(54, &identity)),
            Err(super::ERROR_INVALID_DATA)
        );
        // A claimed length beyond the generated API maximum is never trusted.
        assert_eq!(
            super::identity_from_info_buffer(&info_buffer(
                super::CF_PLACEHOLDER_MAX_FILE_IDENTITY_LENGTH + 1,
                &identity
            )),
            Err(super::ERROR_INVALID_DATA)
        );
    }

    // -- production handlers with fabricated callback structs -----------

    struct CaptureSink(Arc<Mutex<Vec<crate::cfapi::events::ProviderEvent>>>);

    impl EventSink for CaptureSink {
        fn on_fetch_data(&self, request: crate::cfapi::events::FetchRequest) {
            let _ = request;
        }
        fn on_cancel_fetch_data(&self, cancel: crate::cfapi::events::CancelRanges) {
            let _ = cancel;
        }
        fn on_fetch_placeholders(&self, request: crate::cfapi::events::PlaceholdersRequest) {
            self.0
                .lock()
                .unwrap()
                .push(crate::cfapi::events::ProviderEvent::FetchPlaceholders(request));
        }
        fn on_cancel_fetch_placeholders(&self, cancel: crate::cfapi::events::CancelRanges) {
            let _ = cancel;
        }
        fn on_rename(&self, notification: crate::cfapi::events::RenameNotification) {
            self.0
                .lock()
                .unwrap()
                .push(crate::cfapi::events::ProviderEvent::NotifyRename(notification));
        }
        fn on_delete(&self, notification: crate::cfapi::events::DeleteNotification) {
            self.0
                .lock()
                .unwrap()
                .push(crate::cfapi::events::ProviderEvent::NotifyDelete(notification));
        }
        fn on_rename_completion(&self, completion: crate::cfapi::events::RenameCompletion) {
            let _ = completion;
        }
        fn on_delete_completion(&self, completion: crate::cfapi::events::DeleteCompletion) {
            let _ = completion;
        }
    }

    fn context(events: Arc<Mutex<Vec<crate::cfapi::events::ProviderEvent>>>) -> Arc<CallbackContext> {
        CallbackContext::new(
            hfdrive_core::ids::WorkspaceId::new(),
            root(ROOT),
            Box::new(CaptureSink(events)),
        )
    }

    #[test]
    fn fetch_placeholders_on_the_root_emits_the_empty_spelling() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let context = context(events.clone());
        let path = wide(ROOT_CALLBACK);
        let info = CF_CALLBACK_INFO {
            NormalizedPath: PCWSTR(path.as_ptr()),
            ..Default::default()
        };
        let params = CF_CALLBACK_PARAMETERS {
            ParamSize: 0,
            Anonymous: CF_CALLBACK_PARAMETERS_0 {
                FetchPlaceholders: CF_CALLBACK_PARAMETERS_0_3 {
                    Flags: Default::default(),
                    Pattern: PCWSTR::null(),
                },
            },
        };
        handle_fetch_placeholders(&context, &info, &params);
        let captured = events.lock().unwrap();
        assert_eq!(captured.len(), 1);
        match &captured[0] {
            crate::cfapi::events::ProviderEvent::FetchPlaceholders(request) => {
                assert_eq!(request.normalized_path, "");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn rename_move_in_keeps_the_outside_source_and_relative_target() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let context = context(events.clone());
        let source = wide("\\Device\\HarddiskVolume3\\Elsewhere\\old");
        let target = wide("\\Users\\momo-\\HF Drive\\drive-dev\\new");
        let info = CF_CALLBACK_INFO {
            NormalizedPath: PCWSTR(source.as_ptr()),
            ..Default::default()
        };
        let params = CF_CALLBACK_PARAMETERS {
            ParamSize: 0,
            Anonymous: CF_CALLBACK_PARAMETERS_0 {
                Rename: CF_CALLBACK_PARAMETERS_0_10 {
                    Flags: CF_CALLBACK_RENAME_FLAG_TARGET_IN_SCOPE
                        | CF_CALLBACK_RENAME_FLAG_IS_DIRECTORY,
                    TargetPath: PCWSTR(target.as_ptr()),
                },
            },
        };
        handle_notify_rename(&context, &info, &params);
        let captured = events.lock().unwrap();
        assert_eq!(captured.len(), 1);
        match &captured[0] {
            crate::cfapi::events::ProviderEvent::NotifyRename(notification) => {
                assert_eq!(notification.normalized_path, "\\Device\\HarddiskVolume3\\Elsewhere\\old");
                assert_eq!(notification.target_path, "new");
                assert!(!notification.source_in_scope);
                assert!(notification.target_in_scope);
                assert!(notification.is_directory);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
}
