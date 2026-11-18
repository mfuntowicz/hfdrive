//! `StorageProviderSyncRootManager` adapters (WinRT).
//!
//! Registration goes **only** through `StorageProviderSyncRootManager`;
//! `CfRegisterSyncRoot` is never called by HF Drive. The WinRT/COM apartment
//! is initialized per calling thread around each call (`CoInitializeEx` in
//! MTA mode). The apartment accounting is exact (K18):
//!
//! * `CoInitializeEx` is reference-counted: both `S_OK` and `S_FALSE` are
//!   successful calls that increment the thread's COM reference count, so
//!   **each** of them requires exactly one matching `CoUninitialize` when the
//!   guard drops. Failed HRESULTs initialize nothing and never schedule
//!   teardown.
//! * Initialization errors (`RPC_E_CHANGED_MODE` and every other failure)
//!   are **returned** and the call that needed COM does not proceed. WinRT
//!   calls never run on an uninitialized or incompatible apartment here.
//! * The result mapping is modeled as pure data ([`ComInit`]) so the
//!   `S_OK`/`S_FALSE`/`RPC_E_CHANGED_MODE` contract is unit-testable
//!   without touching COM.

use std::path::{Path, PathBuf};

use uuid::Uuid;
use windows::core::{GUID, HSTRING};
use windows::Storage::Provider::{
    StorageProviderHardlinkPolicy, StorageProviderHydrationPolicy,
    StorageProviderHydrationPolicyModifier, StorageProviderInSyncPolicy,
    StorageProviderPopulationPolicy, StorageProviderSyncRootInfo,
    StorageProviderSyncRootManager,
};
use windows::Storage::StorageFolder;
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};
use windows_future::AsyncStatus;

/// The COM apartment states one `CoInitializeEx(COINIT_MULTITHREADED)` call
/// can produce. Pure data: the mapping from the raw HRESULT lives in
/// [`ComInit::from_hresult`] and the guard's teardown scheduling in
/// [`MtaGuard::from_state`], so both can be tested deterministically without
/// COM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ComInit {
    /// `S_OK`: this call initialized the apartment and incremented the
    /// thread's COM reference count. One matching `CoUninitialize` runs when
    /// the guard drops.
    Owned,
    /// `S_FALSE`: the thread's apartment was already initialized in this
    /// mode. Still a successful `CoInitializeEx` call — COM is
    /// reference-counted, so this call also incremented the thread's
    /// reference count and one matching `CoUninitialize` runs when the guard
    /// drops. It is never treated as "not ours to undo".
    AlreadyInitialized,
    /// `RPC_E_CHANGED_MODE`: the thread is in a different apartment type.
    /// Every other failure HRESULT maps here too. The COM-using call must
    /// not proceed and the error is returned to its caller.
    Failed { hresult: u32 },
}

impl ComInit {
    /// Map one raw `CoInitializeEx` HRESULT (as `u32`) to the apartment
    /// state. `S_OK` (0) and `S_FALSE` (1) are the successful results, each
    /// of which schedules the matching `CoUninitialize`; every other HRESULT
    /// is a failure that schedules nothing.
    pub(crate) fn from_hresult(hresult: u32) -> Self {
        match hresult {
            0x0000_0000 => ComInit::Owned,               // S_OK
            0x0000_0001 => ComInit::AlreadyInitialized,  // S_FALSE
            code => ComInit::Failed { hresult: code },   // incl. RPC_E_CHANGED_MODE
        }
    }

    /// True exactly for the successful results (`S_OK` and `S_FALSE`): both
    /// increment the thread's COM reference count and each requires exactly
    /// one `CoUninitialize` when the guard drops.
    pub(crate) fn owns_uninitialize(self) -> bool {
        matches!(self, ComInit::Owned | ComInit::AlreadyInitialized)
    }

    /// The error HRESULT to return, if any. `S_OK`/`S_FALSE` are successes.
    pub(crate) fn error(self) -> Option<u32> {
        match self {
            ComInit::Failed { hresult } => Some(hresult),
            _ => None,
        }
    }
}

/// Per-call apartment guard: when the call's `CoInitializeEx` returned
/// `S_OK` **or** `S_FALSE`, the matching `CoUninitialize` runs on drop — both
/// results increment the thread's COM reference count. A failed result never
/// constructs a guard, so no teardown runs for a call that initialized
/// nothing.
#[derive(Debug)]
pub(crate) struct MtaGuard {
    /// Always `true` for a guard created from a successful (`S_OK` or
    /// `S_FALSE`) `CoInitializeEx` call: exactly one `CoUninitialize` is
    /// pending until the guard drops.
    teardown: bool,
}

impl MtaGuard {
    /// Initialize MTA mode on this thread and map the result. Errors are
    /// returned instead of being swallowed: a call that needs COM must not
    /// proceed on an uninitialized/incompatible apartment (`RPC_E_CHANGED_MODE`
    /// included).
    pub(crate) fn enter() -> Result<Self, u32> {
        Self::from_state(map_init_result(unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED)
        }))
    }

    /// Pure half of [`MtaGuard::enter`], testable without COM: a failed
    /// HRESULT is returned unchanged, no guard exists and no teardown is ever
    /// scheduled; both `S_OK` and `S_FALSE` build a guard that schedules
    /// exactly one `CoUninitialize`.
    fn from_state(state: ComInit) -> Result<Self, u32> {
        match state.error() {
            Some(code) => Err(code),
            None => Ok(Self {
                teardown: state.owns_uninitialize(),
            }),
        }
    }

    /// Consume this guard's pending teardown. Returns `true` exactly once for
    /// a guard built from `S_OK`/`S_FALSE`; `Drop` uses this one-shot so tests
    /// can drive the exact drop predicate without issuing a real COM call.
    fn take_teardown(&mut self) -> bool {
        std::mem::replace(&mut self.teardown, false)
    }
}

impl Drop for MtaGuard {
    fn drop(&mut self) {
        if self.take_teardown() {
            // SAFETY: exactly one successful (`S_OK` or `S_FALSE`)
            // `CoInitializeEx` is undone here — each of those calls added one
            // reference to the thread's COM count and this removes exactly
            // that one. Failed results never construct a guard and so never
            // reach this branch.
            unsafe { CoUninitialize() };
        }
    }
}

/// Map the raw COM initialization result into the modeled [`ComInit`]. The
/// three documented outcomes are distinguished explicitly; every other
/// failure stays an error and is returned, never interpreted as success.
pub(crate) fn map_init_result(result: windows::core::HRESULT) -> ComInit {
    ComInit::from_hresult(result.0 as u32)
}

/// Explorer display/icon resources for HF Drive sync roots.
pub(crate) struct RootDisplay {
    pub display_name: String,
    pub icon_resource: String,
    pub version: String,
    pub allow_pinning: bool,
}

/// A registered (or to-be-registered) root, expressed in WinRT terms.
pub(crate) struct RegistrationRequest {
    pub id: String,
    pub path: PathBuf,
    /// Fixed provider GUID (RFC-4122 identity).
    pub provider_guid: Uuid,
    pub display: RootDisplay,
    /// The frozen safe policy; mapped to WinRT values below.
    pub policy: crate::cfapi::registration::SyncPolicy,
}

fn map_policies(
    policy: &crate::cfapi::registration::SyncPolicy,
) -> (
    StorageProviderHydrationPolicy,
    StorageProviderHydrationPolicyModifier,
    StorageProviderPopulationPolicy,
    StorageProviderInSyncPolicy,
    StorageProviderHardlinkPolicy,
) {
    use crate::cfapi::registration::{HardlinkPolicy, HydrationModifiers, HydrationPolicy, PopulationPolicy};
    use windows::Storage::Provider::{
        StorageProviderHydrationPolicyModifier as Mod, StorageProviderInSyncPolicy as InSync,
        StorageProviderPopulationPolicy as Pop,
    };
    let hydration = match policy.hydration {
        HydrationPolicy::Partial => StorageProviderHydrationPolicy::Partial,
    };
    let modifier = match policy.hydration_modifiers {
        HydrationModifiers::None => Mod::None,
    };
    let population = match policy.population {
        PopulationPolicy::Full => Pop::Full,
    };
    let hardlink = match policy.hardlinks {
        HardlinkPolicy::None => StorageProviderHardlinkPolicy::None,
    };
    // In-sync tracking of file content + attributes + timestamps (all named
    // tracking bits); `PreserveInsyncForSyncEngine` is deliberately unset.
    let in_sync = InSync::FileCreationTime
        | InSync::FileReadOnlyAttribute
        | InSync::FileHiddenAttribute
        | InSync::FileSystemAttribute
        | InSync::FileLastWriteTime
        | InSync::DirectoryCreationTime
        | InSync::DirectoryReadOnlyAttribute
        | InSync::DirectoryHiddenAttribute
        | InSync::DirectorySystemAttribute
        | InSync::DirectoryLastWriteTime;
    (hydration, modifier, population, in_sync, hardlink)
}

/// Register (or idempotently re-register) one sync root.
pub(crate) fn register(request: &RegistrationRequest) -> Result<(), u32> {
    // COM initialization failure is returned before any WinRT call runs.
    let _mta = MtaGuard::enter()?;
    let (hydration, modifier, population, in_sync, hardlink) = map_policies(&request.policy);
    let info = StorageProviderSyncRootInfo::new().map_err(|e| super::error_code(&e))?;
    info.SetId(&HSTRING::from(request.id.as_str()))
        .map_err(|e| super::error_code(&e))?;
    let folder = resolve_folder(&request.path)?;
    info.SetPath(&folder).map_err(|e| super::error_code(&e))?;
    info.SetDisplayNameResource(&HSTRING::from(request.display.display_name.as_str()))
        .map_err(|e| super::error_code(&e))?;
    info.SetIconResource(&HSTRING::from(request.display.icon_resource.as_str()))
        .map_err(|e| super::error_code(&e))?;
    info.SetHydrationPolicy(hydration)
        .map_err(|e| super::error_code(&e))?;
    info.SetHydrationPolicyModifier(modifier)
        .map_err(|e| super::error_code(&e))?;
    info.SetPopulationPolicy(population)
        .map_err(|e| super::error_code(&e))?;
    info.SetInSyncPolicy(in_sync).map_err(|e| super::error_code(&e))?;
    info.SetHardlinkPolicy(hardlink)
        .map_err(|e| super::error_code(&e))?;
    info.SetShowSiblingsAsGroup(false)
        .map_err(|e| super::error_code(&e))?;
    info.SetVersion(&HSTRING::from(request.display.version.as_str()))
        .map_err(|e| super::error_code(&e))?;
    info.SetAllowPinning(request.display.allow_pinning)
        .map_err(|e| super::error_code(&e))?;
    info.SetProviderId(GUID::from_u128(request.provider_guid.as_u128()))
        .map_err(|e| super::error_code(&e))?;
    StorageProviderSyncRootManager::Register(&info).map_err(|e| super::error_code(&e))
}

/// Unregister the sync root with `id`. Callers treat "not found" as an
/// already-unregistered success.
pub(crate) fn unregister(id: &str) -> Result<(), u32> {
    let _mta = MtaGuard::enter()?;
    StorageProviderSyncRootManager::Unregister(&HSTRING::from(id))
        .map_err(|e| super::error_code(&e))
}

/// One currently registered sync root on this machine/user (any provider).
pub(crate) struct RegisteredRoot {
    pub id: String,
    pub path: Option<PathBuf>,
}

/// All sync roots registered with Windows (any provider).
pub(crate) fn current_roots(_skip_path_for: Option<&str>) -> Result<Vec<RegisteredRoot>, u32> {
    let _mta = MtaGuard::enter()?;
    let roots =
        StorageProviderSyncRootManager::GetCurrentSyncRoots().map_err(|e| super::error_code(&e))?;
    let size = roots.Size().map_err(|e| super::error_code(&e))?;
    let mut out = Vec::new();
    for index in 0..size {
        let info = roots.GetAt(index).map_err(|e| super::error_code(&e))?;
        let id = info.Id().map_err(|e| super::error_code(&e))?.to_string();
        // A deleted root's IStorageFolder can fail natively. Only its stable
        // ID is needed for identity/overlap checks; never resolve the folder
        // object during enumeration.
        out.push(RegisteredRoot { id, path: None });
    }
    Ok(out)
}

/// Queries one registration by candidate folder without enumerating other roots.
pub(crate) fn sync_root_info_for_folder(folder: &StorageFolder) -> Result<StorageProviderSyncRootInfo, u32> {
    let _mta = MtaGuard::enter()?;
    StorageProviderSyncRootManager::GetSyncRootInformationForFolder(folder)
        .map_err(|e| super::error_code(&e))
}

/// Queries one registration by stable ID without touching its folder object.
pub(crate) fn sync_root_info_for_id(id: &str) -> Result<StorageProviderSyncRootInfo, u32> {
    let _mta = MtaGuard::enter()?;
    StorageProviderSyncRootManager::GetSyncRootInformationForId(&HSTRING::from(id))
        .map_err(|e| super::error_code(&e))
}

/// Resolve a filesystem path to its WinRT folder object, waiting for the
/// async operation on the calling (MTA) thread. Resolving a local folder
/// completes promptly; the wait is bounded and cancellable only by timeout.
pub(crate) fn resolve_folder(path: &Path) -> Result<StorageFolder, u32> {
    let hpath = HSTRING::from(path.to_string_lossy().as_ref());
    let operation =
        StorageFolder::GetFolderFromPathAsync(&hpath).map_err(|e| super::error_code(&e))?;
    // `AsyncStatus` discriminants: Started = 0, Completed = 1, Canceled = 2,
    // Error = 3 (windows-future generated enums). Comparing `.0` keeps the
    // code independent of the enum's derive set.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let status = operation
            .Status()
            .map_err(|e| super::error_code(&e))?;
        if status.0 == AsyncStatus::Completed.0 {
            return operation.GetResults().map_err(|e| super::error_code(&e));
        }
        if status.0 != AsyncStatus::Started.0 {
            // Canceled or Error: surface the async error code when present.
            return Err(operation
                .ErrorCode()
                .map(|hr| hr.0 as u32)
                .unwrap_or(0x8000_4005));
        }
        if std::time::Instant::now() >= deadline {
            // HRESULT_FROM_WIN32(ERROR_TIMEOUT).
            return Err(0x8007_05B4);
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `S_OK` maps to the first successful initialization: the call
    /// incremented the thread's COM reference count, so one matching
    /// `CoUninitialize` is scheduled for exactly this guard.
    #[test]
    fn s_ok_schedules_the_matching_uninitialize() {
        let state = ComInit::from_hresult(0x0000_0000);
        assert_eq!(state, ComInit::Owned);
        assert!(
            state.owns_uninitialize(),
            "S_OK increments the COM refcount and schedules CoUninitialize"
        );
        assert_eq!(state.error(), None, "S_OK is not an error to return");
    }

    /// `S_FALSE` is still a successful, reference-counted `CoInitializeEx`
    /// call (the apartment was already initialized in this mode): it also
    /// incremented the thread's COM reference count and therefore schedules
    /// the matching `CoUninitialize` — it is **not** "someone else's"
    /// initialization to leave alone.
    #[test]
    fn s_false_schedules_the_matching_uninitialize() {
        let state = ComInit::from_hresult(0x0000_0001);
        assert_eq!(state, ComInit::AlreadyInitialized);
        assert!(
            state.owns_uninitialize(),
            "S_FALSE is a successful refcounted CoInitializeEx and requires the matching CoUninitialize"
        );
        assert_eq!(state.error(), None, "S_FALSE is not an error to return");
    }

    /// `RPC_E_CHANGED_MODE` and every other failure HRESULT are returned as
    /// errors and the COM-using call never proceeds on them.
    #[test]
    fn rpc_e_changed_mode_is_an_error_never_a_success() {
        let rpc_e_changed_mode = 0x8001_0106;
        let state = ComInit::from_hresult(rpc_e_changed_mode);
        assert_eq!(
            state,
            ComInit::Failed {
                hresult: rpc_e_changed_mode
            }
        );
        assert!(!state.owns_uninitialize());
        assert_eq!(state.error(), Some(rpc_e_changed_mode));

        // Any other failure (e.g. E_OUTOFMEMORY) is likewise an error and
        // never schedules teardown of an apartment the failed call never
        // initialized.
        let other = 0x8007_000E;
        let state = ComInit::from_hresult(other);
        assert_eq!(
            state,
            ComInit::Failed { hresult: other },
            "no failure is ever interpreted as S_OK/S_FALSE"
        );
        assert!(!state.owns_uninitialize());
        assert_eq!(state.error(), Some(other));
    }

    /// Exactly the two successful HRESULTs schedule `CoUninitialize` (`S_OK`
    /// and `S_FALSE`); the success codes are distinct from the error codes in
    /// the mapping, exhaustively over the three documented outcomes.
    #[test]
    fn only_success_codes_schedule_teardown() {
        for hresult in [0x0000_0000u32, 0x0000_0001, 0x8001_0106, 0x8000_4005, 0x8007_000E] {
            let state = ComInit::from_hresult(hresult);
            let should_uninit = hresult == 0x0000_0000 || hresult == 0x0000_0001;
            assert_eq!(
                state.owns_uninitialize(),
                should_uninit,
                "both S_OK (0) and S_FALSE (1) schedule one CoUninitialize (hresult={hresult:#010x})"
            );
            let should_error = !should_uninit;
            assert_eq!(
                state.error().is_some(),
                should_error,
                "only S_OK/S_FALSE are successes (hresult={hresult:#010x})"
            );
        }
    }

    /// `map_init_result` preserves the HRESULT bits for errors (so callers
    /// return the exact code, e.g. `RPC_E_CHANGED_MODE`), and models the two
    /// success codes by value.
    #[test]
    fn mapping_preserves_exact_hresult_bits() {
        let raw = windows::core::HRESULT(0x8001_0106u32 as i32);
        assert_eq!(
            map_init_result(raw),
            ComInit::Failed {
                hresult: 0x8001_0106
            }
        );
        assert_eq!(
            map_init_result(windows::core::HRESULT(0)),
            ComInit::Owned
        );
        assert_eq!(
            map_init_result(windows::core::HRESULT(1)),
            ComInit::AlreadyInitialized
        );
    }

    /// Every teardown path of the guard for successful results, driven
    /// through the pure `from_state`/`take_teardown` seam without issuing a
    /// COM call: `S_OK` and `S_FALSE` each build a guard whose scheduled
    /// `CoUninitialize` fires exactly once — never twice, never zero times.
    #[test]
    fn guard_teardown_paths_success_is_one_shot_per_call() {
        for hresult in [0x0000_0000u32, 0x0000_0001] {
            let state = ComInit::from_hresult(hresult);
            let mut guard = MtaGuard::from_state(state).unwrap_or_else(|code| {
                panic!("success {hresult:#010x} must build a guard, got error {code:#010x}")
            });
            assert!(
                guard.take_teardown(),
                "successful {hresult:#010x} schedules exactly one teardown"
            );
            assert!(
                !guard.take_teardown(),
                "the scheduled teardown is one-shot for {hresult:#010x}"
            );
            // Dropping after the one-shot was consumed performs no second
            // teardown: Drop's only COM call is gated by `take_teardown`.
            drop(guard);
        }
    }

    /// The failed-HRESULT teardown path: `RPC_E_CHANGED_MODE` and every other
    /// failure return the exact HRESULT and build no guard at all, so no
    /// teardown can ever be scheduled or run.
    #[test]
    fn guard_teardown_paths_failures_schedule_nothing() {
        for hresult in [0x8001_0106u32, 0x8000_4005, 0x8007_000E] {
            let state = ComInit::from_hresult(hresult);
            match MtaGuard::from_state(state) {
                Ok(_) => panic!(
                    "failed HRESULT {hresult:#010x} must not build a guard (no teardown may be scheduled)"
                ),
                Err(code) => assert_eq!(code, hresult, "the exact HRESULT is returned unchanged"),
            }
        }
    }

    /// The full raw-HRESULT-to-guard pipeline preserves the exact HRESULT
    /// bits end-to-end (`map_init_result` -> `MtaGuard::from_state`), and
    /// `RPC_E_CHANGED_MODE` stops before any COM-using call.
    #[test]
    fn enter_pipeline_preserves_exact_hresult_bits() {
        let raw = windows::core::HRESULT(0x8001_0106u32 as i32);
        let err = MtaGuard::from_state(map_init_result(raw))
            .expect_err("RPC_E_CHANGED_MODE must stop before any COM call");
        assert_eq!(err, 0x8001_0106, "the raw HRESULT bits are preserved exactly");

        let raw = windows::core::HRESULT(0x8007_000Eu32 as i32);
        let err = MtaGuard::from_state(map_init_result(raw))
            .expect_err("a failed HRESULT must stop before any COM call");
        assert_eq!(err, 0x8007_000E, "the raw HRESULT bits are preserved exactly");
    }
}
