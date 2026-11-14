//! `StorageProviderSyncRootManager` adapters (WinRT).
//!
//! Registration goes **only** through `StorageProviderSyncRootManager`;
//! `CfRegisterSyncRoot` is never called by HF Drive. The WinRT/COM apartment
//! is initialized per calling thread around each call (`CoInitializeEx` in
//! MTA mode); the guard balances `CoUninitialize` and no apartment state
//! leaks across calls.

use std::path::{Path, PathBuf};

use uuid::Uuid;
use windows::core::{GUID, HSTRING, Interface};
use windows::Storage::Provider::{
    StorageProviderHardlinkPolicy, StorageProviderHydrationPolicy,
    StorageProviderHydrationPolicyModifier, StorageProviderInSyncPolicy,
    StorageProviderPopulationPolicy, StorageProviderSyncRootInfo,
    StorageProviderSyncRootManager,
};
use windows::Storage::StorageFolder;
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};
use windows_future::AsyncStatus;

/// Process/MTA guard: balances `CoInitializeEx` with `CoUninitialize` on the
/// calling thread.
pub(crate) struct MtaGuard(bool);

impl MtaGuard {
    pub(crate) fn enter() -> Self {
        // SAFETY: thread-local COM init/uninit are balanced by the guard.
        let already = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).is_ok() };
        MtaGuard(!already)
    }
}

impl Drop for MtaGuard {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: exactly one successful `CoInitializeEx` is undone.
            unsafe { CoUninitialize() };
        }
    }
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
    let _mta = MtaGuard::enter();
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
    let _mta = MtaGuard::enter();
    StorageProviderSyncRootManager::Unregister(&HSTRING::from(id))
        .map_err(|e| super::error_code(&e))
}

/// One currently registered sync root on this machine/user (any provider).
pub(crate) struct RegisteredRoot {
    pub id: String,
    pub path: Option<PathBuf>,
}

/// All sync roots registered with Windows (any provider).
pub(crate) fn current_roots() -> Result<Vec<RegisteredRoot>, u32> {
    let _mta = MtaGuard::enter();
    let roots =
        StorageProviderSyncRootManager::GetCurrentSyncRoots().map_err(|e| super::error_code(&e))?;
    let size = roots.Size().map_err(|e| super::error_code(&e))?;
    let mut out = Vec::new();
    for index in 0..size {
        let info = roots.GetAt(index).map_err(|e| super::error_code(&e))?;
        let id = info.Id().map_err(|e| super::error_code(&e))?.to_string();
        out.push(RegisteredRoot {
            id,
            path: info_path(&info).ok(),
        });
    }
    Ok(out)
}

/// The folder path of a registered root id, if present.
pub(crate) fn root_path(id: &str) -> Result<Option<PathBuf>, u32> {
    let _mta = MtaGuard::enter();
    match StorageProviderSyncRootManager::GetSyncRootInformationForId(&HSTRING::from(id)) {
        Ok(info) => info_path(&info).map(Some),
        Err(e) => {
            let code = super::error_code(&e);
            // 2 = ERROR_FILE_NOT_FOUND: no such registration id.
            if code == 2 {
                Ok(None)
            } else {
                Err(code)
            }
        }
    }
}

fn info_path(info: &StorageProviderSyncRootInfo) -> Result<PathBuf, u32> {
    let folder = info.Path().map_err(|e| super::error_code(&e))?;
    let item: windows::Storage::IStorageItem = folder.cast().map_err(|e| super::error_code(&e))?;
    let path = item.Path().map_err(|e| super::error_code(&e))?;
    Ok(PathBuf::from(path.to_string()))
}

/// Resolve a filesystem path to its WinRT folder object, waiting for the
/// async operation on the calling (MTA) thread. Resolving a local folder
/// completes promptly; the wait is bounded and cancellable only by timeout.
fn resolve_folder(path: &Path) -> Result<StorageFolder, u32> {
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
