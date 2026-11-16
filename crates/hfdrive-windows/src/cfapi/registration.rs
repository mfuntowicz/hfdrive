//! Stable registration identities and the `StorageProviderSyncRootManager`
//! registration flow.
//!
//! Frozen product identities (stable across builds and releases):
//!
//! * Provider GUID [`HFDRIVE_PROVIDER_GUID`] — `f727443d-0db5-4746-a08f-16afb2d2f289`.
//! * Sync root ID `HFDrive!<windows-user-sid>!<connection-uuid>` — at most
//!   [`SYNC_ROOT_ID_MAX_LEN`] characters; overlong IDs return
//!   [`CfError::SyncRootIdTooLong`], never truncated or asserted.
//! * [`SYNC_POLICY`] — hydration `Partial` with **no** streaming,
//!   auto-dehydration or validation-required modifiers, population `Full`,
//!   hard links `None`. The single-variant enums make the intended policy the
//!   only expressible one.

use std::borrow::Cow;
use std::path::PathBuf;

use hfdrive_core::ids::ConnectionId;
use uuid::Uuid;

use crate::filesystem::validate::ValidatedRoot;

use super::{CfError, CfResult};

/// The one provider GUID for HF Drive (never changes between builds).
pub const HFDRIVE_PROVIDER_GUID: Uuid =
    Uuid::from_u128(0xf727_443d_0db5_4746_a08f_16af_b2d2_f289);

/// Maximum `StorageProviderSyncRootInfo.Id` length accepted by Windows.
pub const SYNC_ROOT_ID_MAX_LEN: usize = 174;

/// Hydration policy for HF Drive roots. Only `Partial` is supported: ranges
/// are hydrated on demand through the provider's fetch pipeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HydrationPolicy {
    Partial,
}

/// Hydration modifiers for HF Drive roots. `None` is the only value: the
/// provider never enables streaming, auto-dehydration or validation-required
/// (it does not acknowledge arbitrary ranges against a whole-file digest).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HydrationModifiers {
    None,
}

/// Population policy for HF Drive roots. `Full`: the directory tree is
/// populated by the provider on connect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PopulationPolicy {
    Full,
}

/// Hard-link policy for HF Drive roots. `None`: placeholders never carry
/// hard links.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardlinkPolicy {
    None,
}

/// The frozen registration policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncPolicy {
    pub hydration: HydrationPolicy,
    pub hydration_modifiers: HydrationModifiers,
    pub population: PopulationPolicy,
    pub hardlinks: HardlinkPolicy,
}

pub const SYNC_POLICY: SyncPolicy = SyncPolicy {
    hydration: HydrationPolicy::Partial,
    hydration_modifiers: HydrationModifiers::None,
    population: PopulationPolicy::Full,
    hardlinks: HardlinkPolicy::None,
};

/// Explorer display/icon resources for a registered root.
#[derive(Clone, Debug)]
pub struct RegistrationInfo {
    pub connection: ConnectionId,
    pub display_name: String,
    /// Icon resource string as shown in Explorer, e.g. `@{HFDrive...,-101}`.
    pub icon_resource: String,
    /// Provider version shown in Explorer.
    pub version: String,
}

/// Outcome of a registration attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationOutcome {
    /// The root was newly registered in this call.
    Registered,
    /// The root was already registered with the same identity; the existing
    /// registration is kept (idempotent reconnect).
    AlreadyRegistered,
}

/// A sync root registered with Windows (any provider).
#[derive(Clone, Debug)]
pub struct RegisteredRoot {
    pub id: String,
    pub path: Option<PathBuf>,
}

/// Build the stable sync root ID for one connection.
///
/// Format: `HFDrive!<user-sid>!<connection-uuid>` (ASCII, ≤ 174 chars).
pub fn sync_root_id(user_sid: &str, connection: ConnectionId) -> CfResult<String> {
    if user_sid.is_empty() || user_sid.contains('!') {
        return Err(CfError::Precondition("user sid must be nonempty and free of '!'"));
    }
    let id = format!("HFDrive!{user_sid}!{connection}");
    if id.chars().count() > SYNC_ROOT_ID_MAX_LEN {
        return Err(CfError::SyncRootIdTooLong {
            max: SYNC_ROOT_ID_MAX_LEN,
        });
    }
    Ok(id)
}

/// Register (or idempotently re-register) a validated root.
///
/// Registration goes through `StorageProviderSyncRootManager` only;
/// `CfRegisterSyncRoot` is never called. An existing registration with the
/// same id and the same path is kept as-is ([`RegistrationOutcome::AlreadyRegistered`]);
/// a registration for this path under a *different* id is an error (the
/// overlap check in [`crate::filesystem::validate`] should have refused it).
pub fn register_sync_root(
    root: &ValidatedRoot,
    user_sid: &str,
    info: &RegistrationInfo,
) -> CfResult<RegistrationOutcome> {
    let id = sync_root_id(user_sid, info.connection)?;
    for existing in registered_sync_roots()? {
        if existing.id == id {
            return match existing.path {
                Some(path) if same_path(&path, &root.final_path) => {
                    Ok(RegistrationOutcome::AlreadyRegistered)
                }
                _ => Err(CfError::Precondition(
                    "a different root is registered under this connection id",
                )),
            };
        }
    }
    crate::ffi::syncroot::register(&crate::ffi::syncroot::RegistrationRequest {
        id,
        path: registration_path(&root.final_path).into_owned(),
        provider_guid: HFDRIVE_PROVIDER_GUID,
        display: crate::ffi::syncroot::RootDisplay {
            display_name: info.display_name.clone(),
            icon_resource: info.icon_resource.clone(),
            version: info.version.clone(),
            allow_pinning: true,
        },
        policy: SYNC_POLICY,
    })
    .map_err(|code| CfError::Win32 {
        operation: "StorageProviderSyncRootManager.Register",
        code,
    })?;
    Ok(RegistrationOutcome::Registered)
}

/// Unregister the connection's sync root. A missing registration is a
/// success (idempotent teardown).
pub fn unregister_sync_root(user_sid: &str, connection: ConnectionId) -> CfResult<()> {
    let id = sync_root_id(user_sid, connection)?;
    match crate::ffi::syncroot::unregister(&id) {
        Ok(()) => Ok(()),
        // 2 = ERROR_FILE_NOT_FOUND: already unregistered.
        Err(2) => Ok(()),
        Err(code) => Err(CfError::Win32 {
            operation: "StorageProviderSyncRootManager.Unregister",
            code,
        }),
    }
}

/// All sync roots registered with Windows (any provider). Used by root
/// overlap validation and by reconnect flows.
pub fn registered_sync_roots() -> CfResult<Vec<RegisteredRoot>> {
    let roots = crate::ffi::syncroot::current_roots().map_err(|code| CfError::Win32 {
        operation: "StorageProviderSyncRootManager.GetCurrentSyncRoots",
        code,
    })?;
    Ok(roots
        .into_iter()
        .map(|root| RegisteredRoot {
            id: root.id,
            path: root.path,
        })
        .collect())
}

/// `StorageFolder.GetFolderFromPathAsync` rejects extended `\\?\` paths.
/// Keep the validated extended path for identity/CFAPI, but register the
/// equivalent ordinary DOS or UNC path through WinRT.
fn registration_path(path: &std::path::Path) -> Cow<'_, std::path::Path> {
    let Some(text) = path.to_str() else {
        return Cow::Borrowed(path);
    };
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return Cow::Owned(std::path::PathBuf::from(format!(r"\\{rest}")));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        return Cow::Borrowed(std::path::Path::new(rest));
    }
    Cow::Borrowed(path)
}

fn same_path(a: &std::path::Path, b: &std::path::Path) -> bool {
    let a = registration_path(a);
    let b = registration_path(b);
    let a_owned = a.to_string_lossy();
    let b_owned = b.to_string_lossy();
    let a = a_owned.trim_end_matches(['\\', '/']);
    let b = b_owned.trim_end_matches(['\\', '/']);
    crate::filesystem::names::windows_case_equivalent(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_guid_is_frozen() {
        assert_eq!(
            HFDRIVE_PROVIDER_GUID.to_string(),
            "f727443d-0db5-4746-a08f-16afb2d2f289"
        );
    }

    #[test]
    fn sync_root_id_format_and_bounds() {
        let connection = ConnectionId::new();
        let id = sync_root_id("S-1-5-21-1-2-3-1001", connection).unwrap();
        assert_eq!(id, format!("HFDrive!S-1-5-21-1-2-3-1001!{connection}"));
        assert!(id.len() <= SYNC_ROOT_ID_MAX_LEN);
        // Overlong ids are rejected, not truncated or asserted away.
        let long_sid = format!("S-1-5-21-{}", "1".repeat(200));
        assert!(matches!(
            sync_root_id(&long_sid, connection),
            Err(CfError::SyncRootIdTooLong { .. })
        ));
        assert!(sync_root_id("", connection).is_err());
        assert!(sync_root_id("bad!sid", connection).is_err());
    }

    #[test]
    fn policy_is_frozen_to_the_supported_combination() {
        assert_eq!(SYNC_POLICY.hydration, HydrationPolicy::Partial);
        assert_eq!(
            SYNC_POLICY.hydration_modifiers,
            HydrationModifiers::None
        );
        assert_eq!(SYNC_POLICY.population, PopulationPolicy::Full);
        assert_eq!(SYNC_POLICY.hardlinks, HardlinkPolicy::None);
    }

    #[test]
    fn registration_path_uses_winrt_compatible_dos_and_unc_paths() {
        assert_eq!(registration_path(std::path::Path::new(r"\\?\F:\Data\Root")).as_ref(), std::path::Path::new(r"F:\Data\Root"));
        assert_eq!(registration_path(std::path::Path::new(r"\\?\UNC\server\share\Root")).as_ref(), std::path::Path::new(r"\\server\share\Root"));
        assert_eq!(registration_path(std::path::Path::new(r"F:\Data\Root")).as_ref(), std::path::Path::new(r"F:\Data\Root"));
    }

    #[test]
    fn reconnect_adopts_the_same_dos_or_unc_root_without_re_registering() {
        for (registered, candidate) in [
            (r"F:\Data\Root", r"\\?\F:\Data\Root"),
            (r"f:\data\ROOT\", r"\\?\F:\Data\Root"),
            (r"\\server\share\Root", r"\\?\UNC\server\share\Root"),
        ] {
            assert!(same_path(
                std::path::Path::new(registered),
                std::path::Path::new(candidate),
            ));
        }
        assert!(!same_path(
            std::path::Path::new(r"F:\Data\Root2"),
            std::path::Path::new(r"\\?\F:\Data\Root"),
        ));
        assert!(!same_path(
            std::path::Path::new(r"\\server\other\Root"),
            std::path::Path::new(r"\\?\UNC\server\share\Root"),
        ));
    }
}
