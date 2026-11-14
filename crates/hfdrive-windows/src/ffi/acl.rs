//! Secured DACL construction: user + SYSTEM only, optionally inheritable.
//!
//! Every object this crate creates that holds secrets or guards provider
//! singleton state (credential files, state-owner file, pipe, mutex) is
//! created with an explicit self-relative DACL granting access to exactly two
//! trustees: the current user SID and the SYSTEM well-known SID. The DACL is
//! marked protected so no parent-directory inheritance can widen it.

use windows::Win32::Security::{
    AddAccessAllowedAce, GetAce, InitializeAcl, InitializeSecurityDescriptor,
    SetSecurityDescriptorControl, SetSecurityDescriptorDacl, ACE_FLAGS, ACE_HEADER, ACL,
    ACL_REVISION, CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE, PSID,
    PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED, SECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR_CONTROL,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

use super::sid::OwnedSid;

/// A self-relative security descriptor with a protected user/SYSTEM DACL.
///
/// The descriptor stays valid while this value is alive; `attributes()`
/// borrows it for the duration of a single object-creation call.
pub(crate) struct SecuredDacl {
    acl: Vec<u32>,
    descriptor: SECURITY_DESCRIPTOR,
}

impl SecuredDacl {
    /// Build a DACL granting `GENERIC_ALL` to the current user and SYSTEM.
    ///
    /// `inheritable` adds `CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE` so
    /// files created inside a directory carrying this DACL inherit the same
    /// restricted trustees.
    pub(crate) fn user_and_system(user_sid: OwnedSid, inheritable: bool) -> windows::core::Result<Self> {
        Self::trustee_and_system(user_sid, inheritable)
    }

    /// Build a DACL granting `GENERIC_ALL` to `trustee` and SYSTEM.
    ///
    /// Used for two restricted shapes: user + SYSTEM (credentials, global
    /// mutex) and logon SID + SYSTEM (the IPC pipe, which must only admit
    /// processes of the provider's interactive logon).
    pub(crate) fn trustee_and_system(trustee: OwnedSid, inheritable: bool) -> windows::core::Result<Self> {
        let user_sid = trustee;
        let system_sid = OwnedSid::well_known(windows::Win32::Security::WinLocalSystemSid)?;
        let user_len = user_sid.len();
        let system_len = system_sid.len();
        // ACL header (8 bytes) plus one ACE per trustee. ACE size is
        // header (4) + mask (4) + SID, rounded up to a 4-byte boundary.
        let ace_bytes = |sid_len: u32| -> usize {
            let raw = 8usize + sid_len as usize;
            raw.next_multiple_of(4)
        };
        let acl_bytes = 8usize + ace_bytes(user_len) + ace_bytes(system_len) + 8;
        // Vec<u32> guarantees the DWORD alignment an ACL requires.
        let mut acl_words = vec![0u32; (acl_bytes + 3) / 4];
        let acl_ptr = acl_words.as_mut_ptr() as *mut ACL;
        let flags = if inheritable {
            ACE_FLAGS(CONTAINER_INHERIT_ACE.0 | OBJECT_INHERIT_ACE.0)
        } else {
            ACE_FLAGS(0)
        };
        // SAFETY: `acl_words` has at least `acl_bytes` capacity and the
        // declared revision/size are consistent with the appended ACEs. The
        // SIDs are copied into the ACL by the OS, so the `OwnedSid` values
        // can be freed as soon as construction finishes.
        unsafe {
            InitializeAcl(acl_ptr, acl_bytes as u32, ACL_REVISION)?;
            AddAccessAllowedAce(acl_ptr, ACL_REVISION, generic_all_mask(), user_sid.as_psid())?;
            AddAccessAllowedAce(acl_ptr, ACL_REVISION, generic_all_mask(), system_sid.as_psid())?;
            if inheritable {
                // Set the inheritance flags on both ACEs (AddAccessAllowedAce
                // writes flags = 0); done by re-deriving the ACEs in place.
                set_ace_flags(acl_ptr, 0, flags)?;
                set_ace_flags(acl_ptr, 1, flags)?;
            }
        }
        drop(user_sid);
        drop(system_sid);

        // `SECURITY_DESCRIPTOR` is a generated POD with no `Default`; build
        // it field by field and let `InitializeSecurityDescriptor` fill in
        // the OS-managed parts.
        let mut descriptor = SECURITY_DESCRIPTOR {
            Revision: 0,
            Sbz1: 0,
            Control: SECURITY_DESCRIPTOR_CONTROL(0),
            Owner: PSID(core::ptr::null_mut()),
            Group: PSID(core::ptr::null_mut()),
            Sacl: core::ptr::null_mut(),
            Dacl: core::ptr::null_mut(),
        };
        // SAFETY: `descriptor` is a generated structure of the right size;
        // `acl_ptr` points into `acl_words`, which outlives this struct.
        unsafe {
            InitializeSecurityDescriptor(
                PSECURITY_DESCRIPTOR(&mut descriptor as *mut _ as *mut core::ffi::c_void),
                SECURITY_DESCRIPTOR_REVISION,
            )?;
            SetSecurityDescriptorDacl(
                PSECURITY_DESCRIPTOR(&mut descriptor as *mut _ as *mut core::ffi::c_void),
                true,
                Some(acl_ptr as *const ACL),
                false,
            )?;
            SetSecurityDescriptorControl(
                PSECURITY_DESCRIPTOR(&mut descriptor as *mut _ as *mut core::ffi::c_void),
                SECURITY_DESCRIPTOR_CONTROL(SE_DACL_PROTECTED.0),
                SECURITY_DESCRIPTOR_CONTROL(SE_DACL_PROTECTED.0),
            )?;
        }

        Ok(Self {
            acl: acl_words,
            descriptor,
        })
    }

    /// `SECURITY_ATTRIBUTES` pointing at this descriptor. The pointer is
    /// valid as long as `self` is borrowed.
    pub(crate) fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
        // Touch the ACL buffer so the compiler keeps it alive and the pointer
        // stays well-defined.
        debug_assert!(!self.acl.is_empty());
        SECURITY_ATTRIBUTES {
            nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: &mut self.descriptor as *mut _ as *mut core::ffi::c_void,
            bInheritHandle: windows::core::BOOL(0),
        }
    }

    /// The DACL pointer inside this descriptor.
    pub(crate) fn dacl_ptr(&self) -> *const ACL {
        self.acl.as_ptr() as *const ACL
    }
}

/// `GENERIC_ALL` as the object access mask. The object manager maps this to
/// the object's specific rights; combined with the restricted DACL this
/// grants full control to the user and SYSTEM only.
fn generic_all_mask() -> u32 {
    windows::Win32::Foundation::GENERIC_ALL.0
}

/// Set the ACE flags of the `index`th ACE inside a freshly built ACL.
///
/// # Safety
/// `acl` must be a valid ACL with at least `index + 1` ACEs.
unsafe fn set_ace_flags(
    acl: *mut ACL,
    index: u32,
    flags: ACE_FLAGS,
) -> windows::core::Result<()> {
    // SAFETY: caller guarantees `acl` validity; `GetAce` returns a pointer
    // into the ACL buffer, which we only mutate in place.
    let mut ace: *mut core::ffi::c_void = core::ptr::null_mut();
    let result = unsafe { GetAce(acl as *const ACL, index, &mut ace) };
    result?;
    // SAFETY: `ace` points at the requested ACE header inside `acl`.
    let header = unsafe { &mut *(ace as *mut ACE_HEADER) };
    header.AceFlags = flags.0 as u8;
    Ok(())
}

/// Apply a protected DACL to an existing filesystem object (directory or
/// file) identified by path. The DACL is marked protected so no inherited
/// ACEs from the parent can widen access.
pub(crate) fn apply_protected_dacl(path: &std::path::Path, dacl: &SecuredDacl) -> Result<(), u32> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION};
    use windows::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};

    let wide: Vec<u16> = OsStr::new(path.as_os_str()).encode_wide().chain(Some(0)).collect();
    // SAFETY: `wide` is NUL-terminated; the DACL pointer belongs to `dacl`,
    // which outlives this call.
    let status = unsafe {
        SetNamedSecurityInfoW(
            windows::core::PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl.dacl_ptr()),
            None,
        )
    };
    if status == windows::Win32::Foundation::WIN32_ERROR(0) {
        Ok(())
    } else {
        Err(status.0)
    }
}

/// Build the user+SYSTEM DACL used by secret-bearing and singleton objects
/// (credential records, the provider global mutex). `inheritable` is used
/// for directories whose children should carry the same restricted trustees.
pub(crate) fn user_system_dacl(inheritable: bool) -> windows::core::Result<SecuredDacl> {
    let user_sid = super::token::current_process_user_sid()?;
    SecuredDacl::user_and_system(user_sid, inheritable)
}

/// Build the **logon SID + SYSTEM** DACL used by the IPC pipe.
///
/// The pipe must only admit processes of the provider's own interactive
/// logon (and SYSTEM), never everyone with the user SID. A process without a
/// token logon SID (e.g. a non-interactive service context) cannot obtain a
/// restricted pipe and this fails closed.
pub(crate) fn logon_system_dacl() -> windows::core::Result<SecuredDacl> {
    let token = super::token::current_process_token()?;
    let logon_sid = super::token::token_logon_sid(token.as_win())
        .ok_or_else(windows::core::Error::from_thread)?;
    SecuredDacl::trustee_and_system(logon_sid, false)
}
