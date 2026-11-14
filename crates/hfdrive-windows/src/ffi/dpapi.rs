//! User-scoped DPAPI protect/unprotect.
//!
//! All protection uses `CRYPTPROTECT_UI_FORBIDDEN` and **never**
//! `CRYPTPROTECT_LOCAL_MACHINE`: ciphertext is only usable by the Windows
//! user that produced it. Plaintext is held in zeroizing buffers and the
//! OS-side output buffers are zeroed before being freed.

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
};

use zeroize::Zeroize;

/// A zeroizing byte buffer used for secret plaintext and DPAPI entropy.
///
/// `expose`/`expose_mut` give slice access; the bytes are wiped on drop.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wrap bytes. Callers should pass ownership of buffers they no longer
    /// need; the copy is wiped on drop.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The byte slice.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// The mutable byte slice (for callers that fill in place).
    pub fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

/// Protect `data` with user-scoped DPAPI. `entropy` (when provided) binds the
/// ciphertext to a caller-chosen context; the same entropy is required to
/// unprotect.
pub fn protect(data: &[u8], entropy: Option<&[u8]>) -> Result<Vec<u8>, u32> {
    if data.is_empty() {
        return Err(87); // ERROR_INVALID_PARAMETER
    }
    let mut entropy_owned: Option<SecretBytes> = None;
    // SAFETY: blobs point at `data`/`entropy_owned`, both alive for the call.
    unsafe {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let entropy_blob;
        let entropy_ptr = match entropy {
            Some(e) => {
                let owned = SecretBytes::new(e.to_vec());
                entropy_blob = CRYPT_INTEGER_BLOB {
                    cbData: owned.len() as u32,
                    pbData: owned.0.as_ptr() as *mut u8,
                };
                entropy_owned = Some(owned);
                Some(&entropy_blob as *const CRYPT_INTEGER_BLOB)
            }
            None => None,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: core::ptr::null_mut(),
        };
        match CryptProtectData(
            &in_blob,
            windows::core::PCWSTR::null(),
            entropy_ptr,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        ) {
            Ok(()) => {
                let mut out = vec![0u8; out_blob.cbData as usize];
                if !out_blob.pbData.is_null() && out_blob.cbData > 0 {
                    core::ptr::copy_nonoverlapping(out_blob.pbData, out.as_mut_ptr(), out.len());
                }
                zero_and_free(out_blob);
                if let Some(mut owned) = entropy_owned {
                    owned.0.zeroize();
                }
                Ok(out)
            }
            Err(e) => {
                if let Some(mut owned) = entropy_owned {
                    owned.0.zeroize();
                }
                Err(super::error_code(&e))
            }
        }
    }
}

/// Unprotect ciphertext produced by [`protect`] with the same entropy.
pub fn unprotect(data: &[u8], entropy: Option<&[u8]>) -> Result<SecretBytes, u32> {
    if data.is_empty() {
        return Err(87); // ERROR_INVALID_PARAMETER
    }
    let mut entropy_owned: Option<SecretBytes> = None;
    // SAFETY: see `protect`; output buffer is wiped before being freed.
    unsafe {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let entropy_blob;
        let entropy_ptr = match entropy {
            Some(e) => {
                let owned = SecretBytes::new(e.to_vec());
                entropy_blob = CRYPT_INTEGER_BLOB {
                    cbData: owned.len() as u32,
                    pbData: owned.0.as_ptr() as *mut u8,
                };
                entropy_owned = Some(owned);
                Some(&entropy_blob as *const CRYPT_INTEGER_BLOB)
            }
            None => None,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: core::ptr::null_mut(),
        };
        match CryptUnprotectData(
            &in_blob,
            None,
            entropy_ptr,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        ) {
            Ok(()) => {
                let mut out = vec![0u8; out_blob.cbData as usize];
                if !out_blob.pbData.is_null() && out_blob.cbData > 0 {
                    core::ptr::copy_nonoverlapping(out_blob.pbData, out.as_mut_ptr(), out.len());
                }
                zero_and_free(out_blob);
                if let Some(mut owned) = entropy_owned {
                    owned.0.zeroize();
                }
                Ok(SecretBytes::new(out))
            }
            Err(e) => {
                if let Some(mut owned) = entropy_owned {
                    owned.0.zeroize();
                }
                Err(super::error_code(&e))
            }
        }
    }
}

/// Wipe a DPAPI output buffer before freeing it.
unsafe fn zero_and_free(blob: CRYPT_INTEGER_BLOB) {
    // SAFETY: `blob.pbData` was allocated by DPAPI (`LocalAlloc` semantics).
    unsafe {
        if !blob.pbData.is_null() && blob.cbData > 0 {
            core::ptr::write_bytes(blob.pbData, 0, blob.cbData as usize);
            let _ = LocalFree(Some(HLOCAL(blob.pbData.cast())));
        }
    }
}
