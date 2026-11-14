//! User-scoped, DPAPI-protected credential records.
//!
//! # Contract
//!
//! * Plaintext is protected with user-scoped DPAPI
//!   (`CRYPTPROTECT_UI_FORBIDDEN`, never `CRYPTPROTECT_LOCAL_MACHINE`): a
//!   ciphertext record copied to another machine or another user is useless.
//! * Record files live under the store's base directory (outside all sync
//!   roots) and are created with a protected DACL granting access to exactly
//!   the current user and SYSTEM.
//! * Saving replaces a record atomically: the new content is written to a
//!   unique temporary file, flushed to stable storage, and moved over the
//!   old name with `MoveFileExW(MOVEFILE_REPLACE_EXISTING |
//!   MOVEFILE_WRITE_THROUGH)`. A crash mid-save leaves either the old record
//!   or the new one, never a torn one. Temporary files are removed on
//!   failure; untracked leftovers are inert (they are valid protected
//!   envelopes under a non-record name and are ignored by `load`).
//! * Record names are validated ([`RecordName::new`]): no traversal, no
//!   reserved device names, no characters that are unsafe in file names.
//! * Plaintext is carried in zeroizing buffers ([`SecretBytes`],
//!   [`SecretString`]); DPAPI output buffers are wiped before being freed.
//!   Nothing in this module logs, prints, or returns secret material in
//!   errors — all errors are structured and non-secret
//!   ([`crate::CredentialError`]).
//!
//! # Typical use
//!
//! ```no_run
//! use hfdrive_windows::credentials::{CredentialStore, RecordName};
//!
//! let store = CredentialStore::open(std::path::PathBuf::from(r"C:\Users\me\AppData\Local\HFDrive\credentials"))?;
//! let name = RecordName::new("oauth-account-a")?;
//! store.save_record(&name, b"token-material", Some(b"binding-context"))?;
//! let plaintext = store.load_record(&name, Some(b"binding-context"))?;
//! // `plaintext` is a SecretBytes: wiped on drop.
//! # Ok::<(), hfdrive_windows::CredentialError>(())
//! ```
//!
//! # Error/lifetime notes for integrators
//!
//! * [`CredentialStore`] is cheap to clone-free and holds no OS handles
//!   between calls; the base directory must exist or be creatable by the
//!   current user.
//! * `load_record` fails with [`crate::CredentialError::UnprotectFailed`] if
//!   the ciphertext was produced for another user, with other entropy, or
//!   has been modified. Never treat that as "record missing".
//! * `delete_record` returns `Ok(false)` when the record was already absent.

use std::path::{Path, PathBuf};

use zeroize::Zeroize;

use crate::error::CredentialError;
use crate::ffi::acl::SecuredDacl;
use crate::ffi::file;

pub use crate::ffi::dpapi::{SecretBytes, protect, unprotect};

/// Magic prefix of every on-disk record envelope.
const RECORD_MAGIC: &[u8; 8] = b"HFDCRED1";

/// Upper bound for a single protected record envelope (1 MiB).
const MAX_RECORD_BYTES: usize = 1024 * 1024;

/// A validated credential record name.
///
/// Names are restricted to `A-Z`, `a-z`, `0-9`, `-`, `_`, `.`; must start
/// with an alphanumeric character; must not end in `.` or a space; must not
/// contain `..`; and must not be (or start with) a reserved DOS device name.
/// The store appends its own file extension, so names never collide with the
/// store's temporary files.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordName(String);

impl RecordName {
    /// Validate and construct a record name.
    pub fn new(name: &str) -> Result<Self, CredentialError> {
        validate_record_name(name)?;
        Ok(Self(name.to_owned()))
    }

    /// The validated name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for RecordName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validate a credential record name (see [`RecordName`]).
pub fn validate_record_name(name: &str) -> Result<(), CredentialError> {
    if name.is_empty() || name.len() > 64 {
        return Err(CredentialError::InvalidRecordName);
    }
    if !name.is_ascii() {
        return Err(CredentialError::InvalidRecordName);
    }
    let bytes = name.as_bytes();
    let first_alphanumeric = bytes[0].is_ascii_alphanumeric();
    if !first_alphanumeric {
        return Err(CredentialError::InvalidRecordName);
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'-' | b'_' | b'.'))
    {
        return Err(CredentialError::InvalidRecordName);
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Err(CredentialError::InvalidRecordName);
    }
    if name.contains("..") {
        return Err(CredentialError::InvalidRecordName);
    }
    if is_reserved_device_name(name) {
        return Err(CredentialError::InvalidRecordName);
    }
    Ok(())
}

/// Reserved DOS device names (checked on the name's base, before the first
/// `.`), including the superscript-digit `COM`/`LPT` spellings.
fn is_reserved_device_name(name: &str) -> bool {
    const RESERVED: &[&str] = &["CON", "PRN", "AUX", "NUL", "CLOCK$"];
    const NUMERIC: &[&str] = &["COM", "LPT"];
    let base = name.split('.').next().unwrap_or(name);
    let upper = base.to_ascii_uppercase();
    if RESERVED.contains(&upper.as_str()) {
        return true;
    }
    // COM1..COM9 / LPT1..LPT9, plus the ¹²³ superscript spellings.
    const SUPERSCRIPT: &[char] = &['¹', '²', '³'];
    for prefix in NUMERIC {
        if let Some(rest) = upper.strip_prefix(prefix) {
            if rest.len() == 1 {
                let c = rest.chars().next().unwrap();
                if c.is_ascii_digit() && c != '0' {
                    return true;
                }
                if SUPERSCRIPT.contains(&c) {
                    return true;
                }
            }
        }
    }
    false
}

/// A store of DPAPI-protected credential records under one directory.
pub struct CredentialStore {
    base: PathBuf,
}

impl CredentialStore {
    /// Open (creating when absent) the store at `base`.
    ///
    /// The directory and every record file are ACLed to the current user and
    /// SYSTEM only. Existing directories are re-ACLed at open so a
    /// pre-existing lax directory cannot widen record access.
    pub fn open(base: PathBuf) -> Result<Self, CredentialError> {
        std::fs::create_dir_all(&base).map_err(CredentialError::Io)?;
        if !base.is_dir() {
            return Err(CredentialError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "credential base is not a directory",
            )));
        }
        harden_directory(&base)?;
        Ok(Self { base })
    }

    /// The store's base directory.
    pub fn base(&self) -> &Path {
        &self.base
    }

    /// Protect `data` with user-scoped DPAPI (helper mirroring the store's
    /// internal protection so callers can build `SetPublicationCredentials`
    /// envelopes). `entropy` optionally binds the ciphertext to a context.
    pub fn protect(data: &[u8], entropy: Option<&[u8]>) -> Result<Vec<u8>, CredentialError> {
        protect(data, entropy).map_err(|code| CredentialError::ProtectFailed { code })
    }

    /// Unprotect ciphertext produced by [`CredentialStore::protect`].
    pub fn unprotect(data: &[u8], entropy: Option<&[u8]>) -> Result<SecretBytes, CredentialError> {
        unprotect(data, entropy).map_err(|code| CredentialError::UnprotectFailed { code })
    }

    /// Atomically save `plaintext` under `name`, protected with `entropy`.
    ///
    /// Any previous record under `name` is replaced only after the new
    /// content is fully written and flushed.
    pub fn save_record(
        &self,
        name: &RecordName,
        plaintext: &[u8],
        entropy: Option<&[u8]>,
    ) -> Result<(), CredentialError> {
        let ciphertext = protect(plaintext, entropy).map_err(|code| CredentialError::ProtectFailed { code })?;
        let envelope = build_envelope(&ciphertext)?;
        let target = self.record_path(name);
        let tmp = self.temp_path(name);
        let mut dacl = user_system_dacl()?;
        let attrs = dacl.attributes();
        let handle = file::create_exclusive(&tmp, Some(&attrs)).map_err(|error| {
            CredentialError::Io(std::io::Error::from_raw_os_error(crate::ffi::error_code(&error) as i32))
        })?;
        let write = (|| -> windows::core::Result<()> {
            file::write_all(handle.as_win(), &envelope)?;
            file::flush(handle.as_win())
        })();
        drop(handle);
        if let Err(e) = write {
            let _ = file::delete_if_exists(&tmp);
            return Err(CredentialError::Io(std::io::Error::other(format!(
                "failed writing credential record (win32={})",
                crate::ffi::error_code(&e)
            ))));
        }
        if let Err(e) = file::replace_file(&tmp, &target) {
            let _ = file::delete_if_exists(&tmp);
            return Err(CredentialError::Io(std::io::Error::other(format!(
                "failed replacing credential record (win32={})",
                crate::ffi::error_code(&e)
            ))));
        }
        Ok(())
    }

    /// Load and unprotect the record stored under `name`.
    ///
    /// `entropy` must match the entropy used at save time.
    pub fn load_record(
        &self,
        name: &RecordName,
        entropy: Option<&[u8]>,
    ) -> Result<SecretBytes, CredentialError> {
        let path = self.record_path(name);
        let handle = file::open_existing(&path).map_err(|e| {
            if crate::ffi::error_code(&e) == crate::ffi::ERROR_FILE_NOT_FOUND {
                CredentialError::NotFound
            } else {
                CredentialError::Io(std::io::Error::other(format!(
                    "failed opening credential record (win32={})",
                    crate::ffi::error_code(&e)
                )))
            }
        })?;
        let bytes = file::read_all(handle.as_win(), MAX_RECORD_BYTES)
            .map_err(|e| CredentialError::Io(std::io::Error::other(format!(
                "failed reading credential record (win32={})",
                crate::ffi::error_code(&e)
            ))))?;
        drop(handle);
        let ciphertext = parse_envelope(&bytes)?;
        unprotect(&ciphertext, entropy).map_err(|code| CredentialError::UnprotectFailed { code })
    }

    /// Delete the record stored under `name`. Returns `false` when it was
    /// already absent.
    pub fn delete_record(&self, name: &RecordName) -> Result<bool, CredentialError> {
        let path = self.record_path(name);
        file::delete_if_exists(&path).map_err(|error| {
            CredentialError::Io(std::io::Error::from_raw_os_error(crate::ffi::error_code(&error) as i32))
        })
    }

    /// List stored record names (filenames only, never content).
    pub fn list_records(&self) -> Result<Vec<RecordName>, CredentialError> {
        let mut out = Vec::new();
        let entries = std::fs::read_dir(&self.base).map_err(CredentialError::Io)?;
        for entry in entries {
            let entry = entry.map_err(CredentialError::Io)?;
            let file_type = entry.file_type().map_err(CredentialError::Io)?;
            if !file_type.is_file() {
                continue;
            }
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else { continue };
            let Some(stem) = name.strip_suffix(RECORD_SUFFIX) else {
                continue;
            };
            if let Ok(record) = RecordName::new(stem) {
                out.push(record);
            }
        }
        out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(out)
    }

    fn record_path(&self, name: &RecordName) -> PathBuf {
        self.base.join(record_file_name(name))
    }

    fn temp_path(&self, name: &RecordName) -> PathBuf {
        let nonce = std::process::id();
        let tick = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        self.base
            .join(format!("{}.{nonce}.{tick}.tmp", name.as_str()))
    }
}

/// File extension appended to record names.
const RECORD_SUFFIX: &str = ".hfdcred";

/// Actual on-disk file name of a record: the validated record name plus the
/// store's file extension. Exposed so callers can persist a truthful
/// `credential_ref` without duplicating the extension convention.
pub fn record_file_name(name: &RecordName) -> String {
    format!("{}{}", name.as_str(), RECORD_SUFFIX)
}

/// A zeroizing UTF-8 string for short-lived secret text (client secrets,
/// refresh tokens). Wiped on drop; `Debug` is redacted.
pub struct SecretString(String);

impl SecretString {
    /// Wrap a string. Prefer [`SecretBytes`] for byte material.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The text.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the string is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        // `String: Zeroize` wipes the underlying UTF-8 bytes in place.
        self.0.zeroize();
    }
}

impl core::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

/// Build the on-disk envelope around DPAPI ciphertext.
fn build_envelope(ciphertext: &[u8]) -> Result<Vec<u8>, CredentialError> {
    if ciphertext.len() > MAX_RECORD_BYTES {
        return Err(CredentialError::CorruptRecord);
    }
    let mut out = Vec::with_capacity(RECORD_MAGIC.len() + 4 + ciphertext.len());
    out.extend_from_slice(RECORD_MAGIC);
    out.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    out.extend_from_slice(ciphertext);
    Ok(out)
}

/// Parse and bounds-check an on-disk envelope.
fn parse_envelope(bytes: &[u8]) -> Result<&[u8], CredentialError> {
    if bytes.len() < RECORD_MAGIC.len() + 4 || &bytes[..RECORD_MAGIC.len()] != RECORD_MAGIC {
        return Err(CredentialError::CorruptRecord);
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&bytes[RECORD_MAGIC.len()..RECORD_MAGIC.len() + 4]);
    let len = u32::from_le_bytes(len_bytes) as usize;
    let body_start = RECORD_MAGIC.len() + 4;
    let body = &bytes[body_start..];
    if len != body.len() || len > MAX_RECORD_BYTES {
        return Err(CredentialError::CorruptRecord);
    }
    Ok(body)
}

/// Apply a protected user/SYSTEM DACL to the store directory.
fn harden_directory(base: &Path) -> Result<(), CredentialError> {
    let dacl = user_system_dacl()?;
    crate::ffi::acl::apply_protected_dacl(base, &dacl).map_err(|code| {
        CredentialError::Io(std::io::Error::other(format!(
            "failed to secure credential directory (win32={code})"
        )))
    })
}

/// Build the user+SYSTEM inheritable DACL used by every store object.
fn user_system_dacl() -> Result<SecuredDacl, CredentialError> {
    crate::ffi::acl::user_system_dacl(true).map_err(|e| {
        CredentialError::Io(std::io::Error::other(format!(
            "failed to build credential DACL (win32={})",
            crate::ffi::error_code(&e)
        )))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_name_validation() {
        assert!(RecordName::new("oauth-account-a").is_ok());
        assert!(RecordName::new("s3.prod-01").is_ok());
        assert!(RecordName::new("X").is_ok());
        assert!(RecordName::new("").is_err());
        assert!(RecordName::new(".hidden").is_err());
        assert!(RecordName::new("../escape").is_err());
        assert!(RecordName::new("a/../b").is_err());
        assert!(RecordName::new("a..b").is_err());
        assert!(RecordName::new("bad name").is_err());
        assert!(RecordName::new("bad/name").is_err());
        assert!(RecordName::new("bad\\name").is_err());
        assert!(RecordName::new("trailing.").is_err());
        assert!(RecordName::new("trailing ").is_err());
        assert!(RecordName::new("nul").is_err());
        assert!(RecordName::new("CON").is_err());
        assert!(RecordName::new("com1").is_err());
        assert!(RecordName::new("LPT9").is_err());
        assert!(RecordName::new("COM¹").is_err());
        assert!(RecordName::new("com0").is_ok());
        assert!(RecordName::new("console").is_ok());
        assert!(RecordName::new(&"x".repeat(65)).is_err());
    }

    #[test]
    fn envelope_roundtrip() {
        let cipher = b"ciphertext-bytes".to_vec();
        let envelope = build_envelope(&cipher).unwrap();
        let parsed = parse_envelope(&envelope).unwrap();
        assert_eq!(parsed, &cipher[..]);
    }

    #[test]
    fn envelope_rejects_tamper() {
        let envelope = build_envelope(b"data").unwrap();
        assert!(parse_envelope(b"not-an-envelope").is_err());
        let mut truncated = envelope.clone();
        truncated.pop();
        assert!(parse_envelope(&truncated).is_err());
        let mut wrong_magic = envelope.clone();
        wrong_magic[0] = b'X';
        assert!(parse_envelope(&wrong_magic).is_err());
    }

    /// Protect/unprotect round-trips through real user-scoped DPAPI and the
    /// record store, and the on-disk file never contains the plaintext.
    /// Secrets are marker values; the assertions below prove they appear
    /// neither in the file nor in any error/Debug rendering.
    #[test]
    fn store_roundtrip_and_no_plaintext_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let store = CredentialStore::open(dir.path().to_path_buf()).unwrap();
        let name = RecordName::new("test-record").unwrap();
        let secret = b"HFD_TEST_MARKER_SECRET_a8f3";
        let entropy = b"binding-context";

        store.save_record(&name, secret, Some(entropy)).unwrap();

        // The ciphertext file must not contain the plaintext marker.
        let path = store.record_path(&name);
        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw.windows(secret.len()).any(|w| w == secret),
            "plaintext marker leaked into the protected record file"
        );

        let loaded = store.load_record(&name, Some(entropy)).unwrap();
        assert_eq!(loaded.expose(), &secret[..]);

        // Wrong entropy must fail with UnprotectFailed, not succeed or leak.
        let err = store.load_record(&name, Some(b"other-context")).unwrap_err();
        assert!(matches!(err, CredentialError::UnprotectFailed { .. }));
        let display = format!("{err}");
        assert!(!display.contains("HFD_TEST_MARKER_SECRET"));

        // SecretBytes Debug is redacted.
        let debug = format!("{:?}", loaded);
        assert!(!debug.contains("HFD_TEST_MARKER_SECRET"));
        assert!(debug.contains("redacted"));

        // Listing shows names only.
        let listed = store.list_records().unwrap();
        assert_eq!(listed, vec![name.clone()]);

        // Delete removes the record; second delete reports absent.
        assert!(store.delete_record(&name).unwrap());
        assert!(!store.delete_record(&name).unwrap());
        assert!(matches!(
            store.load_record(&name, None).unwrap_err(),
            CredentialError::NotFound
        ));
    }

    #[test]
    fn store_atomic_replace_leaves_no_torn_record() {
        let dir = tempfile::tempdir().unwrap();
        let store = CredentialStore::open(dir.path().to_path_buf()).unwrap();
        let name = RecordName::new("rotate").unwrap();
        store.save_record(&name, b"first", None).unwrap();
        store.save_record(&name, b"second", None).unwrap();
        let loaded = store.load_record(&name, None).unwrap();
        assert_eq!(loaded.expose(), b"second");
        // No leftover temporary files from either save.
        let leftovers: Vec<_> = std::fs::read_dir(store.base())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left behind: {leftovers:?}");
    }

    #[test]
    fn secret_string_debug_is_redacted() {
        let s = SecretString::new("HFD_TEST_MARKER_SECRET_b2c1".to_owned());
        let debug = format!("{s:?}");
        assert!(!debug.contains("HFD_TEST_MARKER_SECRET"));
        assert!(debug.contains("redacted"));
    }
}
