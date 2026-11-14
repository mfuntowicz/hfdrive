//! Portable final-component name rules for HF Drive's namespace.
//!
//! Delegates the rules to `hfdrive_core::names` (single source of truth) and
//! adds the Windows-specific ordinal comparison helper used to detect
//! collisions the portable collision key cannot see. Names keep their
//! original spelling; validation never normalizes.

use hfdrive_core::names::validate_name;

pub use hfdrive_core::names::NameError as NameCheckError;

/// Validate one final path component exactly as HF Drive's namespace allows
/// it: nonempty, no control characters or NUL, no `< > : " / \ | ? *`, no
/// trailing dot or space, no reserved DOS device names (including superscript
/// COM/LPT spellings), and at most 255 UTF-16 code units.
pub fn validate_component(name: &str) -> Result<(), NameCheckError> {
    validate_name(name)
}

/// Decode a wide final-component from an OS buffer. Strict UTF-16: invalid
/// or unpaired surrogates are rejected (such paths can never be bound to a
/// portable name), and embedded NUL truncates nothing — a NUL anywhere is
/// rejected.
pub fn decode_component(units: &[u16]) -> Result<String, NameCheckError> {
    if units.iter().any(|&u| u == 0) {
        return Err(NameCheckError::ControlCharacter);
    }
    match String::from_utf16(units) {
        Ok(name) => {
            validate_component(&name)?;
            Ok(name)
        }
        Err(_) => Err(NameCheckError::ForbiddenCharacter),
    }
}

/// True when Windows treats the two spellings as the same name:
/// `CompareStringOrdinal(..., TRUE)` — the same comparison the filesystem
/// applies to case-insensitive directories. Used to detect case-only
/// collisions the portable collision key may miss on this volume.
pub fn windows_case_equivalent(a: &str, b: &str) -> bool {
    let a: Vec<u16> = a.encode_utf16().collect();
    let b: Vec<u16> = b.encode_utf16().collect();
    crate::ffi::nls::equal_ordinal_ignore_case(&a, &b)
}

/// Exact ordinal comparison (`CompareStringOrdinal(..., FALSE)`).
pub fn windows_exact_equal(a: &str, b: &str) -> bool {
    let a: Vec<u16> = a.encode_utf16().collect();
    let b: Vec<u16> = b.encode_utf16().collect();
    crate::ffi::nls::equal_ordinal(&a, &b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_and_invalid_components() {
        assert_eq!(validate_component("report.txt"), Ok(()));
        assert_eq!(validate_component("résumé"), Ok(()));
        assert!(validate_component("").is_err());
        assert!(validate_component("a.").is_err());
        assert!(validate_component("a ").is_err());
        assert!(validate_component("a/b").is_err());
        assert!(validate_component("CON").is_err());
        assert!(validate_component("Lpt\u{b9}.txt").is_err());
    }

    #[test]
    fn decode_rejects_nul_and_invalid_utf16() {
        assert_eq!(decode_component(&[b'a' as u16, 0]), Err(NameCheckError::ControlCharacter));
        // Lone surrogate (0xD83D is a high surrogate without its low pair).
        assert!(decode_component(&[0xD83D]).is_err());
        assert_eq!(decode_component(&[b'o' as u16, b'k' as u16]).unwrap(), "ok");
    }

    #[test]
    fn case_equivalence_matches_ordinal_comparison() {
        assert!(windows_case_equivalent("Report.txt", "REPORT.TXT"));
        assert!(!windows_case_equivalent("Report.txt", "Report.txu"));
        assert!(windows_exact_equal("Report.txt", "Report.txt"));
        assert!(!windows_exact_equal("Report.txt", "report.txt"));
    }
}
