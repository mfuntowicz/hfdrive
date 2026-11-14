//! Locale-independent string adapters (`CompareStringOrdinal`) and UTF-16
//! helpers used by the other filesystem adapters.

use windows::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL};

/// `CompareStringOrdinal(a, b, TRUE) == CSTR_EQUAL` — the ordinal
/// case-insensitive comparison Windows itself uses for file names.
pub(crate) fn equal_ordinal_ignore_case(a: &[u16], b: &[u16]) -> bool {
    // SAFETY: both slices are valid wide strings for the call.
    unsafe { CompareStringOrdinal(a, b, true) == CSTR_EQUAL }
}

/// `CompareStringOrdinal(a, b, FALSE) == CSTR_EQUAL` — exact ordinal
/// comparison.
pub(crate) fn equal_ordinal(a: &[u16], b: &[u16]) -> bool {
    // SAFETY: both slices are valid wide strings for the call.
    unsafe { CompareStringOrdinal(a, b, false) == CSTR_EQUAL }
}

/// Decode a NUL-terminated wide buffer into a `String`, truncating at the
/// first NUL.
pub(crate) fn from_wide_nul(units: &[u16]) -> String {
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}
