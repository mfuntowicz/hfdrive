//! Portable file-name validation and the frozen portable collision key.
//!
//! HF Drive preserves the exact spelling of every name it stores. Portable
//! validation rejects names that Windows cannot represent as a final path
//! component, and the collision key identifies names that must never share a
//! directory even when their spellings differ. The collision key is Unicode
//! NFC normalization followed by Unicode default (non-Turkic) full case
//! folding, hashed with SHA-256. The resolved data versions are frozen in
//! `spec/remote-v1.md` and pinned by tests and golden fixtures: changing them
//! is a remote format migration.

use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;

/// Unicode Character Database version of the pinned `unicode-normalization`
/// crate (`NFC`), exported by that crate as `UNICODE_VERSION`.
pub const NFC_DATA_VERSION: (u8, u8, u8) = unicode_normalization::UNICODE_VERSION;
/// Unicode Character Database version of the pinned `unicode-casefold` crate
/// (default full case folding), exported by that crate as `UNICODE_VERSION`.
pub const CASEFOLD_DATA_VERSION: (u64, u64, u64) = unicode_casefold::UNICODE_VERSION;

/// Maximum name length in UTF-16 code units, the Windows component limit.
pub const MAX_NAME_UTF16_UNITS: usize = 255;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NameError {
    #[error("an item name cannot be empty")]
    Empty,
    #[error("an item name cannot exceed 255 UTF-16 code units")]
    TooLong,
    #[error("an item name cannot contain control characters or NUL")]
    ControlCharacter,
    #[error("an item name cannot contain characters Windows forbids in file names")]
    ForbiddenCharacter,
    #[error("an item name cannot end in a dot or space")]
    TrailingDotOrSpace,
    #[error("an item name uses a reserved DOS device name")]
    ReservedDeviceName,
}

const FORBIDDEN_CHARACTERS: [char; 9] = ['<', '>', ':', '"', '/', '\\', '|', '?', '*'];

/// Validates a name as a portable final path component. Spelling, case and
/// Unicode form are otherwise preserved exactly; nothing is normalized here.
pub fn validate_name(name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name.chars().any(char::is_control) {
        return Err(NameError::ControlCharacter);
    }
    if name.chars().any(|c| FORBIDDEN_CHARACTERS.contains(&c)) {
        return Err(NameError::ForbiddenCharacter);
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Err(NameError::TrailingDotOrSpace);
    }
    if is_reserved_device_name(name) {
        return Err(NameError::ReservedDeviceName);
    }
    if name.encode_utf16().count() > MAX_NAME_UTF16_UNITS {
        return Err(NameError::TooLong);
    }
    Ok(())
}

/// True when Windows treats the name (with or without an extension) as a DOS
/// device, including the superscript-digit COM/LPT spellings.
fn is_reserved_device_name(name: &str) -> bool {
    let base = name.split('.').next().unwrap_or("");
    let folded = base.to_ascii_uppercase();
    match folded.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" => return true,
        _ => {}
    }
    let suffix = match folded.get(..3) {
        Some("COM" | "LPT") => &folded[3..],
        _ => return false,
    };
    let mut digits = suffix.chars();
    match (digits.next(), digits.next()) {
        (Some(digit), None) => matches!(
            digit,
            '0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}' | '\u{2070}' | '\u{2074}'..='\u{2079}'
        ),
        _ => false,
    }
}

/// The portable collision key of a name: the UTF-8 bytes of the Unicode NFC
/// form followed by Unicode default (non-Turkic) full case folding.
///
/// Two names with equal collision keys must never share one parent. The
/// original spelling of the winning name is preserved in the item record; the
/// uniqueness index stores this key as lowercase hex (`n/<parent>/<hex>`).
pub fn collision_key(name: &str) -> Vec<u8> {
    name.nfc().case_fold().collect::<String>().into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rejects_unportable_final_components() {
        assert_eq!(validate_name("report.txt"), Ok(()));
        assert_eq!(validate_name("résumé"), Ok(()));
        assert_eq!(validate_name("報告"), Ok(()));
        assert_eq!(validate_name(""), Err(NameError::Empty));
        assert_eq!(validate_name("a\0b"), Err(NameError::ControlCharacter));
        assert_eq!(validate_name("a\nb"), Err(NameError::ControlCharacter));
        assert_eq!(validate_name("a/b"), Err(NameError::ForbiddenCharacter));
        assert_eq!(validate_name("a\\b"), Err(NameError::ForbiddenCharacter));
        assert_eq!(validate_name("a:b"), Err(NameError::ForbiddenCharacter));
        assert_eq!(validate_name("name."), Err(NameError::TrailingDotOrSpace));
        assert_eq!(validate_name("name "), Err(NameError::TrailingDotOrSpace));
        assert_eq!(validate_name("CON"), Err(NameError::ReservedDeviceName));
        assert_eq!(validate_name("con.txt"), Err(NameError::ReservedDeviceName));
        assert_eq!(validate_name("NUL.tar.gz"), Err(NameError::ReservedDeviceName));
        assert_eq!(validate_name("COM0"), Err(NameError::ReservedDeviceName));
        assert_eq!(validate_name("lpt9.log"), Err(NameError::ReservedDeviceName));
        assert_eq!(validate_name("COM\u{b9}"), Err(NameError::ReservedDeviceName));
        assert_eq!(validate_name("LPT\u{b3}.txt"), Err(NameError::ReservedDeviceName));
        assert_eq!(validate_name("COM\u{2074}"), Err(NameError::ReservedDeviceName));
        assert_eq!(validate_name("conin$"), Err(NameError::ReservedDeviceName));
        assert_eq!(validate_name("CONOUT$.log"), Err(NameError::ReservedDeviceName));
        assert_eq!(validate_name("COMPUTER"), Ok(()));
        assert_eq!(validate_name("COMA"), Ok(()));
        assert_eq!(validate_name(&"x".repeat(255)), Ok(()));
        assert_eq!(validate_name(&"x".repeat(256)), Err(NameError::TooLong));
        // Length counts UTF-16 code units: astral characters count as two.
        assert_eq!(validate_name(&"\u{e9}".repeat(255)), Ok(()));
        assert_eq!(validate_name(&"\u{e9}".repeat(256)), Err(NameError::TooLong));
        assert_eq!(validate_name(&"\u{1f600}".repeat(128)), Err(NameError::TooLong));
    }

    #[test]
    fn collision_key_folds_case_and_unicode_form() {
        // NFC composed and decomposed spellings collide.
        assert_eq!(collision_key("Ä"), collision_key("A\u{308}"));
        // Full default case folding, not simple lowercasing: ß and ẞ fold to "ss".
        assert_eq!(collision_key("STRASSE"), collision_key("STRA\u{df}E"));
        assert_eq!(collision_key("straße"), collision_key("STRASSE"));
        // Folding expansions collide with the pre-folded spelling.
        assert_eq!(collision_key("\u{df}"), collision_key("ss"));
        assert_eq!(collision_key("\u{1e9e}"), collision_key("SS"));
        // The dotless-i locale rules are not applied.
        assert_ne!(collision_key("I"), collision_key("\u{131}"));
        // Distinct names do not collide.
        assert_ne!(collision_key("a"), collision_key("b"));
    }

    #[test]
    fn collision_key_data_versions_are_frozen() {
        // Changing either value changes collision identities for existing
        // workspaces and requires a remote format migration.
        assert_eq!(NFC_DATA_VERSION, (18, 0, 0));
        assert_eq!(CASEFOLD_DATA_VERSION, (9, 0, 0));
    }

    #[test]
    fn collision_key_golden_hex() {
        // Golden values are the lowercase hex of the NFC-then-full-casefold
        // UTF-8 bytes, as stored in `n/<parent-id>/<collision-key-hex>`.
        // "Ä" and "A<combining diaeresis>" both fold to U+00E4.
        assert_eq!(hex::encode(collision_key("Ä")), "c3a4");
        assert_eq!(hex::encode(collision_key("A\u{308}")), "c3a4");
        // "ß"/"ẞ" fold to "ss"; "Straße" folds to "strasse".
        assert_eq!(hex::encode(collision_key("ss")), "7373");
        assert_eq!(hex::encode(collision_key("\u{df}")), "7373");
        assert_eq!(hex::encode(collision_key("\u{1e9e}")), "7373");
        assert_eq!(hex::encode(collision_key("Stra\u{df}e")), "73747261737365");
        // "İ" (U+0130) full-folds to "i" + U+0307.
        assert_eq!(hex::encode(collision_key("\u{130}")), "69cc87");
        // The dotless-i letter stays distinct from "i".
        assert_eq!(hex::encode(collision_key("\u{131}")), "c4b1");
        assert_eq!(hex::encode(collision_key("i")), "69");
    }
}
