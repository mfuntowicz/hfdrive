//! Decimal-string encoding for full-width `u64` wire fields.
//!
//! Wire contract: every `u64` (byte counts, generations, sequences, sizes) is
//! serialized as a JSON string containing base-10 digits, so JSON clients that
//! materialize numbers as IEEE-754 doubles never lose precision. Decoding
//! accepts only canonical decimal strings: non-empty, digits only, no leading
//! `+`/`-`, no leading zero unless the value is exactly `"0"`, and the value
//! must fit in `u64`.

use serde::{Deserialize, Deserializer, Serializer};

/// Serializes a `u64` as its canonical decimal string.
pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

/// Deserializes a `u64` from its canonical decimal string form.
pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let text = String::deserialize(deserializer)?;
    parse(&text).map_err(serde::de::Error::custom)
}

/// Parses a canonical decimal `u64` string, rejecting any other shape.
pub fn parse(text: &str) -> Result<u64, &'static str> {
    if text.is_empty() {
        return Err("expected decimal string, got empty string");
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err("decimal string has a leading zero");
    }
    let mut value: u64 = 0;
    for byte in text.bytes() {
        if !byte.is_ascii_digit() {
            return Err("decimal string contains a non-digit character");
        }
        let digit = u64::from(byte - b'0');
        value = value
            .checked_mul(10)
            .and_then(|scaled| scaled.checked_add(digit))
            .ok_or("decimal string overflows u64")?;
    }
    Ok(value)
}

/// Optional `u64` fields are omitted from the wire entirely when `None`.
pub mod option {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::parse;

    /// Serializes `Some` as a canonical decimal string.
    ///
    /// Pair with `skip_serializing_if = "Option::is_none"`; `None` is never
    /// written (the wire contract omits absent optional fields).
    pub fn serialize<S>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(inner) => super::serialize(inner, serializer),
            None => serializer.serialize_none(),
        }
    }

    /// Deserializes an optional canonical decimal `u64` string.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = Option::<String>::deserialize(deserializer)?;
        match text {
            None => Ok(None),
            Some(text) => parse(&text).map(Some).map_err(serde::de::Error::custom),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn accepts_canonical_decimal_strings() {
        assert_eq!(parse("0"), Ok(0));
        assert_eq!(parse("1"), Ok(1));
        assert_eq!(parse("18446744073709551615"), Ok(u64::MAX));
    }

    #[test]
    fn rejects_non_canonical_decimal_strings() {
        assert!(parse("").is_err());
        assert!(parse("00").is_err());
        assert!(parse("01").is_err());
        assert!(parse("+1").is_err());
        assert!(parse("-1").is_err());
        assert!(parse("1.0").is_err());
        assert!(parse("1e3").is_err());
        assert!(parse("18446744073709551616").is_err());
        assert!(parse(" 1").is_err());
        assert!(parse("1 ").is_err());
    }
}
