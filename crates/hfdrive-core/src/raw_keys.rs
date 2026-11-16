//! Deterministic raw import keys for the Explorer upload feature.
//!
//! A raw import binds selected local files/folders to exact bucket-relative
//! keys under the shared prefix `hfdrive-imports/<import-id>/`, with no
//! workspace, managed catalog, HEAD, or connection involved:
//!
//! * each selected **folder** root contributes its basename as the first key
//!   segment; folder children preserve their validated relative paths below it,
//! * each selected **file** root contributes its basename as its key suffix,
//! * when several selected roots share a basename (under portable or Windows
//!   case-insensitive equality), deterministic suffixes are added in input
//!   order (`name`, `name (2)`, `name (3)`; for file roots the suffix is
//!   inserted before the final extension).
//!
//! Every derived segment is re-validated before any upload: an unsupported
//! path (Windows-forbidden name, reserved device name, or a key a canonical
//! [`RelativeKey`] cannot carry — `%`, `#`, `\`, `:`, or more than 1024 UTF-8
//! bytes) is rejected during preflight and never truncated, re-encoded, or
//! silently skipped. Key spelling is preserved exactly; portable (NFC + full
//! casefold) and Windows case-insensitive equality are both considered, so
//! one request can never derive two keys that collide in a case-insensitive
//! bucket namespace.

use crate::names::collision_key;
use crate::storage::{RelativeKey, StorageValueError};
use uuid::Uuid;

/// Maximum importable files in one request.
///
/// This is a request bound, not a result-shaping guarantee: one per-file
/// receipt is at least 178 bytes + key + decimal size on the wire, so 10 000
/// receipts can never fit the protocol's 1 MiB IPC frame in one `import`
/// result (typical keys reach the frame at ≈ 4 200 records). Consumers MUST
/// page or cap the per-file result records to the frame bound; the import
/// request bound and the response framing are independent concerns.
pub const MAX_IMPORT_FILES: usize = 10_000;

/// Import-target prefix `hfdrive-imports/<import-id>` for one import id
/// (lowercase hyphenated UUID spelling).
pub fn import_prefix(import_id: &str) -> Result<RelativeKey, StorageValueError> {
    validate_import_id(import_id)?;
    RelativeKey::new(format!("hfdrive-imports/{import_id}"))
}

/// Validate one import id and derive the exact raw key of `relative_path`
/// below `hfdrive-imports/<import-id>/`. The relative path must be
/// non-empty, `/`-separated and portable (each segment passes
/// [`crate::names::validate_name`]).
pub fn import_key(import_id: &str, relative_path: &str) -> Result<RelativeKey, StorageValueError> {
    let prefix = import_prefix(import_id)?;
    if relative_path.is_empty() {
        return Err(StorageValueError::Key);
    }
    RelativeKey::new(format!("{prefix}/{relative_path}"))
}

fn validate_import_id(import_id: &str) -> Result<(), StorageValueError> {
    let ok = import_id.len() == 36
        && !import_id.bytes().any(|c| c.is_ascii_uppercase())
        && Uuid::parse_str(import_id)
            .map(|id| id.hyphenated().to_string() == import_id)
            .unwrap_or(false);
    if ok { Ok(()) } else { Err(StorageValueError::Key) }
}

/// One local file mapped to its exact bucket-relative key below the import
/// prefix.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RawKeyFile {
    /// The selected source root path string exactly as submitted.
    pub source: String,
    /// The root's qualified basename (with deterministic suffix), or `None`
    /// for nothing: every file carries its root qualifier.
    pub root_qualifier: Option<String>,
    /// Validated relative path below the source root (empty for a file root).
    pub relative_path: String,
    /// Exact bucket-relative key under the import prefix.
    pub key: String,
}

/// One directory that produced no importable files. Native `addFile` bindings
/// have no create-directory operation, so empty directories are never claimed
/// as imported; they are reported explicitly instead.
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RawKeyEmptyDirectory {
    /// The selected source root path string exactly as submitted.
    pub source: String,
    /// Validated relative path below the source root (empty for a root).
    pub relative_path: String,
    /// Why the directory produced no files.
    pub reason: String,
}

/// The complete deterministic key plan for one import request.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RawKeyPlan {
    pub files: Vec<RawKeyFile>,
    pub empty_directories: Vec<RawKeyEmptyDirectory>,
}

/// One enumeration entry of a selected source root.
///
/// Root entries have `relative_path` empty; every child entry carries the
/// validated relative path below its root and repeats the root's `source`
/// string. `is_dir` distinguishes directories (which may be empty) from files.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RawKeySource {
    pub source: String,
    pub is_dir: bool,
    pub relative_path: String,
}

/// Why a source or key cannot become a raw import key. Every failure is a
/// preflight rejection: nothing is truncated, re-encoded, or skipped.
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum RawKeyError {
    #[error("import id must be a lowercase hyphenated UUID")]
    ImportId,
    #[error("source #{index} has no usable basename")]
    NoBasename { index: usize },
    #[error("source #{index} path {relative:?} is not portable key material: {reason}")]
    Component { index: usize, relative: String, reason: String },
    #[error("source #{index} path {relative:?} cannot be a canonical relative key: {reason}")]
    UnsupportedKey { index: usize, relative: String, reason: String },
    #[error("source #{index} path {relative:?} duplicates another source's raw key")]
    DuplicateKey { index: usize, relative: String },
    #[error("the request selects no files or directories")]
    EmptySelection,
    #[error("at most {limit} files may be imported in one request")]
    TooManyFiles { limit: usize },
}

/// Deterministic root-key plan for one import request. Sources are listed in
/// request order; a root entry precedes its children. Directories that yield
/// no files are reported as empty (with a reason), never as imported.
pub fn plan_raw_keys(import_id: &str, entries: &[RawKeySource]) -> Result<RawKeyPlan, RawKeyError> {
    plan_raw_keys_with_limit(import_id, entries, MAX_IMPORT_FILES)
}

/// [`plan_raw_keys`] with an explicit file bound (for previews and tests).
pub fn plan_raw_keys_with_limit(
    import_id: &str,
    entries: &[RawKeySource],
    max_files: usize,
) -> Result<RawKeyPlan, RawKeyError> {
    import_prefix(import_id).map_err(|_| RawKeyError::ImportId)?;

    // Bind every entry to its source root: roots are the empty-relative-path
    // entries; a child belongs to the nearest preceding directory root with
    // the same `source` string. A child without such a root is refused.
    let mut root_of: Vec<usize> = Vec::with_capacity(entries.len());
    let mut open_roots: Vec<usize> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        if entry.relative_path.is_empty() {
            root_of.push(index);
            if entry.is_dir {
                open_roots.push(index);
            }
        } else {
            let root = open_roots
                .iter()
                .rev()
                .find(|root| entries[**root].source == entry.source)
                .copied();
            match root {
                Some(root) => root_of.push(root),
                None => {
                    return Err(RawKeyError::Component {
                        index,
                        relative: entry.relative_path.clone(),
                        reason: "child entry has no preceding selected folder root".to_owned(),
                    });
                }
            }
        }
    }

    // Qualify every root basename in input order: `name`, `name (2)`, `name (3)`.
    // Folder roots gain the suffix at the end; file roots gain it before the
    // final extension. Both portable and Windows case-insensitive equality make
    // two roots "the same basename".
    let mut root_names: Vec<Option<String>> = vec![None; entries.len()];
    let mut taken_portable: Vec<Vec<u8>> = Vec::new();
    let mut taken_folded: Vec<Vec<u8>> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        if root_of[index] != index {
            continue;
        }
        let base = basename(&entry.source).ok_or(RawKeyError::NoBasename { index })?;
        let mut candidate = base.clone();
        let mut attempt = 1usize;
        let name = loop {
            if let Err(error) = crate::names::validate_name(&candidate) {
                return Err(RawKeyError::Component {
                    index,
                    relative: entry.relative_path.clone(),
                    reason: error.to_string(),
                });
            }
            let portable = collision_key(&candidate);
            let folded = windows_fold(&candidate);
            let clash = taken_portable.iter().any(|key| key == &portable)
                || taken_folded.iter().any(|key| key == &folded);
            if !clash {
                break candidate;
            }
            attempt += 1;
            if attempt > 4096 {
                return Err(RawKeyError::Component {
                    index,
                    relative: entry.relative_path.clone(),
                    reason: "basename disambiguation suffixes were exhausted".to_owned(),
                });
            }
            candidate = if entry.is_dir {
                format!("{base} ({attempt})")
            } else {
                suffixed(&base, attempt)
            };
        };
        taken_portable.push(collision_key(&name));
        taken_folded.push(windows_fold(&name));
        root_names[index] = Some(name);
    }

    // Derive exact keys. Uniqueness is enforced within the request under both
    // equality rules; nothing ever collides silently.
    let mut plan = RawKeyPlan { files: Vec::new(), empty_directories: Vec::new() };
    let mut used_keys: Vec<Vec<u8>> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        if entry.is_dir {
            continue;
        }
        let relative = validate_relative_path(index, &entry.relative_path)?;
        let root_name = root_names[root_of[index]]
            .clone()
            .ok_or(RawKeyError::NoBasename { index })?;
        let suffix = if relative.is_empty() { root_name } else { format!("{root_name}/{relative}") };
        let key = import_key(import_id, &suffix).map_err(|_| RawKeyError::UnsupportedKey {
            index,
            relative: entry.relative_path.clone(),
            reason: "key exceeds the canonical relative-key bound or carries forbidden characters".to_owned(),
        })?;
        let fingerprint = key_fingerprint(key.as_str());
        if used_keys.iter().any(|existing| existing == &fingerprint) {
            return Err(RawKeyError::DuplicateKey {
                index,
                relative: entry.relative_path.clone(),
            });
        }
        used_keys.push(fingerprint);
        plan.files.push(RawKeyFile {
            source: entry.source.clone(),
            root_qualifier: root_names[root_of[index]].clone(),
            relative_path: relative.clone(),
            key: key.as_str().to_owned(),
        });
        if plan.files.len() > max_files {
            return Err(RawKeyError::TooManyFiles { limit: max_files });
        }
    }

    // Directories with no file below them are explicit results, never silently
    // claimed as imported.
    for (index, entry) in entries.iter().enumerate() {
        if !entry.is_dir {
            continue;
        }
        let relative = validate_relative_path(index, &entry.relative_path)?;
        let root = root_of[index];
        let prefix = if relative.is_empty() { String::new() } else { format!("{relative}/") };
        let has_files = entries.iter().enumerate().any(|(other, candidate)| {
            !candidate.is_dir
                && root_of[other] == root
                && (prefix.is_empty() || candidate.relative_path.starts_with(&prefix))
        });
        if !has_files {
            plan.empty_directories.push(RawKeyEmptyDirectory {
                source: entry.source.clone(),
                relative_path: relative.clone(),
                reason: if relative.is_empty() {
                    "the selected folder contains no importable files".to_owned()
                } else {
                    "directory contains no importable files".to_owned()
                },
            });
        }
    }

    if plan.files.is_empty() && plan.empty_directories.is_empty() {
        return Err(RawKeyError::EmptySelection);
    }
    Ok(plan)
}

fn basename(source: &str) -> Option<String> {
    let trimmed = source.trim_end_matches(['\\', '/']);
    let cut = trimmed.rsplit(['\\', '/']).next()?;
    if cut.is_empty() { None } else { Some(cut.to_owned()) }
}

/// Validate one `/`-separated relative path of portable final components and
/// return it unchanged. An empty path means the root itself.
fn validate_relative_path(index: usize, relative: &str) -> Result<String, RawKeyError> {
    if relative.is_empty() {
        return Ok(String::new());
    }
    if relative.contains('\\') || relative.starts_with('/') || relative.ends_with('/') {
        return Err(RawKeyError::Component {
            index,
            relative: relative.to_owned(),
            reason: "path must be relative and `/`-separated".to_owned(),
        });
    }
    for part in relative.split('/') {
        if let Err(error) = crate::names::validate_name(part) {
            return Err(RawKeyError::Component {
                index,
                relative: relative.to_owned(),
                reason: error.to_string(),
            });
        }
    }
    Ok(relative.to_owned())
}

/// Insert ` (n)` before the final extension (`report.tar.gz` ->
/// `report.tar (2).gz`); a name without an extension gains the suffix at the
/// end.
fn suffixed(base: &str, attempt: usize) -> String {
    let (stem, ext) = match base.rfind('.') {
        Some(position) if position > 0 => (&base[..position], &base[position..]),
        _ => (base, ""),
    };
    format!("{stem} ({attempt}){ext}")
}

/// Fingerprint used to detect key collisions under either equality rule
/// (portable collision key, Windows case-insensitive), plus exact spelling.
fn key_fingerprint(key: &str) -> Vec<u8> {
    let mut out = collision_key(key);
    out.push(0xff);
    out.extend_from_slice(&windows_fold(key));
    out
}

/// Conservative Windows case-insensitive fold (Unicode simple uppercase
/// mapping). Two keys that differ only by case never share one request.
fn windows_fold(value: &str) -> Vec<u8> {
    value.chars().flat_map(char::to_uppercase).collect::<String>().into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "00112233-4455-4677-8899-aabbccddeeff";
    const PREFIX: &str = "hfdrive-imports/00112233-4455-4677-8899-aabbccddeeff";

    fn root(source: &str) -> RawKeySource {
        RawKeySource { source: source.to_owned(), is_dir: false, relative_path: String::new() }
    }

    fn folder(source: &str, children: &[(&str, bool)]) -> Vec<RawKeySource> {
        let mut out = vec![RawKeySource {
            source: source.to_owned(),
            is_dir: true,
            relative_path: String::new(),
        }];
        out.extend(children.iter().map(|(child, is_dir)| RawKeySource {
            source: source.to_owned(),
            is_dir: *is_dir,
            relative_path: (*child).to_owned(),
        }));
        out
    }

    #[test]
    fn file_roots_take_their_basename() {
        let plan = plan_raw_keys(ID, &[root("C:\\Users\\a\\hello.txt"), root("C:\\tmp\\data.bin")]).unwrap();
        assert_eq!(plan.files[0].key, format!("{PREFIX}/hello.txt"));
        assert_eq!(plan.files[1].key, format!("{PREFIX}/data.bin"));
    }

    #[test]
    fn folder_roots_prefix_their_children() {
        let plan = plan_raw_keys(
            ID,
            &folder("C:\\Users\\a\\photos", &[("img.png", false), ("raw", true), ("raw/img.cr2", false)]),
        )
        .unwrap();
        assert_eq!(plan.files[0].key, format!("{PREFIX}/photos/img.png"));
        assert_eq!(plan.files[1].key, format!("{PREFIX}/photos/raw/img.cr2"));
        assert!(plan.empty_directories.is_empty());
    }

    #[test]
    fn duplicate_root_basenames_get_deterministic_suffixes() {
        let mut sources = folder("C:\\a\\docs", &[("x.txt", false)]);
        sources.extend(folder("C:\\b\\docs", &[("y.txt", false)]));
        sources.push(root("C:\\c\\docs"));
        sources.push(root("C:\\d\\docs"));
        let plan = plan_raw_keys(ID, &sources).unwrap();
        assert_eq!(plan.files[0].key, format!("{PREFIX}/docs/x.txt"));
        assert_eq!(plan.files[1].key, format!("{PREFIX}/docs (2)/y.txt"));
        assert_eq!(plan.files[2].key, format!("{PREFIX}/docs (3)"));
        assert_eq!(plan.files[3].key, format!("{PREFIX}/docs (4)"));
    }

    #[test]
    fn file_root_suffix_lands_before_the_final_extension() {
        let mut sources = vec![root("C:\\a\\report.tar.gz"), root("C:\\b\\report.tar.gz")];
        sources.push(root("C:\\c\\report.tar.gz"));
        let plan = plan_raw_keys(ID, &sources).unwrap();
        assert_eq!(plan.files[0].key, format!("{PREFIX}/report.tar.gz"));
        assert_eq!(plan.files[1].key, format!("{PREFIX}/report.tar (2).gz"));
        assert_eq!(plan.files[2].key, format!("{PREFIX}/report.tar (3).gz"));
    }

    #[test]
    fn case_equivalent_root_basenames_are_suffixed_not_lost() {
        let sources = vec![root("C:\\a\\Data.bin"), root("C:\\b\\data.bin")];
        let plan = plan_raw_keys(ID, &sources).unwrap();
        assert_eq!(plan.files[0].key, format!("{PREFIX}/Data.bin"));
        assert_eq!(plan.files[1].key, format!("{PREFIX}/data (2).bin"));
    }

    #[test]
    fn portable_equivalent_root_basenames_are_suffixed_not_lost() {
        let sources = vec![root("C:\\a\\\u{e9}.txt"), root("C:\\b\\e\u{301}.txt")];
        let plan = plan_raw_keys(ID, &sources).unwrap();
        assert_eq!(plan.files.len(), 2);
        assert_ne!(plan.files[0].key, plan.files[1].key);
    }

    #[test]
    fn case_equivalent_children_in_one_root_fail_preflight() {
        // NTFS can hold both spellings in one directory; the bucket namespace
        // cannot. Preflight rejects instead of overwriting or skipping.
        let plan = plan_raw_keys(
            ID,
            &folder("C:\\a\\root", &[("X.txt", false), ("x.txt", false)]),
        );
        assert!(matches!(plan, Err(RawKeyError::DuplicateKey { index: 2, .. })));
    }

    #[test]
    fn unsupported_keys_fail_preflight_instead_of_skipping() {
        // `%` is legal in a Windows name but a canonical RelativeKey cannot
        // carry it (no URL encoding is ever applied).
        let plan = plan_raw_keys(ID, &[root("C:\\a\\100%.txt")]);
        assert!(matches!(plan, Err(RawKeyError::UnsupportedKey { index: 0, .. })));
        // Reserved device names are refused as portable components.
        let plan = plan_raw_keys(ID, &[root("C:\\a\\CON")]);
        assert!(matches!(plan, Err(RawKeyError::Component { index: 0, .. })));
        // Overlong derived keys are refused, never truncated: six 210-char
        // segments exceed the 1024-byte canonical key bound.
        let segment = "x".repeat(210);
        let deep_path = (0..6).map(|_| segment.clone()).collect::<Vec<_>>().join("/");
        let entries = vec![
            RawKeySource { source: "C:\\a\\deep".to_owned(), is_dir: true, relative_path: String::new() },
            RawKeySource { source: "C:\\a\\deep".to_owned(), is_dir: false, relative_path: deep_path },
        ];
        let plan = plan_raw_keys(ID, &entries);
        assert!(matches!(plan, Err(RawKeyError::UnsupportedKey { .. }) | Err(RawKeyError::Component { .. })));
    }

    #[test]
    fn empty_directories_are_reported_not_claimed() {
        let plan = plan_raw_keys(
            ID,
            &folder("C:\\a\\mixed", &[("a.txt", false), ("empty", true)]),
        )
        .unwrap();
        assert_eq!(plan.files.len(), 1);
        assert_eq!(plan.empty_directories.len(), 1);
        assert_eq!(plan.empty_directories[0].relative_path, "empty");
        assert_eq!(plan.empty_directories[0].reason, "directory contains no importable files");

        // An entirely empty selection is an explicit result with no files and
        // one reported empty directory, never a claimed import.
        let plan = plan_raw_keys(ID, &folder("C:\\a\\empty", &[])).unwrap();
        assert!(plan.files.is_empty());
        assert_eq!(plan.empty_directories.len(), 1);
        assert_eq!(plan.empty_directories[0].relative_path, "");

        // No entries at all is refused.
        assert_eq!(plan_raw_keys(ID, &[]), Err(RawKeyError::EmptySelection));
    }

    #[test]
    fn import_key_matches_the_shared_prefix_contract() {
        assert_eq!(import_prefix(ID).unwrap().as_str(), PREFIX);
        assert_eq!(import_key(ID, "docs/a.txt").unwrap().as_str(), format!("{PREFIX}/docs/a.txt"));
        assert!(import_prefix("not-a-uuid").is_err());
        assert!(import_prefix("00112233-4455-4677-8899-AABBCCDDEEFF").is_err());
        assert!(import_key(ID, "").is_err());
    }

    #[test]
    fn file_bound_is_enforced() {
        let entries = vec![root("C:\\a\\f.bin")];
        assert!(matches!(
            plan_raw_keys_with_limit(ID, &entries, 0),
            Err(RawKeyError::TooManyFiles { limit: 0 })
        ));
    }

    #[test]
    fn root_and_child_must_stay_associated() {
        let orphan = vec![RawKeySource {
            source: "C:\\a\\orphan".to_owned(),
            is_dir: false,
            relative_path: "x.txt".to_owned(),
        }];
        assert!(matches!(plan_raw_keys(ID, &orphan), Err(RawKeyError::Component { .. })));
    }
}
