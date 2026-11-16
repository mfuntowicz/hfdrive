//! Startup/periodic metadata enumeration.
//!
//! Walks a sync root's tree without ever reading file content (placeholder
//! metadata is enumerated from attribute/identity queries only). Completeness
//! is part of the result: [`ScanReport::complete`] is true only for a fully
//! walked, fully accessible scan, and **only then** may the caller infer
//! disappearance/deletion of items it did not see. Denied directories and
//! budget exhaustion mark the scan incomplete; they never delete anything.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::ffi::volume as raw;

use super::volume::{placeholder_state, FileIdentity, PlaceholderState};
use super::{FsError, FsResult};

/// Bounds for one scan.
#[derive(Clone, Copy, Debug)]
pub struct ScanBudget {
    pub max_entries: usize,
    pub max_depth: usize,
}

impl Default for ScanBudget {
    fn default() -> Self {
        ScanBudget {
            max_entries: 200_000,
            max_depth: 512,
        }
    }
}

/// One enumerated entry (metadata only).
#[derive(Clone, Debug)]
pub struct MetadataEntry {
    pub relative_path: PathBuf,
    pub name: String,
    pub is_directory: bool,
    pub identity: FileIdentity,
    pub size: u64,
    pub creation_time_100ns: i64,
    pub last_write_time_100ns: i64,
    pub placeholder: PlaceholderState,
}

/// Visitor return: keep going or stop early (the report is then incomplete).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VisitFlow {
    Continue,
    Stop,
}

/// Outcome of one scan.
#[derive(Clone, Debug, Default)]
pub struct ScanReport {
    /// True only when every reachable directory was fully enumerated with no
    /// denials, budget exhaustion or early stop. Disappearance may only be
    /// inferred when this is true.
    pub complete: bool,
    pub entries: usize,
    /// Directories that could not be enumerated (access denied, missing).
    pub denied: Vec<PathBuf>,
    /// True when the entry budget was exhausted.
    pub overflow: bool,
}

/// Enumerate `root`'s metadata tree. Reparse points (other than this
/// provider's placeholders) are reported but never followed.
pub fn scan_metadata(
    root: &Path,
    budget: &ScanBudget,
    cancel: &AtomicBool,
    visit: &mut dyn FnMut(&MetadataEntry) -> VisitFlow,
) -> FsResult<ScanReport> {
    let mut report = ScanReport {
        complete: true,
        ..Default::default()
    };
    let mut stack = vec![(root.to_path_buf(), PathBuf::new(), 0usize)];
    while let Some((dir, relative, depth)) = stack.pop() {
        if cancel.load(Ordering::SeqCst) {
            return Err(FsError::Cancelled);
        }
        if depth > budget.max_depth {
            report.complete = false;
            report.overflow = true;
            continue;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => {
                report.complete = false;
                report.denied.push(relative.clone());
                continue;
            }
        };
        for entry in entries {
            if cancel.load(Ordering::SeqCst) {
                return Err(FsError::Cancelled);
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    report.complete = false;
                    report.denied.push(relative.clone());
                    continue;
                }
            };
            if report.entries >= budget.max_entries {
                report.complete = false;
                report.overflow = true;
                return Ok(report);
            }
            let os_name = entry.file_name();
            let name_valid = super::names::decode_component(
                &os_name.encode_wide().collect::<Vec<_>>(),
            ).is_ok();
            if !name_valid {
                // Invalid UTF-16 and non-portable names never become a
                // lossy-but-valid-looking sync path or deletion evidence.
                report.complete = false;
            }
            let name = os_name.to_string_lossy().into_owned();
            let path = entry.path();
            let state = match super::volume::query_file_state(&path) {
                Ok(state) => state,
                Err(_) => {
                    report.complete = false;
                    report.denied.push(join(&relative, &name));
                    continue;
                }
            };
            let is_directory = state.identity.attributes & raw::ATTR_DIRECTORY != 0;
            let placeholder = placeholder_state(state.identity.attributes, state.identity.reparse_tag);
            let item = MetadataEntry {
                relative_path: join(&relative, &os_name),
                name: name.clone(),
                is_directory,
                identity: state.identity.clone(),
                size: state.size,
                creation_time_100ns: 0,
                last_write_time_100ns: state.last_write_time_100ns,
                placeholder,
            };
            report.entries += 1;
            if visit(&item) == VisitFlow::Stop {
                report.complete = false;
                return Ok(report);
            }
            // Cloud directories stay inside this connected namespace. Never
            // follow name-surrogate links or claim their unseen children absent.
            if is_directory && name_valid {
                if !state.identity.is_reparse_point() || placeholder.is_placeholder() {
                    stack.push((path, item.relative_path.clone(), depth + 1));
                } else {
                    report.complete = false;
                }
            }
        }
    }
    Ok(report)
}

fn join(relative: &Path, name: impl AsRef<OsStr>) -> PathBuf {
    relative.join(Path::new(name.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_builds_relative_paths() {
        assert_eq!(join(Path::new(""), "a"), PathBuf::from("a"));
        assert_eq!(join(Path::new("x"), "a"), PathBuf::from("x/a"));
    }

    #[test]
    fn budget_default_is_bounded() {
        let budget = ScanBudget::default();
        assert!(budget.max_entries > 0 && budget.max_depth > 0);
    }
}
