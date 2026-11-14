//! Platform-independent identities, remote format, catalog and synchronization
//! invariants.
#![forbid(unsafe_code)]

pub mod catalog;
pub mod catalog_diff;
pub mod history;
pub mod reconcile;
pub mod format;
pub mod ids;
pub mod names;
pub mod settings;
pub mod storage;
