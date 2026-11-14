//! Provider-owned durable state: locations, schema, and the database worker.
//!
//! The state layer is the durable boundary for intent, snapshots, journal
//! actions, publication baselines and setup reservations. It owns no
//! filesystem or network effects: those stay with the provider and the Windows
//! adapters. Everything lives under the caller-supplied base directory, never
//! inside a synchronization root, and credentials are only ever referenced by
//! name (DPAPI envelope files), never stored in these databases.
//!
//! # Integration contract
//!
//! - One dedicated worker thread owns the control database plus one database
//!   per account. Every call is a typed command on a bounded queue; there is
//!   no arbitrary SQL surface and no I/O await inside a transaction.
//! - Schema identity: each database carries a distinct `application_id` and a
//!   forward-only `user_version`. Fresh creation (we win the exclusive create)
//!   is distinct from an unknown preexisting file, which is refused untouched.
//!   Newer schemas are refused; corrupt or unreadable databases are refused
//!   and preserved (with their WAL) for recovery — never recreated.
//! - Forward migrations take a SQLite online backup first
//!   (`<db>.<unix-ms>.v<to>.bak` beside the database); identity and schema
//!   land in one transaction.
//! - Idempotent IPC mutations go through the operation ledger
//!   (`begin_operation`/`mark_dispatched`/`finish_operation`/`fail_operation`/
//!   `reconcile_operation`): one operation id binds to one exact request
//!   digest, completed operations replay their persisted result, and an
//!   interrupted external operation is reported as uncertain and never
//!   blindly replayed.
//! - Setup reservations (`reserve_setup`) bind an account and exact
//!   `DriveBinding` plus an immutable explicit `initialize` intent before any
//!   credential/probe/local-root work. Drafts are not registered connections
//!   and never appear as connected Explorer roots; the account-side and
//!   control-side journal commits are separate and reconciled explicitly.
//! - Probe runs journal exact created keys with reserve-before-effect states;
//!   cleanup enumerates only confirmed-created keys of the same run.
//! - Outbox entries move through the eight durable states only along their
//!   legal edges with their evidence; completion is generation-guarded and the
//!   applied baseline refuses to advance past pending local actions. Scan
//!   epochs gate deletion evidence: only a fully completed, non-invalidated
//!   scan may infer disappearance.
#![forbid(unsafe_code)]

mod api;
mod convert;
mod error;
mod model;
mod schema;
mod sql;
mod store;
mod worker;

pub use api::{AccountStore, StateStore};
pub use error::StateError;
pub use model::*;
pub use store::{CompletionOutcome, ObservationFlags, OperationResolution, OutboxTransition};

use hfdrive_core::ids::{AccountKey, WorkspaceId};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct StatePaths {
    base: PathBuf,
}

impl StatePaths {
    /// The Windows adapter supplies the physical per-user LocalAppData/HFDrive path.
    pub fn new(base: PathBuf) -> Self {
        Self { base }
    }
    pub fn base(&self) -> &Path {
        &self.base
    }
    pub fn control_database(&self) -> PathBuf {
        self.base.join("control.sqlite3")
    }
    pub fn account(&self, account: AccountKey) -> AccountPaths {
        AccountPaths {
            base: self.base.join("accounts").join(account.to_string()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AccountPaths {
    base: PathBuf,
}

impl AccountPaths {
    pub fn base(&self) -> &Path {
        &self.base
    }
    pub fn database(&self) -> PathBuf {
        self.base.join("state.sqlite3")
    }
    pub fn credentials(&self) -> PathBuf {
        self.base.join("credentials")
    }
    pub fn recovery(&self) -> PathBuf {
        self.base.join("recovery")
    }
    pub fn drive(&self, workspace: WorkspaceId) -> DrivePaths {
        DrivePaths {
            base: self.base.join("drives").join(workspace.to_string()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DrivePaths {
    base: PathBuf,
}

impl DrivePaths {
    pub fn base(&self) -> &Path {
        &self.base
    }
    pub fn snapshots(&self) -> PathBuf {
        self.base.join("snapshots")
    }
    pub fn range_cache(&self) -> PathBuf {
        self.base.join("range-cache")
    }
    pub fn xet_cache(&self) -> PathBuf {
        self.base.join("xet-cache")
    }
}
