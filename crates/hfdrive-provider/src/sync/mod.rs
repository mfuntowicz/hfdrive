//! The synchronization engine: connection registry, durable local capture
//! and outbox planning, crash-safe publication and guarded local application.
//!
//! Module map:
//!
//! * [`registry`] — root admission, Windows registration, connect/restore;
//! * [`controller`] — the per-connection runtime and its control plane;
//! * [`engine`] — the global connection registry and unlink/drain lifecycle;
//! * [`observe`] — bounded watcher/USN/scan observation, echo suppression,
//!   coalescing and deletion-evidence rules;
//! * [`outbox`] — the durable intent schema and the eight-phase state
//!   machine, including crash recovery classification;
//! * [`capture`] — materialize-then-capture coherent immutable snapshots;
//! * [`plan`] — reconciliation integration (durable views -> pure core merge
//!   -> persisted plan records);
//! * [`publish`] — the crash-safe publication and application loop;
//! * [`apply`] — guarded CFAPI local application with journaled actions;
//! * [`remote`] — the remote effect boundary (native Xet + conditional HEAD);
//! * [`activity`] — live in-flight hydration/population spans for the
//!   read-only `list_activity` projection;
//! * [`work_errors`] — classified durable failure recording for that
//!   projection (safe codes/details, never tokens or payloads).
//!
//! Remote effects stay journaled: every external intent persists before its
//! effect, dispatched candidates are resolved by identity through committed
//! ancestry, and no incomplete evidence is ever re-driven as a write.
pub mod activity;
pub mod apply;
pub mod capture;
pub mod cfapi_pump;
pub mod controller;
pub mod engine;
pub mod observe;
pub mod outbox;
pub mod plan;
pub mod publish;
pub mod registry;
pub mod remote;
pub mod work_errors;

#[cfg(test)]
pub(crate) mod test_support;

pub use cfapi_pump::{PumpChild, PumpHost, PumpOutcome, run_pump};
pub use controller::{
    ConnectionConfig, ConnectionHealth, ConnectionRuntime, RuntimeState, WatchFailure, WatchUpdate,
};
pub use engine::{ConnectionServices, EngineConfig, EngineError, SyncEngine, UnlinkOutcome, UnlinkPlan};
pub use outbox::{PhaseStep, SyncIntent};
pub use publish::{PublishError, RoundContext, RoundOutcome};
pub use remote::{RemoteError, RemoteHead, RemoteOps};
