//! Native Hugging Face Bucket/Xet boundary.
//!
//! This crate is the only place that touches the official `hf-hub` Git revision
//! (`473de943`) and `hf-xet` 1.8.1. No SDK type (HF client, Xet session/commit/
//! stream/handle, SDK error) escapes this boundary: consumers see only HF Drive
//! core identities (`hfdrive_core::{ids, storage}`), `hfdrive_auth`'s
//! `TokenSource`/`AuthorizationLease`, and the sanitized types below.
//!
//! Surface split:
//! - [`NativeApi`]: per-account client/credential generation handling
//!   (`TokenSource`-backed), one controlled 401 refresh, and lease capture for
//!   the parent's pre-publication authorization checks.
//! - [`NativeControl`]: namespace control plane (list/create/verify buckets,
//!   object metadata, bounded native HEAD-record reads, prefix inspection).
//!   Works from a [`hfdrive_core::storage::BucketBinding`] +
//!   [`hfdrive_core::storage::RemotePrefix`] **before any workspace identity
//!   exists**, and never creates a Xet session or cache directory.
//! - [`NativeBucketStore`]: drive-bound storage plane (tree, paths-info,
//!   batches, event source, staged immutable uploads, bounded cancellable
//!   range reads) for one [`hfdrive_core::storage::DriveBinding`].
//!
//! Durability contract: uploads expose three separately persistable
//! checkpoints ([`IngestionCheckpoint`] -> [`CasCommitCheckpoint`] ->
//! [`BoundObject`]); the managed HEAD stays outside this crate. A cancellation
//! or transport failure after a request was dispatched is reported as such and
//! is never described as rollback.
//!
//! Errors never carry bearer tokens, CAS/CDN or presigned URL material, SDK
//! error strings, or response bodies, and this crate emits no log records.
#![forbid(unsafe_code)]

mod auth;
mod control;
mod http;
mod store;
mod wire;
mod xet;
pub mod wire_budget;

pub use auth::{NativeApi, NativeLease};
pub use control::{
    BucketRegion, BucketSummary, CreateBucket, HeadRead, NativeControl, OwnerLocator, OwnerRef, OwnerResolution,
    PrefixInspection, PrefixState, VerifiedOwner,
};
pub use store::{
    BatchAdd, BatchFailure, BatchOp, BatchReport, BoundObject, CasCommitCheckpoint, ChangeOp, EventCursor, EventResume,
    IngestionCheckpoint, NativeBucketStore, NativeChange, NativeEvent, NativeEventStream, NativeRawStore, NativeTreeEntry,
    ObjectMetadata, PageCursor, PathInfo, PathKind, PathsInfoReport, RangeCache, RangeReader, StagedCommitted, StagedIngested,
    StagedUpload, TreePage, UploadSource,
};
pub use wire::{HeadFormat, HeadRecord};
pub use xet::XetLimits;

/// Maximum accepted size of one JSON response body (listings, reports).
pub(crate) const MAX_JSON_BYTES: usize = 32 * 1024 * 1024;

/// Sanitized native failure. No variant carries SDK error text, URLs, signed
/// query strings, or response bodies. [`NativeError::InvalidRequest`]'s
/// `detail` is stripped of control characters and query/fragment material and
/// is bounded in length by this crate.
#[derive(Clone, Debug, thiserror::Error)]
pub enum NativeError {
    #[error("sign-in is required")]
    NeedsSignIn,
    #[error("native storage access was denied")]
    PermissionDenied,
    #[error("remote content is unavailable; no deletion is inferred")]
    RemoteContentUnavailable,
    #[error("native Xet capability is unavailable for this object")]
    XetRequired,
    #[error("requested range is outside the immutable object")]
    InvalidRange,
    #[error("native request was cancelled; accepted mutations require recovery")]
    Cancelled,
    #[error("native service throttled this connection")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("native transport failed")]
    Transport,
    #[error("native response violated the storage contract")]
    InvalidResponse,
    /// HTTP 409 on bucket creation or another explicit conflict. Never proof
    /// that the application owns the existing resource.
    #[error("the native resource already exists; ownership is not implied")]
    AlreadyExists,
    /// Canonical owner/bucket identity, lease account binding, or credential
    /// generation did not match what the caller selected.
    #[error("native resource identity does not match the selected binding")]
    IdentityMismatch,
    /// The service rejected the request shape (4xx) or a local precondition
    /// failed. `detail` is sanitized: no controls, no query strings, bounded.
    #[error("native request was rejected: {detail}")]
    InvalidRequest { detail: String },
    /// The staged source changed after capture (size or SHA-256 mismatch
    /// against the ingestion result); recapture, never bind.
    #[error("the staged source changed after capture")]
    SourceChanged,
    /// A bounded listing exceeded its configured entry limit; the listing is
    /// incomplete and must never be treated as exhaustive.
    #[error("native listing exceeded the configured entry limit")]
    TooManyEntries,
}

impl NativeError {
    /// Short sanitized detail: first line only, control characters removed,
    /// query/fragment dropped, bounded length. Never call with URL or token
    /// material.
    pub(crate) fn detail(raw: &str) -> String {
        let line = raw.lines().next().unwrap_or("");
        let cut = line.split(['?', '#']).next().unwrap_or("");
        let mut out = String::with_capacity(cut.len().min(160));
        for ch in cut.chars().filter(|c| !c.is_control()).take(160) {
            out.push(ch);
        }
        if out.is_empty() {
            out.push_str("request rejected");
        }
        out
    }
}

/// Native adapter configuration.
#[derive(Clone, Debug)]
pub struct NativeConfig {
    /// HF API base URL (no trailing slash). Production uses
    /// `https://huggingface.co`; tests may point at a local fixture server.
    pub endpoint: String,
    /// Per account/drive persistent Xet shard and upload-metadata cache root
    /// (`DrivePaths::xet_cache`). When empty, `hf-xet` derives its own default;
    /// that fallback is for tests only.
    pub xet_cache_dir: std::path::PathBuf,
    /// Xet transfer/concurrency bounds, applied programmatically (never
    /// through process-global environment variables).
    pub xet_limits: XetLimits,
    /// Maximum accepted managed HEAD record size in bytes. The v1 remote
    /// format bounds HEAD at 16 KiB; larger records are reported as
    /// [`HeadRead::TooLarge`], never read and never treated as absent.
    pub max_head_bytes: usize,
    /// Maximum entries one bounded tree walk may yield before failing with
    /// [`NativeError::TooManyEntries`].
    pub max_listed_entries: usize,
    /// Maximum chunk size handed to a [`RangeReader`] consumer.
    pub range_chunk_bytes: usize,
}

impl Default for NativeConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://huggingface.co".to_owned(),
            xet_cache_dir: std::path::PathBuf::new(),
            xet_limits: XetLimits::default(),
            max_head_bytes: 16 * 1024,
            max_listed_entries: 1_000_000,
            range_chunk_bytes: 1024 * 1024,
        }
    }
}
