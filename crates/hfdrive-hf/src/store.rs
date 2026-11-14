//! Drive-bound storage plane: listings, per-result batch reconciliation,
//! staged immutable uploads with three durable checkpoints, bounded
//! cancellable range reads, and the raw event source.

use bytes::Bytes;
use futures_util::StreamExt;
use hfdrive_core::storage::{
    ByteRange, DriveBinding, ImmutableKey, ObjectRef, PayloadKey, RelativeKey, Sha256Digest, StableSnapshot, XetFileId,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use xet::xet_session::{UniqueId, XetDownloadStream, XetDownloadStreamGroup, XetUploadCommit};

use crate::auth::NativeLease;
use crate::http;
use crate::wire::{self, BatchResponseWire, TreeEntryWire};
use crate::wire_budget::WireBudget;
use crate::xet::{map_xet_error, XetStore};
use crate::{NativeApi, NativeConfig, NativeError};
use hfdrive_auth::TokenSource;

/// Maximum size of one metadata record upload (commits bound at 1 MiB).
pub(crate) const MAX_METADATA_BYTES: usize = 1024 * 1024;
/// Maximum accepted SSE event payload.
pub(crate) const MAX_EVENT_BYTES: usize = 4 * 1024 * 1024;
/// Batch chunk size mandated by the service.
pub(crate) const BATCH_CHUNK: usize = 1000;
/// Paths-info chunk size mandated by the service.
pub(crate) const PATHS_INFO_CHUNK: usize = 1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    File,
    Directory,
}

/// One listing entry. `key` is the raw wire path for display/browsing; typed
/// requests always carry a validated [`RelativeKey`].
#[derive(Clone, Debug)]
pub struct NativeTreeEntry {
    pub key: String,
    pub kind: PathKind,
    pub size: u64,
    pub xet_file_id: Option<XetFileId>,
    pub mtime: Option<String>,
    pub mtime_nanos: Option<u64>,
    pub uploaded_at: Option<String>,
}

impl NativeTreeEntry {
    fn from_wire(entry: TreeEntryWire, mtime_nanos: Option<u64>) -> Self {
        Self {
            key: entry.path,
            kind: if entry.is_file { PathKind::File } else { PathKind::Directory },
            size: entry.size,
            xet_file_id: entry.xet_hash,
            mtime: entry.mtime,
            mtime_nanos,
            uploaded_at: entry.uploaded_at,
        }
    }
}

/// Opaque validated pagination cursor (a same-origin, bucket-contained next
/// URL). Re-validated on every use.
#[derive(Clone, Debug)]
pub struct PageCursor(String);

impl PageCursor {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PageCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One tree page.
#[derive(Clone, Debug, Default)]
pub struct TreePage {
    pub entries: Vec<NativeTreeEntry>,
    pub next: Option<PageCursor>,
}

/// Metadata for one bucket object (native HEAD). `xet_file_id` is `None` for
/// objects without a Xet identifier; such payloads fail the native capability
/// gate and must never be treated as generic HTTP payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectMetadata {
    pub key: RelativeKey,
    pub size: u64,
    pub xet_file_id: Option<XetFileId>,
}

impl ObjectMetadata {
    /// Capability gate: payloads without a native Xet identifier are refused,
    /// never silently served as generic HTTP.
    pub fn require_xet(&self) -> Result<XetFileId, NativeError> {
        self.xet_file_id.clone().ok_or(NativeError::XetRequired)
    }
}

/// Targeted metadata lookup result: found entries plus explicitly missing
/// keys. A missing key is an observed absence at lookup time, never a deletion.
#[derive(Clone, Debug, Default)]
pub struct PathsInfoReport {
    pub found: Vec<PathInfo>,
    pub missing: Vec<RelativeKey>,
}

#[derive(Clone, Debug)]
pub struct PathInfo {
    pub key: RelativeKey,
    pub kind: PathKind,
    pub size: u64,
    pub xet_file_id: Option<XetFileId>,
}

impl PathInfo {
    pub fn require_xet(&self) -> Result<XetFileId, NativeError> {
        self.xet_file_id.clone().ok_or(NativeError::XetRequired)
    }
}

/// One native batch mutation.
#[derive(Clone, Debug)]
pub enum BatchOp {
    /// Register an already-ingested Xet payload or metadata record at an exact
    /// bucket-relative key.
    Add(BatchAdd),
    /// Remove one bucket-relative key. Callers must only delete keys they
    /// persisted as created.
    Delete(RelativeKey),
}

#[derive(Clone, Debug)]
pub struct BatchAdd {
    pub key: RelativeKey,
    pub xet_file_id: XetFileId,
    pub size: u64,
}

/// One operation the service refused inside an otherwise accepted batch.
#[derive(Clone, Debug)]
pub struct BatchFailure {
    pub key: String,
    pub reason: String,
}

/// Full per-operation accounting for one `apply_batch` call. A 200 response can
/// still be partial: `is_complete()` must hold before a caller advances past
/// this mutation.
#[derive(Clone, Debug)]
pub struct BatchReport {
    pub submitted: usize,
    pub succeeded: usize,
    pub failures: Vec<BatchFailure>,
    /// The service's overall batch verdict. A `success: false` response is
    /// never complete, even when its counters happen to add up.
    pub success: bool,
}

impl Default for BatchReport {
    fn default() -> Self {
        Self { submitted: 0, succeeded: 0, failures: Vec::new(), success: true }
    }
}

impl BatchReport {
    pub fn is_complete(&self) -> bool {
        self.success && self.failures.is_empty() && self.succeeded == self.submitted
    }
}

/// Durable record of the ingestion boundary (bytes handed to Xet, digest
/// verified). Persist before starting CAS commit work.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestionCheckpoint {
    pub target_key: String,
    pub xet_file_id: XetFileId,
    pub size: u64,
    pub sha256: Sha256Digest,
    pub sdk_task_id: u64,
}

/// Durable record of the CAS commit boundary (metadata pushed to Xet CAS).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CasCommitCheckpoint {
    pub target_key: String,
    pub xet_file_id: XetFileId,
    pub size: u64,
    pub sha256: Sha256Digest,
    pub sdk_task_id: u64,
}

/// Durable record of the exact bucket-path binding boundary. This is the only
/// record from which a payload [`ObjectRef`] may be rebuilt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundObject {
    pub key: RelativeKey,
    pub xet_file_id: XetFileId,
    pub size: u64,
    pub sha256: Sha256Digest,
}

impl BoundObject {
    /// Rebuild the payload reference for `objects/<upload-uuid>` keys.
    pub fn payload_ref(&self) -> Result<ObjectRef, NativeError> {
        let key: PayloadKey = self.key.as_str().parse().map_err(|_| NativeError::InvalidResponse)?;
        Ok(ObjectRef {
            key,
            sha256: self.sha256,
            size: self.size,
            xet_file_id: self.xet_file_id.clone(),
        })
    }
}

/// Upload input. Snapshots are flushed immutable capture files; records are
/// small in-memory metadata documents owned by value so the SDK upload seam can
/// take the buffer without an avoidable copy. No live mutable source is ever
/// uploaded.
#[derive(Clone, Debug)]
pub enum UploadSource {
    Snapshot(StableSnapshot),
    Record(Vec<u8>),
}

/// Event-stream resume position. Cursors are opaque; `since` is the bucket
/// `updatedAt` instant format the events route documents.
#[derive(Clone, Debug)]
pub enum EventResume {
    Cursor(EventCursor),
    Since(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventCursor(String);

impl EventCursor {
    pub fn new(value: String) -> Result<Self, NativeError> {
        if value.is_empty() || value.len() > 512 || value.bytes().any(|b| b.is_ascii_control()) {
            return Err(NativeError::InvalidRequest {
                detail: "event cursor must be non-empty, bounded, and free of control characters".to_owned(),
            });
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeOp {
    Add,
    Update,
    Delete,
}

/// One entry of a `changes` event. `key` is the raw wire path.
#[derive(Clone, Debug)]
pub struct NativeChange {
    pub key: String,
    pub op: ChangeOp,
    pub size: Option<u64>,
    pub xet_file_id: Option<XetFileId>,
    pub uploaded_at: Option<String>,
    pub mtime: Option<String>,
    pub mtime_nanos: Option<u64>,
}

/// Raw bucket change feed events. Events are HEAD invalidations; nothing here
/// is a deletion decision.
#[derive(Clone, Debug)]
pub enum NativeEvent {
    Ready { cursor: Option<EventCursor> },
    Changes { cursor: Option<EventCursor>, changes: Vec<NativeChange> },
    Reset { reason: String },
    Reconnect { cursor: Option<EventCursor> },
}

/// Raw SSE source for the later scheduler: typed events plus the last observed
/// opaque cursor. `: ping` comments never surface; end-of-stream is `Ok(None)`
/// and the caller reconnects with its cursor. [`NativeEventStream::idle_for`]
/// reports silence at the encoded-body level (heartbeats included) for the
/// watch loop's reconnect fallback.
pub struct NativeEventStream {
    events: std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<wire::SseEvent, wire::SseError>> + Send>>,
    activity: std::sync::Arc<std::sync::Mutex<std::time::Instant>>,
    cursor: Option<EventCursor>,
    ended: bool,
}

impl NativeEventStream {
    pub fn cursor(&self) -> Option<&EventCursor> {
        self.cursor.as_ref()
    }

    /// Time since the last encoded body byte of the feed, heartbeat comments
    /// included.
    pub fn idle_for(&self) -> std::time::Duration {
        self.activity.lock().unwrap_or_else(|e| e.into_inner()).elapsed()
    }

    pub async fn next_event(&mut self, cancel: &CancellationToken) -> Result<Option<NativeEvent>, NativeError> {
        loop {
            if self.ended {
                return Ok(None);
            }
            let outcome = tokio::select! {
                _ = cancel.cancelled() => Err(NativeError::Cancelled),
                next = self.events.next() => match next {
                    None => {
                        self.ended = true;
                        return Ok(None);
                    }
                    Some(Err(_)) => Err(NativeError::Transport),
                    Some(Ok(event)) => Ok(event),
                },
            };
            let event = match outcome {
                Ok(event) => event,
                Err(error) => return Err(error),
            };
            if event.data.len() > MAX_EVENT_BYTES {
                return Err(NativeError::InvalidResponse);
            }
            match event.event.as_str() {
                "ready" | "reconnect" => {
                    let cursor = wire::event_cursor(&event.data).map_err(|_| NativeError::InvalidResponse)?;
                    self.track(&cursor);
                    if event.event == "reconnect" {
                        self.ended = true;
                        return Ok(Some(NativeEvent::Reconnect { cursor }));
                    }
                    return Ok(Some(NativeEvent::Ready { cursor }));
                }
                "changes" => {
                    let (cursor, changes) =
                        wire::event_changes(&event.data).map_err(|_| NativeError::InvalidResponse)?;
                    self.track(&cursor);
                    return Ok(Some(NativeEvent::Changes { cursor, changes }));
                }
                "reset" => {
                    let reason = wire::event_reset_reason(&event.data).map_err(|_| NativeError::InvalidResponse)?;
                    self.ended = true;
                    return Ok(Some(NativeEvent::Reset { reason }));
                }
                // Unknown event kinds are skipped raw; the feed stays alive.
                _ => continue,
            }
        }
    }

    fn track(&mut self, cursor: &Option<EventCursor>) {
        if cursor.is_some() {
            self.cursor = cursor.clone();
        }
    }
}

/// Cache-fill bookkeeping for one range read over an immutable object: every
/// delivered chunk is recorded as a clean immutable cache segment at its
/// absolute offset. The cache key pins the exact content version, so a fill can
/// never leak bytes into another version's ranges.
struct RangeFill {
    cache: RangeCache,
    object: ObjectRef,
    /// Absolute offset of the next delivered byte within the object.
    next_offset: u64,
}

/// Bounded ordered cancellable range reader over one immutable object. The
/// Xet download group and stream are owned here so their lifetimes cover the
/// whole read; bytes are delivered in order and at most `range_chunk_bytes`
/// per chunk. There is no whole-file fallback. A reader may instead serve
/// cached segments (a complete [`RangeCache`] hit) without any SDK work, and
/// every delivered chunk is counted as **logical** read bytes at the consumer
/// boundary (wire bytes are counted at the transport boundary, separately).
pub struct RangeReader {
    group: Option<XetDownloadStreamGroup>,
    stream: Option<XetDownloadStream>,
    /// Complete cache hit: ordered segments covering the validated range.
    cached: Option<std::vec::IntoIter<Bytes>>,
    fill: Option<RangeFill>,
    budget: Option<WireBudget>,
    remaining: u64,
    max_chunk: usize,
    pending: Option<Bytes>,
    done: bool,
}

impl RangeReader {
    fn empty() -> Self {
        Self {
            group: None,
            stream: None,
            cached: None,
            fill: None,
            budget: None,
            remaining: 0,
            max_chunk: 0,
            pending: None,
            done: true,
        }
    }

    /// A reader over already-cached immutable bytes; no SDK work happens and
    /// no cache fill is recorded (the bytes are already cached).
    fn cached(pieces: Vec<Bytes>, total: u64, budget: WireBudget, max_chunk: usize) -> Self {
        Self {
            group: None,
            stream: None,
            cached: Some(pieces.into_iter()),
            fill: None,
            budget: Some(budget),
            remaining: total,
            max_chunk,
            pending: None,
            done: false,
        }
    }

    /// Explicitly (re)start the SDK reconstruction task. Idempotent.
    pub fn start(&mut self) {
        if let Some(stream) = self.stream.as_mut() {
            stream.start();
        }
    }

    /// Bytes still owed by the validated range.
    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    /// SDK task id for correlation, when a stream exists.
    pub fn task_id(&self) -> Option<u64> {
        self.stream.as_ref().map(|s| s.task_id().0)
    }

    /// Next ordered chunk, `Ok(None)` at end of the validated range. An empty
    /// range completes immediately without SDK work.
    pub async fn next_chunk(&mut self, cancel: &CancellationToken) -> Result<Option<Bytes>, NativeError> {
        if cancel.is_cancelled() {
            self.cancel();
            return Err(NativeError::Cancelled);
        }
        if let Some(pending) = self.pending.take() {
            let piece = self.split_chunk(pending);
            return Ok(Some(self.deliver(piece)));
        }
        if let Some(cached) = self.cached.as_mut() {
            match cached.next() {
                Some(bytes) => {
                    if (bytes.len() as u64) > self.remaining {
                        return Err(NativeError::InvalidResponse);
                    }
                    self.remaining -= bytes.len() as u64;
                    let piece = self.split_chunk(bytes);
                    return Ok(Some(self.deliver(piece)));
                }
                None => {
                    self.done = true;
                    return if self.remaining == 0 { Ok(None) } else { Err(NativeError::InvalidResponse) };
                }
            }
        }
        if self.done {
            return Ok(None);
        }
        let outcome = {
            let Some(stream) = self.stream.as_mut() else {
                self.done = true;
                return Ok(None);
            };
            tokio::select! {
                _ = cancel.cancelled() => Err(NativeError::Cancelled),
                next = stream.next() => next.map_err(map_xet_error),
            }
        };
        match outcome {
            Err(NativeError::Cancelled) => {
                self.cancel();
                Err(NativeError::Cancelled)
            }
            Err(error) => {
                self.cancel();
                Err(error)
            }
            Ok(None) => {
                self.done = true;
                if self.remaining != 0 {
                    // The immutable object ended before its validated size;
                    // content is unavailable, no deletion is inferred.
                    self.stream = None;
                    self.group = None;
                    Err(NativeError::RemoteContentUnavailable)
                } else {
                    Ok(None)
                }
            }
            Ok(Some(bytes)) => {
                if (bytes.len() as u64) > self.remaining {
                    self.cancel();
                    return Err(NativeError::InvalidResponse);
                }
                self.remaining -= bytes.len() as u64;
                let piece = self.split_chunk(bytes);
                Ok(Some(self.deliver(piece)))
            }
        }
    }

    /// Consumer-boundary accounting for one delivered chunk: count it as
    /// logical read content and, when this read feeds a cache, record the
    /// clean immutable bytes at their absolute object offset.
    fn deliver(&mut self, chunk: Bytes) -> Bytes {
        if let Some(budget) = &self.budget {
            budget.note_logical_read(chunk.len() as u64);
        }
        if let Some(fill) = &mut self.fill {
            fill.cache.insert(&fill.object, fill.next_offset, chunk.clone());
            fill.next_offset += chunk.len() as u64;
        }
        chunk
    }

    /// Cancel this reader's range interest. Other readers on the same group
    /// stay alive.
    pub fn cancel(&mut self) {
        if let Some(stream) = self.stream.as_mut() {
            stream.cancel();
        }
    }

    /// Abort the whole bucket read group. Teardown only: every in-flight range
    /// reader of this drive fails.
    pub fn abort(&mut self) {
        if let Some(group) = self.group.as_ref() {
            let _ = group.abort();
        }
        self.stream = None;
        self.group = None;
        self.cached = None;
        self.done = true;
    }

    fn split_chunk(&mut self, bytes: Bytes) -> Bytes {
        if bytes.len() <= self.max_chunk || self.max_chunk == 0 {
            return bytes;
        }
        let head = bytes.slice(..self.max_chunk);
        self.pending = Some(bytes.slice(self.max_chunk..));
        head
    }
}

impl Drop for RangeReader {
    fn drop(&mut self) {
        self.cancel();
    }
}

struct StoreInner<T: TokenSource> {
    api: NativeApi<T>,
    binding: DriveBinding,
    config: NativeConfig,
    xet: std::sync::Mutex<Option<XetStore>>,
}

/// Storage plane for one connected drive ([`DriveBinding`]).
pub struct NativeBucketStore<T: TokenSource> {
    inner: Arc<StoreInner<T>>,
}

impl<T: TokenSource> Clone for NativeBucketStore<T> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl<T: TokenSource> NativeBucketStore<T> {
    /// The binding's `account_key` must equal the [`NativeApi`] account; a
    /// mismatch is [`NativeError::IdentityMismatch`] at construction, so a
    /// cross-account lease can never reach a dispatch from this store.
    pub fn new(api: NativeApi<T>, binding: DriveBinding, config: NativeConfig) -> Result<Self, NativeError> {
        if binding.account_key != api.account() {
            return Err(NativeError::IdentityMismatch);
        }
        Ok(Self {
            inner: Arc::new(StoreInner { api, binding, config, xet: std::sync::Mutex::new(None) }),
        })
    }

    pub fn binding(&self) -> &DriveBinding {
        &self.inner.binding
    }

    /// Capture the operation lease; thread it through every dispatch of one
    /// durable operation.
    pub fn capture_lease(&self) -> Result<NativeLease, NativeError> {
        self.inner.api.capture_lease()
    }

    fn xet(&self) -> Result<XetStore, NativeError> {
        let mut guard = self.inner.xet.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(store) = guard.as_ref() {
            return Ok(store.clone());
        }
        let store =
            XetStore::new(&self.inner.config.xet_cache_dir, self.inner.config.xet_limits, self.inner.api.budget())?;
        *guard = Some(store.clone());
        Ok(store)
    }

    fn bucket_ns_name(&self) -> (&str, &str) {
        let bucket = &self.inner.binding.bucket;
        (bucket.owner_namespace.as_str(), bucket.bucket_name.as_str())
    }

    // ---- listings and metadata ----

    /// One tree page. Pagination links are followed only when they stay on the
    /// API origin inside this bucket's API prefix.
    pub async fn list_tree_page(
        &self,
        lease: &NativeLease,
        prefix: Option<&str>,
        recursive: bool,
        limit: u32,
        cursor: Option<PageCursor>,
        cancel: &CancellationToken,
    ) -> Result<TreePage, NativeError> {
        tree_page(
            &self.inner.api,
            lease,
            &self.inner.binding.bucket,
            prefix,
            recursive,
            limit,
            cursor,
            cancel,
        )
        .await
    }

    /// Full bounded tree walk. Never returns a partial listing silently.
    pub async fn list_tree(
        &self,
        lease: &NativeLease,
        prefix: Option<&str>,
        recursive: bool,
        cancel: &CancellationToken,
    ) -> Result<Vec<NativeTreeEntry>, NativeError> {
        let mut out = Vec::new();
        let mut cursor: Option<PageCursor> = None;
        loop {
            let page = self
                .list_tree_page(lease, prefix, recursive, 1000, cursor, cancel)
                .await?;
            out.extend(page.entries);
            if out.len() > self.inner.config.max_listed_entries {
                return Err(NativeError::TooManyEntries);
            }
            cursor = page.next;
            if cursor.is_none() {
                return Ok(out);
            }
        }
    }

    /// Targeted metadata lookup chunked at the service's 1000-path limit with
    /// full per-key reconciliation.
    pub async fn paths_info(
        &self,
        lease: &NativeLease,
        keys: &[RelativeKey],
        cancel: &CancellationToken,
    ) -> Result<PathsInfoReport, NativeError> {
        let (ns, name) = self.bucket_ns_name();
        let url = http::bucket_api_url(self.inner.api.endpoint(), ns, name, &["paths-info"])?;
        let mut report = PathsInfoReport::default();
        let mut found_keys: HashSet<String> = HashSet::new();
        for chunk in keys.chunks(PATHS_INFO_CHUNK) {
            let mut body = String::from("{\"paths\":[");
            for (index, key) in chunk.iter().enumerate() {
                if index > 0 {
                    body.push(',');
                }
                body.push_str(&serde_json::to_string(key.as_str()).map_err(|_| NativeError::InvalidResponse)?);
            }
            body.push_str("]}");
            let response = self
                .inner
                .api
                .post_bytes(lease, url.clone(), "application/json", Bytes::from(body), cancel)
                .await?;
            let values: Vec<serde_json::Value> =
                serde_json::from_slice(&response).map_err(|_| NativeError::InvalidResponse)?;
            for value in &values {
                let entry = TreeEntryWire::parse(value)?;
                if !chunk.iter().any(|k| k.as_str() == entry.path) {
                    return Err(NativeError::InvalidResponse);
                }
                if !found_keys.insert(entry.path.clone()) {
                    return Err(NativeError::InvalidResponse);
                }
                let key = wire::wire_key(&entry.path)?;
                report.found.push(PathInfo {
                    key,
                    kind: if entry.is_file { PathKind::File } else { PathKind::Directory },
                    size: entry.size,
                    xet_file_id: entry.xet_hash,
                });
            }
        }
        for key in keys {
            if !found_keys.contains(key.as_str()) {
                report.missing.push(key.clone());
            }
        }
        Ok(report)
    }

    /// Native HEAD metadata for one key (`Ok(None)` when the object is absent).
    pub async fn file_metadata(
        &self,
        lease: &NativeLease,
        key: &RelativeKey,
        cancel: &CancellationToken,
    ) -> Result<Option<ObjectMetadata>, NativeError> {
        let (ns, name) = self.bucket_ns_name();
        let Some((size, xet_hash)) = self
            .inner
            .api
            .hf_file_metadata(lease, ns, name, key.as_str(), cancel)
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(ObjectMetadata {
            key: key.clone(),
            size,
            xet_file_id: XetFileId::new(xet_hash).ok(),
        }))
    }

    /// Read one bounded managed metadata record through the native resolve path.
    /// A size gate rejects oversized records instead of truncating them; this is
    /// never a generic payload HTTP/Xet fallback.
    pub async fn read_record(
        &self,
        lease: &NativeLease,
        key: &RelativeKey,
        max_bytes: usize,
        cancel: &CancellationToken,
    ) -> Result<Option<bytes::Bytes>, NativeError> {
        if max_bytes == 0 {
            return Err(NativeError::InvalidRequest { detail: "record bound must be positive".to_owned() });
        }
        let Some(metadata) = self.file_metadata(lease, key, cancel).await? else { return Ok(None); };
        if metadata.size > max_bytes as u64 {
            return Err(NativeError::InvalidRequest { detail: "managed record exceeds its size bound".to_owned() });
        }
        let (ns, name) = self.bucket_ns_name();
        let url = http::resolve_url(self.inner.api.endpoint(), ns, name, key.as_str())?;
        self.inner.api.resolve_record(lease, url, max_bytes, cancel).await.map(Some)
    }

    // ---- capability probes (usable before every publication transaction) ----

    /// Real native read-authorization check against the selected bucket.
    pub async fn check_native_read(&self, lease: &NativeLease, cancel: &CancellationToken) -> Result<(), NativeError> {
        let (ns, name) = self.bucket_ns_name();
        let url = http::bucket_api_url(self.inner.api.endpoint(), ns, name, &[])?;
        self.inner.api.probe(lease, url, cancel).await
    }

    /// Real native write-authorization check against the selected bucket
    /// (the write-token route requires write permission). The token body is
    /// never read.
    pub async fn check_native_write(&self, lease: &NativeLease, cancel: &CancellationToken) -> Result<(), NativeError> {
        let (ns, name) = self.bucket_ns_name();
        let url = http::bucket_api_url(self.inner.api.endpoint(), ns, name, &["xet-write-token"])?;
        self.inner.api.probe(lease, url, cancel).await
    }

    // ---- mutations ----

    /// Apply add/delete operations in 1000-operation NDJSON chunks with full
    /// per-operation accounting. Adds are always sent before deletes inside a
    /// chunk. A partial `BatchReport` is a success at the HTTP level and must
    /// be reconciled by the caller before advancing.
    pub async fn apply_batch(
        &self,
        lease: &NativeLease,
        ops: Vec<BatchOp>,
        cancel: &CancellationToken,
    ) -> Result<BatchReport, NativeError> {
        self.inner.api.check_lease(lease)?;
        if ops.is_empty() {
            return Ok(BatchReport::default());
        }
        let mut seen: HashSet<&str> = HashSet::new();
        for op in &ops {
            let key = match op {
                BatchOp::Add(add) => add.key.as_str(),
                BatchOp::Delete(key) => key.as_str(),
            };
            if !seen.insert(key) {
                return Err(NativeError::InvalidRequest {
                    detail: "one batch call must not touch the same key twice".to_owned(),
                });
            }
        }
        // Wire rule: all add operations precede all delete operations.
        let mut ordered = ops;
        ordered.sort_by_key(|op| match op {
            BatchOp::Add(_) => 0u8,
            BatchOp::Delete(_) => 1u8,
        });

        let (ns, name) = self.bucket_ns_name();
        let url = http::bucket_api_url(self.inner.api.endpoint(), ns, name, &["batch"])?;
        let mut report = BatchReport::default();
        for chunk in ordered.chunks(BATCH_CHUNK) {
            let mut body = String::new();
            for op in chunk {
                match op {
                    BatchOp::Add(add) => {
                        body.push_str("{\"type\":\"addFile\",\"path\":");
                        body.push_str(&serde_json::to_string(add.key.as_str()).map_err(|_| NativeError::InvalidResponse)?);
                        body.push_str(",\"xetHash\":\"");
                        body.push_str(add.xet_file_id.as_str());
                        body.push_str("\",\"size\":");
                        body.push_str(&add.size.to_string());
                        body.push('}');
                    }
                    BatchOp::Delete(key) => {
                        body.push_str("{\"type\":\"deleteFile\",\"path\":");
                        body.push_str(&serde_json::to_string(key.as_str()).map_err(|_| NativeError::InvalidResponse)?);
                        body.push('}');
                    }
                }
                body.push('\n');
            }
            let response = self
                .inner
                .api
                .post_bytes(lease, url.clone(), "application/x-ndjson", Bytes::from(body), cancel)
                .await?;
            let value: serde_json::Value = serde_json::from_slice(&response).map_err(|_| NativeError::InvalidResponse)?;
            let chunk_report = BatchResponseWire::parse(value, chunk.len())?;
            report.submitted += chunk.len();
            report.succeeded += chunk_report.succeeded as usize;
            report.success &= chunk_report.success;
            for (path, reason) in chunk_report.failed {
                if !chunk.iter().any(|op| match op {
                    BatchOp::Add(add) => add.key.as_str() == path,
                    BatchOp::Delete(key) => key.as_str() == path,
                }) {
                    return Err(NativeError::InvalidResponse);
                }
                report.failures.push(BatchFailure { key: path, reason });
            }
        }
        Ok(report)
    }

    // ---- staged immutable uploads ----

    /// Begin one staged upload. Validates the source against its capture
    /// record and derives the exact managed key; nothing touches the network.
    pub fn begin_upload(
        &self,
        lease: &NativeLease,
        target: ImmutableKey,
        source: UploadSource,
    ) -> Result<StagedUpload<T>, NativeError> {
        self.inner.api.check_lease(lease)?;
        let target_key = self.inner.binding.prefix.immutable_key(target);
        let (expected_size, expected_sha256) = match &source {
            UploadSource::Snapshot(snapshot) => {
                let size = std::fs::metadata(&snapshot.path).map_err(|_| NativeError::SourceChanged)?.len();
                if size != snapshot.size {
                    return Err(NativeError::SourceChanged);
                }
                (snapshot.size, snapshot.sha256)
            }
            UploadSource::Record(bytes) => (bytes.len() as u64, Sha256Digest::of(bytes)),
        };
        if let UploadSource::Record(bytes) = &source
            && bytes.len() > MAX_METADATA_BYTES
        {
            return Err(NativeError::InvalidRequest { detail: "metadata record exceeds 1 MiB".to_owned() });
        }
        Ok(StagedUpload {
            store: self.clone(),
            lease: lease.clone(),
            source,
            target_key,
            expected_size,
            expected_sha256,
        })
    }

    /// Full ingestion -> CAS commit -> exact path binding for one snapshot.
    /// Returns an [`ObjectRef`] only after all three boundaries are confirmed;
    /// the staged API is the recovery-friendly variant.
    pub async fn upload_snapshot(
        &self,
        lease: &NativeLease,
        snapshot: StableSnapshot,
        cancel: &CancellationToken,
    ) -> Result<ObjectRef, NativeError> {
        let upload_id = snapshot.upload_id;
        let staged = self.begin_upload(lease, ImmutableKey::Payload(upload_id), UploadSource::Snapshot(snapshot))?;
        let (ingested, _checkpoint) = staged.ingest(cancel).await?;
        let (committed, _checkpoint) = ingested.commit_cas(cancel).await?;
        let bound = committed.bind(cancel).await?;
        Ok(ObjectRef {
            key: PayloadKey::new(upload_id),
            sha256: bound.sha256,
            size: bound.size,
            xet_file_id: bound.xet_file_id,
        })
    }

    /// Metadata records use the same native immutable-upload path as payloads;
    /// there is no S3 payload fallback here. The payload is taken by value so
    /// the canonical record bytes reach the SDK upload seam without a copy.
    pub async fn upload_metadata(
        &self,
        lease: &NativeLease,
        key: ImmutableKey,
        payload: Vec<u8>,
        cancel: &CancellationToken,
    ) -> Result<BoundObject, NativeError> {
        let staged = self.begin_upload(lease, key, UploadSource::Record(payload))?;
        let (ingested, _) = staged.ingest(cancel).await?;
        let (committed, _) = ingested.commit_cas(cancel).await?;
        committed.bind(cancel).await
    }

    // ---- range reads ----

    /// Open one bounded ordered range over an immutable object. Empty ranges
    /// complete without SDK work; out-of-bounds ranges fail before any SDK
    /// call. There is no whole-file download fallback.
    pub async fn open_range(
        &self,
        lease: &NativeLease,
        object: &ObjectRef,
        range: ByteRange,
        cancel: &CancellationToken,
    ) -> Result<RangeReader, NativeError> {
        self.open_range_inner(lease, object, range, None, cancel).await
    }

    /// Same as [`NativeBucketStore::open_range`], served through a shared
    /// bounded [`RangeCache`]. Complete cached coverage of the validated range
    /// is delivered without any SDK work; a miss fetches the whole range from
    /// Xet and records every delivered chunk as a clean immutable cache
    /// segment (keyed by the exact content version).
    pub async fn open_range_cached(
        &self,
        lease: &NativeLease,
        object: &ObjectRef,
        range: ByteRange,
        cache: &RangeCache,
        cancel: &CancellationToken,
    ) -> Result<RangeReader, NativeError> {
        self.open_range_inner(lease, object, range, Some(cache), cancel).await
    }

    async fn open_range_inner(
        &self,
        lease: &NativeLease,
        object: &ObjectRef,
        range: ByteRange,
        cache: Option<&RangeCache>,
        cancel: &CancellationToken,
    ) -> Result<RangeReader, NativeError> {
        self.inner.api.check_lease(lease)?;
        range.validate_for(object.size).map_err(|_| NativeError::InvalidRange)?;
        if range.is_empty() {
            return Ok(RangeReader::empty());
        }
        if let Some(pieces) = cache.and_then(|cache| cache.lookup(object, range)) {
            return Ok(RangeReader::cached(pieces, range.len(), self.inner.api.budget().clone(), self.inner.config.range_chunk_bytes));
        }
        let state = self.inner.api.client_state().await?;
        let refresh_url = XetStore::read_token_url(self.inner.api.endpoint(), &self.inner.binding.bucket)?;
        let group = self
            .xet()?
            .read_group(&self.inner.binding.bucket, &refresh_url, state.bearer.clone(), state.generation)
            .await?;
        let info = crate::xet::file_info(object.xet_file_id.as_str(), object.size);
        let stream = tokio::select! {
            _ = cancel.cancelled() => return Err(NativeError::Cancelled),
            result = group.download_stream(info, Some(range.as_range())) => result.map_err(map_xet_error)?,
        };
        let mut reader = RangeReader {
            group: Some(group),
            stream: Some(stream),
            cached: None,
            fill: cache.map(|cache| RangeFill {
                cache: cache.clone(),
                object: object.clone(),
                next_offset: range.start(),
            }),
            budget: Some(self.inner.api.budget().clone()),
            remaining: range.len(),
            max_chunk: self.inner.config.range_chunk_bytes,
            pending: None,
            done: false,
        };
        reader.start();
        Ok(reader)
    }

    // ---- events ----

    /// Raw change-feed source. Cursors are opaque and persisted by the caller.
    pub async fn events(
        &self,
        lease: &NativeLease,
        resume: Option<EventResume>,
        cancel: &CancellationToken,
    ) -> Result<NativeEventStream, NativeError> {
        let (ns, name) = self.bucket_ns_name();
        let mut url = http::bucket_api_url(self.inner.api.endpoint(), ns, name, &["events"])?;
        {
            let mut query = url.query_pairs_mut();
            match &resume {
                Some(EventResume::Cursor(cursor)) => {
                    query.append_pair("cursor", cursor.as_str());
                }
                Some(EventResume::Since(since)) => {
                    if since.is_empty() || since.len() > 64 || since.bytes().any(|b| b.is_ascii_control()) {
                        return Err(NativeError::InvalidRequest {
                            detail: "event resume instant must be bounded and free of control characters".to_owned(),
                        });
                    }
                    query.append_pair("since", since);
                }
                None => {}
            }
        }
        let response = self.inner.api.open_event_stream(lease, url, cancel).await?;
        let source = wire::sse_stream(response, self.inner.api.budget().clone());
        Ok(NativeEventStream {
            events: source.events,
            activity: source.activity,
            cursor: None,
            ended: false,
        })
    }
}

/// Shared tree-page fetch used by the storage plane and by pre-workspace
/// prefix inspection. Pagination links are followed only when they stay on the
/// API origin inside this bucket's API prefix.
pub(crate) async fn tree_page<T: TokenSource>(
    api: &NativeApi<T>,
    lease: &NativeLease,
    bucket: &hfdrive_core::storage::BucketBinding,
    prefix: Option<&str>,
    recursive: bool,
    limit: u32,
    cursor: Option<PageCursor>,
    cancel: &CancellationToken,
) -> Result<TreePage, NativeError> {
    if !(1..=5000).contains(&limit) {
        return Err(NativeError::InvalidRequest { detail: "tree page limit must be 1..=5000".to_owned() });
    }
    let ns = bucket.owner_namespace.as_str();
    let name = bucket.bucket_name.as_str();
    let api_prefix = http::bucket_api_prefix(ns, name);
    let url = match cursor {
        Some(PageCursor(raw)) => {
            let url = reqwest::Url::parse(&raw).map_err(|_| NativeError::InvalidResponse)?;
            wire::validate_next(&url, api.endpoint(), &api_prefix)?;
            url
        }
        None => {
            let mut tail = vec!["tree".to_owned()];
            if let Some(prefix) = prefix.filter(|p| !p.is_empty()) {
                for part in wire::encode_key_path(prefix).split('/').filter(|s| !s.is_empty()) {
                    tail.push(part.to_owned());
                }
            }
            let refs: Vec<&str> = tail.iter().map(String::as_str).collect();
            let mut url = http::bucket_api_url(api.endpoint(), ns, name, &refs)?;
            url.query_pairs_mut()
                .append_pair("recursive", if recursive { "true" } else { "false" })
                .append_pair("limit", &limit.to_string());
            url
        }
    };

    let (body, next) = api.get_page(lease, url, &api_prefix, cancel).await?;
    let values: Vec<serde_json::Value> = serde_json::from_slice(&body).map_err(|_| NativeError::InvalidResponse)?;
    let mut entries = Vec::with_capacity(values.len());
    for value in &values {
        let entry = TreeEntryWire::parse(value)?;
        let mtime_nanos = value.get("mtimeNanos").and_then(|v| v.as_u64());
        entries.push(NativeTreeEntry::from_wire(entry, mtime_nanos));
    }
    Ok(TreePage {
        entries,
        next: next.map(|url| PageCursor(url.into())),
    })
}

/// Staged upload: ingestion boundary not yet crossed.
pub struct StagedUpload<T: TokenSource> {
    store: NativeBucketStore<T>,
    lease: NativeLease,
    source: UploadSource,
    target_key: RelativeKey,
    expected_size: u64,
    expected_sha256: Sha256Digest,
}

impl<T: TokenSource> StagedUpload<T> {
    pub fn target_key(&self) -> &RelativeKey {
        &self.target_key
    }

    /// Ingest the bytes into Xet. Digest and size are verified against the
    /// capture record; a mismatch is [`NativeError::SourceChanged`] and the
    /// upload must be recaptured, never bound. Returns the durable
    /// [`IngestionCheckpoint`] to persist before continuing.
    pub async fn ingest(self, cancel: &CancellationToken) -> Result<(StagedIngested<T>, IngestionCheckpoint), NativeError> {
        self.store.inner.api.check_lease(&self.lease)?;
        if cancel.is_cancelled() {
            return Err(NativeError::Cancelled);
        }
        let write_url = XetStore::write_token_url(self.store.inner.api.endpoint(), &self.store.inner.binding.bucket)?;
        let state = self.store.inner.api.client_state().await?;
        let commit = self.store.xet()?.write_commit(&write_url, state.bearer.clone()).await?;

        let handle = match self.source {
            UploadSource::Snapshot(snapshot) => {
                let size = std::fs::metadata(&snapshot.path).map_err(|_| NativeError::SourceChanged)?.len();
                if size != self.expected_size {
                    return Err(NativeError::SourceChanged);
                }
                let handle = tokio::select! {
                    _ = cancel.cancelled() => {
                        let _ = commit.abort();
                        return Err(NativeError::Cancelled);
                    }
                    result = commit.upload_from_path(snapshot.path, crate::xet::SHA256_RECOMPUTE) =>
                        result.map_err(map_xet_error)?,
                };
                handle
            }
            UploadSource::Record(bytes) => {
                let handle = tokio::select! {
                    _ = cancel.cancelled() => {
                        let _ = commit.abort();
                        return Err(NativeError::Cancelled);
                    }
                    result = commit.upload_bytes(bytes, crate::xet::SHA256_RECOMPUTE, None) =>
                        result.map_err(map_xet_error)?,
                };
                handle
            }
        };

        let metadata = tokio::select! {
            _ = cancel.cancelled() => {
                let _ = commit.abort();
                return Err(NativeError::Cancelled);
            }
            result = handle.finalize_ingestion() => result.map_err(map_xet_error)?,
        };

        if metadata.xet_info.file_size != Some(self.expected_size) {
            return Err(NativeError::SourceChanged);
        }
        if let Some(reported) = metadata.xet_info.sha256.as_deref()
            && !reported.eq_ignore_ascii_case(&self.expected_sha256.to_string())
        {
            return Err(NativeError::SourceChanged);
        }
        let xet_file_id = XetFileId::new(metadata.xet_info.hash.clone()).map_err(|_| NativeError::InvalidResponse)?;
        let checkpoint = IngestionCheckpoint {
            target_key: self.target_key.to_string(),
            xet_file_id: xet_file_id.clone(),
            size: self.expected_size,
            sha256: self.expected_sha256,
            sdk_task_id: handle.task_id().0,
        };
        Ok((
            StagedIngested {
                store: self.store,
                lease: self.lease,
                target_key: self.target_key,
                commit,
                task_id: handle.task_id().0,
                xet_file_id,
                expected_size: self.expected_size,
                expected_sha256: self.expected_sha256,
            },
            checkpoint,
        ))
    }
}

/// Staged upload past ingestion: CAS commit boundary not yet crossed.
pub struct StagedIngested<T: TokenSource> {
    store: NativeBucketStore<T>,
    lease: NativeLease,
    target_key: RelativeKey,
    commit: XetUploadCommit,
    task_id: u64,
    xet_file_id: XetFileId,
    expected_size: u64,
    expected_sha256: Sha256Digest,
}

impl<T: TokenSource> StagedIngested<T> {
    /// Re-derive the ingestion checkpoint (e.g. after a crash-recovery resume).
    pub fn checkpoint(&self) -> IngestionCheckpoint {
        IngestionCheckpoint {
            target_key: self.target_key.to_string(),
            xet_file_id: self.xet_file_id.clone(),
            size: self.expected_size,
            sha256: self.expected_sha256,
            sdk_task_id: self.task_id,
        }
    }

    /// Push the ingested metadata to the Xet CAS. Returns the durable
    /// [`CasCommitCheckpoint`] to persist before binding.
    pub async fn commit_cas(
        self,
        cancel: &CancellationToken,
    ) -> Result<(StagedCommitted<T>, CasCommitCheckpoint), NativeError> {
        self.store.inner.api.check_lease(&self.lease)?;
        if cancel.is_cancelled() {
            return Err(NativeError::Cancelled);
        }
        let report = tokio::select! {
            _ = cancel.cancelled() => {
                let _ = self.commit.abort();
                return Err(NativeError::Cancelled);
            }
            result = self.commit.commit() => result.map_err(map_xet_error)?,
        };
        let entry = report
            .uploads
            .get(&UniqueId(self.task_id))
            .ok_or(NativeError::InvalidResponse)?;
        let hash = XetFileId::new(entry.xet_info.hash.clone()).map_err(|_| NativeError::InvalidResponse)?;
        if hash != self.xet_file_id || entry.xet_info.file_size != Some(self.expected_size) {
            return Err(NativeError::InvalidResponse);
        }
        let checkpoint = CasCommitCheckpoint {
            target_key: self.target_key.to_string(),
            xet_file_id: self.xet_file_id.clone(),
            size: self.expected_size,
            sha256: self.expected_sha256,
            sdk_task_id: self.task_id,
        };
        Ok((
            StagedCommitted {
                store: self.store,
                lease: self.lease,
                target_key: self.target_key,
                xet_file_id: self.xet_file_id.clone(),
                size: self.expected_size,
                sha256: self.expected_sha256,
            },
            checkpoint,
        ))
    }
}

/// Staged upload past CAS commit: exact bucket-path binding not yet crossed.
pub struct StagedCommitted<T: TokenSource> {
    store: NativeBucketStore<T>,
    lease: NativeLease,
    target_key: RelativeKey,
    xet_file_id: XetFileId,
    size: u64,
    sha256: Sha256Digest,
}

impl<T: TokenSource> StagedCommitted<T> {
    pub fn target_key(&self) -> &RelativeKey {
        &self.target_key
    }

    /// Bind the committed content to the exact managed key and confirm the
    /// binding from the service's per-operation accounting. A refused binding
    /// never yields a [`BoundObject`].
    pub async fn bind(self, cancel: &CancellationToken) -> Result<BoundObject, NativeError> {
        let key = self.target_key.clone();
        let report = self
            .store
            .apply_batch(
                &self.lease,
                vec![BatchOp::Add(BatchAdd {
                    key: key.clone(),
                    xet_file_id: self.xet_file_id.clone(),
                    size: self.size,
                })],
                cancel,
            )
            .await?;
        if !report.is_complete() {
            let reason = report
                .failures
                .first()
                .map(|failure| failure.reason.clone())
                .unwrap_or_else(|| "bucket refused the immutable key binding".to_owned());
            return Err(NativeError::InvalidRequest { detail: reason });
        }
        Ok(BoundObject {
            key,
            xet_file_id: self.xet_file_id.clone(),
            size: self.size,
            sha256: self.sha256,
        })
    }
}

// ---- bounded immutable range cache ----

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct CacheObjectKey {
    key: PayloadKey,
    xet_file_id: XetFileId,
    size: u64,
}

struct CacheSegment {
    start: u64,
    end_exclusive: u64,
    bytes: Bytes,
    used_at: u64,
}

#[derive(Default)]
struct RangeCacheState {
    /// Per object: segments sorted by start and never overlapping.
    objects: HashMap<CacheObjectKey, Vec<CacheSegment>>,
    used_bytes: u64,
    max_bytes: u64,
    stamp: u64,
}

struct RangeCacheInner {
    state: std::sync::Mutex<RangeCacheState>,
}

/// Byte-bounded LRU cache of clean immutable range segments.
///
/// Keying is strict: the managed payload key, the Xet file id and the exact
/// size pin one content version, so a newer version can never be served from
/// older cached bytes. Segments within one object never overlap (a newer
/// insert supersedes overlapping coverage); [`RangeCache::lookup`] returns the
/// requested window only on complete coverage and otherwise reports a miss.
/// Eviction reclaims clean cached bytes only (everything here is
/// reconstructible) in least-recently-used order; resizing the budget live via
/// [`RangeCache::set_max_bytes`] evicts immediately. Delivered windows are
/// zero-copy [`Bytes`] slices; nothing is copied to read or insert.
#[derive(Clone)]
pub struct RangeCache {
    inner: Arc<RangeCacheInner>,
}

impl RangeCache {
    /// A cache admitting at most `max_bytes` of clean immutable segments.
    pub fn new(max_bytes: u64) -> Self {
        Self {
            inner: Arc::new(RangeCacheInner {
                state: std::sync::Mutex::new(RangeCacheState { max_bytes, ..RangeCacheState::default() }),
            }),
        }
    }

    /// Live budget change; shrinking evicts clean segments down to the new
    /// budget immediately (never any other data).
    pub fn set_max_bytes(&self, max_bytes: u64) {
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        state.max_bytes = max_bytes;
        evict_to_budget(&mut state);
    }

    /// The current budget in bytes.
    pub fn max_bytes(&self) -> u64 {
        self.inner.state.lock().unwrap_or_else(|e| e.into_inner()).max_bytes
    }

    /// Currently cached bytes.
    pub fn used_bytes(&self) -> u64 {
        self.inner.state.lock().unwrap_or_else(|e| e.into_inner()).used_bytes
    }

    /// Number of cached segments (diagnostics).
    pub fn segment_count(&self) -> usize {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .objects
            .values()
            .map(Vec::len)
            .sum()
    }

    /// Drop every cached segment (diagnostics/teardown only).
    pub fn clear(&self) {
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        state.objects.clear();
        state.used_bytes = 0;
    }

    /// Serve `range` from cached segments of exactly `object`'s content
    /// version. Complete coverage returns the window as ordered zero-copy
    /// slices; anything less is a miss (never a partial answer).
    pub fn lookup(&self, object: &ObjectRef, range: ByteRange) -> Option<Vec<Bytes>> {
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let key = CacheObjectKey {
            key: object.key,
            xet_file_id: object.xet_file_id.clone(),
            size: object.size,
        };
        let segments = state.objects.get(&key)?;
        let mut pieces = Vec::new();
        let mut cursor = range.start();
        let mut touched = Vec::new();
        for (index, segment) in segments.iter().enumerate() {
            if segment.end_exclusive <= cursor {
                continue;
            }
            if segment.start > cursor || segment.start >= range.end_exclusive() {
                break;
            }
            let from = (cursor - segment.start) as usize;
            let to = ((range.end_exclusive() - segment.start).min(segment.end_exclusive - segment.start)) as usize;
            pieces.push(segment.bytes.slice(from..to));
            touched.push(index);
            cursor = segment.start + to as u64;
            if cursor >= range.end_exclusive() {
                break;
            }
        }
        if cursor < range.end_exclusive() {
            return None;
        }
        state.stamp += 1;
        let stamp = state.stamp;
        if let Some(segments) = state.objects.get_mut(&key) {
            for index in touched {
                segments[index].used_at = stamp;
            }
        }
        Some(pieces)
    }

    /// Record one clean immutable segment at its absolute object offset. The
    /// segment is clipped to the object's validated size; empty or fully
    /// out-of-range input is ignored; overlapping older segments are dropped
    /// (the newest insert supersedes overlapping coverage). The entry is
    /// admitted only while it fits the budget (evicting older clean segments
    /// first); a single segment larger than the whole budget is simply not
    /// cached — delivery is never blocked by the cache.
    pub fn insert(&self, object: &ObjectRef, start: u64, bytes: Bytes) {
        let clipped_end = start.saturating_add(bytes.len() as u64).min(object.size);
        if bytes.is_empty() || start >= clipped_end {
            return;
        }
        let bytes = if start + bytes.len() as u64 > object.size {
            bytes.slice(0..(object.size - start) as usize)
        } else {
            bytes
        };
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        if bytes.len() as u64 > state.max_bytes {
            return;
        }
        let key = CacheObjectKey {
            key: object.key,
            xet_file_id: object.xet_file_id.clone(),
            size: object.size,
        };
        let added = bytes.len() as u64;
        let mut removed_total = 0u64;
        state.stamp += 1;
        let stamp = state.stamp;
        {
            let objects = &mut state.objects;
            let segments = objects.entry(key).or_default();
            let mut survivors = Vec::with_capacity(segments.len() + 1);
            for segment in segments.drain(..) {
                if segment.end_exclusive <= start || segment.start >= clipped_end {
                    survivors.push(segment);
                    continue;
                }
                removed_total = removed_total.saturating_add(segment.bytes.len() as u64);
                if segment.start < start {
                    let keep = (start - segment.start) as usize;
                    removed_total -= keep as u64;
                    survivors.push(CacheSegment {
                        start: segment.start,
                        end_exclusive: start,
                        bytes: segment.bytes.slice(0..keep),
                        used_at: segment.used_at,
                    });
                }
                if segment.end_exclusive > clipped_end {
                    let from = (clipped_end - segment.start) as usize;
                    removed_total -= (segment.bytes.len() - from) as u64;
                    survivors.push(CacheSegment {
                        start: clipped_end,
                        end_exclusive: segment.end_exclusive,
                        bytes: segment.bytes.slice(from..),
                        used_at: segment.used_at,
                    });
                }
            }
            survivors.push(CacheSegment { start, end_exclusive: clipped_end, bytes, used_at: stamp });
            survivors.sort_by_key(|segment| segment.start);
            *segments = survivors;
        }
        state.used_bytes = state.used_bytes.saturating_sub(removed_total);
        state.used_bytes += added;
        evict_to_budget(&mut state);
    }
}

fn evict_to_budget(state: &mut RangeCacheState) {
    while state.used_bytes > state.max_bytes {
        let mut victim: Option<(CacheObjectKey, usize)> = None;
        let mut oldest = u64::MAX;
        for (key, segments) in state.objects.iter() {
            for (index, segment) in segments.iter().enumerate() {
                if segment.used_at < oldest {
                    oldest = segment.used_at;
                    victim = Some((key.clone(), index));
                }
            }
        }
        let Some((key, index)) = victim else { break };
        if let Some(segments) = state.objects.get_mut(&key) {
            let removed = segments.remove(index);
            state.used_bytes = state.used_bytes.saturating_sub(removed.bytes.len() as u64);
            if segments.is_empty() {
                state.objects.remove(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hfdrive_core::ids::UploadId;

    fn object(size: u64, hex: &str) -> ObjectRef {
        ObjectRef {
            key: PayloadKey::new(UploadId::new()),
            sha256: Sha256Digest::of(b"fixture"),
            size,
            xet_file_id: XetFileId::new(hex.repeat(32)).unwrap(),
        }
    }

    fn range(start: u64, end: u64, size: u64) -> ByteRange {
        ByteRange::new(start, end, size).unwrap()
    }

    fn concat(pieces: &[Bytes]) -> Vec<u8> {
        let mut out = Vec::new();
        for piece in pieces {
            out.extend_from_slice(piece);
        }
        out
    }

    #[test]
    fn lookup_hits_exactly_on_complete_coverage_and_clips_edges() {
        let cache = RangeCache::new(1024);
        let object = object(100, "aa");
        cache.insert(&object, 10, Bytes::from_static(b"0123456789"));
        let window = cache.lookup(&object, range(12, 18, 100)).unwrap();
        assert_eq!(concat(&window), b"234567");
        assert_eq!(cache.lookup(&object, range(8, 12, 100)), None, "partial coverage is a miss");
        assert_eq!(cache.lookup(&object, range(0, 100, 100)), None);
    }

    #[test]
    fn adjacent_segments_serve_joined_windows_without_copies() {
        let cache = RangeCache::new(1024);
        let object = object(100, "bb");
        cache.insert(&object, 0, Bytes::from_static(b"aaaa"));
        cache.insert(&object, 4, Bytes::from_static(b"bbbb"));
        let window = cache.lookup(&object, range(2, 6, 100)).unwrap();
        assert_eq!(concat(&window), b"aabb");
    }

    #[test]
    fn version_identity_pins_cached_bytes() {
        let cache = RangeCache::new(1024);
        let first = object(100, "cc");
        let same_key_other_version = ObjectRef { xet_file_id: XetFileId::new("dd".repeat(32)).unwrap(), ..first.clone() };
        cache.insert(&first, 0, Bytes::from_static(b"data"));
        assert!(cache.lookup(&first, range(0, 4, 100)).is_some());
        assert_eq!(cache.lookup(&same_key_other_version, range(0, 4, 100)), None);
    }

    #[test]
    fn newer_insert_supersedes_overlapping_coverage() {
        let cache = RangeCache::new(1024);
        let object = object(100, "ee");
        cache.insert(&object, 0, Bytes::from_static(b"aaaa"));
        cache.insert(&object, 2, Bytes::from_static(b"bbbb"));
        assert_eq!(concat(&cache.lookup(&object, range(0, 6, 100)).unwrap()), b"aabbbb");
        assert_eq!(cache.used_bytes(), 6);
    }

    #[test]
    fn eviction_is_lru_and_budget_is_live_resizable() {
        let cache = RangeCache::new(8);
        let object = object(100, "ff");
        cache.insert(&object, 0, Bytes::from_static(b"0000"));
        cache.insert(&object, 4, Bytes::from_static(b"1111"));
        // Touch the first segment so the second becomes the LRU victim.
        assert!(cache.lookup(&object, range(0, 4, 100)).is_some());
        cache.insert(&object, 8, Bytes::from_static(b"2222"));
        assert_eq!(cache.used_bytes(), 8);
        assert!(cache.lookup(&object, range(4, 8, 100)).is_none(), "the untouched segment was evicted");
        assert!(cache.lookup(&object, range(0, 4, 100)).is_some());
        cache.set_max_bytes(4);
        assert_eq!(cache.used_bytes(), 4);
        assert!(cache.lookup(&object, range(0, 4, 100)).is_some(), "the most recently touched segment remains");
        assert!(cache.lookup(&object, range(8, 12, 100)).is_none(), "the least recently used segment is evicted");
    }

    #[test]
    fn out_of_bounds_and_oversized_segments_never_disturb_the_cache() {
        let cache = RangeCache::new(4);
        let object = object(10, "ab");
        cache.insert(&object, 8, Bytes::from_static(b"0123456789"));
        let window = cache.lookup(&object, range(8, 10, 10)).unwrap();
        assert_eq!(concat(&window), b"01", "inserts clip the segment's leading bytes to the validated object size");
        cache.insert(&object, 0, Bytes::from_static(b"0123456789"));
        assert_eq!(cache.used_bytes(), 2, "a segment larger than the whole budget is not cached");
    }

    #[test]
    fn batch_success_false_is_never_complete_even_when_counters_match() {
        let report = BatchReport {
            submitted: 1,
            succeeded: 1,
            failures: Vec::new(),
            success: false,
        };
        assert!(!report.is_complete());
    }
}
