//! Live in-flight work registry: real hydration and directory-population
//! requests currently running through the CFAPI pump, exposed to the
//! read-only `list_activity` projection.
//!
//! Only work that is actually running is present. A span is opened when the
//! pump accepts a request and removed when that request reaches its terminal
//! outcome (success, failure, cancellation or pump shutdown), so a name,
//! timestamp or byte count here is never synthesized: `started_unix_ms` is
//! the real dispatch time, `completed_bytes` counts chunks actually delivered
//! to the OS, and `total_bytes` is the planned span length when the request
//! carries one (unknown totals stay `None`).
//!
//! Keying invariant: every span carries a fresh unique [`Uuid`] activity id
//! and the registry is keyed by it. CFAPI request keys, transfer keys and
//! item ids may legitimately repeat across overlapping requests, so they are
//! never map keys: dropping (or cancelling) one span can never remove or
//! replace another span's record.

use std::collections::{BinaryHeap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use hfdrive_core::ids::{ConnectionId, ItemId};
use uuid::Uuid;

/// What kind of live work one span covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveWorkKind {
    /// One `FETCH_DATA` request (immutable-version range hydration).
    Fetch,
    /// One `FETCH_PLACEHOLDERS` request (directory population).
    DirectoryPopulation,
}

/// One live in-flight work item as recorded by the pump.
pub struct LiveWork {
    pub connection_id: ConnectionId,
    /// Fresh UUIDv4 activity identity for this in-flight request. Unique per
    /// span: it is the registry key and can never alias another request.
    pub activity_id: Uuid,
    pub kind: LiveWorkKind,
    /// The placeholder item being served, when the request names one.
    pub item_id: Option<ItemId>,
    /// The request's own relative user path (directory population), when it
    /// carries one. Never an internal object key.
    pub path_hint: Option<String>,
    /// Real dispatch time (unix milliseconds).
    pub started_unix_ms: u64,
    /// Planned span length, when the request carries one.
    pub total_bytes: Option<u64>,
    /// Bytes already delivered to the OS for this request. Only real data
    /// bytes count here: a directory-population span moves metadata entries,
    /// not data, and keeps this at 0 — entry counts are never reported as
    /// byte progress.
    pub completed_bytes: Arc<AtomicU64>,
}

/// A read-only view of one live span for the activity projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveWorkView {
    pub activity_id: Uuid,
    pub kind: LiveWorkKind,
    pub item_id: Option<ItemId>,
    pub path_hint: Option<String>,
    pub started_unix_ms: u64,
    pub total_bytes: Option<u64>,
    /// Real data bytes delivered to the OS (0 when the span carries no data
    /// bytes, e.g. directory population).
    pub completed_bytes: u64,
}

/// Registry of live work, shared provider-wide and keyed by the span's
/// unique activity UUID.
#[derive(Default)]
pub struct ActivityRegistry {
    spans: Mutex<HashMap<Uuid, LiveWork>>,
}

/// The largest page the registry honors. The endpoint enforces `1..=200`;
/// this clamp guarantees the internal selection bound can never be exceeded
/// even if a caller misbehaves.
const MAX_PAGE_LIMIT: u32 = 200;

/// Guard owning one registered span: the span is removed when the guard
/// drops, including on early returns and panic unwinding. Removal is keyed
/// by this span's unique activity id, so a late drop cannot disturb any
/// other (possibly overlapping) span. A rejected duplicate registration
/// yields a **non-owning** handle: dropping it removes nothing, so the
/// original live span keeps its registry record until its own guard drops.
/// The handle carries no per-request counter: producers keep their own
/// `LiveWork::completed_bytes` `Arc` (as the pump does) and write to it
/// directly, so a real request pays no extra clone/drop for test access.
pub struct LiveWorkHandle<'a> {
    registry: &'a ActivityRegistry,
    activity_id: Uuid,
    /// True only when this handle's registration actually inserted the span.
    /// A defensively rejected duplicate id is not this handle's span.
    owns_registration: bool,
}

impl ActivityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one live work item and returns its guard. `work.activity_id`
    /// must be a fresh UUIDv4; an attempt to reuse a live id is impossible by
    /// construction (new spans always generate their own id at the call site)
    /// and is rejected here defensively: the existing span is kept and the
    /// returned handle is non-owning (dropping it removes nothing, never the
    /// original span).
    pub fn begin(&self, work: LiveWork) -> LiveWorkHandle<'_> {
        use std::collections::hash_map::Entry;
        let activity_id = work.activity_id;
        let owns_registration = match self
            .spans
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .entry(activity_id)
        {
            Entry::Vacant(entry) => {
                entry.insert(work);
                true
            }
            Entry::Occupied(_) => false,
        };
        LiveWorkHandle { registry: self, activity_id, owns_registration }
    }

    /// The live spans of one connection, for the activity projection, in a
    /// bounded keyset page.
    ///
    /// Ordering is `(started_unix_ms, activity_id)` and `after` is the
    /// previous page's last position (`None` = start of the page stream):
    /// rows strictly after that position are returned, at most `limit + 1`
    /// (the `+ 1` probe lets the caller detect another page and derive its
    /// next cursor; the caller owns page truncation). The endpoint enforces
    /// `1..=200`; larger limits are clamped to [`MAX_PAGE_LIMIT`], and `0`
    /// yields only the overflow probe row. Selection uses a bounded
    /// max-heap of the smallest `limit + 1` positions, so a `Limit=1` probe
    /// never materializes the connection's whole live prefix — only the
    /// selected rows have their `path_hint` cloned.
    pub fn snapshot(
        &self,
        connection: ConnectionId,
        after: Option<(u64, Uuid)>,
        limit: u32,
    ) -> Vec<LiveWorkView> {
        let limit = limit.min(MAX_PAGE_LIMIT) as usize + 1;
        let spans = self.spans.lock().unwrap_or_else(|error| error.into_inner());
        // Bounded selection: a max-heap on the ordering key holds at most
        // `limit` rows and its root is the largest kept position, so a row
        // strictly smaller than the root replaces it. Exactly the `limit`
        // smallest matching positions survive; the rest are never
        // materialized.
        let mut selected: BinaryHeap<(u64, Uuid)> = BinaryHeap::new();
        for work in spans.values() {
            if work.connection_id != connection {
                continue;
            }
            let position = (work.started_unix_ms, work.activity_id);
            if after.is_some_and(|after| position <= after) {
                continue;
            }
            if selected.len() < limit {
                selected.push(position);
            } else if position < *selected.peek().expect("heap is full") {
                selected.pop();
                selected.push(position);
            }
        }
        // `into_sorted_vec` yields ascending positions, and only the
        // selected rows are materialized (path hints cloned per row).
        selected
            .into_sorted_vec()
            .into_iter()
            .map(|(_, activity_id)| {
                let work = spans.get(&activity_id).expect("selected span is still registered");
                LiveWorkView {
                    activity_id: work.activity_id,
                    kind: work.kind,
                    item_id: work.item_id,
                    path_hint: work.path_hint.clone(),
                    started_unix_ms: work.started_unix_ms,
                    total_bytes: work.total_bytes,
                    completed_bytes: work.completed_bytes.load(Ordering::Relaxed),
                }
            })
            .collect()
    }

    fn finish(&self, activity_id: Uuid) {
        self.spans
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&activity_id);
    }
}

impl Drop for LiveWorkHandle<'_> {
    fn drop(&mut self) {
        if self.owns_registration {
            self.registry.finish(self.activity_id);
        }
        // A rejected duplicate owns no registration: dropping it must leave
        // the live span (possibly the same id) untouched.
    }
}

/// Real wall-clock dispatch time (unix milliseconds). Used as the activity
/// start evidence of live work; durable work uses its persisted
/// `created_at_ms` instead.
pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn work(connection: ConnectionId, kind: LiveWorkKind) -> LiveWork {
        LiveWork {
            connection_id: connection,
            activity_id: Uuid::new_v4(),
            kind,
            item_id: None,
            path_hint: None,
            started_unix_ms: 1,
            total_bytes: Some(4096),
            completed_bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    #[test]
    fn live_spans_are_scoped_to_their_connection_and_removed_on_drop() {
        let registry = ActivityRegistry::new();
        let mine = ConnectionId::new();
        let other = ConnectionId::new();
        let job = work(mine, LiveWorkKind::Fetch);
        let progress = job.completed_bytes.clone(); // producer keeps its own Arc
        let handle = registry.begin(job);
        assert_eq!(registry.snapshot(mine, None, 200).len(), 1);
        assert!(
            registry.snapshot(other, None, 200).is_empty(),
            "account/connection boundary"
        );
        progress.store(128, Ordering::Relaxed);
        assert_eq!(registry.snapshot(mine, None, 200)[0].completed_bytes, 128);
        drop(handle);
        assert!(
            registry.snapshot(mine, None, 200).is_empty(),
            "finished work is not in-flight activity"
        );
    }

    /// Uncertain edge: two overlapping requests on the same connection (same
    /// CFAPI request key, same item, interleaved progress). Dropping either
    /// one, in either order, must leave the other span fully intact.
    #[test]
    fn overlapping_spans_never_replace_or_remove_each_other() {
        let registry = ActivityRegistry::new();
        let connection = ConnectionId::new();
        let item = ItemId::new();
        let mut first = work(connection, LiveWorkKind::Fetch);
        first.item_id = Some(item);
        let mut second = work(connection, LiveWorkKind::Fetch);
        second.item_id = Some(item);
        second.started_unix_ms = 1; // same timestamp: ordering must not alias
        let id_first = first.activity_id;
        let id_second = second.activity_id;
        assert_ne!(id_first, id_second, "activity identities are unique per span");
        let progress_second = second.completed_bytes.clone(); // producer Arc
        let handle_first = registry.begin(first);
        let handle_second = registry.begin(second);
        assert_eq!(registry.snapshot(connection, None, 200).len(), 2, "both spans are visible");

        // The later-registered span finishes first (out-of-order drop).
        progress_second.store(64, Ordering::Relaxed);
        drop(handle_second);
        let remaining = registry.snapshot(connection, None, 200);
        assert_eq!(remaining.len(), 1, "only the finished span disappeared");
        assert_eq!(remaining[0].activity_id, id_first);
        assert_eq!(remaining[0].completed_bytes, 0, "the survivor's progress is untouched");

        // A late drop of the finished span's guard is impossible (the guard
        // was consumed), and the surviving span still ends cleanly.
        drop(handle_first);
        assert!(registry.snapshot(connection, None, 200).is_empty());
    }

    /// Uncertain edge: a duplicate activity id can never hijack a live span,
    /// and dropping the rejected duplicate must leave the original span
    /// fully alive (record, kind and byte counter) until the original's own
    /// guard drops — never relying on UUID improbability.
    #[test]
    fn duplicate_activity_ids_cannot_hijack_a_live_span() {
        let registry = ActivityRegistry::new();
        let connection = ConnectionId::new();
        let mut first = work(connection, LiveWorkKind::Fetch);
        let id = first.activity_id;
        first.completed_bytes = Arc::new(AtomicU64::new(7));
        let mut clash = work(connection, LiveWorkKind::DirectoryPopulation);
        clash.activity_id = id;
        clash.completed_bytes = Arc::new(AtomicU64::new(0));
        let progress_first = first.completed_bytes.clone(); // producer Arc
        let progress_clash = clash.completed_bytes.clone(); // rejected work's own Arc
        let handle_first = registry.begin(first);
        let handle_clash = registry.begin(clash);
        let views = registry.snapshot(connection, None, 200);
        assert_eq!(views.len(), 1, "the live span is not replaced by a colliding id");
        assert_eq!(views[0].kind, LiveWorkKind::Fetch, "the original span survives registration");
        assert_eq!(views[0].completed_bytes, 7, "the original counter is untouched");

        // The rejected duplicate owns no registration and its own counter is
        // a different Arc: mutating it while the original is alive changes
        // nothing in the live span, and dropping it removes nothing.
        progress_clash.store(999, Ordering::Relaxed);
        drop(handle_clash);
        let views = registry.snapshot(connection, None, 200);
        assert_eq!(views.len(), 1, "the original span survives the duplicate's drop");
        assert_eq!(views[0].activity_id, id, "the original record is intact");
        assert_eq!(
            views[0].completed_bytes, 7,
            "the rejected duplicate cannot mutate the live span's counter"
        );

        // Only the original's own guard removes it.
        progress_first.store(8, Ordering::Relaxed);
        assert_eq!(registry.snapshot(connection, None, 200)[0].completed_bytes, 8);
        drop(handle_first);
        assert!(registry.snapshot(connection, None, 200).is_empty());
    }

    /// Uncertain edge: totals are truthful under partial delivery — an
    /// unknown total stays unknown and completed bytes never exceed the
    /// bytes actually delivered. Directory population moves no data bytes,
    /// so its span never reports byte progress (total unknown, completed 0).
    #[test]
    fn byte_counters_report_only_delivered_bytes() {
        let registry = ActivityRegistry::new();
        let connection = ConnectionId::new();
        let mut unknown = work(connection, LiveWorkKind::Fetch);
        unknown.total_bytes = None;
        let progress = unknown.completed_bytes.clone(); // producer Arc
        let handle = registry.begin(unknown);
        progress.fetch_add(4096, Ordering::Relaxed);
        let views = registry.snapshot(connection, None, 200);
        assert_eq!(views[0].total_bytes, None, "unknown totals are never invented");
        assert_eq!(views[0].completed_bytes, 4096, "only delivered bytes are counted");
        drop(handle);

        let mut population = work(connection, LiveWorkKind::DirectoryPopulation);
        population.total_bytes = None;
        population.completed_bytes = Arc::new(AtomicU64::new(0));
        // `_span` (not `_`) keeps the RAII guard alive through the asserts.
        let _span = registry.begin(population);
        let views = registry.snapshot(connection, None, 200);
        assert_eq!(
            (views[0].total_bytes, views[0].completed_bytes),
            (None, 0),
            "population spans report no byte progress: entries are not bytes"
        );
    }

    /// Behavioral paging regression: more live rows than a small page. A
    /// `Limit=1` probe returns `limit + 1` rows in `(started_unix_ms,
    /// activity_id)` order strictly after the cursor, and iterating with
    /// that last position as the next cursor visits every row exactly once
    /// — bounded pages, no unbounded live prefix, no gaps or duplicates.
    #[test]
    fn bounded_pages_walk_more_rows_than_a_page() {
        let registry = ActivityRegistry::new();
        let connection = ConnectionId::new();
        // 7 spans at 3 distinct timestamps; ordering is decided by
        // (started_unix_ms, activity_id), computed independently below.
        let starts = [10u64, 10, 20, 20, 20, 30, 30];
        let mut handles = Vec::new(); // keeps every span registered for the walk
        let mut expected: Vec<(u64, Uuid)> = Vec::new();
        for (index, &started) in starts.iter().enumerate() {
            let mut job = work(connection, LiveWorkKind::Fetch);
            job.started_unix_ms = started;
            job.path_hint = Some(format!("row-{index}"));
            expected.push((started, job.activity_id));
            handles.push(registry.begin(job));
        }
        expected.sort();

        // Walk the page stream with limit 1: each page is at most 2 rows
        // (the displayed row + the overflow probe). The caller shows the
        // first `limit` rows and advances its keyset cursor to the last
        // shown row; the probe row is re-fetched on the next page, so each
        // span is visited exactly once.
        let mut cursor: Option<(u64, Uuid)> = None;
        let mut walked: Vec<(u64, Uuid)> = Vec::new();
        loop {
            let page = registry.snapshot(connection, cursor, 1);
            assert!(page.len() <= 2, "a limit-1 page never exceeds limit + 1 rows");
            if page.is_empty() {
                break;
            }
            let shown = &page[..page.len().min(1)];
            for row in shown {
                walked.push((row.started_unix_ms, row.activity_id));
            }
            let last = shown.last().expect("page is nonempty");
            cursor = Some((last.started_unix_ms, last.activity_id));
            if page.len() <= 1 {
                break;
            }
        }
        assert_eq!(
            walked, expected,
            "bounded keyset paging visits every span exactly once in order"
        );
        // A limit-0 probe is bounded too (one overflow row, never the prefix).
        assert!(registry.snapshot(connection, None, 0).len() <= 1);
    }
}
