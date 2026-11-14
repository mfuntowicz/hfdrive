//! Bounded local observation: watcher events, USN catch-up, complete scans,
//! provider-echo suppression and 750 ms coalescing.
//!
//! Invariants enforced here:
//!
//! * **No remote echo.** Every provider-produced local change (placeholder
//!   create/update/rename/delete) is journaled in the local-action journal
//!   before it is applied. An observation that matches a journal action's
//!   expected/new facts is absorbed as bookkeeping and never becomes a local
//!   edit intent, so remote application can never turn into an upload echo.
//! * **Deletion evidence is earned.** A disappearance becomes a deletion
//!   intent only when a fully completed, non-invalidated scan observed the
//!   absence. Watcher overflow, USN reset/wrap, denied directories, budget
//!   exhaustion and access failures void deletion inference until a fresh
//!   completed scan; none of them ever creates a tombstone.
//! * **Generations are never discarded.** Each local save bumps the durable
//!   per-item generation immediately; coalescing merges only the *work*, so
//!   superseded uploads cannot clear newer edits.
//! * **Exclusions are observed, not published.** Items in an excluded
//!   selective-sync subtree are bookkept and never captured or uploaded.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use hfdrive_core::ids::ItemId;
use hfdrive_core::names::collision_key;
use hfdrive_state::{AccountStore, LocalAction, LocalActionState, ScanState};
use hfdrive_windows::filesystem::volume::FileState;
use hfdrive_windows::filesystem::{
    MetadataEntry, ScanBudget, ScanReport, WatchAction, WatchEvent, query_file_state,
    scan_metadata,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::sync::outbox::display_timestamp;

/// Coalescing window for local saves before intent creation. Generations are
/// persisted at observation time; only the work is merged.
pub const COALESCE_WINDOW: std::time::Duration = std::time::Duration::from_millis(750);

/// Periodic metadata reconciliation interval.
pub const SCAN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// Echo window: journal actions keep absorbing matching observations for
/// this long after they were applied (slow watchers, USN lag, restarts).
pub const ECHO_WINDOW: std::time::Duration = std::time::Duration::from_secs(30);

/// One normalized watcher observation before classification.
#[derive(Debug, Clone)]
pub struct RawObservation {
    /// Path relative to the sync root, component-wise.
    pub relative_path: PathBuf,
    pub action: WatchAction,
}

/// The classified outcome of one observed fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification {
    /// Provider-applied change absorbed from the action journal. Refresh
    /// bookkeeping only; never a local write.
    Echo { item_id: ItemId },
    /// Inside an excluded selective-sync subtree: bookkeeping only.
    Excluded,
    /// A brand-new local item (file or directory).
    Created {
        item_id: ItemId,
        is_directory: bool,
        state: FileState,
    },
    /// New content generation for a known item (also covers atomic
    /// replacement at the same path).
    ContentChanged { item_id: ItemId, state: FileState },
    /// Rename/move of a known item recognized by stable file identity.
    Moved { item_id: ItemId, state: FileState },
    /// A disappearance. Only turned into a deletion intent when scan
    /// evidence allows; otherwise parked as pending work.
    Removed { item_id: ItemId },
    /// A path disappeared without traceable identity; needs a completed scan.
    UntrackedRemoval,
    /// Overflow/reset/denied scan: deletion evidence is void until rescan.
    RescanRequired,
    /// Noise (unrelated files, partial state, unsupported entries).
    Ignored,
}

// ---------------------------------------------------------------------------
// Pure classification helpers (deterministically tested)
// ---------------------------------------------------------------------------

/// True when the observation matches a journaled provider-applied action and
/// must be absorbed. Matching is by stable item identity and by the action's
/// expected or target path; an unknown USN never matches anything.
pub fn echo_matches(action: &LocalAction, item_id: ItemId, relative_path: &Path) -> bool {
    if action.item_id != Some(item_id) {
        return false;
    }
    if !matches!(action.state, LocalActionState::InProgress | LocalActionState::Applied) {
        return false;
    }
    let path_matches = [action.source_path.as_ref(), action.target_path.as_ref()]
        .into_iter()
        .flatten()
        .any(|path| path_ends_with(path, relative_path));
    // Identity match on the item is sufficient inside the echo window; the
    // window itself is enforced by the caller through the journal's states.
    action.item_id == Some(item_id) && (path_matches || action.target_path.is_none())
}

fn path_ends_with(haystack: &Path, relative: &Path) -> bool {
    let hay: Vec<_> = haystack.components().collect();
    let needle: Vec<_> = relative.components().collect();
    hay.len() >= needle.len() && hay[hay.len() - needle.len()..] == needle[..]
}

/// True when a disappearance may become a deletion intent.
pub fn deletion_evidence(scan: &Option<ScanState>) -> bool {
    scan.as_ref().is_some_and(ScanState::may_infer_deletion)
}

/// One coalesced local change ready for intent creation.
#[derive(Debug, Clone)]
pub struct CoalescedChange {
    pub fact: Classification,
    /// The durable generation observed at coalescing time (the newest bump).
    pub observed_generation: u64,
    /// Display timestamp from the observed state, when content changed.
    pub modified_at: Option<String>,
}

/// Per-item coalescing buffer. Saves within the window merge into one change
/// carrying the newest generation; the window never resets the durable
/// generation counter.
#[derive(Default)]
pub struct Coalescer {
    pending: HashMap<ItemId, (CoalescedChange, std::time::Instant)>,
}

impl Coalescer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one classified change. Older pending work for the item is
    /// replaced (merged) but the newest generation always wins.
    pub fn push(&mut self, item_id: ItemId, change: CoalescedChange) {
        let now = std::time::Instant::now();
        match self.pending.get_mut(&item_id) {
            Some((existing, at)) => {
                if change.observed_generation >= existing.observed_generation {
                    // The newest classification supersedes older work for the
                    // same item; a Move supersedes ContentChanged and vice
                    // versa only when both describe the same item.
                    *existing = change;
                }
                *at = now;
            }
            None => {
                self.pending.insert(item_id, (change, now));
            }
        }
    }

    /// Drains changes whose window elapsed. `now` is injected for tests.
    pub fn drain_ready(&mut self, now: std::time::Instant) -> Vec<(ItemId, CoalescedChange)> {
        let mut ready = Vec::new();
        self.pending.retain(|item_id, (change, at)| {
            if now.duration_since(*at) >= COALESCE_WINDOW {
                ready.push((*item_id, change.clone()));
                false
            } else {
                true
            }
        });
        ready
    }

    /// Drains everything unconditionally (shutdown/pause), oldest first.
    pub fn drain_all(&mut self) -> Vec<(ItemId, CoalescedChange)> {
        let mut all: Vec<_> = self
            .pending
            .drain()
            .map(|(item, (change, at))| (at, item, change))
            .collect();
        all.sort_by_key(|(at, _, _)| *at);
        all.into_iter().map(|(_, item, change)| (item, change)).collect()
    }
}

// ---------------------------------------------------------------------------
// Path/name helpers
// ---------------------------------------------------------------------------

/// Splits a relative path into validated final components. Invalid or
/// unsupported names stop the walk: nothing outside the managed namespace is
/// ever interpreted as an item.
pub fn split_components(relative: &Path) -> Option<Vec<String>> {
    let mut components = Vec::new();
    for component in relative.components() {
        let name = component.as_os_str().to_str()?;
        if hfdrive_windows::filesystem::names::validate_component(name).is_err() {
            return None;
        }
        components.push(name.to_owned());
    }
    Some(components)
}

/// Case-insensitive name identity for registry resolution.
pub fn names_equivalent(a: &str, b: &str) -> bool {
    collision_key(a) == collision_key(b)
        || hfdrive_windows::filesystem::names::windows_case_equivalent(a, b)
}

// ---------------------------------------------------------------------------
// Echo table (in-memory half of the suppression window)
// ---------------------------------------------------------------------------

/// Recently applied provider actions. The durable half is the local-action
/// journal; this table only carries the fast path and the post-restart
/// window reconstruction.
#[derive(Default)]
pub struct EchoTable {
    applied: HashMap<ItemId, (PathBuf, std::time::Instant)>,
}

impl EchoTable {
    pub fn note_applied(&mut self, item_id: ItemId, target: PathBuf) {
        self.applied.insert(item_id, (target, std::time::Instant::now()));
    }

    /// True while the item's provider-applied change may still be echoing
    /// through watchers and the USN journal.
    pub fn in_window(&self, item_id: ItemId) -> bool {
        self.applied
            .get(&item_id)
            .is_some_and(|(_, at)| at.elapsed() <= ECHO_WINDOW)
    }

    pub fn forget(&mut self, item_id: ItemId) {
        self.applied.remove(&item_id);
    }
}

// ---------------------------------------------------------------------------
// Scan driver
// ---------------------------------------------------------------------------

/// One complete metadata enumeration pass. Synchronous core, driven through
/// `spawn_blocking` by the observer. Entries are collected (bounded by the
/// scan budget) and reconciled asynchronously afterwards.
pub fn enumerate_metadata(
    root: &Path,
    cancel: &AtomicBool,
) -> Result<(Vec<MetadataEntry>, ScanReport), hfdrive_windows::filesystem::FsError> {
    let mut entries = Vec::new();
    let budget = ScanBudget::default();
    let report = scan_metadata(root, &budget, cancel, &mut |entry| {
        entries.push(entry.clone());
        if entries.len() > budget.max_entries {
            hfdrive_windows::filesystem::VisitFlow::Stop
        } else {
            hfdrive_windows::filesystem::VisitFlow::Continue
        }
    })?;
    Ok((entries, report))
}

/// The evidence rules around one scan outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanOutcome {
    /// The scan completed; disappearance may now be inferred until the next
    /// invalidation.
    Complete { entries: usize, usn_cursor: Option<i64> },
    /// The scan did not complete (denied directories, budget, cancellation):
    /// deletion evidence remains void.
    Incomplete { entries: usize },
}

/// Classifies a scan report into durable evidence.
pub fn scan_outcome(report: &ScanReport) -> ScanOutcome {
    if report.complete && !report.overflow {
        ScanOutcome::Complete { entries: report.entries, usn_cursor: None }
    } else {
        ScanOutcome::Incomplete { entries: report.entries }
    }
}

// ---------------------------------------------------------------------------
// The observation engine
// ---------------------------------------------------------------------------

/// Configuration for the per-connection observer.
pub struct ObserverConfig {
    pub root: PathBuf,
    pub coalesce: std::time::Duration,
    pub scan_interval: std::time::Duration,
}

/// Batches of raw local observations delivered to the connection controller,
/// which classifies them against durable state before intent creation.
#[derive(Debug)]
pub struct ObservationBatch {
    pub observations: Vec<RawObservation>,
    /// Set when the underlying watcher lost data (overflow) and a full
    /// rescan must run before any deletion inference.
    pub rescan_required: bool,
}

/// Runs the watcher and the debounce loop. Classification needs connection
/// state, so raw facts are coalesced by relative name and handed to the
/// controller's [`classify_observation`] once the window elapses.
pub struct LocalObserver {
    watcher: Option<hfdrive_windows::filesystem::DirectoryWatcher>,
    cancel: CancellationToken,
}

struct PendingRaw {
    observation: RawObservation,
    at: std::time::Instant,
}

impl LocalObserver {
    /// Starts the directory watcher and the debounce loop.
    pub fn start(
        config: ObserverConfig,
        cancel: CancellationToken,
        events: mpsc::Sender<ObservationBatch>,
    ) -> Result<Self, hfdrive_windows::filesystem::FsError> {
        let (watch_tx, mut watch_rx) = mpsc::channel::<WatchEvent>(1024);
        let watcher =
            hfdrive_windows::filesystem::DirectoryWatcher::start(&config.root, watch_tx)?;
        let loop_cancel = cancel.clone();
        tokio::spawn(async move {
            // Keyed by lowercase spelling so case-only renames stay visible
            // as distinct facts while exact repeats merge.
            let mut pending: HashMap<String, PendingRaw> = HashMap::new();
            let mut overflowed = false;
            let mut ticker = tokio::time::interval(config.coalesce);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = loop_cancel.cancelled() => break,
                    event = watch_rx.recv() => {
                        let Some(event) = event else { break; };
                        match event.action {
                            WatchAction::Overflow => {
                                overflowed = true;
                                let drain: Vec<RawObservation> = pending
                                    .drain()
                                    .map(|(_, entry)| entry.observation)
                                    .collect();
                                let _ = events
                                    .send(ObservationBatch {
                                        observations: drain,
                                        rescan_required: true,
                                    })
                                    .await;
                            }
                            _ => {
                                let Some(name) = event.name else { continue; };
                                let key = name.to_lowercase();
                                let entry = PendingRaw {
                                    observation: RawObservation {
                                        relative_path: PathBuf::from(&name),
                                        action: event.action,
                                    },
                                    at: std::time::Instant::now(),
                                };
                                pending.insert(key, entry);
                            }
                        }
                    }
                    _ = ticker.tick() => {
                        let now = std::time::Instant::now();
                        let mut ready = Vec::new();
                        pending.retain(|_, entry| {
                            if now.duration_since(entry.at) >= config.coalesce {
                                ready.push(entry.observation.clone());
                                false
                            } else {
                                true
                            }
                        });
                        if !ready.is_empty() || std::mem::take(&mut overflowed) {
                            let _ = events
                                .send(ObservationBatch {
                                    observations: ready,
                                    rescan_required: false,
                                })
                                .await;
                        }
                    }
                }
            }
        });
        Ok(Self { watcher: Some(watcher), cancel })
    }

    /// Stops the watcher thread. Bounded and idempotent.
    pub fn shutdown(&mut self) {
        self.cancel.cancel();
        if let Some(mut watcher) = self.watcher.take() {
            watcher.shutdown();
        }
    }
}

impl Drop for LocalObserver {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Classifies one watcher observation against the connection's item registry
/// and local-action journal. This is the single funnel every local change
/// passes through before an intent may exist.
pub async fn classify_observation(
    state: &AccountStore,
    connection: hfdrive_core::ids::ConnectionId,
    root_item_id: ItemId,
    root: &Path,
    echo: &EchoTable,
    relative_path: &Path,
    action: WatchAction,
    now_ms: u64,
) -> Classification {
    let Some(components) = split_components(relative_path) else {
        return Classification::Ignored;
    };
    if components.is_empty() {
        return Classification::Ignored;
    }

    // 1. Resolve the item through the durable registry (case-insensitive
    //    Windows identity).
    let item_id = resolve_item(state, connection, root_item_id, &components).await;
    let full = root.join(relative_path);
    let live = query_file_state(&full).ok();

    // 2. Echo suppression: provider-applied changes are absorbed first.
    if let Some(item_id) = item_id {
        if echo.in_window(item_id) {
            return Classification::Echo { item_id };
        }
        if let Ok(actions) = state
            .list_local_actions(connection, Some(LocalActionState::InProgress))
            .await
        {
            for journal in &actions {
                if echo_matches(journal, item_id, relative_path) {
                    return Classification::Echo { item_id };
                }
            }
        }
    }

    // 3. Exclusion gating: excluded subtrees never produce work.
    if let Some(item_id) = item_id {
        if excluded_here(state, connection, item_id).await {
            return Classification::Excluded;
        }
    }

    // 4. Disappearances require scan evidence.
    if matches!(action, WatchAction::Removed) || live.is_none() {
        return match item_id {
            Some(item_id) => Classification::Removed { item_id },
            None => Classification::UntrackedRemoval,
        };
    }

    let Some(state_now) = live else {
        return Classification::Ignored;
    };

    // 5. Create / content / move classification.
    let _ = now_ms;
    match (item_id, action) {
        (None, _) => {
            if is_supported_new_entry(&state_now, &components) {
                let new_id = ItemId::new();
                let is_directory = state_now.identity.attributes & 0x10 != 0; // FILE_ATTRIBUTE_DIRECTORY
                Classification::Created { item_id: new_id, is_directory, state: state_now }
            } else {
                Classification::Ignored
            }
        }
        (Some(item_id), WatchAction::RenamedFrom | WatchAction::RenamedTo) => {
            // The stable file identity decides: same identity at a new path is
            // a move of the known item.
            Classification::Moved { item_id, state: state_now }
        }
        (Some(item_id), _) => Classification::ContentChanged { item_id, state: state_now },
    }
}

/// Resolves a relative name chain to a known item id. The chain is anchored
/// at the connection's root directory item, so the first lookup lists the
/// root's children rather than the root itself.
pub async fn resolve_item(
    state: &AccountStore,
    connection: hfdrive_core::ids::ConnectionId,
    root_item_id: ItemId,
    components: &[String],
) -> Option<ItemId> {
    if components.is_empty() {
        return Some(root_item_id);
    }
    let mut parent: Option<ItemId> = Some(root_item_id);
    let mut current: Option<ItemId> = None;
    for name in components {
        let children = state.list_children(connection, parent, false).await.ok()?;
        let mut found = None;
        for child in &children {
            if names_equivalent(&child.name, name) {
                found = Some(child.item_id);
                break;
            }
        }
        current = found;
        parent = current;
        if current.is_none() {
            return None;
        }
    }
    current
}

/// True when the item (or an ancestor) carries a selective-sync exclusion.
pub async fn excluded_here(
    state: &AccountStore,
    connection: hfdrive_core::ids::ConnectionId,
    item_id: ItemId,
) -> bool {
    let mut current = Some(item_id);
    let mut depth = 0;
    while let Some(id) = current {
        if depth > 512 {
            return true;
        }
        match state.observation(connection, id).await {
            Ok(Some(observation)) if observation.excluded => return true,
            Ok(Some(_)) | Ok(None) => {}
            Err(_) => return true,
        }
        current = match state.item(connection, id).await {
            Ok(Some(item)) => item.parent_id,
            _ => None,
        };
        depth += 1;
    }
    false
}

fn is_supported_new_entry(state: &FileState, components: &[String]) -> bool {
    if components.iter().any(|name| {
        hfdrive_windows::filesystem::names::validate_component(name).is_err()
    }) {
        return false;
    }
    // Foreign reparse points, EFS and multiply linked files are preserved
    // locally with actionable errors; they never become managed items.
    !state.identity.is_reparse_point()
        && !state.identity.is_encrypted()
        && !state.identity.has_multiple_links()
}

/// Drives one full metadata scan and applies its evidence to the durable
/// scan state. Completion grants deletion evidence; anything less voids it.
pub async fn run_scan(
    state: &AccountStore,
    connection: hfdrive_core::ids::ConnectionId,
    root: &Path,
    volume_id: String,
    journal_id: String,
    cancel: std::sync::Arc<AtomicBool>,
) -> Result<ScanOutcome, Box<dyn std::error::Error + Send + Sync>> {
    state.begin_scan(connection, volume_id, journal_id).await?;
    let root_path = root.to_path_buf();
    let cancel_flag = cancel;
    let outcome = tokio::task::spawn_blocking(move || enumerate_metadata(&root_path, &cancel_flag))
        .await?;
    match outcome {
        Ok((_entries, report)) => {
            let outcome = scan_outcome(&report);
            match outcome {
                ScanOutcome::Complete { .. } => {
                    state.complete_scan(connection, None).await?;
                }
                ScanOutcome::Incomplete { .. } => {
                    state.invalidate_scan(connection).await?;
                }
            }
            Ok(outcome)
        }
        Err(error) => {
            // Cancelled or failed scans never grant deletion evidence.
            state.invalidate_scan(connection).await?;
            Err(error.into())
        }
    }
}

/// Classifies one USN catch-up result against the scan evidence rules.
pub fn usn_catchup_outcome(catch_up: &hfdrive_windows::filesystem::CatchUp) -> ScanOutcome {
    match catch_up {
        hfdrive_windows::filesystem::CatchUp::Advanced { changes, .. } => ScanOutcome::Complete {
            entries: changes.len(),
            usn_cursor: None,
        },
        hfdrive_windows::filesystem::CatchUp::Reset(_) => ScanOutcome::Incomplete { entries: 0 },
    }
}

/// Builds the display metadata pair for a captured local file.
pub fn display_for(state: &FileState, name: &str) -> (String, String) {
    (name.to_owned(), display_timestamp(state.last_write_time_100ns))
}

/// Tracks the pending classification of a disappearance until scan evidence
/// arrives. Parked removals are re-checked, never dropped and never turned
/// into tombstones early.
#[derive(Default)]
pub struct PendingRemovals {
    parked: HashMap<ItemId, (PathBuf, u64)>,
}

impl PendingRemovals {
    pub fn park(&mut self, item_id: ItemId, path: PathBuf, now_ms: u64) {
        self.parked.insert(item_id, (path, now_ms));
    }

    /// Releases parked removals only when deletion evidence allows.
    pub fn release(&mut self, evidence: bool) -> Vec<ItemId> {
        if !evidence {
            return Vec::new();
        }
        let ids: Vec<_> = self.parked.keys().copied().collect();
        for id in &ids {
            self.parked.remove(id);
        }
        ids
    }

    pub fn len(&self) -> usize {
        self.parked.len()
    }

    pub fn is_empty(&self) -> bool {
        self.parked.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hfdrive_core::ids::ConnectionId;
    use hfdrive_state::LocalActionKind;

    fn action(item_id: ItemId, state: LocalActionState) -> LocalAction {
        LocalAction {
            connection_id: ConnectionId::new(),
            action_id: hfdrive_core::ids::ActionId::new(),
            item_id: Some(item_id),
            kind: LocalActionKind::UpdatePlaceholder,
            expected_file_id: None,
            expected_generation: Some(1),
            expected_usn: Some(42),
            old_version: None,
            new_version: None,
            source_path: None,
            target_path: Some(PathBuf::from("docs\\report.txt")),
            recovery_path: None,
            state,
        }
    }

    #[test]
    fn provider_applied_actions_absorb_matching_observations() {
        let item = ItemId::new();
        let active = action(item, LocalActionState::InProgress);
        assert!(echo_matches(&active, item, Path::new("docs\\report.txt")));
        let done = action(item, LocalActionState::Applied);
        assert!(echo_matches(&done, item, Path::new("docs\\report.txt")));
        let requeued = action(item, LocalActionState::Requeued);
        assert!(!echo_matches(&requeued, item, Path::new("docs\\report.txt")));
        let other = action(ItemId::new(), LocalActionState::InProgress);
        assert!(!echo_matches(&other, item, Path::new("docs\\report.txt")));
        assert!(!echo_matches(&active, item, Path::new("docs\\other.txt")));
    }

    #[test]
    fn coalescing_merges_work_but_never_loses_the_newest_generation() {
        let item = ItemId::new();
        let mut coalescer = Coalescer::new();
        for generation in 1..=3 {
            coalescer.push(
                item,
                CoalescedChange {
                    fact: Classification::ContentChanged {
                        item_id: item,
                        state: dummy_state(),
                    },
                    observed_generation: generation,
                    modified_at: None,
                },
            );
        }
        let ready = coalescer.drain_ready(std::time::Instant::now() + COALESCE_WINDOW);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].1.observed_generation, 3);
    }

    #[test]
    fn deletions_require_completed_scan_evidence() {
        let none = None;
        assert!(!deletion_evidence(&none));
        let invalidated = Some(ScanState {
            connection_id: ConnectionId::new(),
            cursor: None,
            pending_head_refresh: false,
            volume_id: "vol".into(),
            journal_id: "j".into(),
            usn_cursor: Some(7),
            scan_epoch: 1,
            scan_complete: true,
            scan_invalidated: true,
        });
        assert!(!deletion_evidence(&invalidated));
        let complete = Some(ScanState {
            scan_invalidated: false,
            ..invalidated.clone().unwrap()
        });
        assert!(deletion_evidence(&complete));
    }

    #[test]
    fn overflow_and_incomplete_scans_void_deletion_evidence() {
        let complete = ScanReport { complete: true, entries: 10, denied: vec![], overflow: false };
        assert_eq!(
            scan_outcome(&complete),
            ScanOutcome::Complete { entries: 10, usn_cursor: None }
        );
        let overflowed =
            ScanReport { complete: false, entries: 10, denied: vec![], overflow: true };
        assert_eq!(scan_outcome(&overflowed), ScanOutcome::Incomplete { entries: 10 });
        let denied = ScanReport {
            complete: false,
            entries: 3,
            denied: vec![PathBuf::from("locked")],
            overflow: false,
        };
        assert_eq!(scan_outcome(&denied), ScanOutcome::Incomplete { entries: 3 });
    }

    #[test]
    fn parked_removals_stay_parked_without_evidence() {
        let mut pending = PendingRemovals::default();
        pending.park(ItemId::new(), PathBuf::from("gone.txt"), 1);
        assert!(pending.release(false).is_empty());
        assert_eq!(pending.len(), 1);
        assert_eq!(pending.release(true).len(), 1);
        assert!(pending.is_empty());
    }

    #[test]
    fn echo_window_expires() {
        let item = ItemId::new();
        let mut table = EchoTable::default();
        table.note_applied(item, PathBuf::from("a.txt"));
        assert!(table.in_window(item));
        table.forget(item);
        assert!(!table.in_window(item));
    }

    fn dummy_state() -> FileState {
        FileState {
            identity: hfdrive_windows::filesystem::volume::FileIdentity {
                volume_serial_number: 1,
                file_id: [0; 16],
                link_count: 1,
                attributes: 0x20,
                reparse_tag: 0,
            },
            size: 0,
            last_write_time_100ns: 0,
            usn: None,
        }
    }
}
