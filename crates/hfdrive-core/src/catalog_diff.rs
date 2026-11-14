//! Hash-skipping catalog diff.
//!
//! [`diff_items`] compares two catalog roots and yields exactly the item
//! records that differ: additions, removals and modifications, never a full
//! scan disguised as a diff and never phantom changes caused by different
//! B+tree split shapes. Subtrees whose page hashes match are skipped whole;
//! every loaded page's identity (the SHA-256 of its canonical encoding) is
//! verified against the address it was loaded from. Unequal tree shapes are
//! handled by range-aligned descent: the two trees may split the same keys at
//! different boundaries or nest them at different depths, and the diff still
//! pairs entries by key. Only `i/` item entries are compared; the derived
//! `c/` and `n/` indexes never produce item deltas.

use crate::catalog::{encode_and_hash, CatalogError, CatalogRoot, PageSource};
use crate::format::{self, CatalogPage, IndexValue, ItemRecord};
use crate::ids::ItemId;
use crate::storage::Sha256Digest;
use std::collections::BTreeMap;
use std::sync::Arc;

/// One item-level difference between two catalogs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemDelta {
    pub item_id: ItemId,
    /// The record in the `before` catalog; `None` for an addition.
    pub before: Option<ItemRecord>,
    /// The record in the `after` catalog; `None` for a removal.
    pub after: Option<ItemRecord>,
}

impl ItemDelta {
    pub fn is_add(&self) -> bool {
        self.before.is_none()
    }
    pub fn is_remove(&self) -> bool {
        self.after.is_none()
    }
    pub fn is_change(&self) -> bool {
        self.before.is_some() && self.after.is_some()
    }
}

/// The exact item differences between two catalog roots, in item-id order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CatalogDiff {
    pub deltas: Vec<ItemDelta>,
    /// Pages actually read from the source (unique, identity-verified).
    pub pages_loaded: u64,
    /// Page pairs skipped because their hashes matched.
    pub subtrees_skipped: u64,
}

/// A side of the comparison before resolution.
#[derive(Clone, Debug)]
enum Seg {
    /// No subtree on this side.
    Absent,
    /// Already-loaded leaf entries, filtered to the task range.
    Entries(Vec<(String, IndexValue)>),
    /// A stored page to descend.
    Page(Sha256Digest),
}

/// A side after resolution.
enum Resolved {
    Absent,
    Leaf(Vec<(String, IndexValue)>),
    Branch(Vec<(String, Sha256Digest)>),
}

struct Task {
    a: Seg,
    b: Seg,
    lo: Vec<u8>,
    hi: Vec<u8>,
}

/// Compares the item entries of two catalog roots.
///
/// The source must hold every page reachable from either root. The diff is
/// exact across unequal tree shapes and split boundaries: it yields only
/// actual item additions, removals and record changes, and it verifies the
/// content hash of every page it loads.
pub async fn diff_items<S: PageSource>(
    source: &mut S,
    before: CatalogRoot,
    after: CatalogRoot,
) -> Result<CatalogDiff, CatalogError<S::Error>> {
    let mut cache: BTreeMap<Sha256Digest, Arc<CatalogPage>> = BTreeMap::new();
    let mut diff = CatalogDiff::default();
    let mut deltas: BTreeMap<ItemId, (Option<ItemRecord>, Option<ItemRecord>)> = BTreeMap::new();
    let mut stack: Vec<Task> = vec![Task {
        a: Seg::Page(before.digest()),
        b: Seg::Page(after.digest()),
        lo: Vec::new(),
        hi: Vec::new(),
    }];
    while let Some(task) = stack.pop() {
        if let (Seg::Page(a), Seg::Page(b)) = (&task.a, &task.b) {
            if a == b {
                diff.subtrees_skipped += 1;
                continue;
            }
        }
        let resolved_a = resolve(source, task.a, &mut cache, &mut diff).await?;
        let resolved_b = resolve(source, task.b, &mut cache, &mut diff).await?;
        let has_branch = matches!(resolved_a, Resolved::Branch(_))
            || matches!(resolved_b, Resolved::Branch(_));
        if !has_branch {
            // Both sides are flat entry lists (or absent): compare inline.
            let entries_a = into_entries(resolved_a);
            let entries_b = into_entries(resolved_b);
            merge_entries(&entries_a, &entries_b, &task.lo, &task.hi, &mut deltas);
            continue;
        }
        // At least one side is a branch: tile the task range with both sides'
        // child segments and push range-aligned subtasks.
        let segs_a = segments(resolved_a, &task.lo, &task.hi);
        let segs_b = segments(resolved_b, &task.lo, &task.hi);
        for sub in zip_segments(segs_a, segs_b, &task.lo, &task.hi) {
            stack.push(sub);
        }
    }
    for (item_id, (before, after)) in deltas {
        if before != after {
            diff.deltas.push(ItemDelta { item_id, before, after });
        }
    }
    Ok(diff)
}

async fn resolve<S: PageSource>(
    source: &mut S,
    seg: Seg,
    cache: &mut BTreeMap<Sha256Digest, Arc<CatalogPage>>,
    diff: &mut CatalogDiff,
) -> Result<Resolved, CatalogError<S::Error>> {
    match seg {
        Seg::Absent => Ok(Resolved::Absent),
        Seg::Entries(entries) => Ok(Resolved::Leaf(entries)),
        Seg::Page(page_id) => {
            let page = if let Some(page) = cache.get(&page_id) {
                Arc::clone(page)
            } else {
                let page = source
                    .load(page_id)
                    .await
                    .map_err(CatalogError::Storage)?
                    .ok_or(CatalogError::Invariant("missing catalog page"))?;
                let (hash, _) = encode_and_hash(&page)?;
                if hash != page_id {
                    return Err(CatalogError::Invariant("loaded page hash mismatch"));
                }
                diff.pages_loaded += 1;
                let page = Arc::new(page);
                cache.insert(page_id, Arc::clone(&page));
                page
            };
            Ok(match page.as_ref() {
                CatalogPage::Leaf(leaf) => Resolved::Leaf(
                    leaf
                        .entries
                        .iter()
                        .map(|entry| (entry.key.clone(), entry.value.clone()))
                        .collect(),
                ),
                CatalogPage::Branch(branch) => Resolved::Branch(
                    branch
                        .children
                        .iter()
                        .map(|child| (child.first_key.clone(), child.page_id))
                        .collect(),
                ),
            })
        }
    }
}

fn into_entries(resolved: Resolved) -> Vec<(String, IndexValue)> {
    match resolved {
        Resolved::Leaf(entries) => entries,
        _ => Vec::new(),
    }
}

/// Tiles `[lo, hi)` with the side's segments: one segment for a leaf or an
/// absent side, one segment per child for a branch. The first segment starts
/// exactly at `lo`, so entries below a retained `first_key` remain covered.
fn segments(
    resolved: Resolved,
    lo: &[u8],
    hi: &[u8],
) -> Vec<(Vec<u8>, Vec<u8>, Seg)> {
    match resolved {
        Resolved::Absent => vec![(lo.to_vec(), hi.to_vec(), Seg::Absent)],
        Resolved::Leaf(entries) => {
            vec![(lo.to_vec(), hi.to_vec(), Seg::Entries(entries))]
        }
        Resolved::Branch(children) => {
            let mut out: Vec<(Vec<u8>, Vec<u8>, Seg)> = Vec::new();
            let mut cursor = lo.to_vec();
            for (index, (first_key, page_id)) in children.iter().enumerate() {
                let child_lo = if index == 0 {
                    cursor.clone()
                } else {
                    greater(first_key.as_bytes(), &cursor)
                };
                if !hi.is_empty() && child_lo.as_slice() >= hi {
                    break;
                }
                let child_hi = match children.get(index + 1) {
                    Some((next, _)) => {
                        let next = next.as_bytes();
                        if hi.is_empty() || next < hi {
                            next.to_vec()
                        } else {
                            hi.to_vec()
                        }
                    }
                    None => hi.to_vec(),
                };
                if child_lo < child_hi {
                    out.push((child_lo.clone(), child_hi.clone(), Seg::Page(*page_id)));
                    cursor = child_hi;
                }
            }
            if out.is_empty() {
                out.push((lo.to_vec(), hi.to_vec(), Seg::Absent));
            }
            out
        }
    }
}

fn greater(a: &[u8], b: &[u8]) -> Vec<u8> {
    if a > b {
        a.to_vec()
    } else {
        b.to_vec()
    }
}

/// Interval-merges two segment lists that both tile `[lo, hi)`, producing one
/// subtask per overlapping region. Entries on either side are re-filtered to
/// the region so a leaf split differently across the two trees still pairs
/// the same keys together.
fn zip_segments(
    segs_a: Vec<(Vec<u8>, Vec<u8>, Seg)>,
    segs_b: Vec<(Vec<u8>, Vec<u8>, Seg)>,
    lo: &[u8],
    hi: &[u8],
) -> Vec<Task> {
    let mut tasks: Vec<Task> = Vec::new();
    let mut i = 0usize;
    let mut j = 0usize;
    let mut cursor = lo.to_vec();
    loop {
        let end_a = segs_a.get(i).map(|(_, end, _)| end.clone());
        let end_b = segs_b.get(j).map(|(_, end, _)| end.clone());
        let end = match (&end_a, &end_b) {
            (Some(a), Some(b)) => {
                if a <= b {
                    a.clone()
                } else {
                    b.clone()
                }
            }
            (Some(a), None) => a.clone(),
            (None, Some(b)) => b.clone(),
            (None, None) => break,
        };
        let end = if hi.is_empty() || end.as_slice() <= hi {
            end
        } else {
            hi.to_vec()
        };
        if end <= cursor {
            // Defensive: advance whichever side stalled at this boundary.
            if end_a.as_deref() == Some(end.as_slice()) {
                i += 1;
            }
            if end_b.as_deref() == Some(end.as_slice()) {
                j += 1;
            }
            if end_a.as_deref() != Some(end.as_slice()) && end_b.as_deref() != Some(end.as_slice())
            {
                break;
            }
            continue;
        }
        let a = segs_a
            .get(i)
            .map(|(_, _, seg)| narrow(seg.clone(), &cursor, &end))
            .unwrap_or(Seg::Absent);
        let b = segs_b
            .get(j)
            .map(|(_, _, seg)| narrow(seg.clone(), &cursor, &end))
            .unwrap_or(Seg::Absent);
        tasks.push(Task { a, b, lo: cursor.clone(), hi: end.clone() });
        cursor = end.clone();
        if end_a.as_deref() == Some(end.as_slice()) {
            i += 1;
        }
        if end_b.as_deref() == Some(end.as_slice()) {
            j += 1;
        }
    }
    tasks
}

fn narrow(seg: Seg, lo: &[u8], hi: &[u8]) -> Seg {
    match seg {
        Seg::Entries(entries) => Seg::Entries(
            entries
                .into_iter()
                .filter(|(key, _)| {
                    let key = key.as_bytes();
                    key >= lo && (hi.is_empty() || key < hi)
                })
                .collect(),
        ),
        other => other,
    }
}

fn merge_entries(
    entries_a: &[(String, IndexValue)],
    entries_b: &[(String, IndexValue)],
    lo: &[u8],
    hi: &[u8],
    deltas: &mut BTreeMap<ItemId, (Option<ItemRecord>, Option<ItemRecord>)>,
) {
    let mut i = 0usize;
    let mut j = 0usize;
    while i < entries_a.len() || j < entries_b.len() {
        let key_a = entries_a.get(i).map(|(k, _)| k.as_bytes());
        let key_b = entries_b.get(j).map(|(k, _)| k.as_bytes());
        let take_a_only = match (key_a, key_b) {
            (Some(a), Some(b)) => a < b,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => break,
        };
        if take_a_only {
            let (key, value) = &entries_a[i];
            i += 1;
            if in_range(key.as_bytes(), lo, hi) {
                if let Some(item) = item_of(key, value) {
                    let item_id = item.item_id;
                    deltas.entry(item_id).or_default().0 = Some(item);
                }
            }
        } else {
            let equal = key_a == key_b;
            let (key_b, value_b) = &entries_b[j];
            j += 1;
            if in_range(key_b.as_bytes(), lo, hi) {
                if let Some(item) = item_of(key_b, value_b) {
                    let item_id = item.item_id;
                    deltas.entry(item_id).or_default().1 = Some(item);
                }
            }
            if equal {
                let (key_a, value_a) = &entries_a[i];
                i += 1;
                if in_range(key_a.as_bytes(), lo, hi) {
                    if let Some(item) = item_of(key_a, value_a) {
                        let item_id = item.item_id;
                        deltas.entry(item_id).or_default().0 = Some(item);
                    }
                }
            }
        }
    }
}

fn in_range(key: &[u8], lo: &[u8], hi: &[u8]) -> bool {
    key >= lo && (hi.is_empty() || key < hi)
}

/// Extracts the item record of an `i/` entry and verifies its key/value
/// identity. `c/` and `n/` index entries yield no item delta.
fn item_of(key: &str, value: &IndexValue) -> Option<ItemRecord> {
    match format::parse_index_key(key) {
        Ok(format::IndexKey::Item { item_id }) => match value {
            IndexValue::Item(item) if item.item_id == item_id => Some(item.clone()),
            _ => None,
        },
        Ok(_) => None,
        Err(_) => None,
    }
}
