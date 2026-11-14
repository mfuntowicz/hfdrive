//! Persistent copy-on-write B+tree for the managed catalog.
//!
//! The catalog is the authoritative namespace of one managed drive: item
//! records under `i/<item-id>`, live-child indexes under
//! `c/<parent-id>/<name-hex>/<item-id>`, and portable name-uniqueness indexes
//! under `n/<parent-id>/<collision-key-hex>`, all in one tree. Pages are
//! immutable and hash-addressed by the SHA-256 of their canonical encoding.
//! A mutation rewrites only the affected root-to-leaf path: every subtree whose
//! page hash did not change is shared with the previous root, so one save never
//! rewrites a whole manifest. Deletion tombstones the item entry and removes
//! exactly that item's live `c`/`n` indexes; v1 never merges or rebalances
//! pages, so under-occupied pages persist.
//!
//! Pages cross the storage boundary through [`PageSource`] and [`PageSink`]:
//! statically dispatched async traits, so a native async adapter neither
//! blocks nor boxes futures. The caller uploads the [`PublishSet::pages`] of a
//! committed mutation to immutable storage and only then publishes the new
//! HEAD. [`InMemoryPageStore`] is the deterministic offline store used by pure
//! tests and bench evidence.

use crate::format::{
    self, BranchChild, CatalogPage, FormatError, IndexValue, ItemKind, ItemRecord, LeafEntry,
    MAX_PAGE_BYTES, MAX_PAGE_FANOUT,
};
use crate::ids::{ItemId, OperationId};
use crate::names;
use crate::storage::Sha256Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Minimum entries in a leaf and children in a branch away from the root.
/// v1 performs no merge or rebalance on deletion, so pages may fall below it.
pub const MIN_PAGE_OCCUPANCY: usize = MAX_PAGE_FANOUT / 2;

/// A catalog error. `E` is the page storage error type; nothing is boxed.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError<E> {
    #[error("catalog record is not canonical HF Drive JSON: {0}")]
    Format(#[from] FormatError),
    #[error("catalog page storage failed: {0}")]
    Storage(E),
    #[error("catalog item does not exist")]
    MissingItem,
    #[error("catalog parent is not a live directory")]
    NotADirectory,
    #[error("a live item with this name already exists under the parent")]
    DuplicateName,
    #[error("the mutation would introduce a parent cycle")]
    Cycle,
    #[error("the catalog root is not a single live directory")]
    InvalidRoot,
    #[error("item name violates the portable name rules: {0}")]
    InvalidName(#[from] names::NameError),
    #[error("the catalog invariant is broken: {0}")]
    Invariant(&'static str),
}

/// Source of immutable catalog pages, addressed by content hash.
pub trait PageSource {
    type Error;
    /// Loads the page with `page_id`, or `None` when it is absent. A stored
    /// page whose encoding does not hash to `page_id` is store corruption and
    /// MUST NOT be returned as a valid page.
    fn load(
        &mut self,
        page_id: Sha256Digest,
    ) -> impl Future<Output = Result<Option<CatalogPage>, Self::Error>> + Send;
}

/// Sink for the dirty pages of one committed mutation.
pub trait PageSink {
    type Error;
    /// Persists one dirty page as a durable staging step. Each page is offered
    /// at most once per mutation and must survive until the caller has
    /// uploaded it and published the new HEAD.
    fn store(
        &mut self,
        page_id: Sha256Digest,
        page: &CatalogPage,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Encodes a page canonically and returns its content hash.
pub fn encode_and_hash(page: &CatalogPage) -> Result<(Sha256Digest, Vec<u8>), FormatError> {
    let bytes = format::to_page_bytes(page)?;
    if bytes.len() > MAX_PAGE_BYTES {
        return Err(FormatError::TooLarge);
    }
    Ok((Sha256Digest::of(&bytes), bytes))
}

/// The persisted immutable catalog root: the hash of the root page.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CatalogRoot(Sha256Digest);

impl CatalogRoot {
    pub fn from_digest(digest: Sha256Digest) -> Self {
        Self(digest)
    }
    pub fn digest(&self) -> Sha256Digest {
        self.0
    }
}

/// The pages one committed mutation must upload before publishing its HEAD.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishSet {
    pub root: CatalogRoot,
    /// Pages reachable from the new root that the source does not already
    /// hold, in deterministic (hash) order.
    pub pages: Vec<(Sha256Digest, CatalogPage)>,
    /// Path pages whose hash was reused instead of rewritten.
    pub reused_pages: u64,
    /// Pages read from the source during the mutation.
    pub loaded_pages: u64,
}

impl PublishSet {
    /// Total canonical bytes to upload.
    pub fn upload_bytes(&self) -> Result<u64, FormatError> {
        self.pages.iter().try_fold(0u64, |total, (_, page)| {
            let bytes = format::to_page_bytes(page)?;
            total.checked_add(bytes.len() as u64).ok_or(FormatError::TooLarge)
        })
    }
}

// ---------------------------------------------------------------------------
// Deterministic in-memory store for pure tests and bench evidence
// ---------------------------------------------------------------------------

/// Deterministic in-memory page store. Keeps the exact canonical encoding of
/// every page, so tests and bench evidence can assert on the real upload set
/// (page counts and byte volumes) rather than incidental counters.
#[derive(Clone, Debug, Default)]
pub struct InMemoryPageStore {
    pages: BTreeMap<Sha256Digest, Vec<u8>>,
}

impl InMemoryPageStore {
    pub fn new() -> Self {
        Self::default()
    }
    /// The canonical bytes stored for `page_id`, if any.
    pub fn get_bytes(&self, page_id: &Sha256Digest) -> Option<&[u8]> {
        self.pages.get(page_id).map(|bytes| bytes.as_slice())
    }
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }
    pub fn extend(&mut self, other: Self) {
        self.pages.extend(other.pages);
    }
    /// Total canonical bytes stored, including pages superseded by later
    /// mutations (remote storage keeps every immutable page).
    pub fn total_bytes(&self) -> u64 {
        self.pages.values().map(|bytes| bytes.len() as u64).sum()
    }

    fn load_inner(&mut self, page_id: Sha256Digest) -> Result<Option<CatalogPage>, FormatError> {
        let Some(bytes) = self.pages.get(&page_id).cloned() else {
            return Ok(None);
        };
        let page = format::from_page_bytes(&bytes)?;
        let (hash, _) = encode_and_hash(&page)?;
        if hash != page_id {
            return Err(FormatError::NonCanonical);
        }
        Ok(Some(page))
    }

    fn store_inner(&mut self, page_id: Sha256Digest, page: &CatalogPage) -> Result<(), FormatError> {
        let (hash, bytes) = encode_and_hash(page)?;
        if hash != page_id {
            return Err(FormatError::NonCanonical);
        }
        self.pages.entry(page_id).or_insert(bytes);
        Ok(())
    }
}

impl PageSource for InMemoryPageStore {
    type Error = FormatError;
    fn load(
        &mut self,
        page_id: Sha256Digest,
    ) -> impl Future<Output = Result<Option<CatalogPage>, Self::Error>> {
        std::future::ready(self.load_inner(page_id))
    }
}

impl PageSink for InMemoryPageStore {
    type Error = FormatError;
    fn store(
        &mut self,
        page_id: Sha256Digest,
        page: &CatalogPage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        std::future::ready(self.store_inner(page_id, page))
    }
}

// ---------------------------------------------------------------------------
// Page chunking: median splits honouring both page bounds
// ---------------------------------------------------------------------------

fn first_key_of(page: &CatalogPage) -> Result<String, FormatError> {
    match page {
        CatalogPage::Leaf(leaf) => leaf
            .entries
            .first()
            .map(|entry| entry.key.clone())
            .ok_or(FormatError::InvalidShape),
        CatalogPage::Branch(branch) => branch
            .children
            .first()
            .map(|child| child.first_key.clone())
            .ok_or(FormatError::InvalidShape),
    }
}

/// Splits entries into as few pages as possible honouring both page bounds:
/// at most [`MAX_PAGE_FANOUT`] entries and at most [`MAX_PAGE_BYTES`] encoded.
/// Overflow splits at the median and recurses into both halves; a single entry
/// is always far below both bounds.
fn chunk_leaf(
    entries: Vec<LeafEntry>,
) -> Result<Vec<(Sha256Digest, CatalogPage)>, FormatError> {
    if entries.is_empty() {
        return Err(FormatError::InvalidShape);
    }
    let page = CatalogPage::leaf(entries);
    match encode_and_hash(&page) {
        Ok((hash, _)) => return Ok(vec![(hash, page)]),
        Err(FormatError::TooLarge) => {}
        Err(error) => return Err(error),
    }
    let CatalogPage::Leaf(leaf) = page else { unreachable!() };
    let mut entries = leaf.entries;
    if entries.len() < 2 {
        return Err(FormatError::TooLarge);
    }
    let upper = entries.split_off(entries.len() / 2);
    let mut out = chunk_leaf(entries)?;
    out.extend(chunk_leaf(upper)?);
    Ok(out)
}

fn chunk_branch(
    children: Vec<BranchChild>,
) -> Result<Vec<(Sha256Digest, CatalogPage)>, FormatError> {
    if children.is_empty() {
        return Err(FormatError::InvalidShape);
    }
    let page = CatalogPage::branch(children);
    match encode_and_hash(&page) {
        Ok((hash, _)) => return Ok(vec![(hash, page)]),
        Err(FormatError::TooLarge) => {}
        Err(error) => return Err(error),
    }
    let CatalogPage::Branch(branch) = page else { unreachable!() };
    let mut children = branch.children;
    if children.len() < 2 {
        return Err(FormatError::TooLarge);
    }
    let upper = children.split_off(children.len() / 2);
    let mut out = chunk_branch(children)?;
    out.extend(chunk_branch(upper)?);
    Ok(out)
}

/// The child index a branch routes `key` to. The last child covers everything
/// at or above its first key within the parent's range.
fn covering_child_index(children: &[BranchChild], key: &[u8]) -> Result<usize, FormatError> {
    if children.is_empty() {
        return Err(FormatError::InvalidShape);
    }
    let at = children.partition_point(|child| child.first_key.as_bytes() <= key);
    Ok(at.saturating_sub(1))
}

struct Chunk {
    first_key: Vec<u8>,
    page_id: Sha256Digest,
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// A read-only view of a catalog root.
pub struct CatalogReader<'s, S: PageSource> {
    source: &'s mut S,
    root: CatalogRoot,
    cache: BTreeMap<Sha256Digest, Arc<CatalogPage>>,
    loaded_pages: u64,
}

impl<'s, S: PageSource> CatalogReader<'s, S> {
    pub fn new(source: &'s mut S, root: CatalogRoot) -> Self {
        Self { source, root, cache: BTreeMap::new(), loaded_pages: 0 }
    }
    pub fn root(&self) -> CatalogRoot {
        self.root
    }
    /// Pages actually read from the source; the provider maps this to
    /// metadata request counts.
    pub fn loaded_pages(&self) -> u64 {
        self.loaded_pages
    }

    async fn get_page(
        &mut self,
        page_id: Sha256Digest,
    ) -> Result<Arc<CatalogPage>, CatalogError<S::Error>> {
        if let Some(page) = self.cache.get(&page_id) {
            return Ok(Arc::clone(page));
        }
        let page = self
            .source
            .load(page_id)
            .await
            .map_err(CatalogError::Storage)?
            .ok_or(CatalogError::Invariant("missing catalog page"))?;
        let (hash, _) = encode_and_hash(&page)?;
        if hash != page_id {
            return Err(CatalogError::Invariant("loaded page hash mismatch"));
        }
        self.loaded_pages += 1;
        let page = Arc::new(page);
        self.cache.insert(page_id, Arc::clone(&page));
        Ok(page)
    }

    /// Returns the encoded value stored under `key`, if any.
    pub async fn get_encoded(
        &mut self,
        key: &str,
    ) -> Result<Option<IndexValue>, CatalogError<S::Error>> {
        format::parse_index_key(key).map_err(CatalogError::Format)?;
        let mut page_id = self.root.digest();
        loop {
            match self.get_page(page_id).await?.as_ref() {
                CatalogPage::Leaf(leaf) => {
                    return Ok(leaf
                        .entries
                        .iter()
                        .find(|entry| entry.key == key)
                        .map(|entry| entry.value.clone()));
                }
                CatalogPage::Branch(branch) => {
                    let index =
                        covering_child_index(&branch.children, key.as_bytes())
                            .map_err(CatalogError::Format)?;
                    page_id = branch.children[index].page_id;
                }
            }
        }
    }

    /// Returns the item record for `item_id`, deleted or live.
    pub async fn get_item(
        &mut self,
        item_id: ItemId,
    ) -> Result<ItemRecord, CatalogError<S::Error>> {
        match self.get_encoded(&format::item_key(item_id)).await? {
            Some(IndexValue::Item(item)) => Ok(item),
            _ => Err(CatalogError::MissingItem),
        }
    }

    /// Returns the live children of `parent_id` as item records.
    pub async fn children(
        &mut self,
        parent_id: ItemId,
    ) -> Result<Vec<ItemRecord>, CatalogError<S::Error>> {
        let prefix = format::child_key_prefix(parent_id);
        let mut refs = Vec::new();
        {
            let mut collect = |key: String, value: IndexValue| -> Result<(), CatalogError<S::Error>> {
                let IndexValue::Ref { item_id } = value else {
                    return Err(CatalogError::Invariant("child index without reference"));
                };
                match format::parse_index_key(&key).map_err(CatalogError::Format)? {
                    format::IndexKey::Child { item_id: key_id, .. } if key_id == item_id => {
                        refs.push(item_id);
                        Ok(())
                    }
                    _ => Err(CatalogError::Invariant("child key/value mismatch")),
                }
            };
            self.scan_prefix(&prefix, &mut collect).await?;
        }
        let mut out = Vec::with_capacity(refs.len());
        for item_id in refs {
            out.push(self.get_item(item_id).await?);
        }
        Ok(out)
    }

    /// Scans every entry whose key starts with `prefix`, in strictly ascending
    /// key order.
    pub async fn scan_prefix<F>(
        &mut self,
        prefix: &str,
        f: &mut F,
    ) -> Result<(), CatalogError<S::Error>>
    where
        F: FnMut(String, IndexValue) -> Result<(), CatalogError<S::Error>>,
    {
        let prefix = prefix.as_bytes();
        let mut stack = vec![self.root.digest()];
        while let Some(page_id) = stack.pop() {
            match self.get_page(page_id).await?.as_ref() {
                CatalogPage::Leaf(leaf) => {
                    for entry in &leaf.entries {
                        if entry.key.as_bytes().starts_with(prefix) {
                            f(entry.key.clone(), entry.value.clone())?;
                        }
                    }
                }
                CatalogPage::Branch(branch) => {
                    // Depth-first in ascending key order: push children in
                    // reverse so the stack pops the smallest first.
                    for (index, child) in branch.children.iter().enumerate().rev() {
                        if subtree_may_contain(&branch.children, index, prefix) {
                            stack.push(child.page_id);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// True when child `index`'s subtree may hold keys starting with `prefix`.
///
/// Every key in the subtree lies in `[first_key, next_first_key)`. The subtree
/// can hold a prefix key iff its first key is below the prefix range's upper
/// bound and its upper bound is above the prefix itself.
fn subtree_may_contain(children: &[BranchChild], index: usize, prefix: &[u8]) -> bool {
    let lower = children[index].first_key.as_bytes();
    let upper = children.get(index + 1).map(|child| child.first_key.as_bytes());
    let lower_ok = lower.starts_with(prefix) || lower < prefix;
    let upper_ok = match upper {
        None => true,
        Some(upper) => upper > prefix,
    };
    lower_ok && upper_ok
}

// ---------------------------------------------------------------------------
// Mutation
// ---------------------------------------------------------------------------

/// One copy-on-write tree mutation. Applies canonical index entries or the
/// higher-level item operations, then commits the dirty pages; unchanged
/// subtrees are shared by hash and never rewritten.
pub struct CatalogWriter<'s, S: PageSource> {
    source: &'s mut S,
    root: CatalogRoot,
    cache: BTreeMap<Sha256Digest, Arc<CatalogPage>>,
    dirty: BTreeMap<Sha256Digest, Arc<CatalogPage>>,
    reused_pages: u64,
    loaded_pages: u64,
}

impl<'s, S: PageSource> CatalogWriter<'s, S> {
    pub fn new(source: &'s mut S, root: CatalogRoot) -> Self {
        Self {
            source,
            root,
            cache: BTreeMap::new(),
            dirty: BTreeMap::new(),
            reused_pages: 0,
            loaded_pages: 0,
        }
    }

    pub fn root(&self) -> CatalogRoot {
        self.root
    }
    /// Pages whose hash was reused from the previous tree instead of rewritten.
    pub fn reused_pages(&self) -> u64 {
        self.reused_pages
    }
    /// Pages read from the source during this mutation.
    pub fn loaded_pages(&self) -> u64 {
        self.loaded_pages
    }
    /// Distinct pages written by this mutation so far.
    pub fn dirty_pages(&self) -> usize {
        self.dirty.len()
    }

    async fn get_page(
        &mut self,
        page_id: Sha256Digest,
    ) -> Result<Arc<CatalogPage>, CatalogError<S::Error>> {
        if let Some(page) = self.dirty.get(&page_id) {
            return Ok(Arc::clone(page));
        }
        if let Some(page) = self.cache.get(&page_id) {
            return Ok(Arc::clone(page));
        }
        let page = self
            .source
            .load(page_id)
            .await
            .map_err(CatalogError::Storage)?
            .ok_or(CatalogError::Invariant("missing catalog page"))?;
        let (hash, _) = encode_and_hash(&page)?;
        if hash != page_id {
            return Err(CatalogError::Invariant("loaded page hash mismatch"));
        }
        self.loaded_pages += 1;
        let page = Arc::new(page);
        self.cache.insert(page_id, Arc::clone(&page));
        Ok(page)
    }

    /// Looks up `key`, preferring the mutation's own dirty state.
    pub async fn get_encoded(
        &mut self,
        key: &str,
    ) -> Result<Option<IndexValue>, CatalogError<S::Error>> {
        format::parse_index_key(key).map_err(CatalogError::Format)?;
        let mut page_id = self.root.digest();
        loop {
            match self.get_page(page_id).await?.as_ref() {
                CatalogPage::Leaf(leaf) => {
                    return Ok(leaf
                        .entries
                        .iter()
                        .find(|entry| entry.key == key)
                        .map(|entry| entry.value.clone()));
                }
                CatalogPage::Branch(branch) => {
                    let index =
                        covering_child_index(&branch.children, key.as_bytes())
                            .map_err(CatalogError::Format)?;
                    page_id = branch.children[index].page_id;
                }
            }
        }
    }

    pub async fn get_item(
        &mut self,
        item_id: ItemId,
    ) -> Result<ItemRecord, CatalogError<S::Error>> {
        match self.get_encoded(&format::item_key(item_id)).await? {
            Some(IndexValue::Item(item)) => Ok(item),
            _ => Err(CatalogError::MissingItem),
        }
    }

    fn write_page(&mut self, hash: Sha256Digest, page: CatalogPage) {
        self.dirty.entry(hash).or_insert_with(|| Arc::new(page));
    }

    fn emit_level(
        &mut self,
        pages: Vec<(Sha256Digest, CatalogPage)>,
        old_id: Sha256Digest,
    ) -> Result<Vec<Chunk>, CatalogError<S::Error>> {
        if pages.len() == 1 {
            let (hash, page) = &pages[0];
            if *hash == old_id {
                self.reused_pages += 1;
                let first_key = first_key_of(page).map_err(CatalogError::Format)?.into_bytes();
                return Ok(vec![Chunk { first_key, page_id: *hash }]);
            }
        }
        let mut out = Vec::with_capacity(pages.len());
        for (hash, page) in pages {
            let first_key = first_key_of(&page).map_err(CatalogError::Format)?.into_bytes();
            self.write_page(hash, page);
            out.push(Chunk { first_key, page_id: hash });
        }
        Ok(out)
    }

    fn wrap_root(&mut self, mut level: Vec<Chunk>) -> Result<CatalogRoot, CatalogError<S::Error>> {
        if level.is_empty() {
            return Err(CatalogError::Invariant("catalog root vanished"));
        }
        while level.len() > 1 {
            let children: Vec<BranchChild> = level
                .iter()
                .map(|chunk| {
                    Ok(BranchChild {
                        first_key: String::from_utf8(chunk.first_key.clone())
                            .map_err(|_| CatalogError::Invariant("non-UTF-8 first key"))?,
                        page_id: chunk.page_id,
                    })
                })
                .collect::<Result<Vec<_>, CatalogError<S::Error>>>()?;
            let pages = chunk_branch(children).map_err(CatalogError::Format)?;
            let mut next = Vec::with_capacity(pages.len());
            for (hash, page) in pages {
                let first_key = first_key_of(&page).map_err(CatalogError::Format)?.into_bytes();
                self.write_page(hash, page);
                next.push(Chunk { first_key, page_id: hash });
            }
            level = next;
        }
        Ok(CatalogRoot(level[0].page_id))
    }

    /// Writes one canonical index entry; `None` removes the key. Returns
    /// whether the tree changed: setting a key to its current value is a
    /// no-op that leaves the root hash untouched.
    pub async fn apply_entry(
        &mut self,
        key: String,
        value: Option<IndexValue>,
    ) -> Result<bool, CatalogError<S::Error>> {
        match format::parse_index_key(&key).map_err(CatalogError::Format)? {
            format::IndexKey::Item { item_id } => match &value {
                Some(IndexValue::Item(item)) => {
                    if item.item_id != item_id {
                        return Err(CatalogError::Invariant("item key/value mismatch"));
                    }
                    format::validate_item_record(item).map_err(CatalogError::Format)?;
                }
                Some(_) => return Err(CatalogError::Invariant("index key/value shape mismatch")),
                None => {}
            },
            format::IndexKey::Child { item_id, .. } => match &value {
                Some(IndexValue::Ref { item_id: ref_id }) if *ref_id == item_id => {}
                Some(_) => return Err(CatalogError::Invariant("child key/value shape mismatch")),
                None => {}
            },
            format::IndexKey::Name { .. } => match &value {
                Some(IndexValue::Ref { .. }) | None => {}
                Some(_) => return Err(CatalogError::Invariant("index key/value shape mismatch")),
            },
        }

        // Phase 1: descend the root-to-leaf path, loading each page once.
        let mut path: Vec<(Sha256Digest, Arc<CatalogPage>)> = Vec::new();
        let mut page_id = self.root.digest();
        loop {
            let page = self.get_page(page_id).await?;
            match page.as_ref() {
                CatalogPage::Leaf(_) => {
                    path.push((page_id, page));
                    break;
                }
                CatalogPage::Branch(branch) => {
                    let index = covering_child_index(&branch.children, key.as_bytes())
                        .map_err(CatalogError::Format)?;
                    let next = branch.children[index].page_id;
                    path.push((page_id, page));
                    page_id = next;
                }
            }
        }

        // Phase 2: rewrite the path bottom-up, sharing unchanged subtrees by
        // hash and splitting each rewritten page at its median when needed.
        let mut produced: Vec<Chunk> = Vec::new();
        for (old_id, page) in path.into_iter().rev() {
            match page.as_ref() {
                CatalogPage::Leaf(leaf) => {
                    let mut entries = leaf.entries.clone();
                    let at = entries.partition_point(|entry| entry.key < key);
                    let present = entries.get(at).is_some_and(|entry| entry.key == key);
                    let changed = match (&value, present) {
                        (Some(new), true) => {
                            if entries[at].value == *new {
                                false
                            } else {
                                entries[at].value = new.clone();
                                true
                            }
                        }
                        (Some(new), false) => {
                            entries.insert(
                                at,
                                LeafEntry { key: key.clone(), value: new.clone() },
                            );
                            true
                        }
                        (None, true) => {
                            entries.remove(at);
                            true
                        }
                        (None, false) => false,
                    };
                    if !changed {
                        self.reused_pages += 1;
                        return Ok(false);
                    }
                    if entries.is_empty() {
                        // v1 never removes the root item entry, so an emptied
                        // leaf is dropped instead of rebalanced into siblings.
                        produced = Vec::new();
                        continue;
                    }
                    let pages = chunk_leaf(entries).map_err(CatalogError::Format)?;
                    produced = self.emit_level(pages, old_id)?;
                }
                CatalogPage::Branch(branch) => {
                    let mut children = branch.children.clone();
                    let index = covering_child_index(&children, key.as_bytes())
                        .map_err(CatalogError::Format)?;
                    children.splice(
                        index..=index,
                        produced.iter().map(|chunk| {
                            Ok(BranchChild {
                                first_key: String::from_utf8(chunk.first_key.clone())
                                    .map_err(|_| {
                                        CatalogError::Invariant("non-UTF-8 first key")
                                    })?,
                                page_id: chunk.page_id,
                            })
                        })
                        .collect::<Result<Vec<_>, CatalogError<S::Error>>>()?,
                    );
                    if children.is_empty() {
                        produced = Vec::new();
                        continue;
                    }
                    let pages = chunk_branch(children).map_err(CatalogError::Format)?;
                    produced = self.emit_level(pages, old_id)?;
                }
            }
        }
        self.root = self.wrap_root(produced)?;
        Ok(true)
    }

    /// Inserts or updates a live item record, maintaining its `c`/`n` indexes.
    ///
    /// Enforces live-directory parents, acyclic parent links, and portable
    /// sibling-name uniqueness through the collision-key slot; a name slot
    /// occupied by another live item is never overwritten. Exactly one live
    /// root is enforced by [`verify`] before publication.
    pub async fn insert_item(&mut self, item: &ItemRecord) -> Result<(), CatalogError<S::Error>> {
        format::validate_item_record(item).map_err(CatalogError::Format)?;
        if item.deleted {
            return Err(CatalogError::Invariant("insert_item requires a live record"));
        }
        let old = match self.get_encoded(&format::item_key(item.item_id)).await? {
            Some(IndexValue::Item(old)) => Some(old),
            Some(_) => return Err(CatalogError::Invariant("item index without record")),
            None => None,
        };
        if let Some(parent_id) = item.parent_id {
            if parent_id == item.item_id {
                return Err(CatalogError::Cycle);
            }
            names::validate_name(&item.name)?;
            let parent = self.get_item(parent_id).await?;
            if parent.deleted || parent.kind != ItemKind::Directory {
                return Err(CatalogError::NotADirectory);
            }
            if old.as_ref().is_some_and(|old| old.parent_id != item.parent_id) {
                self.check_acyclic_move(item.item_id, parent_id).await?;
            }
        } else if !(item.name.is_empty() && item.kind == ItemKind::Directory) {
            return Err(CatalogError::Invariant("live non-root item needs a parent"));
        }

        let name_slot = item.parent_id.map(|parent_id| {
            (
                format::name_key(parent_id, &names::collision_key(&item.name)),
                format::child_key(parent_id, &item.name, item.item_id),
            )
        });
        if let Some((name_key, _)) = &name_slot {
            if let Some(IndexValue::Ref { item_id: occupant }) = self.get_encoded(name_key).await? {
                if occupant != item.item_id {
                    return Err(CatalogError::DuplicateName);
                }
            }
        }

        // A tombstone has no live indexes; a live record drops its old indexes
        // when the location or name changed.
        if let Some(old) = &old {
            if !old.deleted {
                if let Some(parent_id) = old.parent_id {
                    let location_changed =
                        old.parent_id != item.parent_id || old.name != item.name;
                    if location_changed {
                        self.apply_entry(
                            format::child_key(parent_id, &old.name, old.item_id),
                            None,
                        )
                        .await?;
                        self.apply_entry(
                            format::name_key(
                                parent_id,
                                &names::collision_key(&old.name),
                            ),
                            None,
                        )
                        .await?;
                    }
                }
            }
        }

        if let Some((name_key, child_key)) = name_slot {
            self.apply_entry(child_key, Some(IndexValue::Ref { item_id: item.item_id }))
                .await?;
            self.apply_entry(name_key, Some(IndexValue::Ref { item_id: item.item_id }))
                .await?;
        }
        self.apply_entry(
            format::item_key(item.item_id),
            Some(IndexValue::Item(item.clone())),
        )
        .await?;
        Ok(())
    }

    /// Tombstones a live item and removes exactly its live `c`/`n` indexes.
    ///
    /// The deletion record keeps the item's identity, location and kind and
    /// stays in the tree as an `i/` entry (v1 has no garbage collection).
    /// Descendants are untouched: directory deletion removes only the
    /// descendants the caller tombstones explicitly.
    pub async fn tombstone_item(
        &mut self,
        deletion: &ItemRecord,
    ) -> Result<(), CatalogError<S::Error>> {
        format::validate_item_record(deletion).map_err(CatalogError::Format)?;
        if !deletion.deleted {
            return Err(CatalogError::Invariant("tombstone_item requires a deleted record"));
        }
        let old = self.get_item(deletion.item_id).await?;
        if old.deleted {
            return Err(CatalogError::Invariant("item is already a tombstone"));
        }
        if old.parent_id != deletion.parent_id
            || old.name != deletion.name
            || old.kind != deletion.kind
        {
            return Err(CatalogError::Invariant("deletion record changes identity/location"));
        }
        if let Some(parent_id) = old.parent_id {
            self.apply_entry(format::child_key(parent_id, &old.name, old.item_id), None)
                .await?;
            self.apply_entry(
                format::name_key(parent_id, &names::collision_key(&old.name)),
                None,
            )
            .await?;
        }
        self.apply_entry(
            format::item_key(deletion.item_id),
            Some(IndexValue::Item(deletion.clone())),
        )
        .await?;
        Ok(())
    }

    async fn check_acyclic_move(
        &mut self,
        item_id: ItemId,
        mut parent_id: ItemId,
    ) -> Result<(), CatalogError<S::Error>> {
        // Each item has exactly one parent, so this walk terminates at the
        // root or proves a cycle; the bound also protects against a corrupt
        // remote tree.
        for _ in 0..1_000_000u64 {
            if parent_id == item_id {
                return Err(CatalogError::Cycle);
            }
            let parent = self.get_item(parent_id).await?;
            match parent.parent_id {
                None => return Ok(()),
                Some(next) => parent_id = next,
            }
        }
        Err(CatalogError::Cycle)
    }

    /// Finishes the mutation without persisting anything. The returned pages
    /// are exactly the pages reachable from the new root that the source does
    /// not already hold; upload them, then publish the new HEAD.
    pub fn commit(self) -> Result<PublishSet, CatalogError<S::Error>> {
        let mut pages = Vec::new();
        let mut seen = BTreeSet::new();
        let mut stack = vec![self.root.digest()];
        while let Some(page_id) = stack.pop() {
            if !seen.insert(page_id) {
                continue;
            }
            let Some(page) = self.dirty.get(&page_id) else {
                // Pristine pages are already stored; they stop the walk.
                continue;
            };
            if let CatalogPage::Branch(branch) = page.as_ref() {
                for child in &branch.children {
                    stack.push(child.page_id);
                }
            }
            pages.push((page_id, (**page).clone()));
        }
        pages.sort_by_key(|(hash, _)| *hash);
        Ok(PublishSet {
            root: self.root,
            pages,
            reused_pages: self.reused_pages,
            loaded_pages: self.loaded_pages,
        })
    }

    /// Finishes the mutation and persists every dirty page through `sink`.
    pub async fn commit_to(
        self,
        sink: &mut impl PageSink<Error = S::Error>,
    ) -> Result<PublishSet, CatalogError<S::Error>> {
        let set = self.commit()?;
        for (hash, page) in &set.pages {
            sink.store(*hash, page).await.map_err(CatalogError::Storage)?;
        }
        Ok(set)
    }
}

// ---------------------------------------------------------------------------
// Initial catalog and whole-tree verification
// ---------------------------------------------------------------------------

/// Builds the initial empty catalog: one live directory root with a null
/// parent and an empty name, and no child or name index entries.
pub fn initialize(
    root_item_id: ItemId,
    initialization_operation: OperationId,
) -> Result<(CatalogRoot, PublishSet), FormatError> {
    let root_item = ItemRecord {
        item_id: root_item_id,
        parent_id: None,
        name: String::new(),
        kind: ItemKind::Directory,
        item_revision: initialization_operation,
        content_version_id: None,
        deleted: false,
        content_operation: initialization_operation,
        location_operation: initialization_operation,
        deletion_operation: None,
    };
    let page = CatalogPage::leaf(vec![LeafEntry {
        key: format::item_key(root_item_id),
        value: IndexValue::Item(root_item),
    }]);
    let (hash, _) = encode_and_hash(&page)?;
    Ok((
        CatalogRoot(hash),
        PublishSet {
            root: CatalogRoot(hash),
            pages: vec![(hash, page)],
            reused_pages: 0,
            loaded_pages: 0,
        },
    ))
}

/// Whole-tree consistency report produced by [`verify`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VerifyStats {
    pub item_entries: u64,
    pub child_indexes: u64,
    pub name_indexes: u64,
    pub live_items: u64,
    pub tombstones: u64,
    pub pages: u64,
    /// Total canonical bytes of every page in the live tree (the manifest).
    pub bytes: u64,
    pub max_depth: u64,
}

/// Verifies the whole tree before publication: page hashes and global key
/// order, one live root, live-directory parents, acyclic parent links, and
/// that every live item's `c`/`n` indexes exist and name exactly it.
pub async fn verify<S: PageSource>(
    source: &mut S,
    root: CatalogRoot,
) -> Result<VerifyStats, CatalogError<S::Error>> {
    let mut cache: BTreeMap<Sha256Digest, Arc<CatalogPage>> = BTreeMap::new();
    let mut stats = VerifyStats::default();
    let mut items: BTreeMap<ItemId, ItemRecord> = BTreeMap::new();
    let mut child_indexes: BTreeMap<(ItemId, String), ItemId> = BTreeMap::new();
    let mut name_indexes: BTreeMap<(ItemId, Vec<u8>), ItemId> = BTreeMap::new();
    let mut last_key: Option<String> = None;

    // Depth-first in ascending key order so the global order check below is
    // exact. (page_id, depth)
    let mut stack = vec![(root.digest(), 0u64)];
    while let Some((page_id, depth)) = stack.pop() {
        stats.max_depth = stats.max_depth.max(depth);
        let page = if let Some(page) = cache.get(&page_id) {
            Arc::clone(page)
        } else {
            let page = source
                .load(page_id)
                .await
                .map_err(CatalogError::Storage)?
                .ok_or(CatalogError::Invariant("missing catalog page"))?;
            let (hash, bytes) = encode_and_hash(&page)?;
            if hash != page_id {
                return Err(CatalogError::Invariant("loaded page hash mismatch"));
            }
            stats.bytes += bytes.len() as u64;
            let page = Arc::new(page);
            cache.insert(page_id, Arc::clone(&page));
            page
        };
        stats.pages += 1;
        match page.as_ref() {
            CatalogPage::Leaf(leaf) => {
                for entry in &leaf.entries {
                    if last_key.as_ref().is_some_and(|last| *last >= entry.key) {
                        return Err(CatalogError::Invariant("catalog keys out of order"));
                    }
                    last_key = Some(entry.key.clone());
                    match (
                        format::parse_index_key(&entry.key).map_err(CatalogError::Format)?,
                        &entry.value,
                    ) {
                        (format::IndexKey::Item { item_id }, IndexValue::Item(item)) => {
                            if item.item_id != item_id {
                                return Err(CatalogError::Invariant("item key/value mismatch"));
                            }
                            format::validate_item_record(item).map_err(CatalogError::Format)?;
                            if item.deleted {
                                stats.tombstones += 1;
                            } else {
                                stats.live_items += 1;
                            }
                            items.insert(item_id, item.clone());
                            stats.item_entries += 1;
                        }
                        (
                            format::IndexKey::Child { parent_id, name, item_id },
                            IndexValue::Ref { item_id: ref_id },
                        ) => {
                            if *ref_id != item_id {
                                return Err(CatalogError::Invariant("child key/value mismatch"));
                            }
                            child_indexes.insert((parent_id, name), item_id);
                            stats.child_indexes += 1;
                        }
                        (
                            format::IndexKey::Name { parent_id, collision_key },
                            IndexValue::Ref { item_id },
                        ) => {
                            name_indexes.insert((parent_id, collision_key), *item_id);
                            stats.name_indexes += 1;
                        }
                        _ => {
                            return Err(CatalogError::Invariant("index key/value shape mismatch"));
                        }
                    }
                }
            }
            CatalogPage::Branch(branch) => {
                if branch.children.is_empty() {
                    return Err(CatalogError::Invariant("branch page without children"));
                }
                for child in branch.children.iter().rev() {
                    stack.push((child.page_id, depth + 1));
                }
            }
        }
    }

    // Exactly one live root: a directory with a null parent and empty name.
    let live_roots: Vec<&ItemRecord> = items
        .values()
        .filter(|item| !item.deleted && item.parent_id.is_none())
        .collect();
    if live_roots.len() != 1 {
        return Err(CatalogError::InvalidRoot);
    }
    let root_item = live_roots[0];
    if root_item.kind != ItemKind::Directory || !root_item.name.is_empty() {
        return Err(CatalogError::InvalidRoot);
    }

    // Acyclicity with memoized walks: each item's ancestor chain reaches the
    // root or the tree is corrupt.
    let mut settled: BTreeSet<ItemId> = BTreeSet::new();
    for item_id in items.keys().copied().collect::<Vec<_>>() {
        if settled.contains(&item_id) {
            continue;
        }
        let mut chain = Vec::new();
        let mut cursor = item_id;
        loop {
            if settled.contains(&cursor) {
                break;
            }
            if chain.contains(&cursor) {
                return Err(CatalogError::Cycle);
            }
            chain.push(cursor);
            match items.get(&cursor).and_then(|item| item.parent_id) {
                None => break,
                Some(next) => cursor = next,
            }
        }
        for id in chain {
            settled.insert(id);
        }
    }

    for (item_id, item) in &items {
        if item.deleted {
            if child_indexes.values().any(|owner| owner == item_id)
                || name_indexes.values().any(|owner| owner == item_id)
            {
                return Err(CatalogError::Invariant("tombstone keeps live indexes"));
            }
            continue;
        }
        if let Some(parent_id) = item.parent_id {
            let parent =
                items.get(&parent_id).ok_or(CatalogError::Invariant("missing parent"))?;
            if parent.deleted || parent.kind != ItemKind::Directory {
                return Err(CatalogError::Invariant(
                    "live item without live directory parent",
                ));
            }
            match name_indexes.get(&(parent_id, names::collision_key(&item.name))) {
                Some(owner) if owner == item_id => {}
                _ => return Err(CatalogError::Invariant("missing or foreign name index")),
            }
            match child_indexes.get(&(parent_id, item.name.clone())) {
                Some(owner) if owner == item_id => {}
                _ => return Err(CatalogError::Invariant("missing or foreign child index")),
            }
        }
    }
    for ((parent_id, _), owner) in &child_indexes {
        match items.get(owner) {
            Some(item) if !item.deleted && item.parent_id == Some(*parent_id) => {}
            _ => return Err(CatalogError::Invariant("child index points at a foreign item")),
        }
    }
    for ((parent_id, collision_key), owner) in &name_indexes {
        match items.get(owner) {
            Some(item)
                if !item.deleted
                    && item.parent_id == Some(*parent_id)
                    && names::collision_key(&item.name) == *collision_key =>
            {
            }
            _ => return Err(CatalogError::Invariant("name index points at a foreign item")),
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::VersionId;

    /// Minimal executor for the immediately-ready in-memory store futures.
    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        loop {
            match future.as_mut().poll(&mut cx) {
                std::task::Poll::Ready(value) => return value,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    /// Commits the writer (which borrows the store) and then stores its pages.
    /// The commit consumes the writer before the store is borrowed again.
    macro_rules! commit {
        ($writer:ident, $store:ident) => {{
            let set = $writer.commit().unwrap();
            for (hash, page) in &set.pages {
                block_on($store.store(*hash, page)).unwrap();
            }
            set
        }};
    }

    fn dir(parent: Option<ItemId>, name: &str) -> ItemRecord {
        let op = OperationId::new();
        ItemRecord {
            item_id: ItemId::new(),
            parent_id: parent,
            name: name.to_owned(),
            kind: ItemKind::Directory,
            item_revision: op,
            content_version_id: None,
            deleted: false,
            content_operation: op,
            location_operation: op,
            deletion_operation: None,
        }
    }

    fn file(parent: ItemId, name: &str) -> ItemRecord {
        let op = OperationId::new();
        ItemRecord {
            item_id: ItemId::new(),
            parent_id: Some(parent),
            name: name.to_owned(),
            kind: ItemKind::File,
            item_revision: op,
            content_version_id: Some(VersionId::new()),
            deleted: false,
            content_operation: op,
            location_operation: op,
            deletion_operation: None,
        }
    }

    fn store_with_root() -> (InMemoryPageStore, CatalogRoot, ItemRecord) {
        let mut store = InMemoryPageStore::new();
        let root_id = ItemId::new();
        let op = OperationId::new();
        let (root, initial) = initialize(root_id, op).unwrap();
        block_on(initial_sink_pages(&mut store, &initial));
        let root_item = ItemRecord {
            item_id: root_id,
            parent_id: None,
            name: String::new(),
            kind: ItemKind::Directory,
            item_revision: op,
            content_version_id: None,
            deleted: false,
            content_operation: op,
            location_operation: op,
            deletion_operation: None,
        };
        (store, root, root_item)
    }

    async fn initial_sink_pages(store: &mut InMemoryPageStore, set: &PublishSet) {
        for (hash, page) in &set.pages {
            store.store(*hash, page).await.unwrap();
        }
    }

    #[test]
    fn initial_catalog_is_one_live_root_leaf() {
        let (mut store, root, root_item) = store_with_root();
        let stats = block_on(verify(&mut store, root)).unwrap();
        assert_eq!(stats.item_entries, 1);
        assert_eq!(stats.live_items, 1);
        assert_eq!(stats.child_indexes, 0);
        assert_eq!(stats.name_indexes, 0);
        assert_eq!(stats.pages, 1);
        let item = block_on(CatalogReader::new(&mut store, root).get_item(root_item.item_id)).unwrap();
        assert_eq!(item.parent_id, None);
        assert!(item.name.is_empty());
    }

    #[test]
    fn insert_read_children_and_items() {
        let (mut store, root, root_item) = store_with_root();
        let child = dir(Some(root_item.item_id), "Sub");
        let grandchild = file(child.item_id, "note.txt");
        let root = {
            let mut writer = CatalogWriter::new(&mut store, root);
            block_on(writer.insert_item(&child)).unwrap();
            block_on(writer.insert_item(&grandchild)).unwrap();
            let set = commit!(writer, store);
            assert_ne!(set.root, root);
            set.root
        };
        let root = {
            let mut reader = CatalogReader::new(&mut store, root);
            let found = block_on(reader.get_item(grandchild.item_id)).unwrap();
            assert_eq!(found.name, "note.txt");
            let children = block_on(reader.children(root_item.item_id)).unwrap();
            assert_eq!(children.len(), 1);
            assert_eq!(children[0].item_id, child.item_id);
            reader.root()
        };
        let stats = block_on(verify(&mut store, root)).unwrap();
        assert_eq!(stats.live_items, 3);
        assert_eq!(stats.child_indexes, 2);
        assert_eq!(stats.name_indexes, 2);
    }

    #[test]
    fn one_save_rewrites_only_the_affected_path() {
        let (mut store, root, root_item) = store_with_root();
        let mut root = root;
        for batch in 0..4 {
            let mut writer = CatalogWriter::new(&mut store, root);
            for index in 0..100u32 {
                let item = dir(Some(root_item.item_id), &format!("d{batch:02}{index:03}"));
                block_on(writer.insert_item(&item)).unwrap();
            }
            let set = commit!(writer, store);
            root = set.root;
        }
        let stats = block_on(verify(&mut store, root)).unwrap();
        assert_eq!(stats.live_items, 401);
        assert!(stats.pages >= 5, "tree must be paginated: {} pages", stats.pages);

        let mut writer = CatalogWriter::new(&mut store, root);
        let inserted = dir(Some(root_item.item_id), "d9999");
        block_on(writer.insert_item(&inserted)).unwrap();
        let set = writer.commit().unwrap();
        // One insert touches only the root-to-leaf paths of its three indexes
        // plus at most one split per rewritten page.
        assert!(set.pages.len() <= 12, "one save wrote {} pages", set.pages.len());
        for (hash, page) in &set.pages { block_on(store.store(*hash, page)).unwrap(); }
        let mut old_reader = CatalogReader::new(&mut store, root);
        assert!(matches!(block_on(old_reader.get_item(inserted.item_id)), Err(CatalogError::MissingItem)));
        let mut new_reader = CatalogReader::new(&mut store, set.root);
        assert_eq!(block_on(new_reader.get_item(inserted.item_id)).unwrap(), inserted);
    }

    #[test]
    fn equal_entry_is_a_no_op() {
        let (mut store, root, root_item) = store_with_root();
        let item = dir(Some(root_item.item_id), "Same");
        let mut writer = CatalogWriter::new(&mut store, root);
        block_on(writer.insert_item(&item)).unwrap();
        let first = commit!(writer, store);
        let mut writer = CatalogWriter::new(&mut store, first.root);
        block_on(writer.insert_item(&item)).unwrap();
        let second = writer.commit().unwrap();
        assert!(second.pages.is_empty());
        assert_eq!(second.root, first.root);
        assert!(second.reused_pages >= 1);
    }

    #[test]
    fn duplicate_portable_names_are_rejected() {
        let (mut store, root, root_item) = store_with_root();
        let mut writer = CatalogWriter::new(&mut store, root);
        block_on(writer.insert_item(&dir(Some(root_item.item_id), "Stra\u{df}e"))).unwrap();
        // "STRASSE" collides after full case folding.
        assert!(matches!(
            block_on(writer.insert_item(&dir(Some(root_item.item_id), "STRASSE"))),
            Err(CatalogError::DuplicateName)
        ));
        block_on(writer.insert_item(&dir(Some(root_item.item_id), "R\u{e9}sum\u{e9}"))).unwrap();
        // A decomposed spelling collides with the composed one.
        assert!(matches!(
            block_on(writer.insert_item(&dir(
                Some(root_item.item_id),
                "Re\u{301}sume\u{301}"
            ))),
            Err(CatalogError::DuplicateName)
        ));
        // Distinct names remain distinct.
        block_on(writer.insert_item(&dir(Some(root_item.item_id), "STRASSEN"))).unwrap();
    }

    #[test]
    fn tombstone_removes_only_live_indexes() {
        let (mut store, root, root_item) = store_with_root();
        let item = dir(Some(root_item.item_id), "Gone");
        let sibling = dir(Some(root_item.item_id), "Kept");
        let mut root = root;
        {
            let mut writer = CatalogWriter::new(&mut store, root);
            block_on(writer.insert_item(&item)).unwrap();
            block_on(writer.insert_item(&sibling)).unwrap();
            root = commit!(writer, store).root;
        }
        let mut deletion = item.clone();
        deletion.deleted = true;
        deletion.deletion_operation = Some(OperationId::new());
        deletion.item_revision = deletion.deletion_operation.unwrap();
        {
            let mut writer = CatalogWriter::new(&mut store, root);
            block_on(writer.tombstone_item(&deletion)).unwrap();
            root = commit!(writer, store).root;
        }

        let mut reader = CatalogReader::new(&mut store, root);
        // The tombstone stays as an item entry.
        let tomb = block_on(reader.get_item(item.item_id)).unwrap();
        assert!(tomb.deleted);
        // Its live indexes are gone; the sibling's remain.
        assert!(block_on(reader.get_encoded(&format::child_key(
            root_item.item_id,
            &item.name,
            item.item_id
        )))
        .unwrap()
        .is_none());
        assert!(block_on(reader.get_encoded(&format::name_key(
            root_item.item_id,
            &names::collision_key(&item.name)
        )))
        .unwrap()
        .is_none());
        assert!(block_on(reader.get_encoded(&format::child_key(
            root_item.item_id,
            &sibling.name,
            sibling.item_id
        )))
        .unwrap()
        .is_some());
        drop(reader);
        let stats = block_on(verify(&mut store, root)).unwrap();
        assert_eq!(stats.tombstones, 1);
        assert_eq!(stats.live_items, 2);
    }

    #[test]
    fn moves_and_case_only_renames_update_indexes() {
        let (mut store, root, root_item) = store_with_root();
        let parent_a = dir(Some(root_item.item_id), "A");
        let parent_b = dir(Some(root_item.item_id), "B");
        let item = dir(Some(parent_a.item_id), "Name");
        let mut root = root;
        {
            let mut writer = CatalogWriter::new(&mut store, root);
            block_on(writer.insert_item(&parent_a)).unwrap();
            block_on(writer.insert_item(&parent_b)).unwrap();
            block_on(writer.insert_item(&item)).unwrap();
            root = commit!(writer, store).root;
        }
        // Move to B under a case-only rename of the name slot.
        let mut moved = item.clone();
        moved.parent_id = Some(parent_b.item_id);
        moved.name = "nAME".to_owned();
        moved.location_operation = OperationId::new();
        moved.item_revision = moved.location_operation;
        {
            let mut writer = CatalogWriter::new(&mut store, root);
            block_on(writer.insert_item(&moved)).unwrap();
            root = commit!(writer, store).root;
        }
        let mut reader = CatalogReader::new(&mut store, root);
        assert!(block_on(reader.get_encoded(&format::child_key(
            parent_a.item_id,
            &item.name,
            item.item_id
        )))
        .unwrap()
        .is_none());
        assert!(block_on(reader.get_encoded(&format::child_key(
            parent_b.item_id,
            "nAME",
            item.item_id
        )))
        .unwrap()
        .is_some());
        // The name slot follows the item: same collision key, new parent.
        assert!(block_on(reader.get_encoded(&format::name_key(
            parent_b.item_id,
            &names::collision_key("nAME")
        )))
        .unwrap()
        .is_some());
        drop(reader);
        let stats = block_on(verify(&mut store, root)).unwrap();
        assert_eq!(stats.child_indexes, 3);
        assert_eq!(stats.name_indexes, 3);
    }

    #[test]
    fn directory_cycles_are_rejected() {
        let (mut store, root, root_item) = store_with_root();
        let outer = dir(Some(root_item.item_id), "Outer");
        let inner = dir(Some(outer.item_id), "Inner");
        let mut root = root;
        {
            let mut writer = CatalogWriter::new(&mut store, root);
            block_on(writer.insert_item(&outer)).unwrap();
            block_on(writer.insert_item(&inner)).unwrap();
            root = commit!(writer, store).root;
        }
        let mut looped = outer.clone();
        looped.parent_id = Some(inner.item_id);
        looped.location_operation = OperationId::new();
        looped.item_revision = looped.location_operation;
        let mut writer = CatalogWriter::new(&mut store, root);
        assert!(matches!(
            block_on(writer.insert_item(&looped)),
            Err(CatalogError::Cycle)
        ));
    }

    #[test]
    fn non_directory_parents_are_rejected() {
        let (mut store, root, root_item) = store_with_root();
        let parent_file = file(root_item.item_id, "parent.txt");
        let mut root = root;
        {
            let mut writer = CatalogWriter::new(&mut store, root);
            block_on(writer.insert_item(&parent_file)).unwrap();
            root = commit!(writer, store).root;
        }
        let mut writer = CatalogWriter::new(&mut store, root);
        assert!(matches!(
            block_on(writer.insert_item(&dir(Some(parent_file.item_id), "Child"))),
            Err(CatalogError::NotADirectory)
        ));
    }

    #[test]
    fn one_live_root_is_enforced_before_publication() {
        let (mut store, mut root, root_item) = store_with_root();
        let mut second_root = dir(Some(root_item.item_id), "Second");
        second_root.item_id = ItemId::new();
        second_root.parent_id = None;
        second_root.name = String::new();
        {
            let mut writer = CatalogWriter::new(&mut store, root);
            block_on(writer.insert_item(&second_root)).unwrap();
            root = commit!(writer, store).root;
        }
        assert!(matches!(
            block_on(verify(&mut store, root)),
            Err(CatalogError::InvalidRoot)
        ));
    }

    #[test]
    fn tampered_page_bytes_fail_the_hash_check() {
        let (mut store, root, _) = store_with_root();
        // Valid canonical bytes under the wrong content hash must never be accepted.
        let root_id = root.digest();
        let mut page = format::from_page_bytes(store.get_bytes(&root_id).unwrap()).unwrap();
        let CatalogPage::Leaf(leaf) = &mut page else { panic!("initial root must be a leaf") };
        let IndexValue::Item(item) = &mut leaf.entries[0].value else { panic!("root item") };
        item.item_revision = "00000000-0000-4000-8000-000000000009".parse().unwrap();
        let bytes = format::to_page_bytes(&page).unwrap();
        store.pages.insert(root_id, bytes);
        let err = block_on(verify(&mut store, root)).unwrap_err();
        assert!(matches!(err, CatalogError::Storage(FormatError::NonCanonical)));
    }

    #[test]
    fn page_bounds_produce_median_splits() {
        // A leaf larger than the fanout splits at the median; every page then
        // honours both bounds and the tree still verifies.
        let mut entries: Vec<LeafEntry> = (0..(MAX_PAGE_FANOUT * 3))
            .map(|index| {
                let item = ItemRecord {
                    item_id: ItemId::new(),
                    parent_id: Some(ItemId::new()),
                    name: format!("entry-{index:05}"),
                    kind: ItemKind::File,
                    item_revision: OperationId::new(),
                    content_version_id: Some(VersionId::new()),
                    deleted: false,
                    content_operation: OperationId::new(),
                    location_operation: OperationId::new(),
                    deletion_operation: None,
                };
                LeafEntry {
                    key: format::item_key(item.item_id),
                    value: IndexValue::Item(item),
                }
            })
            .collect();
        // Leaf entries must be strictly ascending by key.
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        let pages = chunk_leaf(entries).unwrap();
        assert!(pages.len() >= 3);
        for (hash, page) in &pages {
            assert!(page.len() <= MAX_PAGE_FANOUT);
            let (rehash, bytes) = encode_and_hash(page).unwrap();
            assert_eq!(&rehash, hash);
            assert!(bytes.len() <= MAX_PAGE_BYTES);
        }
    }
}
