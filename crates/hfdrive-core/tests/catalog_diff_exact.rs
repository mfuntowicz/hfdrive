//! Hash-skipping catalog diff exactness: unequal tree shapes, split
//! boundary changes, deletes, subtree reuse, and page-identity verification.

use hfdrive_core::catalog::{
    initialize, verify, CatalogWriter, InMemoryPageStore, PageSink, PageSource, PublishSet,
};
use hfdrive_core::catalog_diff::{diff_items, ItemDelta};
use hfdrive_core::format::{CatalogPage, ItemKind, ItemRecord};
use hfdrive_core::ids::{ItemId, OperationId, VersionId};
use hfdrive_core::storage::Sha256Digest;
use hfdrive_core::format::FormatError;
use uuid::Uuid;

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

fn root_item() -> ItemId {
    ItemId::from_uuid(Uuid::from_u128(0x2222_2222_2222_4222_8222_2222_2222_2222)).unwrap()
}

fn init_op() -> OperationId {
    OperationId::from_uuid(Uuid::from_u128(0x1000)).unwrap()
}

fn file(n: u128, rev: u128) -> ItemRecord {
    let item_id = ItemId::from_uuid(Uuid::from_u128(n)).unwrap();
    let rev = OperationId::from_uuid(Uuid::from_u128(rev)).unwrap();
    ItemRecord {
        item_id,
        parent_id: Some(root_item()),
        name: format!("f{n:x}.txt"),
        kind: ItemKind::File,
        item_revision: rev,
        content_version_id: Some(VersionId::from_uuid(Uuid::from_u128(n)).unwrap()),
        deleted: false,
        content_operation: rev,
        location_operation: rev,
        deletion_operation: None,
    }
}

fn tombstone(record: &ItemRecord, del_op: u128) -> ItemRecord {
    let mut t = record.clone();
    t.deleted = true;
    let del_op = OperationId::from_uuid(Uuid::from_u128(del_op)).unwrap();
    t.deletion_operation = Some(del_op);
    t.item_revision = del_op;
    t
}

/// Builds a catalog: root plus `records` applied in order (live records are
/// inserted, deleted records are tombstoned over their live insert).
fn build(records: &[ItemRecord]) -> (hfdrive_core::catalog::CatalogRoot, InMemoryPageStore) {
    block_on(async {
        let mut store = InMemoryPageStore::new();
        let (root, set): (_, PublishSet) = initialize(root_item(), init_op()).unwrap();
        for (hash, page) in &set.pages {
            store.store(*hash, page).await.unwrap();
        }
        let mut writer = CatalogWriter::new(&mut store, root);
        for record in records {
            if record.deleted {
                writer.tombstone_item(record).await.unwrap();
            } else {
                writer.insert_item(record).await.unwrap();
            }
        }
        let set = writer.commit().unwrap();
        for (hash, page) in &set.pages {
            store.store(*hash, page).await.unwrap();
        }
        verify(&mut store, set.root).await.unwrap();
        (set.root, store)
    })
}

#[test]
fn identical_roots_yield_no_deltas() {
    let records: Vec<ItemRecord> = (0..50u128).map(|n| file(0x3000 + n, 0x4000 + n)).collect();
    let (root_a, mut store_a) = build(&records);
    let (root_b, mut store_b) = build(&records);
    assert_eq!(root_a.digest(), root_b.digest());
    let diff = block_on(diff_items(&mut store_a, root_a, root_b)).unwrap();
    assert_eq!(diff.deltas.len(), 0);
    assert!(diff.subtrees_skipped >= 1, "the shared root is skipped by hash");
    let diff = block_on(diff_items(&mut store_b, root_a, root_b)).unwrap();
    assert_eq!(diff.deltas.len(), 0);
}

#[test]
fn single_change_yields_one_exact_delta() {
    let base: Vec<ItemRecord> = (0..50u128).map(|n| file(0x3000 + n, 0x4000 + n)).collect();
    let mut changed = base.clone();
    changed[17].content_version_id = Some(VersionId::from_uuid(Uuid::from_u128(0xDEAD)).unwrap());
    changed[17].content_operation =
        OperationId::from_uuid(Uuid::from_u128(0x4000 + 17 + 0x100)).unwrap();
    changed[17].item_revision = changed[17].content_operation;
    let (root_a, mut store) = build(&base);
    let (root_b, store_b) = build(&changed);
    store.extend(store_b);
    let diff = block_on(diff_items(&mut store, root_a, root_b)).unwrap();
    assert_eq!(diff.deltas.len(), 1);
    let delta = &diff.deltas[0];
    assert!(delta.is_change());
    assert_eq!(delta.item_id, base[17].item_id);
    assert_eq!(delta.before.as_ref().unwrap().item_revision, base[17].item_revision);
    assert_eq!(delta.after.as_ref().unwrap().item_revision, changed[17].item_revision);
}

#[test]
fn unequal_split_shapes_yield_only_real_changes() {
    // Tree A: 200 live items inserted ascending.
    let live: Vec<ItemRecord> = (0..200u128).map(|n| file(0x3000 + n, 0x4000 + n)).collect();
    // Tree B: 250 items inserted ascending, then 50 tombstoned. v1 never
    // rebalances, so B's page shapes and hashes differ from A's even where
    // the live records are identical.
    let mut b_records = live.clone();
    b_records.extend((200..250u128).map(|n| file(0x3000 + n, 0x4000 + n)));
    let extras: Vec<ItemRecord> = (200..250u128)
        .map(|n| tombstone(&file(0x3000 + n, 0x4000 + n), 0x9000 + n))
        .collect();
    b_records.extend(extras.iter().cloned());
    let (root_a, mut store) = build(&live);
    let (root_b, store_b) = build(&b_records);
    store.extend(store_b);
    assert_ne!(root_a.digest(), root_b.digest(), "shapes genuinely differ");

    let diff = block_on(diff_items(&mut store, root_a, root_b)).unwrap();
    assert_eq!(diff.deltas.len(), 50, "only the 50 extra tombstones differ");
    for delta in &diff.deltas {
        assert!(delta.is_add(), "tombstone records are additions in B");
        assert!(delta.after.as_ref().unwrap().deleted);
        assert!(u128::from_be_bytes(*delta.item_id.as_bytes()) >= 0x3000 + 200);
    }

    // Reversed direction: exactly the same 50 as removals, nothing else.
    let diff = block_on(diff_items(&mut store, root_b, root_a)).unwrap();
    assert_eq!(diff.deltas.len(), 50);
    assert!(diff.deltas.iter().all(ItemDelta::is_remove));
}

#[test]
fn hash_skipping_reports_skipped_subtrees_and_avoids_full_scan() {
    let base: Vec<ItemRecord> = (0..300u128).map(|n| file(0x3000 + n, 0x4000 + n)).collect();
    let mut changed = base.clone();
    changed[0].item_revision =
        OperationId::from_uuid(Uuid::from_u128(0x4000 + 0x1000)).unwrap();
    changed[0].content_operation = changed[0].item_revision;
    let (root_a, mut store) = build(&base);
    let (root_b, store_b) = build(&changed);
    store.extend(store_b);
    let diff = block_on(diff_items(&mut store, root_a, root_b)).unwrap();
    assert_eq!(diff.deltas.len(), 1);
    assert!(
        diff.subtrees_skipped > 0,
        "unchanged subtrees are skipped by hash, not scanned"
    );
    let total_pages = {
        let mut stats = block_on(verify(&mut store, root_a)).unwrap();
        let other = block_on(verify(&mut store, root_b)).unwrap();
        stats.pages += other.pages;
        stats.pages
    };
    assert!(
        diff.pages_loaded < total_pages,
        "loaded {} of {total_pages} pages",
        diff.pages_loaded
    );
}

#[test]
fn removed_item_entry_yields_exactly_one_remove_delta() {
    let records: Vec<ItemRecord> = (0..10u128).map(|n| file(0x3000 + n, 0x4000 + n)).collect();
    let (root_a, mut store) = build(&records);
    // Tree B drops one item entry outright (raw index removal). Derived c/n
    // indexes never produce item deltas.
    let (root_b, store_b) = block_on(async {
        let mut store_b = InMemoryPageStore::new();
        let (root, set) = initialize(root_item(), init_op()).unwrap();
        for (hash, page) in &set.pages {
            store_b.store(*hash, page).await.unwrap();
        }
        let mut writer = CatalogWriter::new(&mut store_b, root);
        for record in &records {
            writer.insert_item(record).await.unwrap();
        }
        writer
            .apply_entry(
                hfdrive_core::format::item_key(records[4].item_id),
                None,
            )
            .await
            .unwrap();
        let set = writer.commit().unwrap();
        for (hash, page) in &set.pages {
            store_b.store(*hash, page).await.unwrap();
        }
        (set.root, store_b)
    });
    store.extend(store_b);
    let diff = block_on(diff_items(&mut store, root_a, root_b)).unwrap();
    assert_eq!(diff.deltas.len(), 1);
    assert!(diff.deltas[0].is_remove());
    assert_eq!(diff.deltas[0].item_id, records[4].item_id);
    assert!(diff.deltas[0].after.is_none());
}

/// A source that hands out a page whose bytes do not hash to its address.
struct CorruptStore {
    inner: InMemoryPageStore,
    corrupt: Sha256Digest,
}

impl PageSource for CorruptStore {
    type Error = FormatError;
    fn load(
        &mut self,
        page_id: Sha256Digest,
    ) -> impl Future<Output = Result<Option<CatalogPage>, Self::Error>> + Send {
        let page = self.inner.load(page_id);
        let corrupt = page_id == self.corrupt;
        async move {
            let page = page.await?;
            Ok(page.map(|mut page| {
                if corrupt {
                    if let CatalogPage::Leaf(leaf) = &mut page {
                        leaf.entries.clear();
                    }
                }
                page
            }))
        }
    }
}

#[test]
fn corrupt_page_identity_is_rejected() {
    let records: Vec<ItemRecord> = (0..10u128).map(|n| file(0x3000 + n, 0x4000 + n)).collect();
    let (root_a, inner) = build(&records);
    let mut changed = records.clone();
    changed[0].item_revision =
        OperationId::from_uuid(Uuid::from_u128(0x4000 + 0x1000)).unwrap();
    changed[0].content_operation = changed[0].item_revision;
    let (root_b, store_b) = build(&changed);
    let mut store = CorruptStore { inner, corrupt: root_a.digest() };
    store.inner.extend(store_b);
    let result = block_on(diff_items(&mut store, root_a, root_b));
    match result {
        Err(hfdrive_core::catalog::CatalogError::Invariant("loaded page hash mismatch")) => {}
        other => panic!("expected page identity rejection, got {other:?}"),
    }
}
