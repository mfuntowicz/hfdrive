//! Deterministic 100k-item catalog evidence.
//!
//! Builds a 100,101-item catalog (root, 100 directories, 100,000 files) and
//! measures the real upload set of one save: a single item insert must produce
//! a handful of pages on the affected root-to-leaf paths, never a full-manifest
//! upload. Counters are the exact page set and canonical bytes a caller would
//! upload before publishing HEAD, not incidental statistics. This test does
//! real encoding and hashing work and can take about a minute.

use hfdrive_core::catalog::{
    initialize, verify, CatalogWriter, InMemoryPageStore, PageSink, PublishSet,
};
use hfdrive_core::format::{ItemKind, ItemRecord};
use hfdrive_core::ids::{ItemId, OperationId, VersionId};
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

fn directory(parent: ItemId, name: &str) -> ItemRecord {
    let item_id = ItemId::from_uuid(Uuid::new_v5(parent.as_uuid(), name.as_bytes())).unwrap();
    let op = OperationId::from_uuid(Uuid::new_v5(item_id.as_uuid(), b"fixture-create")).unwrap();
    ItemRecord {
        item_id,
        parent_id: Some(parent),
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
    let item_id = ItemId::from_uuid(Uuid::new_v5(parent.as_uuid(), name.as_bytes())).unwrap();
    let op = OperationId::from_uuid(Uuid::new_v5(item_id.as_uuid(), b"fixture-create")).unwrap();
    ItemRecord {
        item_id,
        parent_id: Some(parent),
        name: name.to_owned(),
        kind: ItemKind::File,
        item_revision: op,
        content_version_id: Some(VersionId::from_uuid(Uuid::new_v5(item_id.as_uuid(), b"fixture-content")).unwrap()),
        deleted: false,
        content_operation: op,
        location_operation: op,
        deletion_operation: None,
    }
}

fn store_pages(store: &mut InMemoryPageStore, set: &PublishSet) {
    for (hash, page) in &set.pages {
        block_on(store.store(*hash, page)).unwrap();
    }
}

#[test]
fn one_save_on_a_100k_item_catalog_rewrites_only_affected_pages() {
    let mut store = InMemoryPageStore::new();
    let root_id = ItemId::from_uuid(Uuid::from_u128(0x7b53b6cb_0c58_4e9d_8d4b_2caad4b15e01)).unwrap();
    let init_op = OperationId::from_uuid(Uuid::from_u128(0x7b53b6cb_0c58_4e9d_8d4b_2caad4b15e02)).unwrap();
    let (mut root, initial) = initialize(root_id, init_op).unwrap();
    store_pages(&mut store, &initial);
    let root_item = ItemRecord {
        item_id: root_id,
        parent_id: None,
        name: String::new(),
        kind: ItemKind::Directory,
        item_revision: init_op,
        content_version_id: None,
        deleted: false,
        content_operation: init_op,
        location_operation: init_op,
        deletion_operation: None,
    };

    // 100 directories, then 100,000 files (1,000 per directory) in batches of
    // 500 insertions, committing each batch like a publication cycle would.
    let mut dirs = Vec::new();
    {
        let mut writer = CatalogWriter::new(&mut store, root);
        for index in 0..100u32 {
            let dir = directory(root_item.item_id, &format!("dir-{index:03}"));
            block_on(writer.insert_item(&dir)).unwrap();
            dirs.push(dir);
        }
        let set = writer.commit().unwrap();
        store_pages(&mut store, &set);
        root = set.root;
    }
    eprintln!("catalog scale: inserted 100 directories");
    let mut since_commit = 0u32;
    let mut writer = CatalogWriter::new(&mut store, root);
    for (directory_index, parent) in dirs.iter().enumerate() {
        for index in 0..1000u32 {
            if index == 0 {
                eprintln!("catalog scale: inserting directory {} of 100", directory_index + 1);
            }
            let item = file(parent.item_id, &format!("item-{index:04}.bin"));
            block_on(writer.insert_item(&item)).unwrap();
            since_commit += 1;
            if since_commit == 500 {
                let set = writer.commit().unwrap();
                store_pages(&mut store, &set);
                root = set.root;
                writer = CatalogWriter::new(&mut store, root);
                since_commit = 0;
            }
        }
    }
    assert_eq!(since_commit, 0);

    eprintln!("catalog scale: verifying complete catalog");
    let stats = block_on(verify(&mut store, root)).unwrap();
    assert_eq!(stats.live_items, 1 + 100 + 100_000);
    assert_eq!(stats.item_entries, 1 + 100 + 100_000);
    assert_eq!(stats.child_indexes, 100 + 100_000);
    assert_eq!(stats.name_indexes, 100 + 100_000);
    assert!(stats.pages > 2_000, "manifest is paginated: {} pages", stats.pages);
    assert!(stats.bytes > 8 * 1024 * 1024, "manifest is material: {} bytes", stats.bytes);

    // The measured save: one more file in an existing directory.
    eprintln!("catalog scale: measuring one-save upload set");
    let mut writer = CatalogWriter::new(&mut store, root);
    block_on(writer.insert_item(&file(dirs[42].item_id, "one-more.bin"))).unwrap();
    let set = writer.commit().unwrap();

    // The save rewrites only its root-to-leaf paths (three index kinds) plus
    // at most one median split per rewritten page.
    assert!(set.pages.len() <= 12, "one save wrote {} pages", set.pages.len());
    let upload_bytes = set.upload_bytes().unwrap();
    eprintln!("catalog evidence: items={} manifest_pages={} manifest_bytes={} save_pages={} save_bytes={}",
        stats.live_items, stats.pages, stats.bytes, set.pages.len(), upload_bytes);
    assert!(
        upload_bytes * 20 < stats.bytes,
        "one save wrote {} of {} manifest bytes",
        upload_bytes,
        stats.bytes
    );
    assert!(
        (set.pages.len() as u64) * 20 < stats.pages,
        "one save wrote {} of {} manifest pages",
        set.pages.len(),
        stats.pages
    );
}
