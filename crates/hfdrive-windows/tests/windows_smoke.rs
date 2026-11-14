//! Isolated Windows smoke scenarios — **authored but not run** as part of
//! this slice. Each test is `#[ignore]`d and must be executed manually by an
//! operator on a disposable NTFS scratch area; they are the exact test
//! boundaries documented in `docs/filesystem-semantics.md`.
//!
//! Prerequisites (each scenario names its own):
//!
//! * `HFDRIVE_SMOKE_ROOT` — an empty scratch directory on a fixed NTFS
//!   volume, outside every sync root and the HF Drive state directory. The
//!   tests create and delete their own files **only inside it**.
//! * `HFDRIVE_SMOKE_SYNC_ROOT` — (placeholder scenarios only) an already
//!   registered and connected dev sync root the operator set up beforehand.
//!   These tests **never** register or unregister sync roots themselves.
//!
//! Nothing here proves Explorer or HF acceptance; those are separate
//! milestone gates run through `scripts/acceptance.ps1`.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

use hfdrive_core::ids::SnapshotId;
use hfdrive_windows::filesystem::names::validate_component;
use hfdrive_windows::filesystem::{
    capture_snapshot, query_file_state, scan_metadata, usn::UsnReader, validate_sync_root,
    DirectoryWatcher, RootContext, ScanBudget, VisitFlow, WatchAction,
};
use hfdrive_windows::cfapi::{create_placeholders, PlaceholderCreate, PlaceholderRequestOutcome};
use hfdrive_windows::cfapi::{MetadataSpec, PlaceholderIdentity};
use hfdrive_core::ids::{ItemId, WorkspaceId};

fn scratch(tag: &str) -> PathBuf {
    let root = std::env::var("HFDRIVE_SMOKE_ROOT")
        .expect("set HFDRIVE_SMOKE_ROOT to an empty NTFS scratch directory");
    let dir = PathBuf::from(root).join(format!("smoke-{tag}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create scratch");
    dir
}

#[ignore = "manual smoke: run on a disposable NTFS scratch area (HFDRIVE_SMOKE_ROOT)"]
#[test]
fn smoke_validate_sync_root_accepts_plain_ntfs_directory() {
    let dir = scratch("validate-ok");
    let state_dir = dir.join("_state");
    fs::create_dir_all(&state_dir).unwrap();
    let context = RootContext {
        state_dir,
        configured_roots: Vec::new(),
        ignored_existing_root: None,
    };
    let validated = validate_sync_root(&dir, &context).expect("plain NTFS dir validates");
    assert_eq!(validated.volume.file_system, "NTFS");
    assert!(validated.volume.is_fixed);
    assert_eq!(validated.identity.link_count, 1);
    let _ = fs::remove_dir_all(&dir);
}

#[ignore = "manual smoke: run on a disposable NTFS scratch area (HFDRIVE_SMOKE_ROOT)"]
#[test]
fn smoke_validate_rejects_nested_overlapping_roots() {
    let dir = scratch("validate-overlap");
    let outer = dir.join("outer");
    let inner = outer.join("inner");
    fs::create_dir_all(&inner).unwrap();
    let state_dir = dir.join("_state");
    fs::create_dir_all(&state_dir).unwrap();
    let first = RootContext {
        state_dir: state_dir.clone(),
        configured_roots: Vec::new(),
        ignored_existing_root: None,
    };
    validate_sync_root(&outer, &first).expect("outer validates");
    let second = RootContext {
        state_dir,
        configured_roots: vec![outer.clone()],
        ignored_existing_root: None,
    };
    assert!(
        validate_sync_root(&inner, &second).is_err(),
        "nested root must be refused as an overlap"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[ignore = "manual smoke: run on a disposable NTFS scratch area (HFDRIVE_SMOKE_ROOT)"]
#[test]
fn smoke_capture_snapshot_binds_identity_size_and_digest() {
    let dir = scratch("capture");
    let source = dir.join("hello.txt");
    fs::write(&source, b"hello hello hello").unwrap();
    let staging = dir.join("staging");
    let expect = query_file_state(&source).expect("state");
    let captured = capture_snapshot(&source, &staging, SnapshotId::new(), Some(&expect))
        .expect("coherent capture");
    assert_eq!(captured.size, 17);
    let staged = fs::read(&captured.staged_path).expect("staged bytes");
    assert_eq!(staged, b"hello hello hello", "staged bytes equal source");
    assert_eq!(captured.evidence.state_before.identity, expect.identity);
    assert_eq!(captured.evidence.state_before.size, expect.size);
    let _ = fs::remove_dir_all(&dir);
}

#[ignore = "manual smoke: run on a disposable NTFS scratch area (HFDRIVE_SMOKE_ROOT)"]
#[test]
fn smoke_capture_refuses_hardlinked_files_and_preserves_local_copy() {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Storage::FileSystem::CreateHardLinkW;
    let dir = scratch("capture-hardlink");
    let source = dir.join("linked.bin");
    fs::write(&source, b"data").unwrap();
    let link = dir.join("linked-alias.bin");
    let src_w: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let link_w: Vec<u16> = link.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: both paths are NUL-terminated and inside the scratch area.
    unsafe {
        CreateHardLinkW(
            windows::core::PCWSTR(link_w.as_ptr()),
            windows::core::PCWSTR(src_w.as_ptr()),
            None,
        )
        .expect("create hard link for the scenario");
    }
    let staging = dir.join("staging");
    let result = capture_snapshot(&source, &staging, SnapshotId::new(), None);
    assert!(
        matches!(result, Err(hfdrive_windows::filesystem::FsError::HardLinked)),
        "multiply linked files are refused for upload"
    );
    assert!(source.exists(), "the local file is preserved");
    let _ = fs::remove_dir_all(&dir);
}

#[ignore = "manual smoke: run on a disposable NTFS scratch area (HFDRIVE_SMOKE_ROOT)"]
#[test]
fn smoke_capture_refuses_a_file_held_by_another_writer() {
    let dir = scratch("capture-sharing");
    let source = dir.join("busy.bin");
    fs::write(&source, b"busy").unwrap();
    // Hold the file with write access while denying read sharing so the
    // capture's coherent open must fail with a sharing violation.
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::GENERIC_WRITE;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_MODE,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    let w: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: NUL-terminated scratch path; the handle is closed below.
    let holder = unsafe {
        CreateFileW(
            windows::core::PCWSTR(w.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_MODE(FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
        .expect("open holder")
    };
    let staging = dir.join("staging");
    let result = capture_snapshot(&source, &staging, SnapshotId::new(), None);
    // SAFETY: closing the scenario's holder handle.
    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(holder);
    }
    assert!(
        matches!(
            result,
            Err(hfdrive_windows::filesystem::FsError::SharingViolation)
        ),
        "capture refuses concurrent writers instead of staging a torn copy"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[ignore = "manual smoke: run on a disposable NTFS scratch area (HFDRIVE_SMOKE_ROOT)"]
#[test]
fn smoke_watch_delivers_changes_and_flags_overflow() {
    let dir = scratch("watch");
    let (sender, mut receiver) = tokio::sync::mpsc::channel(64);
    let mut watcher =
        DirectoryWatcher::start(&dir, sender).expect("watch starts on a plain directory");
    fs::write(dir.join("created.txt"), b"x").expect("create");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime");
    let events: Vec<_> = runtime.block_on(async {
        let mut events = Vec::new();
        while let Some(event) =
            tokio::time::timeout(std::time::Duration::from_secs(5), receiver.recv())
                .await
                .expect("event within timeout")
        {
            events.push(event);
            if events.len() >= 3 {
                break;
            }
        }
        events
    });
    assert!(
        events
            .iter()
            .any(|e| e.action == WatchAction::Added && e.name.as_deref() == Some("created.txt")),
        "creation observed: {events:?}"
    );
    assert!(!watcher.overflowed(), "no overflow in a quiet tree");
    watcher.shutdown();
    let _ = fs::remove_dir_all(&dir);
}

#[ignore = "manual smoke: run on a disposable NTFS scratch area (HFDRIVE_SMOKE_ROOT)"]
#[test]
fn smoke_scan_metadata_completeness_gates_deletion_inference() {
    let dir = scratch("scan");
    fs::create_dir_all(dir.join("sub")).unwrap();
    fs::write(dir.join("sub/a.txt"), b"a").unwrap();
    let budget = ScanBudget::default();
    let cancel = AtomicBool::new(false);
    let mut seen = 0usize;
    let report = scan_metadata(&dir, &budget, &cancel, &mut |_entry| {
        seen += 1;
        VisitFlow::Continue
    })
    .expect("scan");
    assert!(report.complete, "a quiet tree scans completely");
    assert_eq!(report.entries, seen);
    assert!(report.entries >= 2, "sub and a.txt observed");
    let _ = fs::remove_dir_all(&dir);
}

#[ignore = "manual smoke: run on a disposable NTFS scratch area (HFDRIVE_SMOKE_ROOT)"]
#[test]
fn smoke_usn_catchup_observes_changes_and_resets_on_cursor_loss() {
    let dir = scratch("usn");
    let file = dir.join("tracked.txt");
    fs::write(&file, b"one").unwrap();
    let state = query_file_state(&dir).expect("volume state");
    let volume = hfdrive_windows::filesystem::query_volume(&dir).expect("volume identity");
    let reader = UsnReader::open(&volume).expect("active USN journal on NTFS");
    let journal = reader.journal();
    let cursor = hfdrive_windows::filesystem::UsnCursor {
        journal_id: journal.journal_id,
        usn: journal.next_usn,
    };
    fs::write(&file, b"two two").expect("modify");
    let catch_up = reader.catch_up(cursor, 256 * 1024).expect("catch up");
    match catch_up {
        hfdrive_windows::filesystem::CatchUp::Advanced { changes, .. } => {
            assert!(!changes.is_empty(), "the modification is observed");
        }
        other => panic!("expected advanced catch-up, got {other:?}"),
    }
    // A cursor from a foreign journal is a reset, never a silent skip.
    let foreign = hfdrive_windows::filesystem::UsnCursor {
        journal_id: journal.journal_id.wrapping_add(1),
        usn: cursor.usn,
    };
    assert!(matches!(
        reader.catch_up(foreign, 256 * 1024).unwrap(),
        hfdrive_windows::filesystem::CatchUp::Reset(
            hfdrive_windows::filesystem::ResetReason::JournalIdChanged { .. }
        )
    ));
    let _ = state;
    let _ = fs::remove_dir_all(&dir);
}

#[ignore = "manual smoke: requires a pre-registered dev sync root (HFDRIVE_SMOKE_SYNC_ROOT); never registers/unregisters roots"]
#[test]
fn smoke_create_placeholders_reports_existing_paths_without_overwrite() {
    let root = std::env::var("HFDRIVE_SMOKE_SYNC_ROOT")
        .expect("set HFDRIVE_SMOKE_SYNC_ROOT to a registered dev sync root");
    let root = PathBuf::from(root);
    let workspace = WorkspaceId::new();
    let item = ItemId::new();
    let create = PlaceholderCreate {
        name: "smoke-placeholder.bin".into(),
        metadata: MetadataSpec {
            size: 0,
            creation_time_100ns: 0,
            last_write_time_100ns: 0,
            attributes: 0x20, // FILE_ATTRIBUTE_ARCHIVE
        },
        identity: PlaceholderIdentity::directory(workspace, item),
        mark_in_sync: false,
    };
    let first = create_placeholders(&root, &[create.clone()]).expect("batch");
    assert_eq!(first.len(), 1);
    // Second create must report the existing path for reconciliation and
    // must not overwrite it.
    let second = create_placeholders(&root, &[create]).expect("batch");
    assert!(
        matches!(
            second[0].outcome,
            PlaceholderRequestOutcome::AlreadyExists { .. }
                | PlaceholderRequestOutcome::Failed { .. }
        ),
        "existing paths are reconciled, never overwritten: {:?}",
        second[0].outcome
    );
    let _ = fs::remove_file(root.join("smoke-placeholder.bin"));
}

#[ignore = "manual smoke: requires a pre-registered dev sync root (HFDRIVE_SMOKE_SYNC_ROOT); never registers/unregisters roots"]
#[test]
fn smoke_revert_to_normal_converts_placeholders_and_preserves_dirty_content() {
    use hfdrive_windows::cfapi::{revert_to_normal, GuardOutcome, MetadataSpec, PlaceholderIdentity, PlaceholderCreate};
    use hfdrive_core::ids::{ItemId, WorkspaceId};

    let root = std::env::var("HFDRIVE_SMOKE_SYNC_ROOT")
        .expect("set HFDRIVE_SMOKE_SYNC_ROOT to a registered dev sync root");
    let root = PathBuf::from(root);
    let workspace = WorkspaceId::new();

    // A freshly created placeholder is fully resident (empty), so unlink's
    // conversion must succeed and leave a normal, existing file behind.
    let create = PlaceholderCreate {
        name: "smoke-unlink.bin".into(),
        metadata: MetadataSpec {
            size: 0,
            creation_time_100ns: 0,
            last_write_time_100ns: 0,
            attributes: 0x20,
        },
        identity: PlaceholderIdentity::directory(workspace, ItemId::new()),
        mark_in_sync: false,
    };
    let outcomes = create_placeholders(&root, &[create]).expect("create placeholder");
    assert!(matches!(
        outcomes[0].outcome,
        PlaceholderRequestOutcome::Created { .. }
    ));
    let target = root.join("smoke-unlink.bin");
    let expect = query_file_state(&target).expect("observed state");
    let outcome = revert_to_normal(&target, &expect).expect("conversion");
    assert!(
        matches!(outcome, GuardOutcome::Applied { .. }),
        "resident placeholder converts to a normal file: {outcome:?}"
    );
    assert!(target.exists(), "content is preserved by conversion");
    // Idempotent end state: a normal file is 'already converted'.
    let expect = query_file_state(&target).expect("observed state");
    let outcome = revert_to_normal(&target, &expect).expect("idempotent");
    assert!(matches!(outcome, GuardOutcome::Applied { .. }));
    // Dirty content since the observed state must be preserved as-is.
    let create = PlaceholderCreate {
        name: "smoke-unlink-dirty.bin".into(),
        metadata: MetadataSpec {
            size: 0,
            creation_time_100ns: 0,
            last_write_time_100ns: 0,
            attributes: 0x20,
        },
        identity: PlaceholderIdentity::directory(workspace, ItemId::new()),
        mark_in_sync: false,
    };
    let _ = create_placeholders(&root, &[create]).expect("create placeholder");
    let dirty = root.join("smoke-unlink-dirty.bin");
    let stale = query_file_state(&dirty).expect("observed state");
    fs::write(&dirty, b"local edits").expect("dirties the placeholder");
    let outcome = revert_to_normal(&dirty, &stale).expect("guard check runs");
    assert!(
        matches!(outcome, GuardOutcome::Mismatch(_)),
        "changed content is never converted against a stale guard"
    );
    assert!(dirty.exists(), "dirty content is preserved untouched");
    let _ = fs::remove_file(target);
    let _ = fs::remove_file(dirty);
}

#[ignore = "manual smoke: run on a disposable NTFS scratch area (HFDRIVE_SMOKE_ROOT)"]
#[test]
fn smoke_names_validate_the_same_rules_as_the_namespace() {
    assert!(validate_component("ok.txt").is_ok());
    assert!(validate_component("CON").is_err());
    assert!(validate_component("bad.").is_err());
}
