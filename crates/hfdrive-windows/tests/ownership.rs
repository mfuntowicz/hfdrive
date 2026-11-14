//! Consumer-visible tests for the single-provider lease.
//!
//! These use real Windows kernel objects (named mutex, byte-range file lock)
//! but only with per-test `Local\` mutex names and temporary directories: no
//! privileged or machine-global state is created or modified.

use std::path::PathBuf;

use hfdrive_windows::ownership::{OwnerInfo, ProviderLease};

fn unique_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "hfdrive-ownership-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn unique_mutex(label: &str) -> String {
    // A `Local\` namespace name: never the real per-user provider mutex.
    format!(
        r"Local\HFDrive.Test.{}.{}.{}",
        label,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

#[test]
fn lease_acquire_exclusive_release_reacquire() {
    let root = unique_root("exclusive");
    let mutex = unique_mutex("exclusive");

    let lease = ProviderLease::acquire_with_mutex_name(&root, &mutex)
        .expect("first acquisition must succeed");
    assert_eq!(lease.session_id(), hfdrive_session_id());

    // While held, a second acquisition (same process, another thread) must
    // fail without taking anything.
    {
        let root2 = root.clone();
        let mutex2 = mutex.clone();
        let result = std::thread::spawn(move || {
            ProviderLease::acquire_with_mutex_name(&root2, &mutex2).map(|_| ())
        })
        .join()
        .unwrap();
        assert!(
            matches!(
                result,
                Err(hfdrive_windows::OwnershipError::AlreadyRunning)
                    | Err(hfdrive_windows::OwnershipError::StateLockUnavailable { .. })
            ),
            "second acquisition must be refused, got {result:?}"
        );
    }

    // The owner record is readable and reports this process.
    let owner = hfdrive_windows::ownership::probe(&root)
        .unwrap()
        .expect("an owner record must exist while the lease is held");
    assert_eq!(owner.pid, std::process::id());

    drop(lease);

    // After release the lease is free and can be taken again.
    assert!(
        hfdrive_windows::ownership::probe(&root).unwrap().is_none(),
        "lease must be free after drop"
    );
    let lease2 = ProviderLease::acquire_with_mutex_name(&root, &mutex)
        .expect("re-acquisition after release must succeed");
    let owner2 = hfdrive_windows::ownership::probe(&root).unwrap().unwrap();
    assert_eq!(owner2.pid, std::process::id());
    drop(lease2);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn same_process_reacquisition_on_one_thread_is_refused() {
    let root = unique_root("samethread");
    let mutex = unique_mutex("samethread");
    let first = ProviderLease::acquire_with_mutex_name(&root, &mutex).unwrap();

    // The named mutex is recursive for one thread, so the state-file lock is
    // what must refuse this; either refusal is correct behavior.
    let second = ProviderLease::acquire_with_mutex_name(&root, &mutex).map(|_| ());
    assert!(
        second.is_err(),
        "a second lease in one process must not succeed"
    );
    drop(first);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn owner_info_fields_are_usable_and_sanitized() {
    // OwnerInfo is the loggable record: PIDs/session IDs/timestamps only.
    let info = OwnerInfo {
        pid: 7,
        session_id: 3,
        recorded_at: 1_700_000_000,
    };
    let dump = format!("{info:?}");
    assert!(dump.contains("pid: 7"));
    assert!(dump.contains("session_id: 3"));
}

/// The current logon session ID, recomputed independently for comparison.
fn hfdrive_session_id() -> u32 {
    // `ProviderLease::session_id` is verified against the OS value here via
    // the token-derived identity exposed by the IPC module.
    hfdrive_windows::ipc::own_identity()
        .expect("own identity must be readable")
        .session_id
}

#[test]
fn default_state_root_points_under_localappdata() {
    let root = hfdrive_windows::ownership::default_state_root().unwrap();
    let local = std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA must be set on Windows");
    let expected = PathBuf::from(local).join("HFDrive");
    assert_eq!(root, expected);
}

#[test]
fn mutex_name_shape_is_stable() {
    assert_eq!(
        hfdrive_windows::ownership::mutex_name("S-1-5-21-1"),
        r"Global\HFDrive.Provider.S-1-5-21-1"
    );
}
