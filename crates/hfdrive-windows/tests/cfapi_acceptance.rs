//! Real Windows CFAPI acceptance on an explicitly authorized disposable root.
//! Ignored by default so ordinary suites never register a sync root.

use std::fs;
use std::path::PathBuf;

use hfdrive_core::ids::{ItemId, WorkspaceId};
use hfdrive_windows::cfapi::{
    create_placeholders, register_sync_root, revert_to_normal, unregister_sync_root, CfConnection,
    ConnectConfig, GuardOutcome, MetadataSpec, PlaceholderCreate, PlaceholderIdentity,
    PlaceholderRequestOutcome,
    RegistrationInfo,
};
use hfdrive_windows::filesystem::{query_file_state, validate_sync_root, RootContext};

#[ignore = "authorized disposable CFAPI sync root only"]
#[test]
fn cfapi_register_create_guard_shutdown_and_unregister() {
    let base = std::env::var("HFDRIVE_SMOKE_ROOT")
        .expect("set HFDRIVE_SMOKE_ROOT to the authorized acceptance directory");
    let root = PathBuf::from(base).join("cfapi-root");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let connection = hfdrive_core::ids::ConnectionId::new();
    let pipe = hfdrive_windows::ipc::current_pipe_name().unwrap();
    let user_sid = pipe
        .strip_prefix(r"\\.\pipe\LOCAL\HFDrive.")
        .and_then(|value| value.strip_suffix(".v1"))
        .expect("current user SID in pipe name")
        .to_owned();
    let validated = validate_sync_root(&root, &RootContext {
        state_dir: root.join("_state"),
        configured_roots: Vec::new(),
        existing_sync_root_id: None,
    }).expect("validated disposable NTFS root");
    eprintln!("existing sync roots: {:?}", hfdrive_windows::cfapi::registered_sync_roots().unwrap());
    let registration = register_sync_root(&validated, &user_sid, &RegistrationInfo {
        connection,
        display_name: "HF Drive CFAPI acceptance".to_owned(),
        icon_resource: "@{C:\\Windows\\System32\\imageres.dll},-101".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    }).expect("register disposable sync root");
    eprintln!("registration: {registration:?}");

    let workspace = WorkspaceId::new();
    let mut streams = None;
    let mut connected = None;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (connection_handle, provider_streams) = CfConnection::connect(&root, ConnectConfig {
            workspace,
            queues: Default::default(),
        }).expect("connect CFAPI callbacks");
        connected = Some(connection_handle);
        streams = Some(provider_streams);

        let create = PlaceholderCreate {
            name: "resident-empty.bin".to_owned(),
            metadata: MetadataSpec {
                size: 0,
                creation_time_100ns: 0,
                last_write_time_100ns: 0,
                attributes: 0x20,
            },
            identity: PlaceholderIdentity::directory(workspace, ItemId::new()),
            mark_in_sync: false,
        };
        let created = create_placeholders(&root, &[create]).expect("create empty placeholder");
        assert!(matches!(created[0].outcome, PlaceholderRequestOutcome::Created { .. }));
        let target = root.join("resident-empty.bin");
        let observed = query_file_state(&target).expect("observe empty placeholder");
        let outcome = revert_to_normal(&target, &observed).expect("revert resident placeholder");
        eprintln!("revert outcome: {outcome:?}");
        assert!(matches!(outcome, GuardOutcome::Applied { .. }));
        assert!(target.exists(), "empty content survives conversion");

        let dirty = PlaceholderCreate {
            name: "dirty.bin".to_owned(),
            metadata: MetadataSpec {
                size: 0,
                creation_time_100ns: 0,
                last_write_time_100ns: 0,
                attributes: 0x20,
            },
            identity: PlaceholderIdentity::directory(workspace, ItemId::new()),
            mark_in_sync: false,
        };
        let created = create_placeholders(&root, &[dirty]).expect("create dirty placeholder");
        assert!(matches!(created[0].outcome, PlaceholderRequestOutcome::Created { .. }));
        let dirty_path = root.join("dirty.bin");
        let stale = query_file_state(&dirty_path).expect("observe before edit");
        fs::write(&dirty_path, b"local-only bytes").unwrap();
        assert!(matches!(
            revert_to_normal(&dirty_path, &stale).expect("dirty guard result"),
            GuardOutcome::Mismatch(_)
        ));
        assert_eq!(fs::read(&dirty_path).unwrap(), b"local-only bytes");
    }));

    drop(streams.take());
    if let Some(connection) = connected.take() {
        connection.shutdown().expect("disconnect CFAPI callbacks");
    }
    unregister_sync_root(&user_sid, connection).expect("unregister disposable sync root");
    let _ = fs::remove_dir_all(&root);
    result.unwrap();
}
