//! Consumer-visible tests for the authenticated IPC boundary.
//!
//! The live test drives a real provider-style server and client through a
//! uniquely named pipe (`\\.\pipe\LOCAL\HFDrive.Test...`) inside one process:
//! no per-user provider pipe is claimed and no machine-global state is
//! touched. Both sides authenticate the other before any byte of payload.

use hfdrive_windows::ipc::{self, AuthenticatedStream, IpcClient, IpcPolicy, IpcServer};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn unique_pipe() -> String {
    format!(
        r"\\.\pipe\LOCAL\HFDrive.Test.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

#[test]
fn authenticated_roundtrip_over_real_pipe() {
    let own = ipc::own_identity().expect("own identity must be readable");
    if own.logon_sid.is_none() {
        let policy = IpcPolicy::for_current_process().expect("policy");
        assert!(matches!(policy.verify(&own, &own), Err(hfdrive_windows::IpcError::ForeignLogonSid)));
        return;
    }

    let name = unique_pipe();
    // Both ends run in this test binary: explicitly allow our own image as a
    // development build output so policy can pass (the production allowlist
    // accepts only the canonical HF Drive build outputs).
    let policy = IpcPolicy::for_current_process()
        .expect("policy")
        .with_dev_allow_path(std::env::current_exe().unwrap());

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let _runtime_scope = runtime.enter();

    let server_name = name.clone();
    let server = IpcServer::bind_named(policy.clone(), &server_name).expect("bind server");

    let client_task = runtime.spawn({
        let policy = policy.clone();
        let name = name.clone();
        async move {
            let mut stream = IpcClient::connect_named(&policy, &name)
                .await
                .expect("client connect + server authentication");
            // The client has already validated the server identity.
            assert_eq!(stream.peer().pid, std::process::id());
            stream.write_all(b"ping-from-client").await.unwrap();
            let mut buf = [0u8; 16];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong-from-server");
            stream.peer().clone()
        }
    });

    let mut accepted: AuthenticatedStream = runtime
        .block_on(server.accept())
        .expect("server accept + client authentication");

    // The server has already validated the client identity before returning.
    assert_eq!(accepted.peer().pid, std::process::id());
    assert_eq!(accepted.local().user_sid, accepted.peer().user_sid);
    assert!(accepted.peer().logon_sid.is_some());

    runtime
        .block_on(async {
            let mut buf = [0u8; 16];
            accepted.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping-from-client");
            accepted.write_all(b"pong-from-server").await.unwrap();
            accepted.flush().await.unwrap();
        });

    let peer = runtime.block_on(client_task).unwrap();
    assert_eq!(peer.user_sid, own.user_sid);
    assert_eq!(peer.session_id, own.session_id);
}

