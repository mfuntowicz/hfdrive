#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use hfdrive_protocol::{ClientRole, Envelope, HelloRequest, Request, read_envelope, write_envelope};
use hfdrive_provider::{MAX_CLIENTS, Provider, serve};
use hfdrive_state::StatePaths;
use hfdrive_windows::{ipc::{IpcClient, IpcPolicy, IpcServer}, ownership::{ProviderLease, default_state_root}};
use std::{process::ExitCode, sync::Arc};
use tokio::{sync::Semaphore, task::JoinSet};

#[derive(Debug, thiserror::Error)]
enum HostError {
    #[error(transparent)]
    Ipc(#[from] hfdrive_windows::IpcError),
    #[error(transparent)]
    Ownership(#[from] hfdrive_windows::OwnershipError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Protocol(#[from] hfdrive_protocol::ProtocolCodecError),
    #[error(transparent)]
    State(#[from] hfdrive_state::StateError),
    #[error(transparent)]
    Engine(#[from] hfdrive_provider::sync::EngineError),
    #[error("existing provider did not complete protocol negotiation")]
    Handshake,
    #[error("structured logging could not initialize")]
    Logging,
}

fn policy() -> Result<IpcPolicy, HostError> {
    let policy = IpcPolicy::for_current_process()?;
    #[cfg(debug_assertions)]
    {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
        let output = root.join("target/x86_64-pc-windows-msvc/debug");
        let mut policy = policy.with_dev_allow_path(output.join("hfdrive.exe"))
            .with_dev_allow_path(output.join("hfdrive-provider.exe"));
        if let Some(path) = option_env!("HFDRIVE_DEV_DESKTOP_PATH") {
            policy = policy.with_dev_allow_path(std::path::PathBuf::from(path));
        }
        return Ok(policy);
    }
    #[cfg(not(debug_assertions))]
    Ok(policy)
}

fn main() -> ExitCode {
    // AWS SDK/S3 request futures have deep native call stacks. Give Tokio
    // workers an explicit bounded stack instead of relying on the small
    // platform default or a process-global RUST_MIN_STACK override.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(16 * 1024 * 1024)
        .build()
        .expect("provider Tokio runtime");
    runtime.block_on(async_main())
}

async fn async_main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("hfdrive-provider: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), HostError> {
    tracing_subscriber::fmt().json()
        .with_env_filter("off,hfdrive_provider=info,hfdrive_windows=warn")
        .try_init().map_err(|_| HostError::Logging)?;
    let state_root = default_state_root()?;
    let policy = policy()?;
    let _lease = match ProviderLease::acquire(&state_root) {
        Ok(lease) => lease,
        Err(hfdrive_windows::OwnershipError::AlreadyRunning) => {
            let mut stream = IpcClient::connect(&policy).await?;
            let id = uuid::Uuid::new_v4();
            let request = Request::Hello(HelloRequest {
                protocol_major: 1, protocol_minor: 0, role: ClientRole::Cli,
                build_version: env!("CARGO_PKG_VERSION").to_owned(),
            });
            write_envelope(&mut stream, &Envelope::request(id, request)).await?;
            let reply = tokio::time::timeout(std::time::Duration::from_secs(10), read_envelope(&mut stream))
                .await.map_err(|_| HostError::Handshake)??.ok_or(HostError::Handshake)?;
            if reply.request_id != id || !matches!(reply.body, hfdrive_protocol::Body::Response { outcome: Ok(hfdrive_protocol::ResponseResult::Hello(_)) }) {
                return Err(HostError::Handshake);
            }
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let provider = Provider::open(StatePaths::new(state_root), std::env::var(hfdrive_auth::OAUTH_CLIENT_ID_ENV).ok(), _lease.user_sid().to_owned()).await?;
    tokio::spawn(provider.clone().observe_accounts());
    let server = IpcServer::bind(policy)?;
    let permits = Arc::new(Semaphore::new(MAX_CLIENTS));
    let mut clients = JoinSet::new();
    tracing::info!(protocol_major = 1, protocol_minor = 0, "provider IPC ready");
    loop {
        tokio::select! {
            _ = provider.shutdown.cancelled() => break,
            signal = tokio::signal::ctrl_c() => {
                signal?;
                provider.shutdown.cancel();
            }
            result = clients.join_next(), if !clients.is_empty() => {
                if result.is_some_and(|result| result.is_err()) {
                    tracing::warn!("client worker terminated unexpectedly");
                }
            }
            connection = server.accept() => {
                match connection {
                    Ok(stream) => {
                        let Ok(permit) = permits.clone().try_acquire_owned() else { drop(stream); continue; };
                        let provider = provider.clone();
                        clients.spawn(async move {
                            let _permit = permit;
                            serve(stream, provider).await;
                        });
                    }
                    Err(error) => {
                        tracing::warn!(error = %error, "IPC accept failed");
                        tokio::select! {
                            _ = provider.shutdown.cancelled() => break,
                            _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {}
                        }
                    }
                }
            }
        }
    }
    provider.shutdown.cancel();
    provider.drain().await?;
    while clients.join_next().await.is_some() {}
    tracing::info!("provider stopped; durable work retained");
    Ok(())
}
