mod account;
mod args;
mod client;

use args::{Cli, Command, ProviderCommand};
use clap::Parser;
use hfdrive_protocol::{ClientRole, ConnectRequest, ExitProviderRequest, ExportDiagnosticsRequest, GetStatusRequest, HelloRequest, ListBucketsRequest, ListConflictsRequest, ListHistoryRequest, ListOwnersRequest, LoginFlow, PrepareUnlinkRequest, ProbeStorageRequest, Request, ResponseResult, RestoreRequest, SignOutRequest, StartLoginRequest, UnlinkRequest};
use hfdrive_windows::ipc::{IpcClient, IpcPolicy};
use std::{io::Write, process::ExitCode, time::Duration};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error(transparent)]
    Ipc(#[from] hfdrive_windows::IpcError),
    #[error(transparent)]
    Client(#[from] client::ClientError),
    #[error(transparent)]
    Output(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("provider request timed out; accepted durable work may still be pending")]
    Timeout,
    #[error("provider returned an incompatible response")]
    Response,
    #[error("online-only content cannot open while the provider is stopped; repeat with --confirm to exit")]
    ExitConfirmation,
    #[error("this build does not advertise that command; no work was submitted")]
    Unavailable,
    #[error("another login attempt replaced this one; inspect the provider's current account state")]
    LoginSuperseded,
    #[error("login ended: {0:?}")]
    LoginEnded(hfdrive_protocol::LoginPhase),
}

fn policy() -> Result<IpcPolicy, CliError> {
    let policy = IpcPolicy::for_current_process()?;
    #[cfg(debug_assertions)]
    {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
        return Ok(policy.with_dev_allow_path(root.join("target/x86_64-pc-windows-msvc/debug/hfdrive-provider.exe")));
    }
    #[cfg(not(debug_assertions))]
    Ok(policy)
}

#[tokio::main]
async fn main() -> ExitCode {
    let arguments = Cli::parse();
    match run(arguments).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("hfdrive: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(arguments: Cli) -> Result<(), CliError> {
    if matches!(&arguments.command, Command::Provider { command: ProviderCommand::Exit { confirm: false } }) {
        return Err(CliError::ExitConfirmation);
    }
    let cancellation = CancellationToken::new();
    let stop = cancellation.clone();
    tokio::spawn(async move { if tokio::signal::ctrl_c().await.is_ok() { stop.cancel(); } });
    let mut stream = IpcClient::connect(&policy()?).await?;
    let hello = Request::Hello(HelloRequest {
        protocol_major: 1, protocol_minor: 0, role: ClientRole::Cli,
        build_version: env!("CARGO_PKG_VERSION").to_owned(),
    });
    let hello = tokio::time::timeout(Duration::from_secs(10), client::call(&mut stream, hello, &cancellation))
        .await.map_err(|_| CliError::Timeout)??;
    let ResponseResult::Hello(hello) = hello else { return Err(CliError::Response); };
    if hello.protocol_major != 1 || hello.protocol_minor != 0 { return Err(CliError::Response); }
    let request = match &arguments.command {
        Command::Status { .. } => Request::GetStatus(GetStatusRequest {}),
        Command::Login { device, purpose, organization_id } => Request::StartLogin(StartLoginRequest {
            operation_id: Uuid::new_v4(),
            flow: if *device { LoginFlow::Device } else { LoginFlow::Pkce },
            purpose: match purpose {
                args::LoginPurpose::Signin => hfdrive_protocol::LoginPurpose::Signin,
                args::LoginPurpose::ReadStorage => hfdrive_protocol::LoginPurpose::ReadStorage,
                args::LoginPurpose::WriteStorage => hfdrive_protocol::LoginPurpose::WriteStorage,
                args::LoginPurpose::CreateStorage => hfdrive_protocol::LoginPurpose::CreateStorage,
            },
            organization_id: organization_id.clone(),
        }),
        Command::Logout => Request::SignOut(SignOutRequest { operation_id: Uuid::new_v4() }),
        Command::Owners => Request::ListOwners(ListOwnersRequest { cursor: None, limit: 200 }),
        Command::Buckets { owner } => Request::ListBuckets(ListBucketsRequest { owner_namespace: owner.clone(), cursor: None, limit: 200 }),
        Command::Connect { accept_preview: Some(preview_id), .. } => Request::Connect(ConnectRequest {
            operation_id: Uuid::new_v4(), preview_id: *preview_id,
        }),
        Command::Probe { connection, run_id } => Request::ProbeStorage(ProbeStorageRequest {
            operation_id: Uuid::new_v4(), connection_id: *connection, run_id: *run_id,
        }),
        Command::History { item, cursor } => Request::ListHistory(ListHistoryRequest {
            connection_id: item.connection, item_id: Some(item.item), cursor: cursor.clone(), limit: 200,
        }),
        Command::Conflicts { connection, cursor } => Request::ListConflicts(ListConflictsRequest {
            connection_id: connection.connection, cursor: cursor.clone(), limit: 200,
        }),
        Command::Restore { item, version } => Request::Restore(RestoreRequest {
            operation_id: Uuid::new_v4(), connection_id: item.connection, item_id: item.item, version_id: *version,
        }),
        Command::Unlink { connection, accept_preview, export_to } => {
            if export_to.is_some() {
                return Err(CliError::Unavailable);
            }
            match accept_preview {
                Some(operation) => Request::Unlink(UnlinkRequest {
                    operation_id: *operation,
                    connection_id: connection.connection,
                    mode: hfdrive_protocol::UnlinkMode::SafeRemove,
                }),
                None => Request::PrepareUnlink(PrepareUnlinkRequest {
                    operation_id: Uuid::new_v4(),
                    connection_id: connection.connection,
                    mode: hfdrive_protocol::UnlinkMode::SafeRemove,
                }),
            }
        }
        Command::Diagnostics { command: args::DiagnosticsCommand::Export { output } } => {
            Request::ExportDiagnostics(ExportDiagnosticsRequest {
                operation_id: Uuid::new_v4(),
                connection_id: None,
                destination_path: output.to_string_lossy().into_owned(),
            })
        }
        Command::Provider { command: ProviderCommand::Exit { confirm: true } } => {
            Request::ExitProvider(ExitProviderRequest { operation_id: Uuid::new_v4() })
        }
        Command::Provider { command: ProviderCommand::PrepareUpgrade { .. } } => {
            Request::PrepareUpgrade(hfdrive_protocol::PrepareUpgradeRequest { operation_id: Uuid::new_v4() })
        }
        _ => return Err(CliError::Unavailable),
    };
    let request_timeout = match &arguments.command {
        Command::Probe { .. } => Duration::from_secs(180),
        _ => Duration::from_secs(30),
    };
    if !hello.supported_features.iter().any(|method| method == request.method()) { return Err(CliError::Unavailable); }
    let response = tokio::time::timeout(request_timeout, client::call(&mut stream, request, &cancellation))
        .await.map_err(|_| CliError::Timeout)??;
    match (&arguments.command, response) {
        (Command::Status { json }, ResponseResult::GetStatus(status)) => {
            let mut output = std::io::stdout().lock();
            if *json {
                serde_json::to_writer_pretty(&mut output, &status)?;
                writeln!(output)?;
            } else {
                writeln!(output, "Provider {} connected.", hello.provider_version)?;
                match status.account.state {
                    hfdrive_protocol::AuthenticationState::SignedIn => {
                        let profile = status.account.profile.as_ref().ok_or(CliError::Response)?;
                        writeln!(output, "Signed in as {} (account {}).", profile.namespace, profile.account_key)?;
                    }
                    hfdrive_protocol::AuthenticationState::SignedOut => writeln!(output, "Not signed in.")?,
                    hfdrive_protocol::AuthenticationState::SigningIn => writeln!(output, "Waiting for authorization.")?,
                    hfdrive_protocol::AuthenticationState::NeedsSignIn => writeln!(output, "Sign-in required; local work is retained.")?,
                }
                if status.connections.is_empty() { writeln!(output, "No configured connections.")?; }
                for connection in status.connections {
                    writeln!(output, "{}  {}  {} / {}  {}", connection.connection_id,
                        state_text(connection.state), connection.owner.namespace.as_deref().unwrap_or("namespace not reported"), connection.bucket.name, connection.root_path)?;
                }
            }
        }
        (Command::Login { .. }, ResponseResult::StartLogin(login)) => {
            account::wait_for_login(&mut stream, login, &cancellation).await?;
        }
        (Command::Logout, ResponseResult::SignOut(result)) if result.signed_out => {
            writeln!(std::io::stdout().lock(), "Signed out. Local work and registered folders are retained.")?;
        }
        (Command::Owners, ResponseResult::ListOwners(mut page)) => {
            let mut previous_cursor = None;
            loop {
                {
                    let mut output = std::io::stdout().lock();
                    for owner in page.items {
                        writeln!(output, "{:?}\t{}\t{}\trole={:?}\trestrictions={:?}", owner.owner_kind, owner.owner_id,
                            owner.namespace.as_deref().unwrap_or("namespace not reported"), owner.role, owner.restrictions)?;
                    }
                }
                let Some(cursor) = page.next_cursor else { break; };
                if previous_cursor.as_ref() == Some(&cursor) { return Err(CliError::Response); }
                previous_cursor = Some(cursor.clone());
                let result = tokio::time::timeout(request_timeout, client::call(&mut stream,
                    Request::ListOwners(ListOwnersRequest { cursor: Some(cursor), limit: 200 }), &cancellation))
                    .await.map_err(|_| CliError::Timeout)??;
                let ResponseResult::ListOwners(next) = result else { return Err(CliError::Response); };
                page = next;
            }
        }
        (Command::Buckets { owner }, ResponseResult::ListBuckets(mut page)) => {
            let mut previous_cursor = None;
            loop {
                {
                    let mut output = std::io::stdout().lock();
                    for bucket in page.items {
                        writeln!(output, "{}\t{}/{}\t{:?}", bucket.bucket_id, bucket.namespace, bucket.name, bucket.visibility)?;
                    }
                }
                let Some(cursor) = page.next_cursor else { break; };
                if previous_cursor.as_ref() == Some(&cursor) { return Err(CliError::Response); }
                previous_cursor = Some(cursor.clone());
                let result = tokio::time::timeout(request_timeout, client::call(&mut stream,
                    Request::ListBuckets(ListBucketsRequest { owner_namespace: owner.clone(), cursor: Some(cursor), limit: 200 }), &cancellation))
                    .await.map_err(|_| CliError::Timeout)??;
                let ResponseResult::ListBuckets(next) = result else { return Err(CliError::Response); };
                page = next;
            }
        }
        (Command::Connect { .. }, ResponseResult::Connect(result)) => {
            writeln!(std::io::stdout().lock(), "Connected {}. State: {:?}. Root: {}.",
                result.status.connection_id, result.status.state, result.status.root_path)?;
        }
        (Command::Probe { .. }, ResponseResult::ProbeStorage(result)) => {
            let mut output = std::io::stdout().lock();
            writeln!(output, "Probe {} capability: {:?}", result.run_id, result.capability)?;
            if let Some(path) = result.report_path { writeln!(output, "Report: {path}")?; }
            for check in result.checks {
                writeln!(output, "{:?}\t{:?}\t{}\t{}\t{}", check.kind, check.outcome, check.expected, check.observed, check.detail.unwrap_or_default())?;
            }
        }
        (Command::History { .. }, ResponseResult::ListHistory(mut page)) => {
            let mut previous_cursor = None;
            loop {
                {
                    let mut output = std::io::stdout().lock();
                    for record in page.items {
                        writeln!(output, "commit {}\tparent={:?}\tgeneration={}\tdevice={}\t{}",
                            record.commit_id, record.parent_commit_id,
                            record.generation.map(|id| id.to_string()).unwrap_or_else(|| "unknown".to_owned()),
                            record.device_id, record.created_at)?;
                        for change in record.changes {
                            writeln!(output, "  {}\t{:?}\t{}\tparent={:?}", change.item_id, change.kind, change.name, change.parent_id)?;
                        }
                    }
                }
                let Some(cursor) = page.next_cursor else { break; };
                if previous_cursor.as_ref() == Some(&cursor) { return Err(CliError::Response); }
                previous_cursor = Some(cursor.clone());
                let item = match &arguments.command {
                    Command::History { item, .. } => item,
                    _ => return Err(CliError::Response),
                };
                let result = tokio::time::timeout(request_timeout, client::call(&mut stream,
                    Request::ListHistory(ListHistoryRequest {
                        connection_id: item.connection, item_id: Some(item.item), cursor: Some(cursor), limit: 200,
                    }), &cancellation)).await.map_err(|_| CliError::Timeout)??;
                let ResponseResult::ListHistory(next) = result else { return Err(CliError::Response); };
                page = next;
            }
        }
        (Command::Conflicts { .. }, ResponseResult::ListConflicts(mut page)) => {
            let mut previous_cursor = None;
            loop {
                {
                    let mut output = std::io::stdout().lock();
                    for conflict in page.items {
                        writeln!(output, "conflict {}\titem={}\t{:?}\t{:?}\t{}", conflict.conflict_id,
                            conflict.item_id, conflict.kind, conflict.resolution_state, conflict.detected_at)?;
                        writeln!(output, "  operations={:?}\trevisions={:?}\tnames={:?}",
                            conflict.competing_operation_ids, conflict.revisions, conflict.original_names)?;
                    }
                }
                let Some(cursor) = page.next_cursor else { break; };
                if previous_cursor.as_ref() == Some(&cursor) { return Err(CliError::Response); }
                previous_cursor = Some(cursor.clone());
                let connection = match &arguments.command {
                    Command::Conflicts { connection, .. } => connection.connection,
                    _ => return Err(CliError::Response),
                };
                let result = tokio::time::timeout(request_timeout, client::call(&mut stream,
                    Request::ListConflicts(ListConflictsRequest {
                        connection_id: connection, cursor: Some(cursor), limit: 200,
                    }), &cancellation)).await.map_err(|_| CliError::Timeout)??;
                let ResponseResult::ListConflicts(next) = result else { return Err(CliError::Response); };
                page = next;
            }
        }
        (Command::Restore { .. }, ResponseResult::Restore(result)) => {
            writeln!(std::io::stdout().lock(), "Restore queued as operation {}. Connection state: {:?}.",
                result.operation_id, result.status.state)?;
        }
        (Command::Unlink { accept_preview: None, .. }, ResponseResult::PrepareUnlink(result)) => {
            let mut output = std::io::stdout().lock();
            writeln!(output, "Safe to unlink: {}. Online-only={} partial={} dirty={} conflicts={} export-bytes={}",
                result.safe_to_unlink, result.online_only_files, result.partial_files,
                result.dirty_files, result.conflict_files, result.required_export_bytes)?;
            for reason in result.blocking_reasons { writeln!(output, "Blocked: {reason}")?; }
        }
        (Command::Unlink { .. }, ResponseResult::Unlink(result)) => {
            writeln!(std::io::stdout().lock(), "Connection {} unregistered={} retained-for-recovery={}.",
                result.connection_id, result.unregistered, result.retained_for_recovery)?;
        }
        (Command::Diagnostics { .. }, ResponseResult::ExportDiagnostics(result)) => {
            writeln!(std::io::stdout().lock(), "Redacted diagnostics archive: {} (redacted={}).",
                result.archive_path, result.redacted)?;
        }
        (Command::Provider { command: ProviderCommand::Exit { .. } }, ResponseResult::ExitProvider(result)) if result.accepted => {
            writeln!(std::io::stdout().lock(), "Provider exit accepted. Registrations and durable work are retained.")?;
        }
        (Command::Provider { command: ProviderCommand::PrepareUpgrade { json } }, ResponseResult::PrepareUpgrade(result)) => {
            if !result.checkpointed { return Err(CliError::Response); }
            let mut output = std::io::stdout().lock();
            if *json {
                serde_json::to_writer(&mut output, &serde_json::json!({
                    "checkpointed": result.checkpointed, "pending_operations": result.pending_operations,
                }))?;
                writeln!(output)?;
            } else {
                writeln!(output, "Provider checkpointed and exited for upgrade; {} pending external operations retained.", result.pending_operations)?;
            }
        }
        _ => return Err(CliError::Response),
    }
    Ok(())
}

fn state_text(state: hfdrive_protocol::ConnectionState) -> &'static str {
    use hfdrive_protocol::ConnectionState::*;
    match state {
        UpToDate => "Up to date",
        PendingUpload => "Pending upload",
        Uploading => "Uploading",
        PublishingChanges => "Publishing changes",
        Downloading => "Downloading",
        Offline => "Offline",
        NeedsSignIn => "Needs sign-in",
        StorageSetupRequired => "Storage setup required",
        PermissionDenied => "Permission denied",
        Conflict => "Conflict",
        DiskFull => "Disk full",
        WriteSyncPaused => "Write sync paused",
    }
}
