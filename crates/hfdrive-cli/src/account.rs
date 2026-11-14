use crate::{CliError, client};
use hfdrive_protocol::{AuthenticationState, Body, CancelLoginRequest, ClientRole, Envelope, Event, HelloRequest, LoginPhase, Request, ResponseResult, StartLoginResult, SubscribeStatusRequest, read_envelope};
use hfdrive_windows::ipc::IpcClient;
use std::{io::Write, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub async fn wait_for_login<S>(stream: &mut S, login: StartLoginResult, cancel: &CancellationToken) -> Result<(), CliError>
where S: AsyncRead + AsyncWrite + Unpin {
    {
        let mut output = std::io::stdout().lock();
        if let (Some(uri), Some(code)) = (&login.verification_uri, &login.user_code) {
            writeln!(output, "Open {uri} and enter {code}. Expires {}.", login.expires_at)?;
        } else {
            writeln!(output, "Complete sign-in in your system browser. Expires {}.", login.expires_at)?;
        }
    }
    let deadline = tokio::time::sleep(Duration::from_secs(330));
    tokio::pin!(deadline);
    let result = tokio::select! {
        _ = cancel.cancelled() => Err(client::ClientError::Cancelled.into()),
        _ = &mut deadline => Err(CliError::Timeout),
        result = observe_login(stream, login.session_id, cancel) => result,
    };
    if cancel.is_cancelled() || matches!(result, Err(CliError::Timeout)) {
        // A cancelled frame may be partial. Never reuse that byte stream to send cancellation.
        if cancel_login_separately(login.session_id).await.is_err() {
            eprintln!("Login cancellation was not acknowledged; check account state before assuming authorization stopped.");
        }
    }
    result
}

async fn observe_login<S>(stream: &mut S, session_id: Uuid, cancel: &CancellationToken) -> Result<(), CliError>
where S: AsyncRead + AsyncWrite + Unpin {
    let snapshot = subscribe(stream, cancel).await?;
    let mut sequence = snapshot.sequence;
    if completed(&snapshot.account, session_id)? { return Ok(()); }
    loop {
        let envelope: Envelope = read_envelope(stream).await.map_err(client::ClientError::Codec)?
            .ok_or(client::ClientError::Closed)?;
        let Body::Event(Event::StatusChanged(status)) = envelope.body else { continue; };
        if status.sequence <= sequence { continue; }
        if !status.snapshot && sequence.checked_add(1) != Some(status.sequence) {
            let snapshot = subscribe(stream, cancel).await?;
            sequence = snapshot.sequence;
            if completed(&snapshot.account, session_id)? { return Ok(()); }
        } else {
            sequence = status.sequence;
            if completed(&status.account, session_id)? { return Ok(()); }
        }
    }
}

async fn subscribe<S>(stream: &mut S, cancel: &CancellationToken) -> Result<hfdrive_protocol::StatusSnapshot, CliError>
where S: AsyncRead + AsyncWrite + Unpin {
    match client::call(stream, Request::SubscribeStatus(SubscribeStatusRequest { last_sequence: None }), cancel).await? {
        ResponseResult::SubscribeStatus(result) if result.subscribed => Ok(result.snapshot),
        _ => Err(CliError::Response),
    }
}

fn completed(account: &hfdrive_protocol::AccountStatus, session_id: Uuid) -> Result<bool, CliError> {
    let Some(login) = &account.login else { return Err(CliError::LoginSuperseded); };
    if login.session_id != session_id { return Err(CliError::LoginSuperseded); }
    match login.phase {
        LoginPhase::Pending => Ok(false),
        LoginPhase::Completed => {
            if account.state != AuthenticationState::SignedIn { return Err(CliError::Response); }
            let profile = account.profile.as_ref().ok_or(CliError::Response)?;
            writeln!(std::io::stdout().lock(), "Signed in as {} (account {}).", profile.namespace, profile.account_key)?;
            Ok(true)
        }
        phase => {
            if let Some(error) = &account.last_error { return Err(client::ClientError::Remote(error.clone()).into()); }
            Err(CliError::LoginEnded(phase))
        }
    }
}

async fn cancel_login_separately(session_id: Uuid) -> Result<(), CliError> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let cancel = CancellationToken::new();
        let mut stream = IpcClient::connect(&crate::policy()?).await?;
        let hello = client::call(&mut stream, Request::Hello(HelloRequest {
            protocol_major: 1, protocol_minor: 0, role: ClientRole::Cli,
            build_version: env!("CARGO_PKG_VERSION").to_owned(),
        }), &cancel).await?;
        if !matches!(hello, ResponseResult::Hello(_)) { return Err(CliError::Response); }
        match client::call(&mut stream, Request::CancelLogin(CancelLoginRequest {
            operation_id: Uuid::new_v4(), session_id,
        }), &cancel).await? {
            ResponseResult::CancelLogin(_) => Ok(()),
            _ => Err(CliError::Response),
        }
    }).await.map_err(|_| CliError::Timeout)?
}
