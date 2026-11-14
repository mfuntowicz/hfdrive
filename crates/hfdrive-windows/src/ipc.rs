//! Authenticated local IPC over a per-user named pipe.
//!
//! # Boundary
//!
//! The provider exposes `\\.\pipe\LOCAL\HFDrive.<user-SID>.v1`:
//!
//! * Duplex, byte-mode, **overlapped** (Tokio-managed) named pipe.
//! * `PIPE_REJECT_REMOTE_CLIENTS`: remote named-pipe clients are refused by
//!   the kernel, not by a check after the fact.
//! * The pipe's DACL grants access to exactly the provider's **logon SID**
//!   (the per-logon authorization identifier of the interactive logon the
//!   provider runs in) and SYSTEM. An unrelated local user — and even
//!   another process of the same user outside that logon — cannot open the
//!   pipe. (Credential files and the global mutex use user SID + SYSTEM,
//!   which is the correct shape for those objects.)
//! * Created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a second server
//!   instance for the same name cannot bind it (first-instance protection).
//!
//! # Peer authentication
//!
//! **No protocol byte is exchanged before both sides have authenticated the
//! other.** The server authenticates the connecting client (PID from the pipe
//! handle, then the process token, logon SID via pipe impersonation, package
//! identity, and image path); the client authenticates the server the same
//! way. Both use the same [`IpcPolicy`] rules:
//!
//! 1. Same user SID, same logon session, and **both** sides must present the
//!    same token logon SID. A token without a logon SID (a non-interactive
//!    service context) is refused: it cannot prove it belongs to the
//!    provider's interactive logon.
//! 2. Integrity level at or above [`IpcPolicy::min_integrity_rid`] (default:
//!    medium).
//! 3. Package identity: when the local process is packaged, the peer must
//!    belong to the same package family and its image must live inside the
//!    package's install directory ("its image belongs to the installed
//!    package").
//! 4. Development builds may additionally accept **unpackaged** peers whose
//!    canonical image path is one of the exact allowlisted build outputs
//!    ([`IpcPolicy::with_dev_allow_path`]). In release builds that allowlist
//!    is compiled out: it cannot match, and an unpackaged peer is refused.
//!
//! Failures are reported as structured [`IpcError`] values with no secret or
//! stack-trace content; a rejected connection is closed immediately.
//!
//! # Streams
//!
//! [`AuthenticatedStream`] implements [`tokio::io::AsyncRead`] and
//! [`tokio::io::AsyncWrite`] and exposes the verified [`PeerIdentity`] of the
//! remote side (safe to log; see [`PeerIdentity::sanitized`]). Protocol
//! framing (`read_frame`/`write_frame`) belongs to `hfdrive-protocol` and is
//! layered on top of this stream by the provider/CLI.
//!
//! # Typical use
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use hfdrive_windows::ipc::{IpcPolicy, IpcServer};
//!
//! let policy = IpcPolicy::for_current_process()?;
//! let server = IpcServer::bind(policy)?;
//! let stream = server.accept().await?; // authenticated; then Hello framing
//! # Ok(()) }
//! ```
//!
//! # Error notes for integrators
//!
//! * [`IpcError::ForeignUser`], [`ForeignSession`], [`ForeignLogonSid`],
//!   [`InsufficientIntegrity`], [`PackageMismatch`], [`ImageMismatch`], and
//!   [`DevImageNotAllowed`] all mean "refuse and log", never "retry".
//! * [`IpcError::PipeUnavailable`] on the client side means the provider is
//!   not running or refused us; the CLI/UI should report "provider not
//!   running" and offer to start it.
//! * `accept()` errors do not close the server; call it again.

use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer};

use crate::error::IpcError;
use crate::ffi::acl;
use crate::ffi::handle::OwnedHandle;
use crate::ffi::package::{self, PackageIdentity};
use crate::ffi::pipe;
use crate::ffi::process::PeerProcess;
use crate::ffi::token::{self, DEFAULT_MIN_INTEGRITY_RID, TokenIdentity};

/// Protocol-major-neutral pipe name for this user.
///
/// `\\.\pipe\LOCAL\HFDrive.<user-SID>.v1`. The `LOCAL\` prefix states the
/// pipe's scope; `PIPE_REJECT_REMOTE_CLIENTS` enforces it at the kernel.
pub fn pipe_name(user_sid: &str) -> String {
    pipe::pipe_name(user_sid)
}

/// The exact canonical development build outputs of the HF Drive workspace
/// at `repo_root`, used as the Debug-only peer-image allowlist:
///
/// * `target/x86_64-pc-windows-msvc/debug/hfdrive-provider.exe`
/// * `target/x86_64-pc-windows-msvc/debug/hfdrive.exe`
/// * `desktop/HfDrive.Desktop/bin/x64/Debug/net11.0-windows10.0.26100.0/win-x64/HfDrive.Desktop.exe`
///
/// Nothing else is accepted as a development peer, and the list has no
/// effect in release builds (see [`IpcPolicy::with_dev_allow_path`]).
pub fn canonical_dev_allowlist(repo_root: &Path) -> Vec<PathBuf> {
    let target = repo_root.join("target/x86_64-pc-windows-msvc/debug");
    vec![
        target.join("hfdrive-provider.exe"),
        target.join("hfdrive.exe"),
        repo_root.join(
            "desktop/HfDrive.Desktop/bin/x64/Debug/net11.0-windows10.0.26100.0/win-x64/HfDrive.Desktop.exe",
        ),
    ]
}

/// Verified identity facts about a pipe peer (or about this process).
///
/// Contains no secrets: SIDs, PIDs, session IDs, integrity RIDs, package
/// names, and image paths are identity facts. [`PeerIdentity::sanitized`]
/// yields a form with the image path reduced to its file name for logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Process ID.
    pub pid: u32,
    /// Logon session ID (`TokenSessionId`).
    pub session_id: u32,
    /// Token user SID string, e.g. `S-1-5-21-...`.
    pub user_sid: String,
    /// Token logon SID string (per-logon authorization identifier), when the
    /// token carries one.
    pub logon_sid: Option<String>,
    /// RID of the mandatory integrity-level SID (e.g. 8192 = medium).
    pub integrity_rid: u32,
    /// Package family name when the peer is packaged.
    pub package_family: Option<String>,
    /// Package full name when the peer is packaged.
    pub package_full_name: Option<String>,
    /// Canonical Win32 image path of the peer process.
    pub image_path: String,
}

impl PeerIdentity {
    /// A loggable projection: image reduced to its file name, no paths.
    pub fn sanitized(&self) -> SanitizedIdentity {
        SanitizedIdentity {
            pid: self.pid,
            session_id: self.session_id,
            user_sid: self.user_sid.clone(),
            logon_sid: self.logon_sid.clone(),
            integrity_rid: self.integrity_rid,
            package_family: self.package_family.clone(),
            image_name: Path::new(&self.image_path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "<unknown>".to_owned()),
        }
    }
}

/// Loggable projection of a [`PeerIdentity`] (no filesystem paths).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedIdentity {
    /// Process ID.
    pub pid: u32,
    /// Logon session ID.
    pub session_id: u32,
    /// Token user SID string.
    pub user_sid: String,
    /// Token logon SID string, when present.
    pub logon_sid: Option<String>,
    /// Integrity RID.
    pub integrity_rid: u32,
    /// Package family name, when packaged.
    pub package_family: Option<String>,
    /// Image file name only.
    pub image_name: String,
}

/// Peer-validation policy for both sides of the pipe.
///
/// See the module docs for the exact acceptance rules. Construct with
/// [`IpcPolicy::for_current_process`] (derives the expected package from the
/// current process's own package identity) and refine with the builder
/// methods.
#[derive(Debug, Clone)]
pub struct IpcPolicy {
    min_integrity_rid: u32,
    expected_package_family: Option<String>,
    expected_package_path: Option<PathBuf>,
    dev_allow_paths: Vec<PathBuf>,
}

impl IpcPolicy {
    /// Policy derived from the current process: expected package family and
    /// install path come from our own package identity (absent when this
    /// process is unpackaged), and the minimum integrity level is medium.
    pub fn for_current_process() -> Result<Self, IpcError> {
        let identity = package::current_package().map_err(package_err)?;
        let (expected_package_family, expected_package_path) = match identity {
            Some(PackageIdentity {
                family_name,
                install_path,
                ..
            }) => (Some(family_name), install_path.map(PathBuf::from)),
            None => (None, None),
        };
        Ok(Self {
            min_integrity_rid: DEFAULT_MIN_INTEGRITY_RID,
            expected_package_family,
            expected_package_path,
            dev_allow_paths: Vec::new(),
        })
    }

    /// Require a specific package family (overrides the derived one).
    pub fn with_expected_package_family(mut self, family: impl Into<String>) -> Self {
        self.expected_package_family = Some(family.into());
        self
    }

    /// Set the package install directory used for "image belongs to the
    /// installed package" validation.
    pub fn with_expected_package_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.expected_package_path = Some(path.into());
        self
    }

    /// Raise or lower the minimum accepted integrity RID. The default
    /// (medium) accepts ordinary interactive processes; do not lower it
    /// without a documented reason.
    pub fn with_min_integrity_rid(mut self, rid: u32) -> Self {
        self.min_integrity_rid = rid;
        self
    }

    /// Allow one exact canonical development build output for **unpackaged**
    /// peers.
    ///
    /// Paths must be absolute, canonical build outputs (for example
    /// `F:/Workspace/hfdrive/target/x86_64-pc-windows-msvc/debug/hfdrive.exe`).
    /// Matching is exact apart from ASCII case and separator style.
    ///
    /// **Release builds ignore this list entirely** (it is compiled out by
    /// `debug_assertions`): an unpackaged peer is always refused in release.
    pub fn with_dev_allow_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.dev_allow_paths.push(path.into());
        self
    }

    /// Allow exactly the canonical HF Drive development build outputs under
    /// `repo_root` (see [`canonical_dev_allowlist`]). Debug builds only; in
    /// release the list is inert.
    pub fn with_default_dev_allowlist(mut self, repo_root: &Path) -> Self {
        self.dev_allow_paths
            .extend(canonical_dev_allowlist(repo_root));
        self
    }

    /// The minimum accepted integrity RID in force.
    pub fn min_integrity_rid(&self) -> u32 {
        self.min_integrity_rid
    }

    /// The expected package family, when this policy expects a package.
    pub fn expected_package_family(&self) -> Option<&str> {
        self.expected_package_family.as_deref()
    }

    /// Validate a peer identity against this policy given our own identity.
    pub fn verify(&self, peer: &PeerIdentity, ours: &PeerIdentity) -> Result<(), IpcError> {
        if !sid_eq(&peer.user_sid, &ours.user_sid) {
            return Err(IpcError::ForeignUser);
        }
        if peer.session_id != ours.session_id {
            return Err(IpcError::ForeignSession {
                peer_session_id: peer.session_id,
            });
        }
        match (&peer.logon_sid, &ours.logon_sid) {
            (Some(p), Some(o)) if sid_eq(p, o) => {}
            // Fail closed: a token without a logon SID (non-interactive
            // service context) can never prove it belongs to the provider's
            // interactive logon, so it is refused.
            _ => return Err(IpcError::ForeignLogonSid),
        }
        if peer.integrity_rid < self.min_integrity_rid {
            return Err(IpcError::InsufficientIntegrity {
                peer_rid: peer.integrity_rid,
                min_rid: self.min_integrity_rid,
            });
        }
        match (&self.expected_package_family, &peer.package_family) {
            (Some(expected), Some(family)) => {
                if !expected.eq_ignore_ascii_case(family) {
                    return Err(IpcError::PackageMismatch);
                }
                // "its image belongs to the installed package"
                if let Some(install) = &self.expected_package_path {
                    if !path_under(&peer.image_path, install) {
                        return Err(IpcError::ImageMismatch);
                    }
                }
            }
            (Some(_), None) => {
                // We are packaged; an unpackaged peer is only acceptable as
                // an explicitly allowlisted development build output, and
                // only in debug builds.
                if !self.dev_allow_matches(&peer.image_path) {
                    return Err(IpcError::DevImageNotAllowed);
                }
            }
            (None, Some(_)) => {
                // We are unpackaged (development). A packaged peer is not
                // the HF Drive package we expect to talk to.
                return Err(IpcError::PackageMismatch);
            }
            (None, None) => {
                if !self.dev_allow_matches(&peer.image_path) {
                    return Err(IpcError::DevImageNotAllowed);
                }
            }
        }
        Ok(())
    }

    /// Debug-only development image allowlist check. In release builds this
    /// always returns `false`, so the allowlist cannot escape into release.
    fn dev_allow_matches(&self, image_path: &str) -> bool {
        #[cfg(debug_assertions)]
        {
            self.dev_allow_paths
                .iter()
                .any(|allowed| paths_eq(image_path, allowed))
        }
        #[cfg(not(debug_assertions))]
        {
            let _ = (image_path, &self.dev_allow_paths);
            false
        }
    }
}

/// The provider side of the IPC boundary.
///
/// `bind` creates the first pipe instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`
/// (first-instance protection). `accept` authenticates each connection before
/// returning it; failed connections are closed and reported, and do not stop
/// the server.
pub struct IpcServer {
    policy: IpcPolicy,
    name: String,
    pending: tokio::sync::Mutex<NamedPipeServer>,
}

impl IpcServer {
    /// Bind the per-user pipe for the current user.
    ///
    /// The caller should hold the [`crate::ownership::ProviderLease`] before
    /// binding; the first-instance flag is a second line of defence.
    pub fn bind(policy: IpcPolicy) -> Result<Self, IpcError> {
        Self::bind_named(policy, &current_pipe_name()?)
    }

    /// Bind a specific pipe name (used by tests to run a server and client in
    /// one process without claiming the real per-user name).
    pub fn bind_named(policy: IpcPolicy, name: &str) -> Result<Self, IpcError> {
        let mut dacl = acl::logon_system_dacl().map_err(dacl_err)?;
        let attrs = dacl.attributes();
        let first = pipe::create_server(name, &attrs, true).map_err(pipe_err)?;
        let pending = into_server(first)?;
        Ok(Self {
            policy,
            name: name.to_owned(),
            pending: tokio::sync::Mutex::new(pending),
        })
    }

    /// The pipe name this server is bound to.
    pub fn pipe_name(&self) -> &str {
        &self.name
    }

    /// Accept one connection and authenticate the peer.
    ///
    /// Returns [`IpcError`] for a refused peer; the connection is closed and
    /// the server keeps running. Nothing is read from or written to the
    /// connection before authentication succeeds.
    pub async fn accept(&self) -> Result<AuthenticatedStream, IpcError> {
        loop {
            // The lock serializes accept calls. While it is held we await the
            // connection on the instance that is already waiting for a
            // client, then install the next instance: the pipe name therefore
            // never disappears between two accepted connections.
            let connection = {
                let mut slot = self.pending.lock().await;
                slot.connect().await.map_err(IpcError::Io)?;
                let mut dacl = acl::logon_system_dacl().map_err(dacl_err)?;
                let attrs = dacl.attributes();
                let handle = pipe::create_server(&self.name, &attrs, false).map_err(pipe_err)?;
                let next = into_server(handle)?;
                std::mem::replace(&mut *slot, next)
            };
            match self.authenticate_server_side(&connection) {
                Ok(identity) => {
                    return Ok(AuthenticatedStream::Server {
                        inner: connection,
                        peer: identity,
                        local: own_identity()?,
                    });
                }
                Err(e) => {
                    // Refuse: close the connection (drop) and keep accepting.
                    drop(connection);
                    tracing::debug!(error = %e, "ipc peer refused");
                    continue;
                }
            }
        }
    }

    /// Authenticate the client connected to `connection`.
    fn authenticate_server_side(&self, connection: &NamedPipeServer) -> Result<PeerIdentity, IpcError> {
        use std::os::windows::io::AsRawHandle;
        let raw = windows::Win32::Foundation::HANDLE(connection.as_raw_handle() as *mut core::ffi::c_void);
        // 1. PID from the pipe itself (kernel-authoritative).
        let pid = pipe::client_pid(raw).map_err(pipe_err)?;
        // 2. Process token identity (user, session, integrity, logon SID via
        //    impersonation of this very connection).
        let process = PeerProcess::open(pid).map_err(|e| peer_err(pid, e))?;
        let token_identity = process.identity().map_err(|e| peer_err(pid, e))?;
        let logon_sid = pipe::ImpersonationGuard::impersonate_client(raw)
            .ok()
            .and_then(|guard| guard.identity().ok())
            .and_then(|impersonated| impersonated.logon_sid)
            .map(|sid| sid.to_string().unwrap_or_default())
            .filter(|s| !s.is_empty());
        // Prefer the logon SID observed through impersonation; fall back to
        // the process token's groups when impersonation is unavailable.
        let logon_sid = logon_sid.or_else(|| {
            token_identity
                .logon_sid
                .as_ref()
                .and_then(|sid| sid.to_string())
        });
        let peer = build_identity(pid, &token_identity, logon_sid, &process)?;
        let ours = own_identity()?;
        self.policy.verify(&peer, &ours)?;
        Ok(peer)
    }
}

/// The client side of the IPC boundary.
pub struct IpcClient;

impl IpcClient {
    /// Connect to the current user's provider pipe and authenticate the
    /// server before returning the stream.
    ///
    /// Retries briefly while all pipe instances are busy (`ERROR_PIPE_BUSY`)
    /// and reports [`IpcError::PipeUnavailable`] when no provider answers.
    pub async fn connect(policy: &IpcPolicy) -> Result<AuthenticatedStream, IpcError> {
        Self::connect_named(policy, &current_pipe_name()?).await
    }

    /// Connect to a specific pipe name (tests / non-default deployments).
    pub async fn connect_named(policy: &IpcPolicy, name: &str) -> Result<AuthenticatedStream, IpcError> {
        let client = open_with_retry(name).await?;
        let identity = authenticate_client_side(&client, policy)?;
        Ok(AuthenticatedStream::Client {
            inner: client,
            peer: identity,
            local: own_identity()?,
        })
    }
}

/// An authenticated, framed-ready pipe stream.
///
/// Implements [`AsyncRead`]/[`AsyncWrite`]; the remote side's identity has
/// been verified against the policy before this value exists. Protocol
/// framing is layered on top by `hfdrive-protocol`.
pub enum AuthenticatedStream {
    /// Provider side: connected and authenticated client.
    Server {
        inner: NamedPipeServer,
        peer: PeerIdentity,
        local: PeerIdentity,
    },
    /// Client side: connected and authenticated provider.
    Client {
        inner: NamedPipeClient,
        peer: PeerIdentity,
        local: PeerIdentity,
    },
}

impl AuthenticatedStream {
    /// The verified remote identity.
    pub fn peer(&self) -> &PeerIdentity {
        match self {
            Self::Server { peer, .. } | Self::Client { peer, .. } => peer,
        }
    }

    /// The local identity used during verification.
    pub fn local(&self) -> &PeerIdentity {
        match self {
            Self::Server { local, .. } | Self::Client { local, .. } => local,
        }
    }
}

impl AsyncRead for AuthenticatedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Server { inner, .. } => Pin::new(inner).poll_read(cx, buf),
            Self::Client { inner, .. } => Pin::new(inner).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AuthenticatedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Server { inner, .. } => Pin::new(inner).poll_write(cx, buf),
            Self::Client { inner, .. } => Pin::new(inner).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Server { inner, .. } => Pin::new(inner).poll_flush(cx),
            Self::Client { inner, .. } => Pin::new(inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Server { inner, .. } => Pin::new(inner).poll_shutdown(cx),
            Self::Client { inner, .. } => Pin::new(inner).poll_shutdown(cx),
        }
    }
}

/// Identity facts of the current process (pid, session, SIDs, package, image).
///
/// Used by the provider and CLI for status/diagnostics and as the "ours" side
/// of peer verification.
pub fn own_identity() -> Result<PeerIdentity, IpcError> {
    let pid = std::process::id();
    let process = PeerProcess::open(pid).map_err(|e| peer_err(pid, e))?;
    let token_identity = process.identity().map_err(|e| peer_err(pid, e))?;
    let logon_sid = token_identity
        .logon_sid
        .as_ref()
        .and_then(|sid| sid.to_string());
    build_identity(pid, &token_identity, logon_sid, &process)
}

/// The pipe name of the current user's provider pipe.
pub fn current_pipe_name() -> Result<String, IpcError> {
    let user = token::current_process_user_sid().map_err(token_err)?;
    let sid = user.to_string().ok_or(IpcError::Win32 { code: 1337 })?;
    Ok(pipe::pipe_name(&sid))
}

fn build_identity(
    pid: u32,
    token_identity: &TokenIdentity,
    logon_sid: Option<String>,
    process: &PeerProcess,
) -> Result<PeerIdentity, IpcError> {
    let user_sid = token_identity
        .user_sid
        .to_string()
        .ok_or(IpcError::Win32 { code: 1337 })?;
    // Package identity is a property of the *process* image, so the query
    // takes the process handle, not its token.
    let package = package::process_package(process.handle()).map_err(package_err)?;
    let (package_family, package_full_name) = match package {
        Some(PackageIdentity {
            family_name,
            full_name,
            ..
        }) => (Some(family_name), Some(full_name)),
        None => (None, None),
    };
    let image_path = process.image_path().map_err(|e| peer_err(pid, e))?;
    Ok(PeerIdentity {
        pid,
        session_id: token_identity.session_id,
        user_sid,
        logon_sid,
        integrity_rid: token_identity.integrity_rid,
        package_family,
        package_full_name,
        image_path,
    })
}

/// Authenticate the provider from the client side, before any payload.
fn authenticate_client_side(client: &NamedPipeClient, policy: &IpcPolicy) -> Result<PeerIdentity, IpcError> {
    use std::os::windows::io::AsRawHandle;
    let raw = windows::Win32::Foundation::HANDLE(client.as_raw_handle() as *mut core::ffi::c_void);
    let pid = pipe::server_pid(raw).map_err(pipe_err)?;
    let process = PeerProcess::open(pid).map_err(|e| peer_err(pid, e))?;
    let token_identity = process.identity().map_err(|e| peer_err(pid, e))?;
    let logon_sid = token_identity
        .logon_sid
        .as_ref()
        .and_then(|sid| sid.to_string());
    let peer = build_identity(pid, &token_identity, logon_sid, &process)?;
    let ours = own_identity()?;
    policy.verify(&peer, &ours)?;
    Ok(peer)
}

/// Open the client pipe, retrying briefly while instances are busy.
///
/// The QoS level is raised to `SECURITY_IMPERSONATION`: the server
/// impersonates the client to read its token logon SID, which requires the
/// client to open the pipe with at least identification→impersonation rights
/// (Tokio's default is `SECURITY_IDENTIFICATION`, which would make
/// `ImpersonateNamedPipeClient` fail).
async fn open_with_retry(name: &str) -> Result<NamedPipeClient, IpcError> {
    const ERROR_PIPE_BUSY: i32 = 231;
    const ATTEMPTS: u32 = 20;
    let qos = windows::Win32::Storage::FileSystem::SECURITY_IMPERSONATION.0;
    for attempt in 0..ATTEMPTS {
        match ClientOptions::new().security_qos_flags(qos).open(name) {
            Ok(client) => return Ok(client),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                let backoff = 25u64.saturating_mul(u64::from(attempt + 1)).min(250);
                tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
            }
            Err(e) => {
                return Err(IpcError::PipeUnavailable {
                    code: e.raw_os_error().unwrap_or(0) as u32,
                });
            }
        }
    }
    Err(IpcError::PipeUnavailable {
        code: ERROR_PIPE_BUSY as u32,
    })
}

/// Convert a raw `OwnedHandle` into a Tokio named-pipe server.
///
/// # Safety contract (upheld here)
/// `OwnedHandle` uniquely owns a `CreateNamedPipeW` server handle created
/// with `FILE_FLAG_OVERLAPPED`; `NamedPipeServer::from_raw_handle` takes that
/// ownership.
fn into_server(handle: OwnedHandle) -> Result<NamedPipeServer, IpcError> {
    use std::os::windows::io::IntoRawHandle;
    let raw = handle.into_raw_handle();
    // SAFETY: ownership transfers exactly once into Tokio's pipe wrapper.
    unsafe { NamedPipeServer::from_raw_handle(raw).map_err(IpcError::Io) }
}

/// Whether `path` is inside `root` on a path-segment basis (no `..` escape),
/// compared case-insensitively.
fn path_under(path: &str, root: &Path) -> bool {
    let normalize = |s: &str| -> String {
        s.replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_uppercase()
    };
    let path = normalize(path);
    let root = normalize(&root.to_string_lossy());
    path == root || path.starts_with(&format!("{root}\\"))
}

/// Exact path equality ignoring ASCII case and separator style.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
fn paths_eq(a: &str, b: &Path) -> bool {
    let normalize = |s: &str| s.replace('/', "\\").to_ascii_uppercase();
    normalize(a) == normalize(&b.to_string_lossy())
}

/// SID strings are produced by `ConvertSidToStringSidW`; compare exactly.
fn sid_eq(a: &str, b: &str) -> bool {
    a == b
}

fn pipe_err(e: windows::core::Error) -> IpcError {
    IpcError::Win32 {
        code: crate::ffi::error_code(&e),
    }
}

fn peer_err(pid: u32, e: windows::core::Error) -> IpcError {
    IpcError::PeerUnreachable {
        pid,
        code: crate::ffi::error_code(&e),
    }
}

fn token_err(e: windows::core::Error) -> IpcError {
    IpcError::Win32 {
        code: crate::ffi::error_code(&e),
    }
}

fn dacl_err(e: windows::core::Error) -> IpcError {
    IpcError::Win32 {
        code: crate::ffi::error_code(&e),
    }
}

fn package_err(code: u32) -> IpcError {
    IpcError::Win32 { code }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(
        user_sid: &str,
        session_id: u32,
        logon_sid: Option<&str>,
        integrity_rid: u32,
        package_family: Option<&str>,
        image_path: &str,
    ) -> PeerIdentity {
        PeerIdentity {
            pid: 4242,
            session_id,
            user_sid: user_sid.to_owned(),
            logon_sid: logon_sid.map(str::to_owned),
            integrity_rid,
            package_family: package_family.map(str::to_owned),
            package_full_name: None,
            image_path: image_path.to_owned(),
        }
    }

    fn unpackaged_policy() -> IpcPolicy {
        IpcPolicy {
            min_integrity_rid: DEFAULT_MIN_INTEGRITY_RID,
            expected_package_family: None,
            expected_package_path: None,
            dev_allow_paths: Vec::new(),
        }
    }

    #[test]
    fn accepts_matching_unlogged_dev_peer() {
        let ours = identity("S-1-5-21-1", 2, Some("S-1-5-5-1"), 8192, None, r"C:\dev\hfdrive.exe");
        let peer = identity("S-1-5-21-1", 2, Some("S-1-5-5-1"), 8192, None, r"C:\dev\hfdrive.exe");
        let policy = unpackaged_policy().with_dev_allow_path(r"C:\dev\hfdrive.exe");
        assert!(policy.verify(&peer, &ours).is_ok());
    }

    #[test]
    fn rejects_foreign_user() {
        let ours = identity("S-1-5-21-1", 2, Some("S-1-5-5-1"), 8192, None, r"C:\dev\a.exe");
        let peer = identity("S-1-5-21-2", 2, Some("S-1-5-5-1"), 8192, None, r"C:\dev\a.exe");
        let policy = unpackaged_policy();
        assert!(matches!(
            policy.verify(&peer, &ours),
            Err(IpcError::ForeignUser)
        ));
    }

    #[test]
    fn rejects_foreign_session() {
        let ours = identity("S-1-5-21-1", 2, Some("S-1-5-5-1"), 8192, None, r"C:\dev\a.exe");
        let peer = identity("S-1-5-21-1", 9, Some("S-1-5-5-1"), 8192, None, r"C:\dev\a.exe");
        let policy = unpackaged_policy();
        assert!(matches!(
            policy.verify(&peer, &ours),
            Err(IpcError::ForeignSession { peer_session_id: 9 })
        ));
    }

    #[test]
    fn rejects_missing_logon_sid_on_either_side() {
        // Peer lacks a logon SID (service context): refused.
        let ours = identity("S-1-5-21-1", 2, Some("S-1-5-5-1"), 8192, None, r"C:\dev\a.exe");
        let peer = identity("S-1-5-21-1", 2, None, 8192, None, r"C:\dev\a.exe");
        let policy = unpackaged_policy();
        assert!(matches!(
            policy.verify(&peer, &ours),
            Err(IpcError::ForeignLogonSid)
        ));

        // Both sides lack one (previously tolerated "both absent"): still
        // refused — fail closed, matching the provider contract.
        let ours = identity("S-1-5-21-1", 2, None, 8192, None, r"C:\dev\a.exe");
        let peer = identity("S-1-5-21-1", 2, None, 8192, None, r"C:\dev\a.exe");
        assert!(matches!(
            policy.verify(&peer, &ours),
            Err(IpcError::ForeignLogonSid)
        ));

        // Different logon SIDs: refused.
        let ours = identity("S-1-5-21-1", 2, Some("S-1-5-5-1"), 8192, None, r"C:\dev\a.exe");
        let peer = identity("S-1-5-21-1", 2, Some("S-1-5-5-2"), 8192, None, r"C:\dev\a.exe");
        assert!(matches!(
            policy.verify(&peer, &ours),
            Err(IpcError::ForeignLogonSid)
        ));
    }

    #[test]
    fn rejects_low_integrity() {
        let ours = identity("S-1-5-21-1", 2, Some("S-1-5-5-1"), 8192, None, r"C:\dev\a.exe");
        let peer = identity("S-1-5-21-1", 2, Some("S-1-5-5-1"), 4096, None, r"C:\dev\a.exe");
        let policy = unpackaged_policy();
        assert!(matches!(
            policy.verify(&peer, &ours),
            Err(IpcError::InsufficientIntegrity { peer_rid: 4096, min_rid: 8192 })
        ));
    }

    #[test]
    fn packaged_peer_must_match_family_and_image_location() {
        let ours = identity(
            "S-1-5-21-1",
            2,
            Some("S-1-5-5-1"),
            8192,
            Some("HFDrive_abc"),
            r"C:\Program Files\WindowsApps\HFDrive_abc\HfDrive.Desktop.exe",
        );
        let policy = unpackaged_policy()
            .with_expected_package_family("HFDrive_abc")
            .with_expected_package_path(r"C:\Program Files\WindowsApps\HFDrive_abc");

        // Matching family and image inside the package: accepted.
        let peer = identity(
            "S-1-5-21-1",
            2,
            Some("S-1-5-5-1"),
            8192,
            Some("HFDrive_abc"),
            r"C:\Program Files\WindowsApps\HFDrive_abc\provider\hfdrive-provider.exe",
        );
        assert!(policy.verify(&peer, &ours).is_ok());

        // Image outside the package install directory: refused.
        let outside = identity(
            "S-1-5-21-1",
            2,
            Some("S-1-5-5-1"),
            8192,
            Some("HFDrive_abc"),
            r"C:\Temp\hfdrive-provider.exe",
        );
        assert!(matches!(
            policy.verify(&outside, &ours),
            Err(IpcError::ImageMismatch)
        ));

        // Different package family: refused.
        let other_family = identity(
            "S-1-5-21-1",
            2,
            Some("S-1-5-5-1"),
            8192,
            Some("OtherPkg_xyz"),
            r"C:\Program Files\WindowsApps\HFDrive_abc\x.exe",
        );
        assert!(matches!(
            policy.verify(&other_family, &ours),
            Err(IpcError::PackageMismatch)
        ));

        // Unpackaged peer when we expect a package: dev allowlist decides,
        // and an unlisted image is refused.
        let unpackaged = identity(
            "S-1-5-21-1",
            2,
            Some("S-1-5-5-1"),
            8192,
            None,
            r"C:\dev\evil.exe",
        );
        assert!(matches!(
            policy.verify(&unpackaged, &ours),
            Err(IpcError::DevImageNotAllowed)
        ));
    }

    #[test]
    fn dev_allowlist_is_exact_and_cannot_escape() {
        let ours = identity("S-1-5-21-1", 2, Some("S-1-5-5-1"), 8192, None, r"C:\dev\hfdrive.exe");
        let root = PathBuf::from(r"F:\Workspace\hfdrive");
        let allowed = canonical_dev_allowlist(&root);
        let policy = unpackaged_policy().with_default_dev_allowlist(&root);

        // The exact canonical output is accepted (case/separators aside).
        let provider = identity(
            "S-1-5-21-1",
            2,
            Some("S-1-5-5-1"),
            8192,
            None,
            r"f:\workspace\hfdrive\target\x86_64-pc-windows-msvc\debug\hfdrive.exe",
        );
        assert_eq!(
            allowed[1],
            root.join("target/x86_64-pc-windows-msvc/debug/hfdrive.exe")
        );
        assert!(policy.verify(&provider, &ours).is_ok());

        // A sibling path that merely shares a prefix is refused.
        let prefix_sibling = identity(
            "S-1-5-21-1",
            2,
            Some("S-1-5-5-1"),
            8192,
            None,
            r"F:\Workspace\hfdrive\target\x86_64-pc-windows-msvc\debug\hfdrive.exe.evil",
        );
        assert!(matches!(
            policy.verify(&prefix_sibling, &ours),
            Err(IpcError::DevImageNotAllowed)
        ));

        // A subdirectory escape is refused.
        let escape = identity(
            "S-1-5-21-1",
            2,
            Some("S-1-5-5-1"),
            8192,
            None,
            r"F:\Workspace\hfdrive\target\x86_64-pc-windows-msvc\debug\..\debug\hfdrive.exe",
        );
        assert!(matches!(
            policy.verify(&escape, &ours),
            Err(IpcError::DevImageNotAllowed)
        ));

        // Arbitrary paths never work without an explicit allow entry.
        let arbitrary = identity("S-1-5-21-1", 2, Some("S-1-5-5-1"), 8192, None, r"C:\other\app.exe");
        assert!(matches!(
            policy.verify(&arbitrary, &ours),
            Err(IpcError::DevImageNotAllowed)
        ));
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn dev_allowlist_is_inert_in_release() {
        let ours = identity("S-1-5-21-1", 2, Some("S-1-5-5-1"), 8192, None, r"C:\dev\hfdrive.exe");
        let policy = unpackaged_policy().with_dev_allow_path(r"C:\dev\hfdrive.exe");
        // Even an explicitly allowlisted path is refused in release builds.
        assert!(matches!(
            policy.verify(&ours, &ours),
            Err(IpcError::DevImageNotAllowed)
        ));
    }

    #[test]
    fn sanitized_identity_hides_paths() {
        let peer = identity(
            "S-1-5-21-1",
            2,
            Some("S-1-5-5-1"),
            8192,
            None,
            r"C:\Users\Alice\AppData\Secrets\hfdrive.exe",
        );
        let sanitized = peer.sanitized();
        assert_eq!(sanitized.image_name, "hfdrive.exe");
        let dump = format!("{sanitized:?}");
        assert!(!dump.contains("Secrets"));
        assert!(!dump.contains("Alice"));
    }

    #[test]
    fn pipe_name_is_scoped_per_user() {
        assert_eq!(pipe_name("S-1-5-21-1"), r"\\.\pipe\LOCAL\HFDrive.S-1-5-21-1.v1");
    }
}
