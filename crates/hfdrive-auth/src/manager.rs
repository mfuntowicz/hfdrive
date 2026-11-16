//! `AuthManager`: the provider-owned authorization boundary.
//!
//! Responsibilities:
//!
//! * one outstanding login at a time (PKCE loopback or explicit device flow),
//!   with a monotonic-revision snapshot watch that publishes `Pending` before
//!   `start_login` returns and every terminal transition afterwards;
//! * DPAPI-protected per-account credential envelopes, atomically persisted
//!   **before** any token exposure (login and refresh alike);
//! * single-flight per-account refresh with the plan's refresh deadline
//!   (earlier of five minutes before expiry and 10% of the token lifetime),
//!   old-refresh-token retention on rotation, and `invalid_grant` failing
//!   closed to `NeedsSignIn` — never a retry loop;
//! * credential generations rotate immutable consumers while the
//!   authorization epoch stays untouched by refresh: a refreshed token can
//!   never revive a signed-out lease;
//! * sign-out cancels any pending login (a late callback can never activate),
//!   revokes the epoch before anything else, and removes usable session
//!   secrets while local work is preserved by the caller.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use hfdrive_core::ids::AccountKey;
use hfdrive_core::storage::Namespace;
use openidconnect::{OAuth2TokenResponse, TokenResponse as OidcTokenResponse};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::config::{self, AuthConfig, OidcSettings};
use crate::discovery::{self, Provider};
use crate::error::{self, AuthError};
use crate::flows::{self, CodeClient, HfTokenResponse};
use crate::identity::{validate_avatar_url, AccountProfile, OrgCandidate, VerifiedOrg};
use crate::login::{LoginFlow, LoginPurpose, LoginRequest, LoginSession, LoginState};
use crate::store::{account_credentials_dir, AccountCredentialStore, CredentialEnvelope, ENVELOPE_SCHEMA};
use crate::{AuthorizationAuthority, AuthorizationLease, SecretAccessToken, TokenSource};

/// Immutable ordering-token snapshot of the whole authorization state.
///
/// `revision` increases monotonically on every published change so a consumer
/// awaiting durable selected-account persistence can discard stale snapshots
/// (a later `Pending` can never mask `Completed` or a newer account state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSnapshot {
    /// Monotonic ordering token (strictly increasing per publish).
    pub revision: u64,
    /// The active verified identity, when signed in.
    pub profile: Option<AccountProfile>,
    /// The current (or most recent, terminal) login session.
    pub active_login: Option<LoginSession>,
    /// Most recent sanitized error, for diagnostics.
    pub last_error: Option<AuthError>,
}

/// Browser-launch boundary: opens exactly one validated authorization URL.
/// Production routes through `hfdrive_windows::shell` (system browser, one OS
/// argument, no shell string); deterministic tests inject their own launcher.
pub type BrowserLauncher = Arc<dyn Fn(&str) -> Result<(), AuthError> + Send + Sync>;

fn default_launcher() -> BrowserLauncher {
    Arc::new(|url| {
        hfdrive_windows::shell::open_in_system_browser(url).map_err(|_| AuthError::BrowserLaunch)
    })
}

/// The provider-owned authorization manager. Cheap to clone (shared state).
#[derive(Clone)]
pub struct AuthManager(Arc<Inner>);

struct Inner {
    config: AuthConfig,
    settings: OidcSettings,
    state_base: PathBuf,
    launcher: BrowserLauncher,
    http: Mutex<Option<Result<reqwest::Client, AuthError>>>,
    provider: tokio::sync::Mutex<Option<Arc<Provider>>>,
    accounts: Mutex<HashMap<AccountKey, Arc<AccountEntry>>>,
    active: Mutex<Option<AccountKey>>,
    login: Mutex<LoginSlot>,
    last_error: Mutex<Option<AuthError>>,
    watch_tx: tokio::sync::watch::Sender<AuthSnapshot>,
    revision: AtomicU64,
    cancel_epoch: AtomicU64,
    // Serialize durable credential commits with cancellation/removal. Never held across await.
    credential_commit: Mutex<()>,
    snapshot_publish: Mutex<()>,
    signing_out: AtomicBool,
}

struct LoginSlot {
    session: Option<LoginSession>,
    cancel: Option<CancellationToken>,
    cancel_epoch: u64,
}

struct AccountEntry {
    account: AccountKey,
    issuer: String,
    subject: String,
    authority: AuthorizationAuthority,
    refresh_lock: tokio::sync::Mutex<()>,
    shared: Mutex<SharedAccount>,
}

struct SharedAccount {
    token: Option<Arc<SecretAccessToken>>,
    refresh_token: Option<Zeroizing<String>>,
    refresh_due_at: u64,
    expires_at: u64,
    generation: u64,
    lifetime_secs: u64,
    needs_sign_in: bool,
    profile: AccountProfile,
    covered_purpose: LoginPurpose,
    login_flow: LoginFlow,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl AuthManager {
    /// Production constructor with the pinned Hugging Face OIDC policy.
    ///
    /// `restore` is the explicitly selected account (from the parent's
    /// durable selected-account pointer); nothing is ever scanned or guessed.
    /// A restored record whose issuer/subject no longer hash to `restore` is
    /// preserved untouched and surfaces as
    /// [`AuthError::ExistingSessionPreserved`] — the session is never rebound.
    pub fn new(config: AuthConfig, state_base: PathBuf, restore: Option<AccountKey>) -> Self {
        Self::with_settings(config, OidcSettings::huggingface(), state_base, restore)
    }

    /// Constructor with explicit OIDC trust settings (deterministic fixture
    /// providers in tests use the same code path).
    pub fn with_settings(
        config: AuthConfig,
        settings: OidcSettings,
        state_base: PathBuf,
        restore: Option<AccountKey>,
    ) -> Self {
        Self::with_settings_and_launcher(
            config,
            settings,
            state_base,
            restore,
            default_launcher(),
        )
    }

    /// Constructor with an explicit browser-launch boundary (tests only use
    /// this to stay deterministic; production uses
    /// [`hfdrive_windows::shell`]).
    pub fn with_settings_and_launcher(
        config: AuthConfig,
        settings: OidcSettings,
        state_base: PathBuf,
        restore: Option<AccountKey>,
        launcher: BrowserLauncher,
    ) -> Self {
        let (watch_tx, _) = tokio::sync::watch::channel(AuthSnapshot {
            revision: 0,
            profile: None,
            active_login: None,
            last_error: None,
        });
        let manager = Self(Arc::new(Inner {
            config,
            settings,
            state_base,
            launcher,
            http: Mutex::new(None),
            provider: tokio::sync::Mutex::new(None),
            accounts: Mutex::new(HashMap::new()),
            active: Mutex::new(None),
            login: Mutex::new(LoginSlot {
                session: None,
                cancel: None,
                cancel_epoch: 0,
            }),
            last_error: Mutex::new(None),
            watch_tx,
            revision: AtomicU64::new(0),
            cancel_epoch: AtomicU64::new(0),
            credential_commit: Mutex::new(()),
            snapshot_publish: Mutex::new(()),
            signing_out: AtomicBool::new(false),
        }));
        if let Some(account) = restore {
            let _ = manager.restore_account(account);
        } else {
            manager.publish();
        }
        manager
    }

    /// Snapshot watch. The current value always carries the newest revision.
    pub fn watch(&self) -> tokio::sync::watch::Receiver<AuthSnapshot> {
        self.0.watch_tx.subscribe()
    }

    /// The current snapshot.
    pub fn snapshot(&self) -> AuthSnapshot {
        self.0.watch_tx.borrow().clone()
    }

    /// The active verified identity, when signed in.
    pub fn active_profile(&self) -> Option<AccountProfile> {
        if self.0.signing_out.load(Ordering::SeqCst) { return None; }
        let active = *lock(&self.0.active);
        let entry = self.entry_opt(active?)?;
        Some(lock(&entry.shared).profile.clone())
    }

    /// The real on-disk credential record file name for the durable
    /// `credential_ref` (computed from the credential store's convention).
    pub fn credential_record_file_name(&self) -> String {
        AccountCredentialStore::record_file_name()
    }

    /// The authority epoch of an account (durable `auth_epoch`). Distinct
    /// from credential generations.
    pub fn authorization_epoch(&self, account: AccountKey) -> Result<u64, AuthError> {
        let entry = self.entry_opt(account).ok_or(AuthError::NeedsSignIn)?;
        entry.authority.current_epoch().map_err(|_| AuthError::Internal)
    }

    /// Restore the explicitly selected account from its protected record.
    pub fn restore_account(&self, account: AccountKey) -> Result<AccountProfile, AuthError> {
        let _commit = lock(&self.0.credential_commit);
        if self.0.signing_out.load(Ordering::SeqCst) {
            return Err(AuthError::SignOutInProgress);
        }
        // Restoration is startup-only, never an account switch or a way to revive logout.
        if !lock(&self.0.accounts).is_empty()
            || lock(&self.0.login).session.as_ref().is_some_and(|s| !s.state.is_terminal())
        {
            return Err(AuthError::ExistingSessionPreserved);
        }
        let restored = (|| {
            let dir = account_credentials_dir(&self.0.state_base, account);
            let envelope = AccountCredentialStore::open(dir, account)?.load()?;
            if AccountKey::from_subject(&envelope.issuer, &envelope.subject) != account {
                return Err(AuthError::ExistingSessionPreserved);
            }
            let (entry, profile) = entry_from_envelope(account, envelope)?;
            let needs_sign_in = lock(&entry.shared).needs_sign_in;
            if !needs_sign_in {
                entry.authority.activate().map_err(|_| AuthError::Internal)?;
            }
            Ok((entry, profile, needs_sign_in))
        })();
        let (entry, profile, needs_sign_in) = match restored {
            Ok(value) => value,
            Err(error) => {
                self.set_last_error(Some(error.clone()));
                self.publish();
                return Err(error);
            }
        };
        lock(&self.0.accounts).insert(account, entry);
        *lock(&self.0.active) = Some(account);
        self.set_last_error(needs_sign_in.then_some(AuthError::NeedsSignIn));
        self.publish();
        Ok(profile)
    }

    /// Run-local display backfill for one restored session.
    ///
    /// A credential envelope written before `avatar_url` existed restores with
    /// the avatar absent, so the account status would show the fallback avatar
    /// until a future login/refresh. This performs **one** bounded lookup
    /// against the already discovered/validated userinfo endpoint — the same
    /// verified route and subject agreement as login/refresh, through the same
    /// bounded HTTP path, but bearer-only so it works with no OAuth client id
    /// configured — and fills only the in-memory profile's `avatar_url`.
    ///
    /// It never rotates or rewrites tokens/envelopes and never touches the
    /// authorization epoch: it borrows the session's current access token
    /// directly (only while unexpired) for that one userinfo call — the
    /// `Self::access_token` boundary is never invoked, so the refresh path
    /// (token rotation, envelope rewrite, `invalid_grant` sign-in marking) is
    /// unreachable by construction. Any failure — including an unusable
    /// session — resolves to "no avatar", never to sign-out or a capability
    /// change. The fetched bearer is sent only to the trusted HF userinfo
    /// endpoint, never to the avatar URL.
    ///
    /// Idempotent: returns immediately when the profile already has a
    /// validated avatar. Callers bound the attempt per provider run.
    pub async fn backfill_avatar(&self, account: AccountKey) {
        if self.0.signing_out.load(Ordering::SeqCst)
            || *lock(&self.0.active) != Some(account)
        {
            return;
        }
        let Some(entry) = self.entry_opt(account) else { return };
        let (subject, bearer) = {
            let shared = lock(&entry.shared);
            if shared.needs_sign_in || shared.profile.avatar_url.is_some() {
                return;
            }
            // Display-only: borrow the session token as-is whenever it is
            // merely unexpired — the proactive refresh deadline is irrelevant
            // here. The token is used directly for the one userinfo call and
            // `Self::access_token` is never invoked, so no refresh (token
            // rotation, envelope rewrite, `NeedsSignIn` marking) is reachable.
            let now = unix_now();
            let Some(bearer) = shared.token.clone() else { return };
            if now >= bearer.expires_at() {
                return;
            }
            (shared.profile.subject.clone(), bearer)
        };
        let fetched = async {
            let provider = self.provider().await?;
            // The metadata endpoint is already discovered and strictly
            // validated (trusted host, HTTPS, no redirects) at discovery time.
            let userinfo_endpoint = provider
                .metadata
                .userinfo_endpoint()
                .ok_or(AuthError::ProviderMetadata)?;
            let http = self.http_client()?;
            // Bearer-only fetch: no CodeClient and no client id — a restored
            // session must backfill even when `HFDRIVE_OAUTH_CLIENT_ID` is
            // absent. Subject agreement is enforced by the same parser.
            let userinfo = flows::fetch_userinfo_bearer(
                userinfo_endpoint.as_str(),
                &http,
                bearer.as_str(),
                &subject,
            )
            .await?;
            Ok::<_, AuthError>(flows::avatar_from_userinfo(&userinfo))
        }
        .await;
        // Failure is avatar absence: never a sign-in or capability failure.
        // Only the sanitized error variant is logged (AuthError carries no
        // token, URL, or HTTP body).
        let avatar_url = match fetched {
            Ok(Some(avatar_url)) => Some(avatar_url),
            Ok(None) => {
                tracing::debug!("avatar backfill: no valid avatar claim; keeping fallback");
                None
            }
            Err(error) => {
                tracing::debug!(error = ?error, "avatar backfill failed; keeping fallback");
                None
            }
        };
        let Some(avatar_url) = avatar_url else { return };
        {
            // Only the restored session this fetch started from is updated; a
            // concurrent login/replacement entry keeps its own verified value.
            let Some(current) = self.entry_opt(account) else { return };
            if !Arc::ptr_eq(&current, &entry) { return; }
            let mut shared = lock(&current.shared);
            // Never clobber a value that login/refresh produced meanwhile.
            if shared.needs_sign_in || shared.profile.avatar_url.is_some() {
                return;
            }
            shared.profile.avatar_url = Some(avatar_url);
        }
        self.publish();
    }

    /// Start one login session. Only one may be outstanding at a time; the
    /// snapshot publishes `Pending` before this returns.
    pub fn start_login(
        &self,
        request: LoginRequest,
        cancel: CancellationToken,
    ) -> Result<LoginSession, AuthError> {
        let client_id = self.0.config.require_client_id()?.to_owned();
        let commit_guard = lock(&self.0.credential_commit);
        if self.0.signing_out.load(Ordering::SeqCst) {
            return Err(AuthError::SignOutInProgress);
        }
        let session_id = Uuid::new_v4();
        let expires_at_unix = unix_now() + self.0.settings.login_lifetime_secs;
        let session = LoginSession {
            session_id,
            flow: request.flow,
            purpose: request.purpose,
            state: LoginState::Pending,
            expires_at_unix,
            authorization_url: None,
            user_code: None,
            verification_uri: None,
            error: None,
        };
        let epoch = self.0.cancel_epoch.load(Ordering::SeqCst);
        {
            let mut slot = lock(&self.0.login);
            if slot.session.as_ref().is_some_and(|s| !s.state.is_terminal()) {
                return Err(AuthError::LoginAlreadyInProgress);
            }
            slot.session = Some(session.clone());
            slot.cancel = Some(cancel.clone());
            slot.cancel_epoch = epoch;
        }
        drop(commit_guard);
        self.publish();

        if tokio::runtime::Handle::try_current().is_err() {
            // No async runtime: fail the session instead of panicking.
            self.finish_session(session_id, Err(AuthError::Internal));
            return Err(AuthError::Internal);
        }
        let manager = self.clone();
        tokio::spawn(async move {
            let outcome = manager.run_login(request, session_id, cancel, client_id, epoch).await;
            manager.finish_session(session_id, outcome);
        });
        Ok(session)
    }

    /// Cancel a pending login. Returns false for unknown/terminal sessions.
    pub fn cancel_login(&self, session_id: Uuid) -> bool {
        let commit_guard = lock(&self.0.credential_commit);
        let mut slot = lock(&self.0.login);
        let matched = slot
            .session
            .as_ref()
            .is_some_and(|s| s.session_id == session_id && !s.state.is_terminal());
        if matched {
            self.0.cancel_epoch.fetch_add(1, Ordering::SeqCst);
            if let Some(session) = slot.session.as_mut() {
                session.state = LoginState::Cancelled;
                session.error = Some(AuthError::Cancelled);
            }
            if let Some(token) = slot.cancel.take() {
                token.cancel();
            }
            drop(slot);
            drop(commit_guard);
            self.publish();
        }
        matched
    }

    /// Await the actual outcome of a login session. The terminal session id
    /// stays visible until a new login supersedes it; a superseded id returns
    /// [`AuthError::UnknownLoginSession`] so clients error instead of
    /// observing the wrong attempt.
    pub async fn wait_for_login(&self, session_id: Uuid) -> Result<AccountProfile, AuthError> {
        let mut receiver = self.0.watch_tx.subscribe();
        loop {
            let snapshot = receiver.borrow().clone();
            match &snapshot.active_login {
                Some(session) if session.session_id == session_id => {
                    if session.state.is_terminal() {
                        return match (&session.state, &session.error) {
                            (LoginState::Completed, None) => {
                                snapshot.profile.ok_or(AuthError::Internal)
                            }
                            (_, Some(error)) => Err(error.clone()),
                            _ => Err(AuthError::Internal),
                        };
                    }
                }
                _ => return Err(AuthError::UnknownLoginSession),
            }
            if receiver.changed().await.is_err() {
                return Err(AuthError::UnknownLoginSession);
            }
        }
    }

    /// Sign one account out: cancel any pending login first (a late callback
    /// can never activate), revoke the epoch closing every live lease, drop
    /// usable in-memory secrets, and remove the protected credential record.
    /// Local work is untouched. Record-deletion failure is reported after the
    /// session was already disabled.
    pub async fn sign_out(&self) -> Result<(), AuthError> {
        if self.0.signing_out.swap(true, Ordering::SeqCst) {
            return Err(AuthError::SignOutInProgress);
        }
        self.0.cancel_epoch.fetch_add(1, Ordering::SeqCst);
        // Revocation precedes waiting for a credential commit or doing filesystem I/O.
        for entry in lock(&self.0.accounts).values() {
            revoke_entry(entry);
        }
        {
            let mut slot = lock(&self.0.login);
            if let Some(session) = slot.session.as_mut().filter(|s| !s.state.is_terminal()) {
                session.state = LoginState::Cancelled;
                session.error = Some(AuthError::Cancelled);
            }
            if let Some(token) = slot.cancel.take() { token.cancel(); }
        }
        self.publish();
        let manager = self.clone();
        // Accepted removal finishes even if the requesting IPC connection disappears.
        tokio::task::spawn_blocking(move || {
            let _commit = lock(&manager.0.credential_commit);
            let entries: Vec<_> = lock(&manager.0.accounts).values().cloned().collect();
            *lock(&manager.0.active) = None;
            let mut result = Ok(());
            for entry in entries {
                // Also catches a login that crossed its commit point just before revocation.
                revoke_entry(&entry);
                let dir = account_credentials_dir(&manager.0.state_base, entry.account);
                if let Err(error) = AccountCredentialStore::open(dir, entry.account)
                    .and_then(|store| store.delete().map(|_| ()))
                {
                    if result.is_ok() { result = Err(error); }
                }
            }
            // Retain only non-secret identity/generation metadata so native client caches
            // can never mistake a later login for the previous credential generation.
            manager.set_last_error(result.as_ref().err().cloned());
            manager.0.signing_out.store(false, Ordering::SeqCst);
            manager.publish();
            result
        }).await.map_err(|_| AuthError::Internal)?
    }

    // ---- internals -------------------------------------------------------

    fn entry_opt(&self, account: AccountKey) -> Option<Arc<AccountEntry>> {
        lock(&self.0.accounts).get(&account).cloned()
    }

    fn http_client(&self) -> Result<reqwest::Client, AuthError> {
        let mut slot = lock(&self.0.http);
        if let Some(cached) = &*slot {
            return cached.clone();
        }
        let built = crate::http::build_oidc_client();
        *slot = Some(built.clone());
        built
    }

    /// Discovery with single-flight semantics (one metadata fetch at a time).
    async fn provider(&self) -> Result<Arc<Provider>, AuthError> {
        let mut guard = self.0.provider.lock().await;
        if let Some(provider) = &*guard {
            return Ok(provider.clone());
        }
        let http = self.http_client()?;
        let provider = Arc::new(discovery::fetch_provider(&self.0.settings, &http).await?);
        *guard = Some(provider.clone());
        Ok(provider)
    }

    fn set_last_error(&self, error: Option<AuthError>) {
        *lock(&self.0.last_error) = error;
    }

    fn publish(&self) {
        let _publish = lock(&self.0.snapshot_publish);
        let revision = self.0.revision.fetch_add(1, Ordering::SeqCst) + 1;
        let profile = self.active_profile();
        let active_login = lock(&self.0.login).session.clone();
        let last_error = lock(&self.0.last_error).clone();
        self.0.watch_tx.send_replace(AuthSnapshot {
            revision,
            profile,
            active_login,
            last_error,
        });
    }

    fn update_session(&self, session_id: Uuid, apply: impl FnOnce(&mut LoginSession)) {
        let mut slot = lock(&self.0.login);
        let matched = slot
            .session
            .as_mut()
            .filter(|s| s.session_id == session_id && !s.state.is_terminal());
        if let Some(session) = matched {
            apply(session);
            drop(slot);
            self.publish();
        }
    }

    fn finish_session(&self, session_id: Uuid, outcome: Result<AccountProfile, AuthError>) {
        let _commit = lock(&self.0.credential_commit);
        let terminal_error;
        {
            let mut slot = lock(&self.0.login);
            let Some(session) = slot.session.as_mut() else { return };
            if session.session_id != session_id || session.state.is_terminal() {
                return;
            }
            let (state, error) = match &outcome {
                Ok(_) => (LoginState::Completed, None),
                Err(AuthError::Cancelled) => (LoginState::Cancelled, Some(AuthError::Cancelled)),
                Err(AuthError::Expired) => (LoginState::Expired, Some(AuthError::Expired)),
                Err(AuthError::Denied) => (LoginState::Denied, Some(AuthError::Denied)),
                Err(error) => (LoginState::Failed, Some(error.clone())),
            };
            session.state = state;
            session.error = error.clone();
            slot.cancel = None;
            terminal_error = error;
        }
        if let Some(error) = terminal_error {
            self.set_last_error(Some(error));
        }
        self.publish();
    }

    async fn run_login(
        &self,
        request: LoginRequest,
        session_id: Uuid,
        cancel: CancellationToken,
        client_id: String,
        epoch: u64,
    ) -> Result<AccountProfile, AuthError> {
        match request.flow {
            LoginFlow::Pkce => {
                self.run_pkce(&request, session_id, &cancel, &client_id, epoch)
                    .await
            }
            LoginFlow::Device => {
                self.run_device(&request, session_id, &cancel, &client_id, epoch)
                    .await
            }
        }
    }

    async fn run_pkce(
        &self,
        request: &LoginRequest,
        session_id: Uuid,
        cancel: &CancellationToken,
        client_id: &str,
        epoch: u64,
    ) -> Result<AccountProfile, AuthError> {
        // The listener binds before the browser launches.
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|_| AuthError::Internal)?;
        let port = listener.local_addr().map_err(|_| AuthError::Internal)?.port();
        let redirect_uri = format!("http://127.0.0.1:{port}{}", config::CALLBACK_PATH);
        let provider = self.provider().await?;
        let client = flows::build_code_client(&provider.metadata, client_id, Some(&redirect_uri))?;

        let state = flows::random_b64(32)?;
        let nonce = flows::random_b64(32)?;
        let verifier = flows::random_b64(32)?;
        let url = flows::authorization_url(&client, request, &state, &nonce, &verifier)?;
        self.update_session(session_id, |session| {
            session.authorization_url = Some(url.clone());
        });

        // System-browser launch through the safe boundary (no shell string,
        // one URL argument). Failure tears the session down.
        let launched = {
            let target = url.clone();
            let launcher = self.0.launcher.clone();
            tokio::task::spawn_blocking(move || launcher.as_ref()(&target)).await
        };
        if !matches!(launched, Ok(Ok(()))) {
            return Err(AuthError::BrowserLaunch);
        }

        let expected_host = format!("127.0.0.1:{port}");
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(self.0.settings.login_lifetime_secs);
        let callback =
            flows::run_pkce_callback(listener, &expected_host, &state, deadline, cancel).await?;
        match callback {
            flows::PkceCallback::Code(code) => {
                let http = self.http_client()?;
                let token = flows::exchange_code_once(&client, &http, &code, &verifier).await?;
                self.complete_login(request, &client, token, Some(&nonce), epoch)
                    .await
            }
            flows::PkceCallback::Denied => Err(AuthError::Denied),
            flows::PkceCallback::ProviderError => Err(AuthError::CallbackInvalid),
        }
    }

    async fn run_device(
        &self,
        request: &LoginRequest,
        session_id: Uuid,
        cancel: &CancellationToken,
        client_id: &str,
        epoch: u64,
    ) -> Result<AccountProfile, AuthError> {
        let provider = self.provider().await?;
        let device_client = flows::build_device_client(&provider.metadata, client_id)?;
        let code_client = flows::build_code_client(&provider.metadata, client_id, None)?;
        let http = self.http_client()?;

        let authorization =
            flows::device_authorize(&device_client, &http, request).await?;
        let user_code = authorization.user_code().secret().to_owned();
        let verification_uri = authorization.verification_uri().to_string();
        self.update_session(session_id, |session| {
            session.user_code = Some(user_code.clone());
            session.verification_uri = Some(verification_uri.clone());
        });

        let token = flows::device_poll(&device_client, &http, &authorization, cancel).await?;
        self.complete_login(request, &code_client, token, None, epoch).await
    }

    /// Verify, persist and activate one completed login.
    ///
    /// Order is mandatory: strict identity validation -> purpose check ->
    /// durable atomic save -> epoch activation -> token exposure. The
    /// `cancel_epoch` guard ensures a sign-out during the exchange can never
    /// activate this session.
    async fn complete_login(
        &self,
        request: &LoginRequest,
        client: &CodeClient,
        token: HfTokenResponse,
        nonce: Option<&str>,
        epoch: u64,
    ) -> Result<AccountProfile, AuthError> {
        if self.0.cancel_epoch.load(Ordering::SeqCst) != epoch {
            return Err(AuthError::Cancelled);
        }
        let identity = flows::verify_id_token(client, &token, nonce)?;
        let http = self.http_client()?;
        let userinfo = flows::fetch_userinfo(
            client,
            &http,
            token.access_token().secret(),
            &identity.subject,
        )
        .await?;
        let granted_scopes: Option<Vec<String>> = token
            .scopes()
            .map(|scopes| scopes.iter().map(|s| s.as_str().to_owned()).collect());
        let lifetime_secs = token.expires_in()
            .filter(|duration| !duration.is_zero()).ok_or(AuthError::TokenEndpoint)?.as_secs();
        let refresh_token = token.refresh_token().map(|t| t.secret().to_owned());
        let has_refresh = refresh_token.is_some();
        let profile = flows::build_profile(
            &identity,
            &userinfo,
            granted_scopes.clone(),
            request.purpose,
            request.flow,
            request.organization_id.as_deref(),
            has_refresh,
        )?;
        if !profile.purpose_covered {
            return Err(AuthError::ScopesNotGranted);
        }
        let _commit = lock(&self.0.credential_commit);
        if self.0.signing_out.load(Ordering::SeqCst)
            || lock(&self.0.login).cancel.as_ref().is_none_or(CancellationToken::is_cancelled)
        {
            return Err(AuthError::Cancelled);
        }
        if self.0.cancel_epoch.load(Ordering::SeqCst) != epoch {
            return Err(AuthError::Cancelled);
        }

        let account = profile.account_key;


        let generation = self
            .entry_opt(account)
            .map(|entry| lock(&entry.shared).generation)
            .unwrap_or(0)
            .checked_add(1).ok_or(AuthError::Internal)?;
        let expires_at = unix_now().checked_add(lifetime_secs).ok_or(AuthError::TokenEndpoint)?;
        let authorization_epoch = self.entry_opt(account)
            .map(|entry| entry.authority.current_epoch()).transpose()
            .map_err(|_| AuthError::Internal)?
            .map_or(Some(1), |epoch| epoch.checked_add(2)).ok_or(AuthError::Internal)?;
        let envelope = CredentialEnvelope {
            schema: ENVELOPE_SCHEMA,
            authorization_epoch,
            issuer: identity.issuer.clone(),
            subject: identity.subject.clone(),
            namespace: profile.namespace.as_str().to_owned(),
            avatar_url: validate_avatar_url(profile.avatar_url.as_deref()),
            orgs: profile
                .orgs
                .iter()
                .map(|org| OrgCandidate {
                    subject: org.subject.clone(),
                    name: org.name.clone(),
                    role: org.role.clone(),
                    restrictions: org.restrictions.clone(),
                })
                .collect(),
            granted_scopes: profile.granted_scopes.clone(),
            covered_purpose: request.purpose,
            login_flow: request.flow,
            generation,
            lifetime_secs,
            expires_at,
            access_token: token.access_token().secret().to_owned(),
            refresh_token: refresh_token.clone(),
        };

        // Durable atomic save BEFORE any exposure or activation.
        let dir = account_credentials_dir(&self.0.state_base, account);
        let store = AccountCredentialStore::open(dir, account)?;
        store.save(&envelope)?;
        drop(envelope);

        // Persist first: a failed replacement must not revoke the usable previous login.
        if let Some(old) = (*lock(&self.0.active)).filter(|old| *old != account) {
            if let Some(entry) = self.entry_opt(old) { revoke_entry(&entry); }
        }
        if let Some(entry) = self.entry_opt(account) { revoke_entry(&entry); }
        let authority_epoch = authorization_epoch - 1;

        let entry = Arc::new(AccountEntry {
            account,
            issuer: identity.issuer.clone(),
            subject: identity.subject.clone(),
            authority: AuthorizationAuthority::new(account, authority_epoch),
            refresh_lock: tokio::sync::Mutex::new(()),
            shared: Mutex::new(SharedAccount {
                token: None,
                refresh_token: refresh_token.map(Zeroizing::new),
                refresh_due_at: flows::refresh_due_at(expires_at, lifetime_secs),
                expires_at,
                generation,
                lifetime_secs,
                needs_sign_in: false,
                profile: profile.clone(),
                covered_purpose: request.purpose,
                login_flow: request.flow,
            }),
        });
        entry.authority.activate().map_err(|_| AuthError::Internal)?;
        lock(&entry.shared).token = Some(Arc::new(SecretAccessToken::new(
            Zeroizing::new(token.access_token().secret().to_owned()),
            account,
            generation,
            expires_at,
        )));
        lock(&self.0.accounts).insert(account, entry);
        *lock(&self.0.active) = Some(account);
        self.set_last_error(None);
        {
            let mut slot = lock(&self.0.login);
            if let Some(session) = slot.session.as_mut().filter(|s| !s.state.is_terminal()) {
                session.state = LoginState::Completed;
                session.error = None;
            }
            slot.cancel = None;
        }
        self.publish();
        Ok(profile)
    }

    async fn token_for(
        &self,
        account: AccountKey,
        rejected_generation: Option<u64>,
    ) -> Result<Arc<SecretAccessToken>, AuthError> {
        if self.0.signing_out.load(Ordering::SeqCst) || *lock(&self.0.active) != Some(account) {
            return Err(AuthError::NeedsSignIn);
        }
        let entry = self.entry_opt(account).ok_or(AuthError::NeedsSignIn)?;
        let mut mark_sign_in = false;
        let decision = {
            let shared = lock(&entry.shared);
            if shared.needs_sign_in {
                return Err(AuthError::NeedsSignIn);
            }
            match &shared.token {
                Some(token) => {
                    let now = unix_now();
                    let refresh_missing = shared.refresh_token.is_none();
                    match rejected_generation {
                        // Already rotated past the rejected generation: reuse.
                        Some(rejected) if token.generation() > rejected && now < token.expires_at() => {
                            Some(Ok(token.clone()))
                        }
                        // Caller's token predates the current credential era
                        // (sign-out + fresh login): never refresh on its behalf.
                        Some(rejected) if token.generation() < rejected => {
                            Some(if now < token.expires_at() {
                                Ok(token.clone())
                            } else {
                                Err(AuthError::NeedsSignIn)
                            })
                        }
                        Some(_) => None,
                        None if now < shared.refresh_due_at && now < token.expires_at() => {
                            Some(Ok(token.clone()))
                        }
                        None if now < token.expires_at() && refresh_missing => {
                            Some(Ok(token.clone()))
                        }
                        None if now >= token.expires_at() && refresh_missing => {
                            mark_sign_in = true;
                            Some(Err(AuthError::NeedsSignIn))
                        }
                        None => None,
                    }
                }
                None => {
                    if shared.refresh_token.is_none() {
                        Some(Err(AuthError::NeedsSignIn))
                    } else {
                        None
                    }
                }
            }
        };
        if mark_sign_in {
            self.mark_needs_sign_in(&entry);
        }
        match decision {
            Some(result) => result,
            None => self.refresh_entry(&entry, rejected_generation).await,
        }
    }

    /// Single-flight refresh for one account (serialized by `refresh_lock`).
    async fn refresh_entry(
        &self,
        entry: &Arc<AccountEntry>,
        rejected_generation: Option<u64>,
    ) -> Result<Arc<SecretAccessToken>, AuthError> {
        let _guard = entry.refresh_lock.lock().await;
        {
            let shared = lock(&entry.shared);
            if shared.needs_sign_in {
                return Err(AuthError::NeedsSignIn);
            }
            if let Some(token) = &shared.token {
                let now = unix_now();
                match rejected_generation {
                    Some(rejected) if token.generation() != rejected && now < token.expires_at() => {
                        // A concurrent refresh already produced a usable successor.
                        return Ok(token.clone());
                    }
                    Some(_) => {}
                    None if now < shared.refresh_due_at && now < token.expires_at() => {
                        return Ok(token.clone())
                    }
                    None => {}
                }
                if rejected_generation.is_none() && now < token.expires_at() && shared.refresh_token.is_none() {
                    return Ok(token.clone());
                }
            }
            if shared.refresh_token.is_none() {
                drop(shared);
                self.mark_needs_sign_in(entry);
                return Err(AuthError::NeedsSignIn);
            }
        }
        let refresh_token = {
            let shared = lock(&entry.shared);
            shared
                .refresh_token
                .as_ref()
                .map(|token| Zeroizing::new(token.to_string()))
                .ok_or(AuthError::NeedsSignIn)?
        };
        match self.do_refresh(entry, &refresh_token).await {
            Ok(token) => Ok(token),
            Err(AuthError::InvalidGrant) => {
                // Fail closed: no retry loop, no token, sign-in required.
                self.mark_needs_sign_in(entry);
                Err(AuthError::InvalidGrant)
            }
            Err(error) => {
                // Transient failure: a still-valid token remains usable.
                let shared = lock(&entry.shared);
                if let Some(token) = &shared.token {
                    if rejected_generation.is_none() && unix_now() < token.expires_at() {
                        return Ok(token.clone());
                    }
                }
                Err(error)
            }
        }
    }

    async fn do_refresh(
        &self,
        entry: &Arc<AccountEntry>,
        refresh_token: &str,
    ) -> Result<Arc<SecretAccessToken>, AuthError> {
        let provider = self.provider().await?;
        let client_id = self.0.config.require_client_id()?.to_owned();
        let client = flows::build_code_client(&provider.metadata, &client_id, None)?;
        let http = self.http_client()?;
        let token = flows::refresh_once(&client, &http, refresh_token).await?;

        if !matches!(token.token_type(), openidconnect::core::CoreTokenType::Bearer) {
            return Err(AuthError::TokenEndpoint);
        }
        let identity = if token.id_token().is_some() {
            let identity = flows::verify_id_token(&client, &token, None).map_err(|error| {
                self.mark_needs_sign_in(entry);
                error
            })?;
            if identity.subject != entry.subject || identity.issuer != entry.issuer {
                self.mark_needs_sign_in(entry);
                return Err(AuthError::ExistingSessionPreserved);
            }
            identity
        } else {
            // Refresh may omit an ID token. Userinfo must still agree with the
            // identity verified by the original grant, never a new inferred subject.
            flows::VerifiedIdentity {
                issuer: entry.issuer.clone(), subject: entry.subject.clone(), extra: Default::default(),
            }
        };
        let userinfo = flows::fetch_userinfo(&client, &http, token.access_token().secret(), &entry.subject)
            .await.map_err(|error| {
                if error == AuthError::IdentityValidation { self.mark_needs_sign_in(entry); }
                error
            })?;
        let (purpose, flow) = {
            let shared = lock(&entry.shared);
            (shared.covered_purpose, shared.login_flow)
        };
        let mut profile = flows::build_profile(&identity, &userinfo,
            token.scopes().map(|scopes| scopes.iter().map(|scope| scope.as_str().to_owned()).collect()),
            purpose, flow, None, true).map_err(|error| {
                if error == AuthError::IdentityValidation { self.mark_needs_sign_in(entry); }
                error
            })?;

        let _commit = lock(&self.0.credential_commit);
        if self.0.signing_out.load(Ordering::SeqCst)
            || *lock(&self.0.active) != Some(entry.account)
            || entry.authority.capture().and_then(|lease| lease.check()).is_err()
        {
            return Err(AuthError::NeedsSignIn);
        }
        let now = unix_now();
        let lifetime_secs = token.expires_in()
            .filter(|duration| !duration.is_zero()).ok_or(AuthError::TokenEndpoint)?.as_secs();
        let expires_at = now.checked_add(lifetime_secs).ok_or(AuthError::TokenEndpoint)?;
        let new_refresh = token
            .refresh_token()
            .map(|t| t.secret().to_owned())
            .or_else(|| Some(refresh_token.to_owned()));
        let authorization_changed;
        let authorization_epoch;
        {
            let shared = lock(&entry.shared);
            profile.org_consent_requested = shared.profile.org_consent_requested;
            // Display-only: an omitted `picture` claim on this userinfo
            // response must not drop the already-verified avatar (it is not
            // authorization state, so it never advances the epoch below).
            if profile.avatar_url.is_none() {
                profile.avatar_url = shared.profile.avatar_url.clone();
            }
            for org in &mut profile.orgs {
                org.consented_this_session = shared.profile.orgs.iter()
                    .any(|old| old.subject == org.subject && old.consented_this_session);
            }
            authorization_changed = !profile.same_authorization(&shared.profile);
            let epoch = entry.authority.current_epoch().map_err(|_| AuthError::Internal)?;
            authorization_epoch = epoch.checked_add(u64::from(authorization_changed)).ok_or(AuthError::Internal)?;
        }
        let (generation, envelope) = {
            let shared = lock(&entry.shared);
            let generation = shared.generation.checked_add(1).ok_or(AuthError::Internal)?;
            let envelope = CredentialEnvelope {
                schema: ENVELOPE_SCHEMA,
                authorization_epoch,
                issuer: entry.issuer.clone(),
                subject: entry.subject.clone(),
                namespace: profile.namespace.as_str().to_owned(),
                avatar_url: validate_avatar_url(profile.avatar_url.as_deref()),
                orgs: profile.orgs
                    .iter()
                    .map(|org| OrgCandidate {
                        subject: org.subject.clone(),
                        name: org.name.clone(),
                        role: org.role.clone(),
                        restrictions: org.restrictions.clone(),
                    })
                    .collect(),
                granted_scopes: profile.granted_scopes.clone(),
                covered_purpose: shared.covered_purpose,
                login_flow: shared.login_flow,
                generation,
                lifetime_secs,
                expires_at,
                access_token: token.access_token().secret().to_owned(),
                refresh_token: new_refresh.clone(),
            };
            (generation, envelope)
        };

        // Durable atomic save BEFORE exposing the rotated token.
        let dir = account_credentials_dir(&self.0.state_base, entry.account);
        let store = AccountCredentialStore::open(dir, entry.account)?;
        store.save(&envelope)?;
        drop(envelope);

        let secret = Arc::new(SecretAccessToken::new(
            Zeroizing::new(token.access_token().secret().to_owned()),
            entry.account,
            generation,
            expires_at,
        ));
        {
            let mut shared = lock(&entry.shared);
            if authorization_changed {
                // Activation advances the epoch atomically; old dispatch leases stay revoked.
                entry.authority.activate().map_err(|_| AuthError::Internal)?;
            }
            shared.profile = profile;
            shared.token = Some(secret.clone());
            shared.refresh_token = new_refresh.map(Zeroizing::new);
            shared.generation = generation;
            shared.lifetime_secs = lifetime_secs;
            shared.expires_at = expires_at;
            shared.refresh_due_at = flows::refresh_due_at(expires_at, lifetime_secs);
            shared.needs_sign_in = false;
        }
        self.publish();
        Ok(secret)
    }

    fn mark_needs_sign_in(&self, entry: &Arc<AccountEntry>) {
        let _commit = lock(&self.0.credential_commit);
        revoke_entry(entry);
        if self.0.signing_out.load(Ordering::SeqCst)
            || *lock(&self.0.active) != Some(entry.account)
            || self.entry_opt(entry.account).is_none_or(|current| !Arc::ptr_eq(&current, entry))
        {
            return;
        }
        self.set_last_error(Some(AuthError::NeedsSignIn));
        self.publish();
    }
}

fn revoke_entry(entry: &AccountEntry) {
    let _ = entry.authority.revoke();
    let mut shared = lock(&entry.shared);
    shared.needs_sign_in = true;
    shared.token = None;
    shared.refresh_token = None;
}

fn entry_from_envelope(
    account: AccountKey,
    envelope: CredentialEnvelope,
) -> Result<(Arc<AccountEntry>, AccountProfile), AuthError> {
    let profile = profile_from_envelope(&envelope)?;
    let expires_at = envelope.expires_at;
    let needs_sign_in = unix_now() >= expires_at && envelope.refresh_token.is_none();
    let inactive_epoch = envelope.authorization_epoch.checked_sub(1)
        .ok_or(AuthError::CredentialRecordUnreadable)?;
    let entry = Arc::new(AccountEntry {
        account,
        issuer: envelope.issuer.clone(),
        subject: envelope.subject.clone(),
        authority: AuthorizationAuthority::new(account,
            if needs_sign_in { envelope.authorization_epoch } else { inactive_epoch }),
        refresh_lock: tokio::sync::Mutex::new(()),
        shared: Mutex::new(SharedAccount {
            token: Some(Arc::new(SecretAccessToken::new(
                Zeroizing::new(envelope.access_token.clone()),
                account,
                envelope.generation,
                expires_at,
            ))),
            refresh_token: envelope.refresh_token.clone().map(Zeroizing::new),
            refresh_due_at: flows::refresh_due_at(expires_at, envelope.lifetime_secs),
            expires_at,
            generation: envelope.generation,
            lifetime_secs: envelope.lifetime_secs,
            needs_sign_in,
            profile: profile.clone(),
            covered_purpose: envelope.covered_purpose,
            login_flow: envelope.login_flow,
        }),
    });
    Ok((entry, profile))
}

fn profile_from_envelope(envelope: &CredentialEnvelope) -> Result<AccountProfile, AuthError> {
    let namespace =
        Namespace::new(envelope.namespace.clone()).map_err(|_| AuthError::CredentialRecordUnreadable)?;
    Ok(AccountProfile {
        account_key: AccountKey::from_subject(&envelope.issuer, &envelope.subject),
        issuer: envelope.issuer.clone(),
        subject: envelope.subject.clone(),
        namespace,
        orgs: envelope
            .orgs
            .iter()
            .map(|org| VerifiedOrg {
                subject: org.subject.clone(),
                name: org.name.clone(),
                role: org.role.clone(),
                restrictions: org.restrictions.clone(),
                consented_this_session: false,
            })
            .collect(),
        granted_scopes: envelope.granted_scopes.clone(),
        avatar_url: validate_avatar_url(envelope.avatar_url.as_deref()),
        purpose_covered: config::purpose_covered(
            envelope.covered_purpose,
            envelope.granted_scopes.as_deref(),
        ),
        org_consent_requested: false,
        reconsent_required_for_storage: envelope.login_flow == LoginFlow::Device
            || envelope.refresh_token.is_none(),
    })
}

impl TokenSource for AuthManager {
    fn access_token(
        &self,
        account: AccountKey,
    ) -> impl Future<Output = Result<Arc<SecretAccessToken>, crate::AuthorizationError>> + Send {
        let manager = self.clone();
        async move {
            manager
                .token_for(account, None)
                .await
                .map_err(error::to_authorization_error)
        }
    }

    fn refresh_after_unauthorized(
        &self,
        account: AccountKey,
        rejected_generation: u64,
    ) -> impl Future<Output = Result<Arc<SecretAccessToken>, crate::AuthorizationError>> + Send {
        let manager = self.clone();
        async move {
            manager
                .token_for(account, Some(rejected_generation))
                .await
                .map_err(error::to_authorization_error)
        }
    }

    fn authorization_lease(
        &self,
        account: AccountKey,
    ) -> Result<AuthorizationLease, crate::AuthorizationError> {
        if self.0.signing_out.load(Ordering::SeqCst) || *lock(&self.0.active) != Some(account) {
            return Err(crate::AuthorizationError::NeedsSignIn);
        }
        let lease = self.entry_opt(account)
            .ok_or(crate::AuthorizationError::NeedsSignIn)?
            .authority.capture()?;
        if self.0.signing_out.load(Ordering::SeqCst) || *lock(&self.0.active) != Some(account) {
            return Err(crate::AuthorizationError::NeedsSignIn);
        }
        lease.check()?;
        Ok(lease)
    }
}
