//! TokenSource-backed native client generations, lease identity, and the
//! single controlled 401-refresh boundary. Every dispatch checks the captured
//! operation lease before the request leaves the process.
//!
//! The whole surface is generic over `T: TokenSource` (static dispatch, RPITIT
//! futures shared with the auth slice; no boxed token lookups).

use crate::NativeError;
use crate::wire_budget::WireBudget;
use bytes::Bytes;
use hfdrive_auth::{AuthorizationError, AuthorizationLease, SecretAccessToken, TokenSource};
use hfdrive_core::ids::AccountKey;
use hf_hub::{HFClient, HFError};
use reqwest::header::HeaderMap;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

use crate::http;
use crate::wire;

pub(crate) fn map_auth_error(error: AuthorizationError) -> NativeError {
    match error {
        AuthorizationError::NeedsSignIn => NativeError::NeedsSignIn,
        AuthorizationError::Unavailable => NativeError::Transport,
        AuthorizationError::EpochExhausted => NativeError::InvalidRequest {
            detail: "authorization epoch exhausted; provider restart required".to_owned(),
        },
    }
}

/// Map hf-hub failures to the sanitized native surface. Never forwards SDK
/// strings (they can carry request URLs and response bodies).
pub(crate) fn map_hf_error(error: HFError) -> NativeError {
    match &error {
        HFError::AuthRequired { .. } => NativeError::NeedsSignIn,
        HFError::Forbidden { .. } => NativeError::PermissionDenied,
        HFError::BucketNotFound { .. } | HFError::EntryNotFound { .. } | HFError::RepoNotFound { .. } => {
            NativeError::RemoteContentUnavailable
        }
        HFError::RevisionNotFound { .. } | HFError::LocalEntryNotFound { .. } => NativeError::RemoteContentUnavailable,
        HFError::RateLimited { retry_after, .. } => NativeError::RateLimited {
            retry_after_seconds: retry_after.map(|d| d.as_secs()),
        },
        HFError::Conflict { .. } => NativeError::AlreadyExists,
        HFError::Http { context } => http::status_error(context.status.as_u16(), None),
        HFError::Request { .. } | HFError::Io(_) => NativeError::Transport,
        _ => NativeError::InvalidResponse,
    }
}

pub(crate) fn is_unauthorized(error: &HFError) -> bool {
    match error {
        HFError::AuthRequired { .. } => true,
        HFError::Http { context, .. } => context.status.as_u16() == 401,
        _ => false,
    }
}

/// One immutable client generation: the hf-hub client plus the raw bearer
/// header built from a single credential generation. Rebuilt after rotation.
pub(crate) struct ClientState {
    pub(crate) generation: u64,
    pub(crate) bearer: HeaderMap,
    pub(crate) hf: HFClient,
}

struct ApiInner<T: TokenSource> {
    tokens: Arc<T>,
    account: AccountKey,
    endpoint: String,
    http: reqwest::Client,
    budget: WireBudget,
    state: Mutex<Option<Arc<ClientState>>>,
}

/// Per-account native API handle: the token source, the shared HTTP client,
/// and generation-keyed immutable SDK clients.
pub struct NativeApi<T: TokenSource> {
    inner: Arc<ApiInner<T>>,
}

impl<T: TokenSource> Clone for NativeApi<T> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

/// Captured authorization for one durable operation. Re-checked immediately
/// before every dispatch; a revoked epoch or an account substitution fails
/// closed before any request leaves the process.
#[derive(Clone)]
pub struct NativeLease {
    lease: AuthorizationLease,
    account: AccountKey,
}

impl NativeLease {
    pub fn generation(&self) -> u64 {
        self.lease.generation()
    }
    pub fn account(&self) -> AccountKey {
        self.account
    }
    /// Epoch and account identity check. [`NativeError::IdentityMismatch`]
    /// means the lease belongs to a different account than the binding it is
    /// used with; that is never retried or refreshed around.
    pub fn check(&self) -> Result<(), NativeError> {
        self.lease.check().map_err(map_auth_error)?;
        if self.lease.account() != self.account {
            return Err(NativeError::IdentityMismatch);
        }
        Ok(())
    }
}

impl<T: TokenSource> NativeApi<T> {
    /// `endpoint` must be an absolute HTTP(S) URL without embedded
    /// credentials; production uses `https://huggingface.co`. The shared
    /// transport is the canonical rustls client of this crate. Transfers are
    /// counted and paced through the process-shared [`WireBudget::global`];
    /// use [`NativeApi::new_with_budget`] to supply the provider's configured
    /// instance explicitly.
    pub fn new(tokens: Arc<T>, account: AccountKey, endpoint: String) -> Result<Self, NativeError> {
        Self::new_with_budget(tokens, account, endpoint, WireBudget::global())
    }

    /// Same as [`NativeApi::new`] with an explicit shared transfer budget.
    /// The budget is the one wire-accounting/pacing instance for the process:
    /// pass the same instance to every account, the provider scheduler, and
    /// the publication adapter; it installs itself as [`WireBudget::global`]
    /// when none is installed yet.
    pub fn new_with_budget(
        tokens: Arc<T>,
        account: AccountKey,
        endpoint: String,
        budget: WireBudget,
    ) -> Result<Self, NativeError> {
        budget.install_global();
        match reqwest::Url::parse(&endpoint) {
            Ok(url)
                if (url.scheme() == "https" || url.scheme() == "http")
                    && url.host_str().is_some()
                    && url.username() == ""
                    && url.password().is_none() => {}
            _ => {
                return Err(NativeError::InvalidRequest {
                    detail: "endpoint must be an absolute HTTP(S) URL without credentials".to_owned(),
                });
            }
        }
        let http = http::build_http_client()?;
        Ok(Self {
            inner: Arc::new(ApiInner {
                tokens,
                account,
                endpoint: endpoint.trim_end_matches('/').to_owned(),
                http,
                budget,
                state: Mutex::new(None),
            }),
        })
    }

    pub fn account(&self) -> AccountKey {
        self.inner.account
    }

    /// The shared transfer budget metering this handle's encoded bodies.
    pub fn budget(&self) -> &WireBudget {
        &self.inner.budget
    }

    pub(crate) fn endpoint(&self) -> &str {
        &self.inner.endpoint
    }

    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.inner.http
    }

    /// Capture the operation lease. Thread it through every dispatch of one
    /// durable operation.
    pub fn capture_lease(&self) -> Result<NativeLease, NativeError> {
        let lease = self.inner.tokens.authorization_lease(self.inner.account).map_err(map_auth_error)?;
        Ok(NativeLease { lease, account: self.inner.account })
    }

    /// Check the captured lease (epoch + account identity) before dispatch.
    pub fn check_lease(&self, lease: &NativeLease) -> Result<(), NativeError> {
        lease.check()?;
        if lease.account != self.inner.account {
            return Err(NativeError::IdentityMismatch);
        }
        Ok(())
    }

    fn build_state(&self, token: &Arc<SecretAccessToken>) -> Result<ClientState, NativeError> {
        let mut bearer = HeaderMap::new();
        let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token.as_str()))
            .map_err(|_| NativeError::InvalidResponse)?;
        value.set_sensitive(true);
        bearer.insert(reqwest::header::AUTHORIZATION, value);

        let hf = HFClient::builder()
            .endpoint(&self.inner.endpoint)
            .token(token.as_str())
            .client(self.inner.http.clone())
            // Bucket payloads never use the repository whole-file cache.
            .cache_enabled(false)
            // Exactly one attempt per dispatch; retry/backoff policy belongs
            // to the provider scheduler, not to blind in-SDK loops.
            .retry_max_attempts(0)
            .build()
            .map_err(map_hf_error)?;

        Ok(ClientState { generation: token.generation(), bearer, hf })
    }

    fn store_state(&self, token: &Arc<SecretAccessToken>) -> Result<Arc<ClientState>, NativeError> {
        let mut guard = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = guard.as_ref()
            && state.generation == token.generation()
        {
            return Ok(state.clone());
        }
        let state = Arc::new(self.build_state(token)?);
        *guard = Some(state.clone());
        Ok(state)
    }

    /// Current credential generation as an immutable client state.
    pub(crate) async fn client_state(&self) -> Result<Arc<ClientState>, NativeError> {
        let token = self
            .inner
            .tokens
            .access_token(self.inner.account)
            .await
            .map_err(map_auth_error)?;
        self.store_state(&token)
    }

    /// One controlled refresh after a rejected generation. The immutable
    /// client is rebuilt from the returned secret even if the generation did
    /// not move. Never invoked twice for one request.
    async fn refreshed_state(&self, rejected_generation: u64) -> Result<Arc<ClientState>, NativeError> {
        let token = self
            .inner
            .tokens
            .refresh_after_unauthorized(self.inner.account, rejected_generation)
            .await
            .map_err(map_auth_error)?;
        let mut guard = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let state = Arc::new(self.build_state(&token)?);
        *guard = Some(state.clone());
        Ok(state)
    }

    // ---- concrete dispatch shapes (each with one controlled 401 refresh) ----

    /// GET one JSON body plus its validated `rel="next"` link (when present).
    pub(crate) async fn get_page(
        &self,
        lease: &NativeLease,
        url: reqwest::Url,
        api_prefix: &str,
        cancel: &CancellationToken,
    ) -> Result<(Bytes, Option<reqwest::Url>), NativeError> {
        self.check_lease(lease)?;
        let state = self.client_state().await?;
        match page_once(&state, self, url.clone(), api_prefix, cancel).await {
            Err(NativeError::NeedsSignIn) => {
                let state = self.refreshed_state(state.generation).await?;
                self.check_lease(lease)?;
                page_once(&state, self, url, api_prefix, cancel).await
            }
            other => other,
        }
    }

    /// GET one JSON body; `Ok(None)` on a real 404/410 only.
    pub(crate) async fn get_optional(
        &self,
        lease: &NativeLease,
        url: reqwest::Url,
        cancel: &CancellationToken,
    ) -> Result<Option<Bytes>, NativeError> {
        self.check_lease(lease)?;
        let state = self.client_state().await?;
        match optional_once(&state, self, url.clone(), cancel).await {
            Err(NativeError::NeedsSignIn) => {
                let state = self.refreshed_state(state.generation).await?;
                self.check_lease(lease)?;
                optional_once(&state, self, url, cancel).await
            }
            other => other,
        }
    }

    /// POST one body to the trusted HF API origin.
    pub(crate) async fn post_bytes(
        &self,
        lease: &NativeLease,
        url: reqwest::Url,
        content_type: &'static str,
        body: Bytes,
        cancel: &CancellationToken,
    ) -> Result<Bytes, NativeError> {
        self.check_lease(lease)?;
        let state = self.client_state().await?;
        match http::post_body(&state, self, url.clone(), content_type, body.clone(), cancel).await {
            Err(NativeError::NeedsSignIn) => {
                let state = self.refreshed_state(state.generation).await?;
                self.check_lease(lease)?;
                http::post_body(&state, self, url, content_type, body, cancel).await
            }
            other => other,
        }
    }

    /// Status-only probe; the response body is never read (it may contain
    /// short-lived CAS tokens).
    pub(crate) async fn probe(
        &self,
        lease: &NativeLease,
        url: reqwest::Url,
        cancel: &CancellationToken,
    ) -> Result<(), NativeError> {
        self.check_lease(lease)?;
        let state = self.client_state().await?;
        match http::probe_status(&state, self, url.clone(), cancel).await {
            Err(NativeError::NeedsSignIn) => {
                let state = self.refreshed_state(state.generation).await?;
                self.check_lease(lease)?;
                http::probe_status(&state, self, url, cancel).await
            }
            other => other,
        }
    }

    /// Bounded record read through the native resolve route.
    pub(crate) async fn resolve_record(
        &self,
        lease: &NativeLease,
        url: reqwest::Url,
        bound: usize,
        cancel: &CancellationToken,
    ) -> Result<Bytes, NativeError> {
        self.check_lease(lease)?;
        let state = self.client_state().await?;
        match http::resolve_record_bounded(&state, self, url.clone(), bound, cancel).await {
            Err(NativeError::NeedsSignIn) => {
                let state = self.refreshed_state(state.generation).await?;
                self.check_lease(lease)?;
                http::resolve_record_bounded(&state, self, url, bound, cancel).await
            }
            other => other,
        }
    }

    /// Open one SSE response on the events route.
    pub(crate) async fn open_event_stream(
        &self,
        lease: &NativeLease,
        url: reqwest::Url,
        cancel: &CancellationToken,
    ) -> Result<reqwest::Response, NativeError> {
        self.check_lease(lease)?;
        let state = self.client_state().await?;
        match event_once(&state, self, url.clone(), cancel).await {
            Err(NativeError::NeedsSignIn) => {
                let state = self.refreshed_state(state.generation).await?;
                self.check_lease(lease)?;
                event_once(&state, self, url, cancel).await
            }
            other => other,
        }
    }

    /// Native HEAD metadata through the pinned SDK's `get_file_metadata`
    /// (manual same-origin relative redirect handling). `Ok(None)` on a real
    /// 404 only.
    pub(crate) async fn hf_file_metadata(
        &self,
        lease: &NativeLease,
        namespace: &str,
        name: &str,
        key: &str,
        cancel: &CancellationToken,
    ) -> Result<Option<(u64, String)>, NativeError> {
        self.check_lease(lease)?;
        let state = self.client_state().await?;
        let first = tokio::select! {
            _ = cancel.cancelled() => return Err(NativeError::Cancelled),
            result = hf_meta_once(&state, namespace, name, key) => result,
        };
        match first {
            Err(NativeError::NeedsSignIn) => {
                let state = self.refreshed_state(state.generation).await?;
                self.check_lease(lease)?;
                tokio::select! {
                    _ = cancel.cancelled() => Err(NativeError::Cancelled),
                    result = hf_meta_once(&state, namespace, name, key) => result,
                }
            }
            other => other,
        }
    }
}

async fn page_once<T: TokenSource>(
    state: &ClientState,
    api: &NativeApi<T>,
    url: reqwest::Url,
    api_prefix: &str,
    cancel: &CancellationToken,
) -> Result<(Bytes, Option<reqwest::Url>), NativeError> {
    let (body, headers) = http::get_json(state, api, url.clone(), cancel).await?;
    let next = wire::link_next(&headers, &url, api_prefix)?;
    Ok((body, next))
}

async fn optional_once<T: TokenSource>(
    state: &ClientState,
    api: &NativeApi<T>,
    url: reqwest::Url,
    cancel: &CancellationToken,
) -> Result<Option<Bytes>, NativeError> {
    let request = api.http().get(url).headers(state.bearer.clone()).send();
    let response = tokio::select! {
        _ = cancel.cancelled() => return Err(NativeError::Cancelled),
        result = request => result.map_err(|_| NativeError::Transport)?,
    };
    let status = response.status().as_u16();
    if status == 404 || status == 410 {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(http::error_from_response(&response));
    }
    let body = tokio::select! {
        _ = cancel.cancelled() => return Err(NativeError::Cancelled),
        result = http::read_bounded(response, crate::MAX_JSON_BYTES, api.budget()) => result?,
    };
    Ok(Some(body))
}

async fn event_once<T: TokenSource>(
    state: &ClientState,
    api: &NativeApi<T>,
    url: reqwest::Url,
    cancel: &CancellationToken,
) -> Result<reqwest::Response, NativeError> {
    let request = api
        .http()
        .get(url)
        .headers(state.bearer.clone())
        .header(reqwest::header::ACCEPT, "text/event-stream")
        .send();
    let response = tokio::select! {
        _ = cancel.cancelled() => return Err(NativeError::Cancelled),
        result = request => result.map_err(|_| NativeError::Transport)?,
    };
    if !response.status().is_success() {
        return Err(http::error_from_response(&response));
    }
    Ok(response)
}

async fn hf_meta_once(state: &ClientState, namespace: &str, name: &str, key: &str) -> Result<Option<(u64, String)>, NativeError> {
    let bucket = state.hf.bucket(namespace, name);
    match bucket.get_file_metadata().remote_path(key).send().await {
        Ok(meta) => Ok(Some((meta.size, meta.xet_hash))),
        Err(HFError::EntryNotFound { .. }) => Ok(None),
        Err(error) if is_unauthorized(&error) => Err(NativeError::NeedsSignIn),
        Err(error) => Err(map_hf_error(error)),
    }
}
