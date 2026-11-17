//! OIDC flows: PKCE loopback callback, code exchange, device authorization,
//! refresh and strict ID-token/userinfo identity extraction.
//!
//! All requests go through the shared redirect-free bounded HTTP adapter;
//! public-client requests use `AuthType::RequestBody` (`client_id` in the
//! body, no secret, no Basic header) even though discovery advertises only
//! secret-based methods.

use std::time::Duration;

use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreDeviceAuthorizationResponse, CoreErrorResponseType,
    CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreJsonWebKey,
    CoreRevocableToken, CoreRevocationErrorResponse, CoreTokenIntrospectionResponse, CoreTokenType,
};
use openidconnect::{
    AccessToken, AuthType, AuthenticationFlow, AuthorizationCode, Client, ClientId, CsrfToken,
    DeviceAuthorizationResponse, DeviceCodeErrorResponseType, EmptyExtraDeviceAuthorizationFields,
    EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet, EndpointSet, IdTokenFields, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, RequestTokenError, Scope,
    StandardErrorResponse, StandardTokenResponse, SubjectIdentifier,
    TokenResponse as OidcTokenResponse, UserInfoClaims,
    OAuth2TokenResponse,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::config;
use crate::error::AuthError;
use crate::http;
use crate::identity::{validate_avatar_url, AccountProfile, ExtraClaims, VerifiedOrg};
use crate::login::{LoginFlow, LoginPurpose, LoginRequest};
use crate::protocol::{self, CallbackCheck, MAX_CALLBACK_REQUEST_BYTES};

/// Token endpoint error type (RFC 6749 `BasicErrorResponseType`).
pub(crate) type HfTokenErrorResponse = StandardErrorResponse<CoreErrorResponseType>;
/// ID-token-bearing token response with HF extra claims.
pub(crate) type HfIdTokenFields = IdTokenFields<
    ExtraClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;
pub(crate) type HfTokenResponse = StandardTokenResponse<HfIdTokenFields, CoreTokenType>;
pub(crate) type HfUserInfoClaims = UserInfoClaims<ExtraClaims, CoreGenderClaim>;

type OidcClient<HasAuth, HasDev, HasTok, HasUi> = Client<
    ExtraClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    HfTokenErrorResponse,
    HfTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    HasAuth,
    HasDev,
    EndpointNotSet,
    EndpointNotSet,
    HasTok,
    HasUi,
>;

/// Client for code exchange/refresh/userinfo (metadata endpoints).
pub(crate) type CodeClient = OidcClient<EndpointSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>;
/// Client additionally carrying the device authorization endpoint.
pub(crate) type DeviceClient = OidcClient<EndpointSet, EndpointSet, EndpointMaybeSet, EndpointMaybeSet>;


/// Build the public-client code/refresh/userinfo client. No client secret is
/// ever attached; `AuthType::RequestBody` puts `client_id` in the form body.
pub(crate) fn build_code_client(
    metadata: &crate::discovery::HfProviderMetadata,
    client_id: &str,
    redirect_uri: Option<&str>,
) -> Result<CodeClient, AuthError> {
    let client = CodeClient::from_provider_metadata(
        metadata.clone(),
        ClientId::new(client_id.to_owned()),
        None,
    )
    .set_auth_type(AuthType::RequestBody);
    let client = match redirect_uri {
        Some(uri) => {
            let redirect = RedirectUrl::new(uri.to_owned()).map_err(|_| AuthError::Internal)?;
            client.set_redirect_uri(redirect)
        }
        None => client,
    };
    Ok(client)
}

/// Build the device-flow client. [`AuthError::DeviceFlowUnavailable`] when the
/// provider did not advertise a device authorization endpoint; the advertised
/// endpoint must pass the same trust policy as every other endpoint (K13)
/// before it is ever used.
pub(crate) fn build_device_client(
    settings: &crate::config::OidcSettings,
    metadata: &crate::discovery::HfProviderMetadata,
    client_id: &str,
) -> Result<DeviceClient, AuthError> {
    let client = CodeClient::from_provider_metadata(
        metadata.clone(),
        ClientId::new(client_id.to_owned()),
        None,
    )
    .set_auth_type(AuthType::RequestBody);
    let endpoint = metadata
        .additional_metadata()
        .device_authorization_endpoint
        .clone()
        .ok_or(AuthError::DeviceFlowUnavailable)?;
    settings.validate_endpoint(&endpoint)?;
    let url =
        openidconnect::DeviceAuthorizationUrl::new(endpoint).map_err(|_| AuthError::DeviceFlowUnavailable)?;
    Ok(client.set_device_authorization_url(url))
}

/// Build the authorization URL for a PKCE login: exact loopback redirect
/// (already bound on the client), per-purpose scope set, optional `orgIds`
/// re-consent, PKCE S256 challenge.
pub(crate) fn authorization_url(
    client: &CodeClient,
    request: &LoginRequest,
    state: &str,
    nonce: &str,
    verifier: &str,
) -> Result<String, AuthError> {
    let pkce_verifier = PkceCodeVerifier::new(verifier.to_owned());
    let challenge = PkceCodeChallenge::from_code_verifier_sha256(&pkce_verifier);
    let state = state.to_owned();
    let nonce = nonce.to_owned();
    let mut auth = client.authorize_url(
        AuthenticationFlow::<openidconnect::core::CoreResponseType>::AuthorizationCode,
        move || CsrfToken::new(state),
        move || Nonce::new(nonce),
    );
    for scope in config::scope_strings(request.purpose) {
        auth = auth.add_scope(Scope::new(scope));
    }
    if let Some(org) = &request.organization_id {
        let (name, value) = protocol::org_reconsent_param(org);
        auth = auth.add_extra_param(name, value);
    }
    let (url, _state, _nonce) = auth.set_pkce_challenge(challenge).url();
    Ok(url.to_string())
}

/// Result of one accepted callback.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PkceCallback {
    /// One-time authorization code (consumed exactly once by the caller).
    Code(String),
    /// The user denied the authorization request.
    Denied,
    /// The provider reported a terminal error.
    ProviderError,
}

/// Await exactly one acceptable callback request on the loopback listener.
///
/// Adversarial traffic (wrong method/path/host, duplicate parameters,
/// mismatched state, oversized input) is rejected with an error response and
/// **does not consume** the outstanding attempt. The listener closes when a
/// valid success/denial is consumed, on cancellation or when the deadline
/// passes.
///
/// Every phase of an **accepted** connection — the request-head read and each
/// response write — is bounded by the same login deadline and cancellation
/// token as `accept()` (K12): a peer that sends a partial request head and
/// stalls, or never drains a response, cannot hold the login past its
/// deadline, and cancellation interrupts it at once.
pub(crate) async fn run_pkce_callback(
    listener: TcpListener,
    expected_host: &str,
    state: &str,
    deadline: tokio::time::Instant,
    cancel: &CancellationToken,
) -> Result<PkceCallback, AuthError> {
    let expected_host = expected_host.to_owned();
    let state = state.to_owned();
    loop {
        let accepted = tokio::select! {
            _ = cancel.cancelled() => return Err(AuthError::Cancelled),
            res = tokio::time::timeout_at(deadline, listener.accept()) => match res {
                Err(_) => return Err(AuthError::Expired),
                Ok(Err(_)) => return Err(AuthError::Internal),
                Ok(Ok(conn)) => conn,
            },
        };
        let (mut stream, _peer) = accepted;
        let head = match read_request_head(&mut stream, deadline, cancel).await {
            Ok(Some(head)) => head,
            Ok(None) => {
                // Oversized head: reject, bounded like every other write.
                let _ = respond(
                    &mut stream,
                    deadline,
                    cancel,
                    "431 Request Header Fields Too Large",
                    None,
                )
                .await;
                continue;
            }
            Err(error) => return Err(error),
        };
        if !host_matches(&head.headers, &expected_host) {
            match respond(&mut stream, deadline, cancel, "400 Bad Request", None).await {
                Err(AuthError::Cancelled) => return Err(AuthError::Cancelled),
                _ => continue,
            }
        }
        match protocol::validate_callback(&head.request_line, head.total_bytes, &state) {
            Ok(CallbackCheck::Success { code }) => {
                let sent =
                    respond(&mut stream, deadline, cancel, "302 Found", Some("https://huggingface.co/"))
                        .await;
                return outcome_after_response(sent, PkceCallback::Code(code));
            }
            Ok(CallbackCheck::Denied) => {
                let sent = respond(&mut stream, deadline, cancel, "400 Bad Request", None).await;
                return outcome_after_response(sent, PkceCallback::Denied);
            }
            Ok(CallbackCheck::Failed { .. }) => {
                let sent = respond(&mut stream, deadline, cancel, "400 Bad Request", None).await;
                return outcome_after_response(sent, PkceCallback::ProviderError);
            }
            Err(_) => {
                // Reject without consuming the outstanding attempt.
                match respond(&mut stream, deadline, cancel, "400 Bad Request", None).await {
                    Err(AuthError::Cancelled) => return Err(AuthError::Cancelled),
                    _ => continue,
                }
            }
        }
    }
}

/// Finish one validated callback outcome after its response write.
///
/// The outcome (a one-time code, a recorded denial, a provider failure) was
/// produced by the user's authorization within the login window, so only an
/// **explicit cancellation** aborts it; a write that merely fails or runs out
/// the deadline never discards the code the authorization already minted.
fn outcome_after_response(
    write: Result<(), AuthError>,
    outcome: PkceCallback,
) -> Result<PkceCallback, AuthError> {
    match write {
        Err(AuthError::Cancelled) => Err(AuthError::Cancelled),
        _ => Ok(outcome),
    }
}

/// Bound one accepted-callback connection I/O phase (request-head read or
/// response write) by the login deadline and the login cancellation token
/// (K12). Bounding only `accept()` is not enough: a peer that sends a partial
/// request and stalls, or never drains the response, must not hold the login
/// past its deadline, and cancellation must interrupt the phase immediately.
async fn bound_callback_io<T>(
    deadline: tokio::time::Instant,
    cancel: &CancellationToken,
    work: impl Future<Output = Result<T, AuthError>>,
) -> Result<T, AuthError> {
    tokio::select! {
        _ = cancel.cancelled() => Err(AuthError::Cancelled),
        outcome = tokio::time::timeout_at(deadline, work) => match outcome {
            Err(_) => Err(AuthError::Expired),
            Ok(result) => result,
        },
    }
}

struct RequestHead {
    request_line: String,
    headers: Vec<(String, String)>,
    total_bytes: usize,
}

/// Read one request head (line + headers) with the 16 KiB total bound and the
/// login deadline/cancellation bound (K12): a stalled partial head terminates
/// as `Expired`/`Cancelled`, never as a hung login.
async fn read_request_head(
    stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    deadline: tokio::time::Instant,
    cancel: &CancellationToken,
) -> Result<Option<RequestHead>, AuthError> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let total;
    loop {
        let n = bound_callback_io(deadline, cancel, async {
            stream.read(&mut chunk).await.map_err(|_| AuthError::Internal)
        })
        .await?;
        if n == 0 {
            return Err(AuthError::Internal);
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_CALLBACK_REQUEST_BYTES {
            return Ok(None);
        }
        if let Some(pos) = find_head_end(&buf) {
            total = pos;
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf[..total]).into_owned();
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("").to_owned();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    Ok(Some(RequestHead {
        request_line,
        headers,
        total_bytes: buf.len(),
    }))
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn host_matches(headers: &[(String, String)], expected: &str) -> bool {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
        .count()
        == 1
        && headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("host") && value.eq_ignore_ascii_case(expected))
}

/// Write one minimal response and close the stream. Each write/flush is
/// bounded by the login deadline and cancellation token (K12): a peer that
/// never drains the response cannot hold the login past its deadline.
async fn respond(
    stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    deadline: tokio::time::Instant,
    cancel: &CancellationToken,
    status: &str,
    redirect: Option<&str>,
) -> Result<(), AuthError> {
    let body = b"Authorization could not be completed. You can close this window.";
    let text = match redirect {
        Some(location) => format!(
            "HTTP/1.1 {status}\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ),
        None => format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        ),
    };
    bound_callback_io(deadline, cancel, async {
        stream
            .write_all(text.as_bytes())
            .await
            .map_err(|_| AuthError::Internal)?;
        if redirect.is_none() {
            stream.write_all(body).await.map_err(|_| AuthError::Internal)?;
        }
        let _ = stream.flush().await;
        Ok(())
    })
    .await?;
    let _ = stream.shutdown().await;
    Ok(())
}

/// Exchange a one-time authorization code exactly once (PKCE verifier bound).
pub(crate) async fn exchange_code_once(
    client: &CodeClient,
    http: &reqwest::Client,
    code: &str,
    verifier: &str,
) -> Result<HfTokenResponse, AuthError> {
    let adapter = http::oidc_adapter!(http);
    let request = client
        .exchange_code(AuthorizationCode::new(code.to_owned()))
        .map_err(|_| AuthError::Internal)?
        .set_pkce_verifier(PkceCodeVerifier::new(verifier.to_owned()));
    request.request_async(&adapter).await.map_err(map_token_error)
}

/// Refresh an access token. `invalid_grant` maps to [`AuthError::InvalidGrant`]
/// so the caller fails closed instead of retrying.
pub(crate) async fn refresh_once(
    client: &CodeClient,
    http: &reqwest::Client,
    refresh_token: &str,
) -> Result<HfTokenResponse, AuthError> {
    let adapter = http::oidc_adapter!(http);
    let token = RefreshToken::new(refresh_token.to_owned());
    let request = client
        .exchange_refresh_token(&token)
        .map_err(|_| AuthError::Internal)?;
    request.request_async(&adapter).await.map_err(map_token_error)
}

/// Begin RFC 8628 device authorization (explicit flow, never automatic).
///
/// The `verification_uri` and, when present, `verification_uri_complete`
/// returned by the service are validated against the same endpoint trust
/// policy as every discovered endpoint (K13) **before** anything is published
/// to the user; a rejected pair fails closed with [`AuthError::ProviderMetadata`]
/// so no untrusted URL is ever displayed for manual entry.
pub(crate) async fn device_authorize(
    settings: &crate::config::OidcSettings,
    client: &DeviceClient,
    http: &reqwest::Client,
    request: &LoginRequest,
) -> Result<CoreDeviceAuthorizationResponse, AuthError> {
    let adapter = http::oidc_adapter!(http);
    let mut auth = client.exchange_device_code();
    for scope in config::scope_strings(request.purpose) {
        auth = auth.add_scope(Scope::new(scope));
    }
    if let Some(org) = &request.organization_id {
        let (name, value) = protocol::org_reconsent_param(org);
        auth = auth.add_extra_param(name, value);
    }
    let response = auth
        .request_async::<_, EmptyExtraDeviceAuthorizationFields>(&adapter)
        .await
        .map_err(map_device_auth_error)?;
    settings.validate_endpoint(response.verification_uri().as_str())?;
    if let Some(complete) = response.verification_uri_complete() {
        // `VerificationUriComplete` is a secret newtype: `secret()` yields the
        // raw string for policy validation.
        settings.validate_endpoint(complete.secret().as_str())?;
    }
    Ok(response)
}

/// Poll the device token endpoint until success/terminal failure/cancel.
/// The library honors `interval` (default 5s) and adds 5s on `slow_down`.
pub(crate) async fn device_poll(
    client: &DeviceClient,
    http: &reqwest::Client,
    auth: &DeviceAuthorizationResponse<EmptyExtraDeviceAuthorizationFields>,
    cancel: &CancellationToken,
) -> Result<HfTokenResponse, AuthError> {
    let adapter = http::oidc_adapter!(http);
    let poll = client
        .exchange_device_access_token(auth)
        .map_err(|_| AuthError::Internal)?;
    tokio::select! {
        _ = cancel.cancelled() => Err(AuthError::Cancelled),
        res = poll.request_async(&adapter, |delay: Duration| tokio::time::sleep(delay), None) => {
            match res {
                Ok(token) => Ok(token),
                Err(RequestTokenError::ServerResponse(err)) => match err.error() {
                    DeviceCodeErrorResponseType::AccessDenied => Err(AuthError::Denied),
                    DeviceCodeErrorResponseType::ExpiredToken => Err(AuthError::Expired),
                    _ => Err(AuthError::TokenEndpoint),
                },
                Err(_) => Err(AuthError::TokenEndpoint),
            }
        }
    }
}

/// Strictly verified identity extracted from an ID token.
pub(crate) struct VerifiedIdentity {
    pub(crate) issuer: String,
    pub(crate) subject: String,
    pub(crate) extra: ExtraClaims,
}

/// Verify ID-token signature (RS256 only), issuer, audience and expiry via
/// the openidconnect verifier; bind the nonce for PKCE logins. Access tokens,
/// never ID tokens, authorize APIs.
pub(crate) fn verify_id_token(
    client: &CodeClient,
    response: &HfTokenResponse,
    nonce: Option<&str>,
) -> Result<VerifiedIdentity, AuthError> {
    if !matches!(response.token_type(), CoreTokenType::Bearer) {
        return Err(AuthError::TokenEndpoint);
    }
    let id_token = response.id_token().ok_or(AuthError::IdentityValidation)?;
    let verifier = client
        .id_token_verifier()
        .set_allowed_algs([CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256]);
    let claims = match nonce {
        Some(expected) => {
            let expected = Nonce::new(expected.to_owned());
            id_token.claims(&verifier, &expected)
        }
        None => id_token.claims(&verifier, |_: Option<&Nonce>| Ok(())),
    }
    .map_err(|_| AuthError::IdentityValidation)?;
    Ok(VerifiedIdentity {
        issuer: claims.issuer().as_str().to_owned(),
        subject: claims.subject().to_string(),
        extra: claims.additional_claims().clone(),
    })
}

/// Fetch userinfo with expected-subject enforcement (subject agreement with
/// the verified ID token is checked by the request itself).
pub(crate) async fn fetch_userinfo(
    client: &CodeClient,
    http: &reqwest::Client,
    access_token: &str,
    expected_subject: &str,
) -> Result<HfUserInfoClaims, AuthError> {
    let adapter = http::oidc_adapter!(http);
    let request = client
        .user_info(
            AccessToken::new(access_token.to_owned()),
            Some(SubjectIdentifier::new(expected_subject.to_owned())),
        )
        .map_err(|_| AuthError::ProviderMetadata)?;
    request
        .request_async::<ExtraClaims, _, CoreGenderClaim>(&adapter)
        .await
        .map_err(|error| match error {
            openidconnect::UserInfoError::Request(_) => AuthError::TokenEndpoint,
            openidconnect::UserInfoError::Response(status, _, _) => userinfo_status_error(status),
            _ => AuthError::IdentityValidation,
        })
}

/// Fetch userinfo against the **already discovered and validated** metadata
/// endpoint using only the bearer token — no OAuth client id and no
/// `CodeClient`. Used by the display-only avatar backfill on restored sessions
/// that predate client configuration; the same bounded request/response rules
/// apply (no redirects, bounded body, sanitized errors).
pub(crate) async fn fetch_userinfo_bearer(
    userinfo_endpoint: &str,
    http: &reqwest::Client,
    access_token: &str,
    expected_subject: &str,
) -> Result<HfUserInfoClaims, AuthError> {
    let request = openidconnect::http::Request::builder()
        .method(openidconnect::http::Method::GET)
        .uri(userinfo_endpoint)
        .header(
            openidconnect::http::header::AUTHORIZATION,
            format!("Bearer {access_token}"),
        )
        .header(openidconnect::http::header::ACCEPT, "application/json")
        .body(Vec::new())
        .map_err(|_| AuthError::ProviderMetadata)?;
    let response = http::send_bounded(http, request, http::MAX_OIDC_RESPONSE_BYTES)
        .await
        .map_err(|_| AuthError::TokenEndpoint)?;
    userinfo_from_response(response.status(), response.body(), expected_subject)
}

/// Parse one bounded userinfo response with strict subject agreement, mapping
/// failures to the same sanitized errors as the `CodeClient` path — never a
/// body, URL or token.
fn userinfo_from_response(
    status: openidconnect::http::StatusCode,
    body: &[u8],
    expected_subject: &str,
) -> Result<HfUserInfoClaims, AuthError> {
    if !status.is_success() {
        return Err(userinfo_status_error(status));
    }
    HfUserInfoClaims::from_json::<serde_json::Error>(
        body,
        Some(&SubjectIdentifier::new(expected_subject.to_owned())),
    )
    .map_err(|_| AuthError::IdentityValidation)
}

/// Userinfo status mapping shared by both fetch paths: server errors and 429
/// are transport-side, every other failure is an identity rejection.
fn userinfo_status_error(status: openidconnect::http::StatusCode) -> AuthError {
    if status.is_server_error() || status.as_u16() == 429 {
        AuthError::TokenEndpoint
    } else {
        AuthError::IdentityValidation
    }
}

/// Extract and validate the display-only avatar from verified userinfo.
///
/// This is the single extraction path shared by login, refresh and the
/// restored-session avatar backfill: the standard OIDC `picture` claim's
/// unlocalized value, validated to HTTPS `huggingface.co`/subdomain with no
/// embedded credentials. Absent or rejected claims are `None` — never an
/// identity or login failure, and never combined with a bearer credential.
pub(crate) fn avatar_from_userinfo(userinfo: &HfUserInfoClaims) -> Option<String> {
    let raw_picture = userinfo.standard_claims().picture().and_then(|p| p.get(None));
    validate_avatar_url(raw_picture.map(|u| u.as_str()))
}

/// Build the immutable verified profile.
///
/// * the personal namespace must validate as a canonical [`Namespace`]:
///   absent/invalid `preferred_username` rejects the identity — nothing is
///   invented from the subject;
/// * org display names stay optional display hints;
/// * `granted_scopes: None` means unknown, never proven empty.
pub(crate) fn build_profile(
    identity: &VerifiedIdentity,
    userinfo: &HfUserInfoClaims,
    mut granted_scopes: Option<Vec<String>>,
    purpose: LoginPurpose,
    flow: LoginFlow,
    org_requested: Option<&str>,
    has_refresh: bool,
) -> Result<AccountProfile, AuthError> {
    use hfdrive_core::storage::Namespace;
    if let Some(scopes) = granted_scopes.as_mut() {
        scopes.sort_unstable();
        scopes.dedup();
    }
    if userinfo.subject().to_string() != identity.subject {
        return Err(AuthError::IdentityValidation);
    }
    let raw_namespace = userinfo
        .standard_claims()
        .preferred_username()
        .map(|u| u.to_string());
    let namespace = raw_namespace
        .ok_or(AuthError::IdentityValidation)
        .and_then(|raw| Namespace::new(raw).map_err(|_| AuthError::IdentityValidation))?;

    // Display-only: the standard OIDC `picture` claim, validated to HTTPS
    // `huggingface.co`/subdomain without embedded credentials. An absent or
    // rejected claim is `None`, never an identity/login failure.
    let avatar_url = avatar_from_userinfo(userinfo);

    let mut orgs: Vec<VerifiedOrg> = Vec::new();
    for source in [userinfo.additional_claims(), &identity.extra] {
        for candidate in source.org_candidates() {
            if !orgs.iter().any(|o| o.subject == candidate.subject) {
                orgs.push(VerifiedOrg {
                    subject: candidate.subject,
                    name: candidate.name,
                    role: candidate.role,
                    restrictions: candidate.restrictions,
                    consented_this_session: false,
                });
            }
        }
    }

    let mut org_consent_requested = false;
    if let Some(org_sub) = org_requested {
        let Some(org) = orgs.iter_mut().find(|o| o.subject == org_sub) else {
            return Err(AuthError::OrganizationNotVerified);
        };
        org.consented_this_session = true;
        org_consent_requested = true;
    }

    let purpose_covered = config::purpose_covered(purpose, granted_scopes.as_deref());
    Ok(AccountProfile {
        account_key: hfdrive_core::ids::AccountKey::from_subject(&identity.issuer, &identity.subject),
        issuer: identity.issuer.clone(),
        subject: identity.subject.clone(),
        namespace,
        avatar_url,
        orgs,
        granted_scopes,
        purpose_covered,
        org_consent_requested,
        reconsent_required_for_storage: flow == LoginFlow::Device || !has_refresh,
    })
}

fn map_token_error(err: RequestTokenError<http::HttpTransportError, HfTokenErrorResponse>) -> AuthError {
    match err {
        RequestTokenError::ServerResponse(err) => match err.error() {
            CoreErrorResponseType::InvalidGrant => AuthError::InvalidGrant,
            _ => AuthError::TokenEndpoint,
        },
        _ => AuthError::TokenEndpoint,
    }
}

fn map_device_auth_error(
    err: RequestTokenError<http::HttpTransportError, HfTokenErrorResponse>,
) -> AuthError {
    match err {
        RequestTokenError::ServerResponse(err) => match err.error() {
            CoreErrorResponseType::InvalidGrant => AuthError::InvalidGrant,
            _ => AuthError::TokenEndpoint,
        },
        _ => AuthError::TokenEndpoint,
    }
}

/// Random bytes from the OS CSPRNG (32 bytes for state/nonce/verifier).
pub(crate) fn random_bytes(len: usize) -> Result<zeroize::Zeroizing<Vec<u8>>, AuthError> {
    use rand::rngs::SysRng;
    use rand::TryRng as _;
    let mut bytes = zeroize::Zeroizing::new(vec![0u8; len]);
    let mut rng = SysRng;
    rng.try_fill_bytes(bytes.as_mut_slice())
        .map_err(|_| AuthError::Internal)?;
    Ok(bytes)
}

/// Base64url (no padding) of `len` CSPRNG bytes.
pub(crate) fn random_b64(len: usize) -> Result<String, AuthError> {
    use base64::Engine as _;
    let bytes = random_bytes(len)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes.as_slice()))
}

/// Lifetime policy: refresh at the earlier of five minutes before expiry and
/// 10% of the returned token lifetime.
pub(crate) fn refresh_due_at(expires_at: u64, lifetime_secs: u64) -> u64 {
    let lead = std::cmp::max(300, lifetime_secs / 10);
    expires_at.saturating_sub(lead)
}

#[cfg(test)]
mod tests {
    use super::{
        avatar_from_userinfo, build_device_client, device_authorize, fetch_userinfo_bearer,
        refresh_due_at, run_pkce_callback, HfUserInfoClaims, PkceCallback,
    };
    use crate::config::OidcSettings;
    use crate::error::AuthError;
    use crate::login::{LoginFlow, LoginPurpose, LoginRequest};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    fn userinfo(picture: &str) -> HfUserInfoClaims {
        let json = format!(
            r#"{{"sub":"fixture-subject","preferred_username":"fixture-person","picture":"{picture}"}}"#
        );
        HfUserInfoClaims::from_json::<serde_json::Error>(json.as_bytes(), None)
            .expect("fixture userinfo parses")
    }

    /// Minimal deterministic userinfo responder: returns `body` and records
    /// whether the request carried a bearer Authorization header.
    async fn userinfo_server(body: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/userinfo", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut chunk).await.unwrap();
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            // Prove the bearer-only shape: Authorization present, no client_id.
            let request = String::from_utf8_lossy(&buf);
            assert!(request.starts_with("GET /userinfo"));
            assert!(request.to_ascii_lowercase().contains("authorization: bearer"));
            assert!(!request.contains("client_id"));
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        endpoint
    }

    #[tokio::test]
    async fn bearer_only_userinfo_needs_no_oauth_client_id() {
        // The restored-session backfill path: no CodeClient and no client id
        // anywhere — just the discovered endpoint and the bearer token.
        let endpoint = userinfo_server(
            r#"{"sub":"fixture-subject","preferred_username":"fixture-person",
                "picture":"https://cdn-avatars.huggingface.co/v1/production/uploads/a.jpeg"}"#,
        )
        .await;
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let claims =
            fetch_userinfo_bearer(&endpoint, &client, "fixture-bearer", "fixture-subject")
                .await
                .expect("bearer-only fetch succeeds");
        assert_eq!(
            avatar_from_userinfo(&claims).as_deref(),
            Some("https://cdn-avatars.huggingface.co/v1/production/uploads/a.jpeg")
        );
    }

    #[tokio::test]
    async fn bearer_only_userinfo_enforces_subject_agreement() {
        let endpoint = userinfo_server(
            r#"{"sub":"someone-else","preferred_username":"fixture-person",
                "picture":"https://cdn-avatars.huggingface.co/v1/production/uploads/a.jpeg"}"#,
        )
        .await;
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let outcome =
            fetch_userinfo_bearer(&endpoint, &client, "fixture-bearer", "fixture-subject").await;
        assert_eq!(outcome.unwrap_err(), AuthError::IdentityValidation);
    }

    #[test]
    fn userinfo_picture_is_extracted_and_validated() {
        // The real avatar host observed in production.
        let claims = userinfo("https://cdn-avatars.huggingface.co/v1/production/uploads/a.jpeg");
        assert_eq!(
            avatar_from_userinfo(&claims).as_deref(),
            Some("https://cdn-avatars.huggingface.co/v1/production/uploads/a.jpeg")
        );
        // External and HTTP claims validate away to absence, not an error.
        assert_eq!(avatar_from_userinfo(&userinfo("https://evil.example.com/a.png")), None);
        assert_eq!(avatar_from_userinfo(&userinfo("http://huggingface.co/a.png")), None);
    }

    #[test]
    fn absent_or_malformed_picture_never_fails_the_identity() {
        let json = br#"{"sub":"fixture-subject","preferred_username":"fixture-person"}"#;
        let claims = HfUserInfoClaims::from_json::<serde_json::Error>(json, None)
            .expect("fixture userinfo parses");
        assert_eq!(avatar_from_userinfo(&claims), None);

        assert_eq!(avatar_from_userinfo(&userinfo("not a url")), None);
    }

    #[test]
    fn refresh_due_uses_max_of_five_minutes_and_ten_percent() {
        // Approved semantics: lead = max(300, lifetime/10); never min.
        // 60s lifetime -> lead 300 (clamped by the five-minute floor).
        assert_eq!(refresh_due_at(1_000_000, 60), 1_000_000 - 300);
        // 1800s lifetime -> 10% is 180s, still under the floor -> lead 300.
        assert_eq!(refresh_due_at(1_000_000, 1_800), 1_000_000 - 300);
        // 3600s lifetime -> 10% is 360s, above the floor -> lead 360.
        // A min() implementation would give 300 here; the exact difference
        // is the regression this pins.
        assert_eq!(refresh_due_at(1_000_000, 3_600), 1_000_000 - 360);

        // The boundary where 10% overtakes the floor: 3000s -> lead 300.
        assert_eq!(refresh_due_at(1_000_000, 3_000), 1_000_000 - 300);
        // Just past it: 3610s -> lead 361.
        assert_eq!(refresh_due_at(1_000_000, 3_610), 1_000_000 - 361);

        // Edge: an expiry shorter than the lead saturates at zero, never
        // underflows.
        assert_eq!(refresh_due_at(60, 3_600), 0);
        assert_eq!(refresh_due_at(0, 60), 0);
    }

    /// Minimal deterministic device-authorization responder. The body template
    /// has every `{base}` occurrence replaced with the fixture's own base URL
    /// before it is served, so tests can build URIs relative to the bound port.
    async fn device_server(body_template: &str) -> (String, OidcSettings) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let body = body_template.replace("{base}", &base);
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut chunk).await.unwrap();
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let settings = OidcSettings::fixture(
            &base,
            &format!("{base}/.well-known/openid-configuration"),
            "127.0.0.1",
            300,
        );
        (base, settings)
    }

    fn device_metadata(base: &str, device_endpoint: &str) -> crate::discovery::HfProviderMetadata {
        use openidconnect::core::{
            CoreJwsSigningAlgorithm, CoreResponseType, CoreSubjectIdentifierType,
        };
        use openidconnect::{AuthUrl, IssuerUrl, JsonWebKeySetUrl, ProviderMetadata, ResponseTypes};
        // The alias annotation fixes every generic parameter; only the RS256,
        // code-response and public-subject markers are named explicitly.
        let metadata: crate::discovery::HfProviderMetadata = ProviderMetadata::new(
            IssuerUrl::new(base.to_owned()).unwrap(),
            AuthUrl::new(format!("{base}/authorize")).unwrap(),
            JsonWebKeySetUrl::new(format!("{base}/jwks")).unwrap(),
            vec![ResponseTypes::new(vec![CoreResponseType::Code])],
            vec![CoreSubjectIdentifierType::Public],
            vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
            crate::discovery::HfProviderExtra {
                device_authorization_endpoint: Some(device_endpoint.to_owned()),
            },
        );
        metadata
    }

    fn device_request() -> LoginRequest {
        LoginRequest {
            operation_id: Uuid::new_v4(),
            flow: LoginFlow::Device,
            purpose: LoginPurpose::Signin,
            organization_id: None,
        }
    }

    #[tokio::test]
    async fn device_client_rejects_untrusted_device_endpoints() {
        // The device_authorization_endpoint must satisfy the same policy as
        // every discovered endpoint before any request is built.
        let (base, settings) = device_server("{}").await;
        for bad in [
            "https://evil.example.com/device",
            "https://127.0.0.1@evil.example.com/device",
            "http://127.0.0.1:1/device",
        ] {
            let metadata = device_metadata(&base, bad);
            let error = match build_device_client(&settings, &metadata, "test-client") {
                Err(error) => error,
                Ok(_) => panic!("untrusted device endpoint {bad} was not rejected"),
            };
            assert_eq!(
                error,
                AuthError::ProviderMetadata,
                "untrusted device endpoint {bad} was not rejected"
            );
        }
    }

    #[tokio::test]
    async fn device_flow_rejects_untrusted_verification_uris() {
        // The verification URI(s) the service returns are validated with the
        // same policy before anything is published to the user.
        let body = r#"{
            "device_code": "device-code-1",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://evil.example.com/device",
            "expires_in": 600,
            "interval": 1
        }"#;
        let (base, settings) = device_server(body).await;
        let metadata = device_metadata(&base, &format!("{base}/device"));
        let client = build_device_client(&settings, &metadata, "test-client").unwrap();
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let outcome =
            device_authorize(&settings, &client, &http, &device_request()).await;
        assert_eq!(outcome.unwrap_err(), AuthError::ProviderMetadata);

        // A trusted verification_uri does not launder an untrusted
        // verification_uri_complete.
        let body = r#"{
            "device_code": "device-code-1",
            "user_code": "ABCD-EFGH",
            "verification_uri": "{base}/device",
            "verification_uri_complete": "https://evil.example.com/device?user_code=ABCD-EFGH",
            "expires_in": 600,
            "interval": 1
        }"#;
        let (base, settings) = device_server(body).await;
        let metadata = device_metadata(&base, &format!("{base}/device"));
        let client = build_device_client(&settings, &metadata, "test-client").unwrap();
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let outcome =
            device_authorize(&settings, &client, &http, &device_request()).await;
        assert_eq!(outcome.unwrap_err(), AuthError::ProviderMetadata);

        // And a usercode-bearing userinfo-style bypass in the URI is rejected.
        let body = r#"{
            "device_code": "device-code-1",
            "user_code": "ABCD-EFGH",
            "verification_uri": "http://127.0.0.1@evil.example.com/device",
            "expires_in": 600,
            "interval": 1
        }"#;
        let (base, settings) = device_server(body).await;
        let metadata = device_metadata(&base, &format!("{base}/device"));
        let client = build_device_client(&settings, &metadata, "test-client").unwrap();
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let outcome =
            device_authorize(&settings, &client, &http, &device_request()).await;
        assert_eq!(outcome.unwrap_err(), AuthError::ProviderMetadata);
    }

    #[tokio::test]
    async fn device_flow_accepts_policy_conforming_verification_uris() {
        let body = r#"{
            "device_code": "device-code-1",
            "user_code": "ABCD-EFGH",
            "verification_uri": "{base}/device",
            "verification_uri_complete": "{base}/device?user_code=ABCD-EFGH",
            "expires_in": 600,
            "interval": 1
        }"#;
        let (base, settings) = device_server(body).await;
        let metadata = device_metadata(&base, &format!("{base}/device"));
        let client = build_device_client(&settings, &metadata, "test-client").unwrap();
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let response = device_authorize(&settings, &client, &http, &device_request())
            .await
            .expect("policy-conforming verification URIs are accepted");
        assert_eq!(response.user_code().secret().as_str(), "ABCD-EFGH");
    }

    #[tokio::test]
    async fn callback_accepts_one_valid_request_and_returns_the_code() {
        // K12 must not break the success path: one valid callback is consumed
        // exactly once and answered with the redirect.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let expected_host = format!("127.0.0.1:{port}");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let cancel = CancellationToken::new();
        let server = run_pkce_callback(listener, &expected_host, "state-1", deadline, &cancel);

        // The browser side runs as its own task so the callback future is
        // polled while the request/response bytes flow. `server` borrows
        // `expected_host` until it completes, so the request copies the host.
        let request_host = expected_host.clone();
        let browser = tokio::spawn(async move {
            let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let request = format!(
                "GET /oauth/callback?code=test-code&state=state-1 HTTP/1.1\r\nHost: {request_host}\r\nConnection: close\r\n\r\n"
            );
            client.write_all(request.as_bytes()).await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            String::from_utf8_lossy(&response).into_owned()
        });

        let outcome = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("valid callback completes promptly")
            .expect("valid callback succeeds");
        assert_eq!(outcome, PkceCallback::Code("test-code".to_owned()));

        let text = browser.await.unwrap();
        assert!(text.starts_with("HTTP/1.1 302"), "unexpected response: {text}");
    }

    #[tokio::test]
    async fn callback_stalled_partial_request_hits_the_login_deadline() {
        // K12: a peer that sends a partial request head and stalls must be
        // bounded by the same login deadline as accept(), not just accepted
        // and then hung forever.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let expected_host = format!("127.0.0.1:{port}");
        let deadline = tokio::time::Instant::now() + Duration::from_millis(400);
        let cancel = CancellationToken::new();
        let server = run_pkce_callback(listener, &expected_host, "state-1", deadline, &cancel);

        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        // Partial request head: no terminating CRLFCRLF, and no more bytes.
        client.write_all(b"GET /oauth/callback?co").await.unwrap();

        let outcome = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("stalled read must be deadline-bounded")
            .expect_err("a stalled partial request must never complete a login");
        assert_eq!(outcome, AuthError::Expired);
        drop(client);
    }

    #[tokio::test]
    async fn callback_stalled_partial_request_is_interrupted_by_cancellation() {
        // K12: cancellation bounds the connection I/O phases too, with a
        // deadline far away so only cancellation can end the wait.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let expected_host = format!("127.0.0.1:{port}");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let cancel = CancellationToken::new();
        let server = run_pkce_callback(listener, &expected_host, "state-1", deadline, &cancel);

        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(b"GET /oauth/callback?co").await.unwrap();

        let canceller = {
            let cancel = cancel.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                cancel.cancel();
            }
        };
        let (outcome, ()) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(5), server),
            canceller,
        );
        let outcome = outcome.expect("cancellation must interrupt the stalled read promptly");
        assert_eq!(outcome, Err(AuthError::Cancelled));
        drop(client);
    }
}
