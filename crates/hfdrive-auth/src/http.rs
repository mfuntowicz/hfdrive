//! Strict, bounded OIDC HTTP access over the shared reqwest client.
//!
//! * No redirects are ever followed (`redirect::Policy::none`): a discovery,
//!   token, userinfo or JWKS request that is redirected is a hard failure.
//! * Response bodies are bounded (configurable; 256 KiB default) and read to
//!   completion before parsing; transport errors are sanitized here so no
//!   raw reqwest/url content reaches public error surfaces.
//! * The openidconnect `AsyncHttpClient` contract is honored via a concrete
//!   async-future adapter function — no boxed-future allocation per call and
//!   no reliance on the library's reqwest 0.12 adapter feature.

use crate::error::AuthError;

/// Default maximum response body accepted from OIDC endpoints.
pub(crate) const MAX_OIDC_RESPONSE_BYTES: usize = 256 * 1024;

/// Sanitized transport error; never contains URLs, headers or bodies.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("OIDC request failed (transport)")]
pub struct HttpTransportError;

/// The `openidconnect` request type (bound-checked by the adapter contract).
pub(crate) type OidcRequest = openidconnect::HttpRequest;

/// Build the shared OIDC HTTP client: rustls (platform verifier), HTTP/2,
/// system proxy discovery, JSON, streams; redirects disabled.
pub(crate) fn build_oidc_client() -> Result<reqwest::Client, AuthError> {
    reqwest::Client::builder()
        .tls_backend_rustls()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| AuthError::ProviderMetadata)
}

/// Send one `http::Request` through the shared client and return a bounded
/// `http::Response`. The request must already target a validated endpoint
/// (see [`crate::config::OidcSettings::validate_endpoint`]). Redirects are
/// never followed: a 3xx response is a hard failure.
pub(crate) async fn send_bounded(
    client: &reqwest::Client,
    request: OidcRequest,
    max_bytes: usize,
) -> Result<openidconnect::HttpResponse, HttpTransportError> {
    let (parts, body) = request.into_parts();
    let mut builder = client.request(parts.method, parts.uri.to_string());
    for (name, value) in &parts.headers {
        let name = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes())
            .map_err(|_| HttpTransportError)?;
        let value =
            reqwest::header::HeaderValue::from_bytes(value.as_bytes()).map_err(|_| HttpTransportError)?;
        builder = builder.header(name, value);
    }
    if !body.is_empty() {
        builder = builder.body(body);
    }
    let response = builder.send().await.map_err(|_| HttpTransportError)?;
    if response.status().is_redirection() {
        return Err(HttpTransportError);
    }
    let status = response.status();
    let mut out: Vec<u8> = Vec::new();
    let mut stream = response;
    while let Some(chunk) = stream.chunk().await.map_err(|_| HttpTransportError)? {
        if out.len() + chunk.len() > max_bytes {
            return Err(HttpTransportError);
        }
        out.extend_from_slice(&chunk);
    }
    let mut builder = openidconnect::http::Response::builder().status(status.as_u16());
    // `reqwest` headers are the same `http` 1.x types the adapter contract
    // uses; well-formed response headers copy across unchanged.
    let headers = builder.headers_mut().ok_or(HttpTransportError)?;
    for (name, value) in stream.headers() {
        headers.append(name.clone(), value.clone());
    }
    builder.body(out).map_err(|_| HttpTransportError)
}

/// Build one `openidconnect::AsyncHttpClient` adapter closure over the shared
/// client: a concrete async future per call site, no boxed allocation.
macro_rules! oidc_adapter {
    ($client:expr) => {{
        let client = $client.clone();
        move |request: $crate::http::OidcRequest| {
            let client = client.clone();
            async move {
                $crate::http::send_bounded(&client, request, $crate::http::MAX_OIDC_RESPONSE_BYTES).await
            }
        }
    }};
}
pub(crate) use oidc_adapter;
