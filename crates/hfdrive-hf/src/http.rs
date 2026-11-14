//! Raw HTTP plumbing for the documented HF Bucket REST routes that the pinned
//! SDK cannot serve (partial batch results, same-origin pagination, events,
//! stable identities, bounded HEAD-record reads).

use crate::NativeError;
use crate::wire_budget::{Direction, WireBudget};
use bytes::{Bytes, BytesMut};
use hfdrive_auth::TokenSource;
use reqwest::header::HeaderMap;
use reqwest::Url;
use tokio_util::sync::CancellationToken;

use crate::wire;

/// Shared transport: rustls with platform verification via reqwest's default
/// integration, no automatic redirect following anywhere. Every caller decides
/// explicitly which redirects exist at all.
pub(crate) fn build_http_client() -> Result<reqwest::Client, NativeError> {
    reqwest::Client::builder()
        .tls_backend_rustls()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("HFDrive/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| NativeError::Transport)
}

/// Map a response status to a sanitized error. `retry_after` is the parsed
/// integer-seconds `Retry-After` value when present.
pub(crate) fn status_error(status: u16, retry_after: Option<u64>) -> NativeError {
    match status {
        401 => NativeError::NeedsSignIn,
        403 => NativeError::PermissionDenied,
        404 | 410 => NativeError::RemoteContentUnavailable,
        409 => NativeError::AlreadyExists,
        429 => NativeError::RateLimited { retry_after_seconds: retry_after },
        400..=499 => NativeError::InvalidRequest { detail: "request rejected by the native service".to_owned() },
        _ => NativeError::Transport,
    }
}

pub(crate) fn retry_after_seconds(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Map an unsuccessful raw response to a sanitized error without retaining the
/// body. 401 becomes [`NativeError::NeedsSignIn`] so the dispatch wrappers can
/// perform their single controlled refresh.
pub(crate) fn error_from_response(response: &reqwest::Response) -> NativeError {
    status_error(response.status().as_u16(), retry_after_seconds(response.headers()))
}

/// Read at most `limit` bytes; anything beyond is a contract violation, never
/// silently truncated. Every body chunk is counted and paced at the encoded
/// transport boundary through the shared [`WireBudget`] before it is buffered.
pub(crate) async fn read_bounded(
    response: reqwest::Response,
    limit: usize,
    budget: &WireBudget,
) -> Result<Bytes, NativeError> {
    let mut body = response;
    let mut buffer = BytesMut::new();
    loop {
        let Some(chunk) = body.chunk().await.map_err(|_| NativeError::Transport)? else {
            return Ok(buffer.freeze());
        };
        if buffer.len().saturating_add(chunk.len()) > limit {
            return Err(NativeError::InvalidResponse);
        }
        budget.gate(Direction::Download, chunk.len() as u64).await;
        buffer.extend_from_slice(&chunk);
    }
}

/// One JSON request against the trusted HF API origin. The bearer credential is
/// attached only here, and only for URLs this crate constructed from the
/// validated endpoint. Returns the bounded body plus response headers (for
/// validated `Link` pagination).
pub(crate) async fn get_json<T: TokenSource>(
    state: &crate::auth::ClientState,
    api: &crate::NativeApi<T>,
    url: Url,
    cancel: &CancellationToken,
) -> Result<(Bytes, HeaderMap), NativeError> {
    let request = api.http().get(url.clone()).headers(state.bearer.clone()).send();
    let response = tokio::select! {
        _ = cancel.cancelled() => return Err(NativeError::Cancelled),
        result = request => result.map_err(|_| NativeError::Transport)?,
    };
    if !response.status().is_success() {
        return Err(error_from_response(&response));
    }
    let headers = response.headers().clone();
    let body = tokio::select! {
        _ = cancel.cancelled() => return Err(NativeError::Cancelled),
        result = read_bounded(response, crate::MAX_JSON_BYTES, api.budget()) => result?,
    };
    Ok((body, headers))
}

/// POST a body (NDJSON or JSON) to the trusted HF API origin. The request body
/// is counted and paced at the encoded upload boundary before dispatch; the
/// response body is gated on the download boundary.
pub(crate) async fn post_body<T: TokenSource>(
    state: &crate::auth::ClientState,
    api: &crate::NativeApi<T>,
    url: Url,
    content_type: &'static str,
    body: Bytes,
    cancel: &CancellationToken,
) -> Result<Bytes, NativeError> {
    let request = api
        .http()
        .post(url)
        .headers(state.bearer.clone())
        .header(reqwest::header::CONTENT_TYPE, content_type)
        .body(body.clone());
    // The encoded body is admitted (counted) and paced before it can leave.
    let send = async move {
        api.budget().gate(Direction::Upload, body.len() as u64).await;
        request.send().await
    };
    let response = tokio::select! {
        _ = cancel.cancelled() => return Err(NativeError::Cancelled),
        result = send => result.map_err(|_| NativeError::Transport)?,
    };
    if !response.status().is_success() {
        return Err(error_from_response(&response));
    }
    tokio::select! {
        _ = cancel.cancelled() => Err(NativeError::Cancelled),
        result = read_bounded(response, crate::MAX_JSON_BYTES, api.budget()) => result,
    }
}

/// Status-only GET against the trusted HF API origin. The response body is
/// never read or parsed (it may contain short-lived CAS tokens); the connection
/// is dropped immediately after the status is classified.
pub(crate) async fn probe_status<T: TokenSource>(
    state: &crate::auth::ClientState,
    api: &crate::NativeApi<T>,
    url: Url,
    cancel: &CancellationToken,
) -> Result<(), NativeError> {
    let request = api.http().get(url).headers(state.bearer.clone()).send();
    let response = tokio::select! {
        _ = cancel.cancelled() => return Err(NativeError::Cancelled),
        result = request => result.map_err(|_| NativeError::Transport)?,
    };
    let status = response.status();
    let retry_after = retry_after_seconds(response.headers());
    drop(response);
    if status.is_success() {
        Ok(())
    } else {
        Err(status_error(status.as_u16(), retry_after))
    }
}

/// Bounded GET for one small mutable record through the native resolve route.
///
/// Redirect policy: same-origin locations are followed with the bearer (up to
/// 10 hops); any cross-origin location is followed **without** the HF bearer
/// (the location is a scoped service URL and must never see HF credentials),
/// and its query string never reaches callers or errors. Cross-origin hops use
/// no headers at all. A further redirect after the bound is hit is refused.
pub(crate) async fn resolve_record_bounded<T: TokenSource>(
    state: &crate::auth::ClientState,
    api: &crate::NativeApi<T>,
    start: Url,
    bound: usize,
    cancel: &CancellationToken,
) -> Result<Bytes, NativeError> {
    if bound == 0 {
        return Err(NativeError::InvalidRequest { detail: "record bound must be positive".to_owned() });
    }
    let mut url = start;
    let mut same_origin_bearer = true;
    for _ in 0..10 {
        let mut request = api.http().get(url.clone());
        if same_origin_bearer {
            request = request.headers(state.bearer.clone());
        }
        request = request.header(reqwest::header::RANGE, format!("bytes=0-{}", bound.saturating_sub(1)));
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(NativeError::Cancelled),
            result = request.send() => result.map_err(|_| NativeError::Transport)?,
        };
        let status = response.status();
        if status.is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or(NativeError::InvalidResponse)?;
            let next = url.join(location).map_err(|_| NativeError::InvalidResponse)?;
            if !next_has_credentials(&next) && (next.scheme() == "https" || next.scheme() == "http") {
                same_origin_bearer = same_origin(&url, &next);
                url = next;
                continue;
            }
            return Err(NativeError::RemoteContentUnavailable);
        }
        if !status.is_success() {
            return Err(error_from_response(&response));
        }
        return tokio::select! {
            _ = cancel.cancelled() => Err(NativeError::Cancelled),
            result = read_bounded(response, bound, api.budget()) => result,
        };
    }
    Err(NativeError::RemoteContentUnavailable)
}

fn next_has_credentials(url: &Url) -> bool {
    !url.username().is_empty() || url.password().is_some()
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme() && a.host_str() == b.host_str() && a.port_or_known_default() == b.port_or_known_default()
}

/// Build `{endpoint}/api/buckets/{ns}/{name}[/...]` with every variable
/// segment percent-encoded.
pub(crate) fn bucket_api_url(endpoint: &str, namespace: &str, name: &str, tail: &[&str]) -> Result<Url, NativeError> {
    let mut url = Url::parse(endpoint).map_err(|_| NativeError::InvalidResponse)?;
    {
        let mut segments = url.path_segments_mut().map_err(|_| NativeError::InvalidResponse)?;
        segments.push("api").push("buckets").push(namespace).push(name);
        for part in tail {
            segments.push(part);
        }
    }
    Ok(url)
}

/// Build `{endpoint}/buckets/{ns}/{name}/resolve/{key}` with the key encoded
/// per segment.
pub(crate) fn resolve_url(endpoint: &str, namespace: &str, name: &str, key: &str) -> Result<Url, NativeError> {
    let mut url = Url::parse(endpoint).map_err(|_| NativeError::InvalidResponse)?;
    {
        let mut segments = url.path_segments_mut().map_err(|_| NativeError::InvalidResponse)?;
        segments.push("buckets").push(namespace).push(name).push("resolve");
        for part in wire::encode_key_path(key).split('/').filter(|s| !s.is_empty()) {
            segments.push(part);
        }
    }
    Ok(url)
}

/// The bucket's API prefix used as the pagination containment boundary.
pub(crate) fn bucket_api_prefix(namespace: &str, name: &str) -> String {
    format!("/api/buckets/{namespace}/{name}")
}
