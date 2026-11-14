//! Wire DTOs and pure validation helpers for the documented HF Bucket REST
//! surface (shape taken from `https://huggingface.co/.well-known/openapi.json`,
//! checked 2026-11-13). No SDK types, no network.

use hfdrive_core::{
    ids::WorkspaceId,
    storage::{BucketId, Namespace, RelativeKey, XetFileId},
};
use reqwest::header::HeaderMap;
use reqwest::Url;
use std::str::FromStr;

use crate::NativeError;

/// Stable summary of one bucket as returned by `GET /api/buckets/{namespace}`
/// and `GET /api/buckets/{namespace}/{bucket}`. `_id` is the service's stable
/// ObjectId and is what survives display-name changes.
#[derive(Clone, Debug)]
pub struct BucketSummaryWire {
    pub bucket_id: BucketId,
    pub name: String,
    /// Owner namespace as reported by the service; must match the requested
    /// namespace or the response is rejected.
    pub owner_namespace: String,
    pub private: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub size: u64,
    pub total_files: u64,
}

impl BucketSummaryWire {
    /// Parse one listing/info record, validating `_id`, `id` (`ns/name`) and
    /// the owner namespace against what the caller selected. A display-name
    /// mismatch is [`NativeError::IdentityMismatch`], never silently accepted.
    pub fn parse(value: &serde_json::Value, expected_namespace: &str, expected_name: Option<&str>) -> Result<Self, NativeError> {
        let obj = value.as_object().ok_or(NativeError::InvalidResponse)?;
        let raw_id = obj.get("_id").and_then(|v| v.as_str()).ok_or(NativeError::InvalidResponse)?;
        let bucket_id = BucketId::new(raw_id.to_owned()).map_err(|_| NativeError::InvalidResponse)?;
        let wire_id = obj.get("id").and_then(|v| v.as_str()).ok_or(NativeError::InvalidResponse)?;
        let (owner, name) = wire_id.split_once('/').ok_or(NativeError::InvalidResponse)?;
        if owner != expected_namespace {
            return Err(NativeError::IdentityMismatch);
        }
        if let Some(want) = expected_name
            && name != want
        {
            return Err(NativeError::IdentityMismatch);
        }
        Ok(Self {
            bucket_id,
            name: name.to_owned(),
            owner_namespace: owner.to_owned(),
            private: obj.get("private").and_then(|v| v.as_bool()).unwrap_or(false),
            created_at: obj.get("createdAt").and_then(|v| v.as_str()).map(str::to_owned),
            updated_at: obj.get("updatedAt").and_then(|v| v.as_str()).map(str::to_owned),
            size: obj.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
            total_files: obj.get("totalFiles").and_then(|v| v.as_u64()).unwrap_or(0),
        })
    }
}

/// Response of `POST /api/buckets/{ns}/{bucket}/batch`. A 200 can still carry
/// partial failure; every sent operation must be accounted for by
/// `processed == sent`, `succeeded + failed.len() == processed`.
#[derive(Clone, Debug)]
pub struct BatchResponseWire {
    pub success: bool,
    pub processed: u64,
    pub succeeded: u64,
    pub failed: Vec<(String, String)>,
}

impl BatchResponseWire {
    pub fn parse(value: serde_json::Value, sent: usize) -> Result<Self, NativeError> {
        let obj = value.as_object().ok_or(NativeError::InvalidResponse)?;
        let success = obj.get("success").and_then(|v| v.as_bool()).ok_or(NativeError::InvalidResponse)?;
        let processed = obj.get("processed").and_then(|v| v.as_u64()).ok_or(NativeError::InvalidResponse)?;
        let succeeded = obj.get("succeeded").and_then(|v| v.as_u64()).ok_or(NativeError::InvalidResponse)?;
        let failed_raw = obj.get("failed").and_then(|v| v.as_array()).ok_or(NativeError::InvalidResponse)?;
        let mut failed = Vec::with_capacity(failed_raw.len());
        for item in failed_raw {
            let path = item.get("path").and_then(|v| v.as_str()).ok_or(NativeError::InvalidResponse)?;
            let error = item.get("error").and_then(|v| v.as_str()).unwrap_or("operation failed");
            failed.push((path.to_owned(), NativeError::detail(error)));
        }
        if processed != sent as u64
            || succeeded.checked_add(failed.len() as u64) != Some(processed)
            || processed < succeeded
        {
            return Err(NativeError::InvalidResponse);
        }
        Ok(Self { success, processed, succeeded, failed })
    }
}

/// One entry from `/tree` or `/paths-info`.
#[derive(Clone, Debug)]
pub struct TreeEntryWire {
    pub path: String,
    pub is_file: bool,
    pub size: u64,
    /// Xet Merkle hash; empty string when absent. Files without a valid hash
    /// are exposed as `xet_file_id: None` so the capability gate can reject
    /// them instead of silently switching payload format.
    pub xet_hash: Option<XetFileId>,
    pub mtime: Option<String>,
    pub uploaded_at: Option<String>,
}

impl TreeEntryWire {
    pub fn parse(value: &serde_json::Value) -> Result<Self, NativeError> {
        let obj = value.as_object().ok_or(NativeError::InvalidResponse)?;
        let kind = obj.get("type").and_then(|v| v.as_str()).ok_or(NativeError::InvalidResponse)?;
        let path = obj.get("path").and_then(|v| v.as_str()).ok_or(NativeError::InvalidResponse)?.to_owned();
        let (is_file, size, xet_hash) = match kind {
            "file" => {
                let size = obj.get("size").and_then(|v| v.as_u64()).ok_or(NativeError::InvalidResponse)?;
                let hash_raw = obj.get("xetHash").and_then(|v| v.as_str()).unwrap_or("");
                (true, size, XetFileId::new(hash_raw.to_owned()).ok())
            }
            "directory" => (false, 0, None),
            _ => return Err(NativeError::InvalidResponse),
        };
        Ok(Self {
            path,
            is_file,
            size,
            xet_hash,
            mtime: obj.get("mtime").and_then(|v| v.as_str()).map(str::to_owned),
            uploaded_at: obj.get("uploadedAt").and_then(|v| v.as_str()).map(str::to_owned),
        })
    }
}

/// Managed HEAD record classification. Format/schema decoding lives in Step 3;
/// this crate only classifies enough to answer "is this a supported HF Drive
/// HEAD, which workspace does it name, and is it too big to read safely".
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeadFormat {
    /// `format == "hfdrive"`, integer `schema_version == 1`, empty
    /// `required_features`, parseable `workspace_id`.
    V1 { workspace_id: WorkspaceId },
    /// Recognizable HF Drive record from a newer schema or with required
    /// features this build cannot satisfy. Never treated as empty/initializable.
    Newer { schema_version: u64 },
    /// Not an HF Drive managed HEAD record at all.
    Foreign,
}

#[derive(Clone, Debug)]
pub struct HeadRecord {
    /// Exact bounded record bytes (SHA-256-addressed in Step 3).
    pub bytes: bytes::Bytes,
    pub format: HeadFormat,
}

/// Classify a bounded HEAD record body. Never invents a workspace identity.
pub fn parse_head_record(bytes: &[u8]) -> HeadRecord {
    let format = classify_head(bytes);
    HeadRecord { bytes: bytes::Bytes::copy_from_slice(bytes), format }
}

fn classify_head(bytes: &[u8]) -> HeadFormat {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return HeadFormat::Foreign;
    };
    let Some(obj) = value.as_object() else {
        return HeadFormat::Foreign;
    };
    if obj.get("format").and_then(|v| v.as_str()) != Some("hfdrive") {
        return HeadFormat::Foreign;
    }
    let Some(schema) = obj.get("schema_version").and_then(|v| v.as_u64()) else {
        return HeadFormat::Foreign;
    };
    let required = obj.get("required_features").and_then(|v| v.as_array());
    let needs_newer = required.is_some_and(|f| !f.is_empty());
    if schema != 1 || needs_newer {
        return HeadFormat::Newer { schema_version: schema };
    }
    let Some(raw_workspace) = obj.get("workspace_id").and_then(|v| v.as_str()) else {
        return HeadFormat::Foreign;
    };
    match WorkspaceId::from_str(raw_workspace) {
        Ok(workspace_id) => HeadFormat::V1 { workspace_id },
        Err(_) => HeadFormat::Foreign,
    }
}

/// Parse the `Link` header's `rel="next"` URL and require it to stay on the API
/// origin and inside the bucket's API prefix. hf-hub's own pagination follows
/// any URL the header names; this crate must not.
pub(crate) fn link_next(headers: &HeaderMap, base: &Url, api_prefix: &str) -> Result<Option<Url>, NativeError> {
    let Some(raw) = headers.get(reqwest::header::LINK).and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    let mut found: Option<String> = None;
    for part in raw.split(',') {
        let part = part.trim();
        if !part.contains("rel=\"next\"") {
            continue;
        }
        let Some(start) = part.find('<') else {
            return Err(NativeError::InvalidResponse);
        };
        let Some(end) = part.find('>') else {
            return Err(NativeError::InvalidResponse);
        };
        if end <= start + 1 {
            return Err(NativeError::InvalidResponse);
        }
        if found.replace(part[start + 1..end].to_owned()).is_some() {
            return Err(NativeError::InvalidResponse);
        }
    }
    let Some(next_raw) = found else {
        return Ok(None);
    };
    let next = base.join(&next_raw).map_err(|_| NativeError::InvalidResponse)?;
    validate_next(&next, base.as_str(), api_prefix)?;
    Ok(Some(next))
}

/// Validate a caller-supplied next-page URL (persisted cursor round-trip):
/// same scheme/host/port as the endpoint, inside the API prefix, no embedded
/// credentials.
pub(crate) fn validate_next(next: &Url, endpoint: &str, api_prefix: &str) -> Result<(), NativeError> {
    let base = Url::parse(endpoint).map_err(|_| NativeError::InvalidResponse)?;
    if next.scheme() != base.scheme()
        || next.host_str() != base.host_str()
        || next.port_or_known_default() != base.port_or_known_default()
    {
        return Err(NativeError::InvalidResponse);
    }
    if !next.username().is_empty() || next.password().is_some() {
        return Err(NativeError::InvalidResponse);
    }
    let path = next.path();
    if !(path == api_prefix || path.starts_with(&format!("{api_prefix}/"))) {
        return Err(NativeError::InvalidResponse);
    }
    Ok(())
}

/// Percent-encode a bucket-relative key into a URL path. Each `/`-separated
/// segment keeps only RFC 3986 unreserved bytes; the separators survive.
pub(crate) fn encode_key_path(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for byte in key.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(byte as char),
            b'/' => out.push('/'),
            other => {
                out.push('%');
                out.push(char::from_digit((other >> 4) as u32, 16).unwrap_or('0').to_ascii_uppercase());
                out.push(char::from_digit((other & 0x0f) as u32, 16).unwrap_or('0').to_ascii_uppercase());
            }
        }
    }
    out
}

/// Validate a wire path as a canonical bucket-relative key. Rejecting is what
/// the "metadata reference derives its key from a typed validated ID" rule
/// needs; callers never feed raw wire paths back into requests.
pub(crate) fn wire_key(path: &str) -> Result<RelativeKey, NativeError> {
    RelativeKey::new(path.to_owned()).map_err(|_| NativeError::InvalidResponse)
}

/// Parse the `type`/`op` change field of an events payload.
pub(crate) fn parse_change_op(raw: &str) -> Option<crate::store::ChangeOp> {
    use crate::store::ChangeOp;
    match raw {
        "add" => Some(ChangeOp::Add),
        "update" => Some(ChangeOp::Update),
        "delete" => Some(ChangeOp::Delete),
        _ => None,
    }
}

/// Owner namespace validation re-check for wire values (defense in depth).
pub(crate) fn wire_namespace(raw: &str) -> Result<Namespace, NativeError> {
    Namespace::new(raw.to_owned()).map_err(|_| NativeError::InvalidResponse)
}

// ---- SSE event feed ----

pub(crate) type SseEvent = eventsource_stream::Event;
pub(crate) type SseError = eventsource_stream::EventStreamError<reqwest::Error>;

/// Boxed raw SSE event source plus a shared last-activity stamp. Comments
/// (`: ping`) are consumed by the parser and never surface, but their encoded
/// bytes update the activity stamp so silence detection sees heartbeats.
/// Every encoded body byte of the stream is counted and paced at the download
/// boundary before the event parser sees it.
pub(crate) struct SseSource {
    pub(crate) events: std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<SseEvent, SseError>> + Send>>,
    pub(crate) activity: std::sync::Arc<std::sync::Mutex<std::time::Instant>>,
}

/// Records the last time an encoded body byte arrived (heartbeats included).
struct ActivityStream<S> {
    inner: S,
    activity: std::sync::Arc<std::sync::Mutex<std::time::Instant>>,
}

impl<S> futures_util::Stream for ActivityStream<S>
where
    S: futures_util::Stream + Unpin,
{
    type Item = S::Item;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let poll = std::pin::Pin::new(&mut self.inner).poll_next(cx);
        if matches!(poll, std::task::Poll::Ready(Some(_))) {
            *self.activity.lock().unwrap_or_else(|e| e.into_inner()) = std::time::Instant::now();
        }
        poll
    }
}

pub(crate) fn sse_stream(response: reqwest::Response, budget: crate::wire_budget::WireBudget) -> SseSource {
    use eventsource_stream::Eventsource;
    let activity = std::sync::Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
    let gated = budget.gate_stream(crate::wire_budget::Direction::Download, response.bytes_stream());
    let tracked = ActivityStream { inner: gated, activity: activity.clone() };
    SseSource { events: Box::pin(tracked.eventsource()), activity }
}

fn event_payload(data: &str) -> Result<serde_json::Value, NativeError> {
    serde_json::from_slice(data.as_bytes()).map_err(|_| NativeError::InvalidResponse)
}

// ---- whoami-v2 owner identities ----

use hfdrive_core::storage::{OwnerId, OwnerKind};

/// One owner identity exactly as the authenticated `GET /api/whoami-v2`
/// surface reports it: the **stable id** paired with the canonical namespace
/// spelling the service itself maps it to. This is the only id -> namespace
/// mapping that may authorize a namespace-located request; the display name is
/// retained as a hint and never used as a locator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WhoamiOwner {
    pub owner_id: OwnerId,
    pub owner_kind: OwnerKind,
    /// Canonical namespace as the service maps it, when the reported name is
    /// usable as a URL locator. `None` means the owner cannot back a
    /// namespace-located request at all.
    pub namespace: Option<Namespace>,
    /// Bounded display hint (the raw reported name); never a locator.
    pub display_name: String,
}

fn bounded_id(raw: &serde_json::Value) -> Result<OwnerId, NativeError> {
    let text = raw.as_str().ok_or(NativeError::InvalidResponse)?;
    if text.is_empty() || text.len() > 256 || text.chars().any(char::is_control) {
        return Err(NativeError::InvalidResponse);
    }
    OwnerId::new(text.to_owned()).map_err(|_| NativeError::InvalidResponse)
}

fn bounded_name(raw: &serde_json::Value) -> Result<String, NativeError> {
    let text = raw.as_str().ok_or(NativeError::InvalidResponse)?;
    if text.is_empty() || text.len() > 256 || text.chars().any(char::is_control) {
        return Err(NativeError::InvalidResponse);
    }
    Ok(text.to_owned())
}

fn whoami_entry(value: &serde_json::Value, kind: OwnerKind, expected_type: &str) -> Result<WhoamiOwner, NativeError> {
    let object = value.as_object().ok_or(NativeError::InvalidResponse)?;
    if let Some(raw_type) = object.get("type")
        && raw_type.as_str() != Some(expected_type)
    {
        return Err(NativeError::InvalidResponse);
    }
    let owner_id = bounded_id(object.get("id").ok_or(NativeError::InvalidResponse)?)?;
    let display_name = bounded_name(object.get("name").ok_or(NativeError::InvalidResponse)?)?;
    // The reported name is only usable as a canonical locator when it passes
    // namespace validation; otherwise the owner stays unresolved.
    let namespace = Namespace::new(display_name.clone()).ok();
    Ok(WhoamiOwner { owner_id, owner_kind: kind, namespace, display_name })
}

/// Bounded parse of one whoami-v2 body: the authenticated personal identity
/// first, then its organization memberships, in service order. A malformed
/// record rejects the whole response; nothing is guessed or repaired.
pub(crate) fn parse_whoami_owners(bytes: &[u8]) -> Result<Vec<WhoamiOwner>, NativeError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| NativeError::InvalidResponse)?;
    let object = value.as_object().ok_or(NativeError::InvalidResponse)?;
    if let Some(raw_type) = object.get("type")
        && raw_type.as_str() != Some("user")
    {
        return Err(NativeError::InvalidResponse);
    }
    let mut out = vec![whoami_entry(&value, OwnerKind::Personal, "user")?];
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    seen.insert(out[0].owner_id.as_str().to_owned());
    if let Some(orgs) = object.get("orgs") {
        if !orgs.is_null() {
            let orgs = orgs.as_array().ok_or(NativeError::InvalidResponse)?;
            if orgs.len() > 256 {
                return Err(NativeError::InvalidResponse);
            }
            for org in orgs {
                let entry = whoami_entry(org, OwnerKind::Organization, "org")?;
                if !seen.insert(entry.owner_id.as_str().to_owned()) {
                    return Err(NativeError::InvalidResponse);
                }
                out.push(entry);
            }
        }
    }
    Ok(out)
}

/// `ready`/`reconnect` payload: `{"cursor": ...}` with the cursor optional.
pub(crate) fn event_cursor(data: &str) -> Result<Option<crate::store::EventCursor>, NativeError> {
    let value = event_payload(data)?;
    match value.get("cursor").and_then(|v| v.as_str()) {
        Some(raw) => Ok(Some(crate::store::EventCursor::new(raw.to_owned())?)),
        None => Ok(None),
    }
}

/// `changes` payload: `{"cursor": ..., "changes": [{path, op, ...}]}`.
pub(crate) fn event_changes(
    data: &str,
) -> Result<(Option<crate::store::EventCursor>, Vec<crate::store::NativeChange>), NativeError> {
    use crate::store::{EventCursor, NativeChange};
    let value = event_payload(data)?;
    let cursor = match value.get("cursor").and_then(|v| v.as_str()) {
        Some(raw) => Some(EventCursor::new(raw.to_owned())?),
        None => None,
    };
    let raw_changes = value.get("changes").and_then(|v| v.as_array()).ok_or(NativeError::InvalidResponse)?;
    let mut changes = Vec::with_capacity(raw_changes.len());
    for raw in raw_changes {
        let path = raw.get("path").and_then(|v| v.as_str()).ok_or(NativeError::InvalidResponse)?;
        let op = raw.get("op").and_then(|v| v.as_str()).and_then(parse_change_op).ok_or(NativeError::InvalidResponse)?;
        let xet_file_id = match raw.get("xetHash").and_then(|v| v.as_str()) {
            Some(hash) => Some(XetFileId::new(hash.to_owned()).map_err(|_| NativeError::InvalidResponse)?),
            None => None,
        };
        changes.push(NativeChange {
            key: path.to_owned(),
            op,
            size: raw.get("size").and_then(|v| v.as_u64()),
            xet_file_id,
            uploaded_at: raw.get("uploadedAt").and_then(|v| v.as_str()).map(str::to_owned),
            mtime: raw.get("mtime").and_then(|v| v.as_str()).map(str::to_owned),
            mtime_nanos: raw.get("mtimeNanos").and_then(|v| v.as_u64()),
        });
    }
    Ok((cursor, changes))
}

/// `reset` payload: `{"reason": ...}`. The stream ends after this event and the
/// caller must re-list; nothing here is a deletion.
pub(crate) fn event_reset_reason(data: &str) -> Result<String, NativeError> {
    let value = event_payload(data)?;
    let reason = value.get("reason").and_then(|v| v.as_str()).ok_or(NativeError::InvalidResponse)?;
    Ok(NativeError::detail(reason))
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    #[test]
    fn pagination_rejects_cross_origin_and_cross_endpoint_next_links() {
        let base = Url::parse("https://huggingface.co/api/buckets/ns/b/tree").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::LINK,
            HeaderValue::from_static("<https://evil.example/api/buckets/ns/b/tree?c=1>; rel=\"next\""),
        );
        assert!(matches!(
            link_next(&headers, &base, "/api/buckets/ns/b"),
            Err(NativeError::InvalidResponse)
        ));

        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::LINK,
            HeaderValue::from_static("<https://huggingface.co/api/buckets/other/tree?c=1>; rel=\"next\""),
        );
        assert!(matches!(
            link_next(&headers, &base, "/api/buckets/ns/b"),
            Err(NativeError::InvalidResponse)
        ));

        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::LINK,
            HeaderValue::from_static("<https://huggingface.co/api/buckets/ns/b/tree?cursor=2>; rel=\"next\""),
        );
        let next = link_next(&headers, &base, "/api/buckets/ns/b").unwrap().unwrap();
        assert_eq!(next.as_str(), "https://huggingface.co/api/buckets/ns/b/tree?cursor=2");

        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::LINK,
            HeaderValue::from_static("<http://huggingface.co/api/buckets/ns/b/tree?cursor=2>; rel=\"next\""),
        );
        assert!(matches!(
            link_next(&headers, &base, "/api/buckets/ns/b"),
            Err(NativeError::InvalidResponse)
        ));
    }

    #[test]
    fn duplicate_next_links_are_rejected() {
        let base = Url::parse("https://huggingface.co/api/buckets/ns/b/tree").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::LINK,
            HeaderValue::from_static(
                "<https://huggingface.co/api/buckets/ns/b/tree?cursor=1>; rel=\"next\", \
                 <https://huggingface.co/api/buckets/ns/b/tree?cursor=2>; rel=\"next\"",
            ),
        );
        assert!(matches!(
            link_next(&headers, &base, "/api/buckets/ns/b"),
            Err(NativeError::InvalidResponse)
        ));
    }

    #[test]
    fn head_records_classify_without_inventing_workspace_ids() {
        let v1 = br#"{"format":"hfdrive","schema_version":1,"workspace_id":"1f0d5b2c-6a41-4c2b-9a1a-1b1f1b1f1b1f","root_item_id":"2f0d5b2c-6a41-4c2b-9a1a-1b1f1b1f1b1f","commit_id":"3f0d5b2c-6a41-4c2b-9a1a-1b1f1b1f1b1f","generation":"4f0d5b2c-6a41-4c2b-9a1a-1b1f1b1f1b1f","required_features":[]}"#;
        match parse_head_record(v1).format {
            HeadFormat::V1 { workspace_id } => {
                assert_eq!(workspace_id.to_string(), "1f0d5b2c-6a41-4c2b-9a1a-1b1f1b1f1b1f");
            }
            other => panic!("expected v1, got {other:?}"),
        }

        let newer = br#"{"format":"hfdrive","schema_version":2,"workspace_id":"1f0d5b2c-6a41-4c2b-9a1a-1b1f1b1f1b1f","required_features":[]}"#;
        assert!(matches!(
            parse_head_record(newer).format,
            HeadFormat::Newer { schema_version: 2 }
        ));

        let featured = br#"{"format":"hfdrive","schema_version":1,"workspace_id":"1f0d5b2c-6a41-4c2b-9a1a-1b1f1b1f1b1f","required_features":["encryption"]}"#;
        assert!(matches!(parse_head_record(featured).format, HeadFormat::Newer { .. }));

        let foreign = br#"{"format":"other","schema_version":1}"#;
        assert_eq!(parse_head_record(foreign).format, HeadFormat::Foreign);

        let missing_workspace = br#"{"format":"hfdrive","schema_version":1}"#;
        assert_eq!(parse_head_record(missing_workspace).format, HeadFormat::Foreign);

        let bad_uuid = br#"{"format":"hfdrive","schema_version":1,"workspace_id":"not-a-uuid"}"#;
        assert_eq!(parse_head_record(bad_uuid).format, HeadFormat::Foreign);

        assert_eq!(parse_head_record(b"").format, HeadFormat::Foreign);
    }

    #[test]
    fn batch_accounting_rejects_unexplained_partial_results() {
        let ok = serde_json::json!({"success": true, "processed": 2, "succeeded": 2, "failed": []});
        let parsed = BatchResponseWire::parse(ok, 2).unwrap();
        assert!(parsed.success);

        let partial = serde_json::json!({
            "success": false, "processed": 2, "succeeded": 1,
            "failed": [{"path": "objects/x", "error": "denied\r\ninjected"}]
        });
        let parsed = BatchResponseWire::parse(partial, 2).unwrap();
        assert_eq!(parsed.succeeded, 1);
        assert_eq!(parsed.failed.len(), 1);
        assert_eq!(parsed.failed[0].1, "denied");

        let lied = serde_json::json!({"success": true, "processed": 3, "succeeded": 2, "failed": []});
        assert!(matches!(BatchResponseWire::parse(lied, 2), Err(NativeError::InvalidResponse)));

        let negative = serde_json::json!({"success": true, "processed": -1, "succeeded": 0, "failed": []});
        assert!(matches!(BatchResponseWire::parse(negative, 0), Err(NativeError::InvalidResponse)));
    }

    #[test]
    fn key_encoding_rejects_url_and_traversal_ambiguity() {
        assert_eq!(encode_key_path("objects/abc.bin"), "objects/abc.bin");
        assert_eq!(encode_key_path("a b/c+d"), "a%20b/c%2Bd");
        assert!(wire_key("../escape").is_err());
        assert!(wire_key("objects/../x").is_err());
        assert!(wire_key("a//b").is_err());
    }

    #[test]
    fn event_payloads_track_opaque_cursors_and_reject_ambiguity() {
        let cursor = event_cursor(r#"{"cursor":"opaque-1"}"#).unwrap();
        assert_eq!(cursor.unwrap().as_str(), "opaque-1");
        assert!(event_cursor("{}").unwrap().is_none());
        assert!(event_cursor("not json").is_err());

        let (cursor, changes) = event_changes(
            r#"{"cursor":"opaque-2","changes":[{"path":"objects/x","op":"update","size":7,"xetHash":"abababababababababababababababababababababababababababababababab"}]}"#,
        )
        .unwrap();
        assert_eq!(cursor.unwrap().as_str(), "opaque-2");
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].op, crate::store::ChangeOp::Update);
        // A present-but-invalid Xet id is a contract violation, not a silent
        // "no id" capability result.
        assert!(event_changes(r#"{"cursor":"c","changes":[{"path":"a","op":"add","xetHash":"zz"}]}"#).is_err());
        assert!(event_changes(r#"{"cursor":"c","changes":[{"path":"a","op":"mystery"}]}"#).is_err());

        assert_eq!(event_reset_reason(r#"{"reason":"cursor_too_old"}"#).unwrap(), "cursor_too_old");
    }
}
