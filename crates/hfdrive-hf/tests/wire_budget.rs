//! Transport-level transfer-budget scenario: real local streaming HTTP bodies
//! through the metered boundaries, proving encoded wire bytes are counted
//! exactly, pacing honors live rate changes, cancellation/drop stops delivery
//! and leaks nothing, and there is no bypass through the SDK path (the vendored
//! `xet-client` transport wrappers are the exact code every CAS body funnels
//! through). Wire and logical counters are asserted separately. No external
//! network, no live HF proof.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use hfdrive_auth::{AuthorizationAuthority, AuthorizationError, AuthorizationLease, SecretAccessToken, TokenSource};
use hfdrive_core::ids::{AccountKey, UploadId, WorkspaceId};
use hfdrive_core::storage::{
    ByteRange, BucketBinding, BucketId, BucketName, DriveBinding, Namespace, ObjectRef, OwnerId, OwnerKind,
    PayloadKey, RelativeKey, RemotePrefix, Sha256Digest, XetFileId,
};
use hfdrive_hf::wire_budget::{BudgetConfig, Direction, WireBudget};
use hfdrive_hf::{NativeApi, NativeConfig, NativeControl, NativeEvent, OwnerRef, RangeCache};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use xet_client::common::transport_budget;
use zeroize::Zeroizing;

const SECRET_MARKER: &str = "SECRET_MARKER_WIRE_BUDGET_TEST";

// ---- minimal local fixture server (raw canned responses) ----

struct Fixture {
    addr: std::net::SocketAddr,
    requests: Arc<AtomicUsize>,
    _task: tokio::task::JoinHandle<()>,
}

async fn fixture(responses: Arc<dyn Fn(&str, &str) -> Vec<u8> + Send + Sync>) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn({
        let requests = requests.clone();
        async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let header_end = loop {
                    let Ok(n) = socket.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let content_length = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                while buf.len() < header_end + 4 + content_length {
                    let Ok(n) = socket.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let mut parts = head.split_whitespace();
                let method = parts.next().unwrap_or("").to_uppercase();
                let path = parts.next().unwrap_or("").to_string();
                requests.fetch_add(1, Ordering::SeqCst);
                let response = responses(&method, &path);
                let _ = socket.write_all(&response).await;
                let _ = socket.flush().await;
                let _ = socket.shutdown().await;
            }
        }
    });
    Fixture { addr, requests, _task: task }
}

fn raw_response(body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

// ---- token source stub (same shape as tests/native_failures.rs) ----

struct Stub {
    lease: AuthorizationLease,
    account: AccountKey,
}

impl TokenSource for Stub {
    fn access_token(
        &self,
        _account: AccountKey,
    ) -> impl Future<Output = Result<Arc<SecretAccessToken>, AuthorizationError>> + Send {
        let account = self.account;
        async move {
            Ok(Arc::new(SecretAccessToken::new(
                Zeroizing::new(SECRET_MARKER.to_owned()),
                account,
                1,
                u64::MAX,
            )))
        }
    }

    fn refresh_after_unauthorized(
        &self,
        _account: AccountKey,
        _rejected_generation: u64,
    ) -> impl Future<Output = Result<Arc<SecretAccessToken>, AuthorizationError>> + Send {
        let account = self.account;
        async move {
            Ok(Arc::new(SecretAccessToken::new(
                Zeroizing::new(SECRET_MARKER.to_owned()),
                account,
                1,
                u64::MAX,
            )))
        }
    }

    fn authorization_lease(&self, _account: AccountKey) -> Result<AuthorizationLease, AuthorizationError> {
        Ok(self.lease.clone())
    }
}

fn stub(account: AccountKey) -> Arc<Stub> {
    let authority = AuthorizationAuthority::new(account, 1);
    let lease = authority.activate().expect("fresh authority activates");
    Arc::new(Stub { lease, account })
}

fn account() -> AccountKey {
    AccountKey::from_subject("https://huggingface.co", "wire-budget-person")
}

fn drive(account_key: AccountKey) -> DriveBinding {
    DriveBinding {
        account_key,
        bucket: BucketBinding {
            bucket_id: BucketId::new("64b000000000000000000009".to_owned()).unwrap(),
            bucket_name: BucketName::new("budget-bucket".to_owned()).unwrap(),
            owner_id: OwnerId::new("subject-1".to_owned()).unwrap(),
            owner_kind: OwnerKind::Personal,
            owner_namespace: Namespace::new("ns".to_owned()).unwrap(),
        },
        prefix: RemotePrefix::new(String::new()).unwrap(),
        workspace_id: WorkspaceId::new(),
    }
}

fn owner_ref() -> OwnerRef {
    OwnerRef {
        owner_id: OwnerId::new("subject-1".to_owned()).unwrap(),
        owner_kind: OwnerKind::Personal,
        owner_namespace: Namespace::new("ns".to_owned()).unwrap(),
    }
}

// ---- SDK transport hook over the shared budget ----

struct Hook(WireBudget);

impl transport_budget::TransportBudgetHook for Hook {
    fn gate(&self, direction: transport_budget::Direction, bytes: u64) -> transport_budget::GateFuture {
        let direction = match direction {
            transport_budget::Direction::Upload => Direction::Upload,
            transport_budget::Direction::Download => Direction::Download,
        };
        Box::pin(self.0.gate(direction, bytes))
    }
}

/// The exact SDK transport path (`collect_gated`, the collector every CAS
/// bounded body funnels through) meters a real local streaming body: exact
/// encoded wire bytes counted, dropping the gate mid-wait (the cancellation
/// path) leaks nothing, and the budget stays usable afterwards.
#[tokio::test]
async fn sdk_transport_path_meters_real_streaming_bodies_and_honors_drop() {
    let body: Vec<u8> = (0..64 * 1024u32).map(|index| (index % 251) as u8).collect();
    let served = body.clone();
    let fixture = fixture(Arc::new(move |_method, _path| raw_response(&served))).await;
    let budget = WireBudget::new(BudgetConfig {
        upload_bytes_per_second: 0,
        download_bytes_per_second: 0,
        burst_bytes: 8,
    });
    assert!(
        transport_budget::install_global_hook(Arc::new(Hook(budget.clone()))),
        "the wire-budget hook installs cleanly in a fresh process"
    );

    // 1) Exact accounting over a real streaming response body.
    let client = reqwest::Client::new();
    let response = client.get(format!("http://{}/stream", fixture.addr)).send().await.unwrap();
    let collected = transport_budget::collect_gated(response, transport_budget::Direction::Download).await.unwrap();
    assert_eq!(collected.as_ref(), body.as_slice(), "bytes pass unchanged through the gate");
    assert!(fixture.requests.load(Ordering::SeqCst) >= 1);
    let counters = budget.counters();
    assert_eq!(counters.wire_read_bytes, body.len() as u64, "every encoded body byte is counted exactly once");
    assert_eq!(counters.logical_read_bytes, 0, "wire bytes are never reported as logical bytes");

    // 2) A stalled gate does not deliver; dropping it mid-wait (what request
    //    cancellation does at every boundary) leaves accounting consistent and
    //    the budget usable.
    budget.set_rates(1, 1);
    budget.gate(Direction::Download, 8).await; // drain the 8-byte burst instantly
    let before = budget.counters().wire_read_bytes;
    let doomed = budget.gate(Direction::Download, 1024);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), doomed).await.is_err(),
        "an exhausted 1 B/s bucket must not complete promptly"
    );
    assert_eq!(budget.counters().wire_read_bytes, before + 1024, "dropped gates count at admission and leak no tokens");
    budget.set_rates(0, 0);
    budget.gate(Direction::Download, 8).await;
    assert_eq!(budget.counters().wire_read_bytes, before + 1024 + 8, "the budget stays usable after a dropped gate");
}

/// Pacing is enforced at the encoded-body boundary (not after the fact and not
/// at the UI): a stalled chunk does not deliver until a live rate change
/// releases it.
#[tokio::test]
async fn pacing_blocks_delivery_until_a_live_rate_change_releases_it() {
    let budget = WireBudget::new(BudgetConfig {
        upload_bytes_per_second: 0,
        download_bytes_per_second: 8,
        burst_bytes: 8,
    });
    let source = futures_util::stream::iter([
        Ok::<_, std::io::Error>(Bytes::from_static(b"12345678")),
        Ok(Bytes::from_static(b"abcdefgh")),
    ]);
    let mut gated = budget.gate_stream(Direction::Download, source);
    let first = tokio::time::timeout(Duration::from_secs(2), gated.next()).await.expect("burst is immediate").unwrap().unwrap();
    assert_eq!(first, Bytes::from_static(b"12345678"));
    // Second chunk needs a full token refill at 8 B/s: it must NOT deliver
    // within the burst window. The pending chunk stays inside the stream.
    assert!(
        tokio::time::timeout(Duration::from_millis(400), gated.next()).await.is_err(),
        "pacing holds the chunk at the boundary instead of delivering early"
    );
    // A live budget change releases it at once.
    budget.set_rates(0, 0);
    let second = tokio::time::timeout(Duration::from_secs(2), gated.next()).await.unwrap().unwrap().unwrap();
    assert_eq!(second, Bytes::from_static(b"abcdefgh"));
    assert_eq!(budget.counters().wire_read_bytes, 16);
}

/// Native HF API bodies are metered at the same encoded boundary in both
/// directions (the parent's S3 adapter attaches to the identical buckets).
#[tokio::test]
async fn native_api_request_and_response_bodies_are_metered_exactly() {
    let fixture = fixture(Arc::new(|_method, _path| raw_response(b"[]"))).await;
    let budget = WireBudget::new(BudgetConfig::default());
    let endpoint = format!("http://{}", fixture.addr);
    let api = NativeApi::new_with_budget(stub(account()), account(), endpoint.clone(), budget.clone()).unwrap();
    let control = NativeControl::new(api.clone(), NativeConfig { endpoint, ..NativeConfig::default() });
    let lease = api.capture_lease().unwrap();
    let cancel = CancellationToken::new();

    // GET: one bounded JSON response body.
    control.list_buckets(&lease, &owner_ref(), &cancel).await.unwrap();
    assert_eq!(budget.counters().wire_read_bytes, 2, "the exact encoded response body is counted");

    // POST: request body and response body both cross the boundary.
    let store = control.open_store(drive(account())).unwrap();
    let report = store.paths_info(&lease, &[RelativeKey::new("a".to_owned()).unwrap()], &cancel).await.unwrap();
    assert!(report.found.is_empty());
    let counters = budget.counters();
    assert_eq!(
        counters.wire_write_bytes,
        "{\"paths\":[\"a\"]}".len() as u64,
        "the exact encoded request body is counted"
    );
    assert_eq!(counters.wire_read_bytes, 2 + 2, "response bodies accumulate exactly");
}

/// SSE feed bytes (heartbeats included) are wire-metered and observable at the
/// activity boundary; event parsing never sees ungated bytes.
#[tokio::test]
async fn sse_feed_bytes_are_metered_including_heartbeats() {
    let feed: &[u8] = b": ping\n\nevent: ready\ndata: {\"cursor\":\"c1\"}\n\n";
    let served = feed.to_vec();
    let fixture = fixture(Arc::new(move |_method, _path| raw_response(&served))).await;
    let budget = WireBudget::new(BudgetConfig::default());
    let endpoint = format!("http://{}", fixture.addr);
    let api = NativeApi::new_with_budget(stub(account()), account(), endpoint.clone(), budget.clone()).unwrap();
    let control = NativeControl::new(api.clone(), NativeConfig { endpoint, ..NativeConfig::default() });
    let store = control.open_store(drive(account())).unwrap();
    let lease = api.capture_lease().unwrap();
    let cancel = CancellationToken::new();

    let mut stream = store.events(&lease, None, &cancel).await.unwrap();
    match stream.next_event(&cancel).await.unwrap() {
        Some(NativeEvent::Ready { cursor }) => assert_eq!(cursor.as_ref().map(|cursor| cursor.as_str()), Some("c1")),
        other => panic!("unexpected event: {other:?}"),
    }
    assert_eq!(budget.counters().wire_read_bytes, feed.len() as u64, "heartbeat bytes count as wire bytes");
    assert!(stream.idle_for() < Duration::from_secs(30), "activity tracking sees feed bytes");
}

/// A cached range read delivers reconstructed content (logical counters) with
/// zero wire traffic; the two counters stay distinct at the consumer boundary.
#[tokio::test]
async fn cached_range_reads_count_logical_bytes_and_zero_wire_bytes() {
    let budget = WireBudget::new(BudgetConfig::default());
    let api = NativeApi::new_with_budget(stub(account()), account(), "http://127.0.0.1:1".to_owned(), budget.clone()).unwrap();
    let control = NativeControl::new(api.clone(), NativeConfig::default());
    let store = control.open_store(drive(account())).unwrap();
    let lease = api.capture_lease().unwrap();
    let cancel = CancellationToken::new();

    let object = ObjectRef {
        key: PayloadKey::new(UploadId::new()),
        sha256: Sha256Digest::of(b"fixture"),
        size: 16,
        xet_file_id: XetFileId::new("ab12".repeat(16)).unwrap(),
    };
    let cache = RangeCache::new(1024);
    cache.insert(&object, 0, Bytes::from_static(b"0123456789abcdef"));
    let mut reader = store
        .open_range_cached(&lease, &object, ByteRange::new(4, 12, 16).unwrap(), &cache, &cancel)
        .await
        .unwrap();
    let mut delivered = Vec::new();
    while let Some(chunk) = reader.next_chunk(&cancel).await.unwrap() {
        delivered.extend_from_slice(&chunk);
    }
    assert_eq!(delivered, b"456789ab");
    let counters = budget.counters();
    assert_eq!(counters.logical_read_bytes, 8, "reconstructed content is counted as logical bytes");
    assert_eq!(counters.wire_read_bytes, 0, "a cache hit moves no wire bytes");
}
