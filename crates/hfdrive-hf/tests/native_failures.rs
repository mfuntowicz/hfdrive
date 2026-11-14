//! Deterministic consumer-visible regressions for the native adapter:
//! same-origin pagination, per-operation batch reconciliation, range
//! pre-validation, single controlled 401 refresh, lease account substitution,
//! and bounded HEAD-record classification. All servers are local fixtures;
//! no external network, no tokens in output.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hfdrive_auth::{AuthorizationAuthority, AuthorizationError, AuthorizationLease, SecretAccessToken, TokenSource};
use hfdrive_core::ids::{AccountKey, UploadId, WorkspaceId};
use hfdrive_core::storage::{
    ByteRange, BucketBinding, BucketId, BucketName, DriveBinding, ImmutableKey, Namespace, ObjectRef, OwnerId,
    OwnerKind, PayloadKey, RelativeKey, RemotePrefix, Sha256Digest, StableSnapshot, XetFileId,
};
use hfdrive_hf::{
    BatchAdd, BatchOp, HeadRead, NativeApi, NativeBucketStore, NativeConfig, NativeControl, NativeError, OwnerRef,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const SECRET_MARKER: &str = "SECRET_MARKER_HFDRIVE_TEST";

// ---- local fixture server ----

struct Fixture {
    addr: std::net::SocketAddr,
    requests: Arc<AtomicUsize>,
    bodies: Arc<Mutex<Vec<usize>>>,
    _task: tokio::task::JoinHandle<()>,
}

/// Raw canned response per (method, path, request index, body line count).
type Route = Arc<dyn Fn(&str, &str, usize, usize) -> String + Send + Sync>;

async fn fixture(route: Route) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let task = tokio::spawn({
        let requests = requests.clone();
        let bodies = bodies.clone();
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
                    if let Some(pos) = find_header_end(&buf) {
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
                let body = String::from_utf8_lossy(&buf[header_end + 4..]).to_string();
                let line_count = body.lines().filter(|l| !l.is_empty()).count();
                let index = requests.fetch_add(1, Ordering::SeqCst) + 1;
                bodies.lock().unwrap().push(line_count);

                let mut parts = head.split_whitespace();
                let method = parts.next().unwrap_or("").to_uppercase();
                let path = parts.next().unwrap_or("").to_string();
                let response = route(&method, &path, index, line_count);
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
                let _ = socket.shutdown().await;
            }
        }
    });
    Fixture { addr, requests, bodies, _task: task }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn response(status: &str, headers: &[(&str, &str)], body: &str) -> String {
    let has_length = headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("content-length"));
    let mut out = format!("HTTP/1.1 {status}\r\nConnection: close\r\n");
    if !has_length {
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    out.push_str(body);
    out
}

// ---- token source stub ----

struct Stub {
    lease: AuthorizationLease,
    account: AccountKey,
    refreshes: Arc<AtomicUsize>,
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
        self.refreshes.fetch_add(1, Ordering::SeqCst);
        let account = self.account;
        async move {
            Ok(Arc::new(SecretAccessToken::new(
                Zeroizing::new(SECRET_MARKER.to_owned()),
                account,
                2,
                u64::MAX,
            )))
        }
    }

    fn authorization_lease(&self, _account: AccountKey) -> Result<AuthorizationLease, AuthorizationError> {
        Ok(self.lease.clone())
    }
}

fn stub(api_account: AccountKey, lease_account: AccountKey) -> Arc<Stub> {
    let authority = AuthorizationAuthority::new(lease_account, 1);
    let lease = authority.activate().expect("fresh authority activates");
    Arc::new(Stub { lease, account: api_account, refreshes: Arc::new(AtomicUsize::new(0)) })
}

fn account(name: &str) -> AccountKey {
    AccountKey::from_subject("https://huggingface.co", name)
}

fn owner(namespace: &str) -> OwnerRef {
    OwnerRef {
        owner_id: OwnerId::new("subject-1".to_owned()).unwrap(),
        owner_kind: OwnerKind::Personal,
        owner_namespace: Namespace::new(namespace.to_owned()).unwrap(),
    }
}

fn bucket_binding(account_key: AccountKey, id: &str, namespace: &str, name: &str) -> BucketBinding {
    BucketBinding {
        bucket_id: BucketId::new(id.to_owned()).unwrap(),
        bucket_name: BucketName::new(name.to_owned()).unwrap(),
        owner_id: OwnerId::new("subject-1".to_owned()).unwrap(),
        owner_kind: OwnerKind::Personal,
        owner_namespace: Namespace::new(namespace.to_owned()).unwrap(),
    }
}

fn drive(account_key: AccountKey) -> DriveBinding {
    DriveBinding {
        account_key,
        bucket: bucket_binding(account_key, "64b000000000000000000001", "ns", "b"),
        prefix: RemotePrefix::new(String::new()).unwrap(),
        workspace_id: WorkspaceId::new(),
    }
}

fn config(endpoint: String) -> NativeConfig {
    NativeConfig {
        endpoint,
        max_head_bytes: 1024,
        ..NativeConfig::default()
    }
}

fn bucket_record(id: &str, name: &str) -> String {
    format!(
        r#"{{"_id":"{id}","id":"ns/{name}","author":"ns","private":true,"createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-02T00:00:00Z","size":7,"totalFiles":1,"repoType":"bucket"}}"#
    )
}

// ---- regressions ----

#[tokio::test]
async fn pagination_is_confined_to_the_api_origin() {
    // Relative same-origin continuation links are accepted and walked.
    let route: Route = Arc::new(|method: &str, path: &str, index: usize, _lines: usize| {
        if method == "GET" && path.starts_with("/api/buckets/ns") && !path.starts_with("/api/buckets/ns/") {
            if index == 1 {
                return response(
                    "200 OK",
                    &[("Link", "</api/buckets/ns?cursor=2>; rel=\"next\"")],
                    &format!("[{}]", bucket_record("64b000000000000000000001", "b")),
                );
            }
            return response("200 OK", &[], "[]");
        }
        response("404 Not Found", &[], "{}")
    });
    let server = fixture(route).await;
    let api_account = account("a");
    let tokens = stub(api_account, api_account);
    let api = NativeApi::new(tokens, api_account, format!("http://{}", server.addr)).unwrap();
    let control = NativeControl::new(api, config(format!("http://{}", server.addr)));
    let lease = control.capture_lease().unwrap();
    let cancel = CancellationToken::new();

    let buckets = control.list_buckets(&lease, &owner("ns"), &cancel).await.unwrap();
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].binding.bucket_id.as_str(), "64b000000000000000000001");
    assert_eq!(server.requests.load(Ordering::SeqCst), 2);

    // A cross-origin next link must be refused and never followed.
    let evil: Route = Arc::new(|method, path, _index, _lines| {
        if method == "GET" && path.starts_with("/api/buckets/ns") {
            return response(
                "200 OK",
                &[("Link", "<https://evil.invalid/api/buckets/ns?cursor=2>; rel=\"next\"")],
                "[]",
            );
        }
        response("404 Not Found", &[], "{}")
    });
    let server = fixture(evil).await;
    let tokens = stub(api_account, api_account);
    let api = NativeApi::new(tokens, api_account, format!("http://{}", server.addr)).unwrap();
    let control = NativeControl::new(api, config(format!("http://{}", server.addr)));
    let lease = control.capture_lease().unwrap();
    let error = control.list_buckets(&lease, &owner("ns"), &cancel).await.unwrap_err();
    assert!(matches!(error, NativeError::InvalidResponse));
}

#[tokio::test]
async fn batch_reports_partial_results_per_operation() {
    let route: Route = Arc::new(|method, path, _index, _lines| {
        if method == "POST" && path.ends_with("/batch") {
            return response(
                "200 OK",
                &[],
                r#"{"success":false,"processed":2,"succeeded":1,"failed":[{"path":"objects/x","error":"denied"}]}"#,
            );
        }
        response("404 Not Found", &[], "{}")
    });
    let server = fixture(route).await;
    let api_account = account("a");
    let tokens = stub(api_account, api_account);
    let api = NativeApi::new(tokens.clone(), api_account, format!("http://{}", server.addr)).unwrap();
    let store = NativeBucketStore::new(api, drive(api_account), config(format!("http://{}", server.addr))).unwrap();
    let lease = store.capture_lease().unwrap();
    let cancel = CancellationToken::new();

    let xet_hash = XetFileId::new("ab".repeat(32)).unwrap();
    let report = store
        .apply_batch(
            &lease,
            vec![
                BatchOp::Add(BatchAdd {
                    key: RelativeKey::new("objects/x".to_owned()).unwrap(),
                    xet_file_id: xet_hash,
                    size: 3,
                }),
                BatchOp::Delete(RelativeKey::new("objects/y".to_owned()).unwrap()),
            ],
            &cancel,
        )
        .await
        .unwrap();
    assert_eq!(report.submitted, 2);
    assert_eq!(report.succeeded, 1);
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].key, "objects/x");
    assert_eq!(report.failures[0].reason, "denied");
    assert!(!report.is_complete());

    // A response that does not account for every sent operation is a contract
    // violation, never a silent partial success.
    let lying: Route = Arc::new(|method, path, _index, _lines| {
        if method == "POST" && path.ends_with("/batch") {
            return response("200 OK", &[], r#"{"success":true,"processed":3,"succeeded":3,"failed":[]}"#);
        }
        response("404 Not Found", &[], "{}")
    });
    let server = fixture(lying).await;
    let api = NativeApi::new(tokens, api_account, format!("http://{}", server.addr)).unwrap();
    let store = NativeBucketStore::new(api, drive(api_account), config(format!("http://{}", server.addr))).unwrap();
    let lease = store.capture_lease().unwrap();
    let error = store
        .apply_batch(
            &lease,
            vec![BatchOp::Delete(RelativeKey::new("objects/z".to_owned()).unwrap())],
            &cancel,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, NativeError::InvalidResponse));
}

#[tokio::test]
async fn batches_are_chunked_at_one_thousand_operations() {
    let route: Route = Arc::new(|method: &str, path: &str, _index: usize, lines: usize| {
        if method == "POST" && path.ends_with("/batch") {
            return response(
                "200 OK",
                &[],
                &format!(r#"{{"success":true,"processed":{lines},"succeeded":{lines},"failed":[]}}"#),
            );
        }
        response("404 Not Found", &[], "{}")
    });
    let server = fixture(route).await;
    let api_account = account("a");
    let tokens = stub(api_account, api_account);
    let api = NativeApi::new(tokens, api_account, format!("http://{}", server.addr)).unwrap();
    let store = NativeBucketStore::new(api, drive(api_account), config(format!("http://{}", server.addr))).unwrap();
    let lease = store.capture_lease().unwrap();
    let cancel = CancellationToken::new();

    let xet_hash = XetFileId::new("cd".repeat(32)).unwrap();
    let ops: Vec<BatchOp> = (0..1001)
        .map(|i| {
            BatchOp::Add(BatchAdd {
                key: RelativeKey::new(format!("objects/f{i:04}")).unwrap(),
                xet_file_id: xet_hash.clone(),
                size: 1,
            })
        })
        .collect();
    let report = store.apply_batch(&lease, ops, &cancel).await.unwrap();
    assert_eq!(report.submitted, 1001);
    let counts = server.bodies.lock().unwrap().clone();
    assert_eq!(counts, vec![1000, 1]);
}

#[tokio::test]
async fn empty_and_out_of_bounds_ranges_fail_without_sdk_work() {
    let route: Route = Arc::new(|_method, _path, _index, _lines| response("404 Not Found", &[], "{}"));
    let server = fixture(route).await;
    let api_account = account("a");
    let tokens = stub(api_account, api_account);
    let api = NativeApi::new(tokens, api_account, format!("http://{}", server.addr)).unwrap();
    let store = NativeBucketStore::new(api, drive(api_account), config(format!("http://{}", server.addr))).unwrap();
    let lease = store.capture_lease().unwrap();
    let cancel = CancellationToken::new();

    let object = ObjectRef {
        key: PayloadKey::new(UploadId::new()),
        sha256: Sha256Digest::of(b"payload"),
        size: 10,
        xet_file_id: XetFileId::new("ef".repeat(32)).unwrap(),
    };

    // An empty range completes immediately without any SDK or network work.
    let empty = ByteRange::new(4, 4, 10).unwrap();
    let mut reader = store.open_range(&lease, &object, empty, &cancel).await.unwrap();
    assert!(reader.next_chunk(&cancel).await.unwrap().is_none());
    assert_eq!(server.requests.load(Ordering::SeqCst), 0);

    // A range validated against a larger phantom object is refused against the
    // actual immutable size before any SDK call.
    let stale = ByteRange::new(0, 15, 15).unwrap();
    let error = match store.open_range(&lease, &object, stale, &cancel).await {
        Err(error) => error,
        Ok(_) => panic!("out-of-bounds range was accepted"),
    };
    assert!(matches!(error, NativeError::InvalidRange));
    assert_eq!(server.requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unauthorized_requests_perform_one_controlled_refresh() {
    let route: Route = Arc::new(|method, path, index, _lines| {
        if method == "GET" && path == "/api/buckets/ns/b" {
            if index == 1 {
                return response("401 Unauthorized", &[], "{}");
            }
            return response("200 OK", &[], &bucket_record("64b000000000000000000001", "b"));
        }
        response("404 Not Found", &[], "{}")
    });
    let server = fixture(route).await;
    let api_account = account("a");
    let tokens = stub(api_account, api_account);
    let api = NativeApi::new(tokens.clone(), api_account, format!("http://{}", server.addr)).unwrap();
    let control = NativeControl::new(api, config(format!("http://{}", server.addr)));
    let lease = control.capture_lease().unwrap();
    let cancel = CancellationToken::new();

    let name = BucketName::new("b".to_owned()).unwrap();
    let resolved = control.resolve_bucket(&lease, &owner("ns"), &name, None, &cancel).await.unwrap();
    assert!(resolved.is_some());
    assert_eq!(tokens.refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(server.requests.load(Ordering::SeqCst), 2);

    // A persistent 401 must stop after the single controlled refresh and must
    // never leak the marker secret into errors.
    let route: Route = Arc::new(|_method, _path, _index, _lines| response("401 Unauthorized", &[], "{}"));
    let server = fixture(route).await;
    let tokens = stub(api_account, api_account);
    let api = NativeApi::new(tokens.clone(), api_account, format!("http://{}", server.addr)).unwrap();
    let control = NativeControl::new(api, config(format!("http://{}", server.addr)));
    let lease = control.capture_lease().unwrap();
    let error = control.resolve_bucket(&lease, &owner("ns"), &name, None, &cancel).await.unwrap_err();
    assert!(matches!(error, NativeError::NeedsSignIn));
    assert_eq!(tokens.refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(server.requests.load(Ordering::SeqCst), 2);
    let rendered = format!("{error:?}");
    assert!(!rendered.contains(SECRET_MARKER));
}

#[tokio::test]
async fn lease_account_substitution_is_refused_before_dispatch() {
    let route: Route = Arc::new(|_method, _path, _index, _lines| response("200 OK", &[], "{}"));
    let server = fixture(route).await;
    let api_account = account("a");
    let other_account = account("someone-else");
    let tokens = stub(api_account, other_account);
    let api = NativeApi::new(tokens, api_account, format!("http://{}", server.addr)).unwrap();
    let store = NativeBucketStore::new(api, drive(api_account), config(format!("http://{}", server.addr))).unwrap();
    let lease = store.capture_lease().unwrap();
    let cancel = CancellationToken::new();

    let error = store
        .apply_batch(
            &lease,
            vec![BatchOp::Delete(RelativeKey::new("objects/z".to_owned()).unwrap())],
            &cancel,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, NativeError::IdentityMismatch));
    assert_eq!(server.requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn head_reads_distinguish_absent_unsupported_and_records() {
    const HEAD_BODY: &str = r#"{"format":"hfdrive","schema_version":1,"workspace_id":"1f0d5b2c-6a41-4c2b-9a1a-1b1f1b1f1b1f","root_item_id":"2f0d5b2c-6a41-4c2b-9a1a-1b1f1b1f1b1f","commit_id":"3f0d5b2c-6a41-4c2b-9a1a-1b1f1b1f1b1f","generation":"4f0d5b2c-6a41-4c2b-9a1a-1b1f1b1f1b1f","required_features":[]}"#;

    // Absent: metadata HEAD 404 -> Missing (the only "empty" signal).
    let route: Route = Arc::new(|_method, _path, _index, _lines| response("404 Not Found", &[], ""));
    let server = fixture(route).await;
    let api_account = account("a");
    let tokens = stub(api_account, api_account);
    let api = NativeApi::new(tokens.clone(), api_account, format!("http://{}", server.addr)).unwrap();
    let control = NativeControl::new(api, config(format!("http://{}", server.addr)));
    let lease = control.capture_lease().unwrap();
    let cancel = CancellationToken::new();
    let bucket = bucket_binding(api_account, "64b000000000000000000001", "ns", "b");
    let prefix = RemotePrefix::new("hfdrive/demo".to_owned()).unwrap();

    let read = control.read_head_record(&lease, &bucket, &prefix, &cancel).await.unwrap();
    assert!(matches!(read, HeadRead::Missing));

    // Unsupported: a HEAD record beyond the bound is never read and never
    // reported as empty.
    let route: Route = Arc::new(|method, _path, _index, _lines| {
        if method == "HEAD" {
            return response("200 OK", &[("Content-Length", "4096"), ("x-xet-hash", "")], "");
        }
        response("200 OK", &[], "over-large")
    });
    let server = fixture(route).await;
    let api = NativeApi::new(tokens.clone(), api_account, format!("http://{}", server.addr)).unwrap();
    let control = NativeControl::new(api, config(format!("http://{}", server.addr)));
    let lease = control.capture_lease().unwrap();
    let read = control.read_head_record(&lease, &bucket, &prefix, &cancel).await.unwrap();
    assert!(matches!(read, HeadRead::TooLarge { size: 4096 }));
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);

    // Record: bounded bytes plus a validated v1 workspace id.
    let route: Route = Arc::new(move |method, _path, _index, _lines| {
        if method == "HEAD" {
            return response(
                "200 OK",
                &[("Content-Length", &HEAD_BODY.len().to_string()), ("x-xet-hash", "")],
                "",
            );
        }
        response("200 OK", &[], HEAD_BODY)
    });
    let server = fixture(route).await;
    let api = NativeApi::new(tokens, api_account, format!("http://{}", server.addr)).unwrap();
    let control = NativeControl::new(api, config(format!("http://{}", server.addr)));
    let lease = control.capture_lease().unwrap();
    let read = control.read_head_record(&lease, &bucket, &prefix, &cancel).await.unwrap();
    match read {
        HeadRead::Record(record) => match record.format {
            hfdrive_hf::HeadFormat::V1 { workspace_id } => {
                assert_eq!(
                    workspace_id.to_string(),
                    "1f0d5b2c-6a41-4c2b-9a1a-1b1f1b1f1b1f"
                );
            }
            other => panic!("expected v1 format, got {other:?}"),
        },
        other => panic!("expected record, got {other:?}"),
    }
}

#[tokio::test]
async fn vanished_snapshot_source_demands_recapture() {
    // Pure shape check: upload targets are typed ImmutableKeys (HEAD can never
    // be addressed), and a vanished staged source is a recapture demand, never
    // a blind upload.
    let snapshot = StableSnapshot {
        snapshot_id: hfdrive_core::ids::SnapshotId::new(),
        upload_id: UploadId::new(),
        path: std::path::PathBuf::from("nonexistent.bin"),
        size: 0,
        sha256: Sha256Digest::of(b""),
    };
    let route: Route = Arc::new(|_m, _p, _i, _l| response("404 Not Found", &[], "{}"));
    let server = fixture(route).await;
    let api_account = account("a");
    let tokens = stub(api_account, api_account);
    let api = NativeApi::new(tokens, api_account, format!("http://{}", server.addr)).unwrap();
    let store = NativeBucketStore::new(api, drive(api_account), config(format!("http://{}", server.addr))).unwrap();
    let lease = store.capture_lease().unwrap();
    let error = store
        .begin_upload(
            &lease,
            ImmutableKey::Payload(snapshot.upload_id),
            hfdrive_hf::UploadSource::Snapshot(snapshot),
        )
        .err()
        .expect("vanished source must be refused");
    assert!(matches!(error, NativeError::SourceChanged));
}
