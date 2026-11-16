//! Deterministic raw-import surface tests for the account+bucket storage
//! plane: exact raw-key staged uploads/resumes, checkpoint reconciliation, and
//! occupant metadata. Local fixture servers only; no external network and no
//! Xet SDK transfers (live ingestion is covered by the live suite).

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hfdrive_auth::{AuthorizationAuthority, AuthorizationError, AuthorizationLease, SecretAccessToken, TokenSource};
use hfdrive_core::ids::AccountKey;
use hfdrive_core::storage::{
    BucketBinding, BucketId, BucketName, Namespace, OwnerId, OwnerKind, RelativeKey, Sha256Digest, XetFileId,
};
use hfdrive_hf::{
    CasCommitCheckpoint, NativeApi, NativeConfig, NativeControl, NativeError, NativeRawStore, UploadSource,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const SECRET_MARKER: &str = "SECRET_MARKER_HFDRIVE_RAW_IMPORT_TEST";

// ---- local fixture server ----

struct Fixture {
    addr: std::net::SocketAddr,
    requests: Arc<AtomicUsize>,
    _task: tokio::task::JoinHandle<()>,
}

type Route = Arc<dyn Fn(&str, &str, usize, &str) -> String + Send + Sync>;

async fn fixture(route: Route) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn({
        let requests = requests.clone();
        async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return; };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let header_end = loop {
                    let Ok(n) = socket.read(&mut chunk).await else { return; };
                    if n == 0 { return; }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") { break pos; }
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
                    let Ok(n) = socket.read(&mut chunk).await else { break; };
                    if n == 0 { break; }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let body = String::from_utf8_lossy(&buf[header_end + 4..]).to_string();
                let index = requests.fetch_add(1, Ordering::SeqCst) + 1;

                let mut parts = head.split_whitespace();
                let method = parts.next().unwrap_or("").to_uppercase();
                let path = parts.next().unwrap_or("").to_string();
                let response = route(&method, &path, index, &body);
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
                let _ = socket.shutdown().await;
            }
        }
    });
    Fixture { addr, requests, _task: task }
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
        self.access_token(_account)
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

fn account(name: &str) -> AccountKey {
    AccountKey::from_subject("https://huggingface.co", name)
}

fn bucket() -> BucketBinding {
    BucketBinding {
        bucket_id: BucketId::new("64b0000000000000000000aa".to_owned()).unwrap(),
        bucket_name: BucketName::new("import-bucket".to_owned()).unwrap(),
        owner_id: OwnerId::new("subject-1".to_owned()).unwrap(),
        owner_kind: OwnerKind::Personal,
        owner_namespace: Namespace::new("ns".to_owned()).unwrap(),
    }
}

fn config(endpoint: String, cache_dir: std::path::PathBuf) -> NativeConfig {
    NativeConfig {
        endpoint,
        xet_cache_dir: cache_dir,
        max_head_bytes: 1024,
        ..NativeConfig::default()
    }
}

fn key(text: &str) -> RelativeKey {
    RelativeKey::new(text.to_owned()).unwrap()
}

fn cas_checkpoint(target_key: &str, size: u64, sha256: Sha256Digest) -> CasCommitCheckpoint {
    CasCommitCheckpoint {
        target_key: target_key.to_owned(),
        xet_file_id: XetFileId::new("ab".repeat(32)).unwrap(),
        size,
        sha256,
        sdk_task_id: 1,
    }
}

fn staged_file(name: &str, bytes: &[u8]) -> (std::path::PathBuf, Sha256Digest) {
    let path = std::env::temp_dir().join(format!("hfdrive-raw-import-{name}.bin"));
    std::fs::write(&path, bytes).unwrap();
    (path, Sha256Digest::of(bytes))
}

// ---- regressions ----

#[tokio::test]
async fn raw_store_requires_the_api_account_and_exposes_no_workspace() {
    let route: Route = Arc::new(|_m, _p, _i, _b| response("404 Not Found", &[], "{}"));
    let server = fixture(route).await;
    let api_account = account("a");
    let api = NativeApi::new(stub(api_account), api_account, format!("http://{}", server.addr)).unwrap();
    let endpoint = format!("http://{}", server.addr);
    let cache = std::env::temp_dir().join("hfdrive-raw-cache-a");
    let raw = NativeRawStore::new(api.clone(), api_account, bucket(), config(endpoint.clone(), cache.clone())).unwrap();
    // Exact account+bucket binding; no workspace/prefix accessor exists on the
    // raw surface (compile-time guarantee: `binding()` belongs to the managed
    // store only).
    assert_eq!(raw.bucket(), &bucket());
    assert_eq!(raw.capture_lease().unwrap().account(), api_account);

    // A foreign account is rejected at construction, so a cross-account lease
    // can never reach a dispatch.
    let foreign = account("b");
    let api = NativeApi::new(stub(api_account), api_account, format!("http://{}", server.addr)).unwrap();
    assert!(matches!(
        NativeRawStore::new(api, foreign, bucket(), config(endpoint, cache)),
        Err(NativeError::IdentityMismatch)
    ));
}

#[tokio::test]
async fn control_opens_raw_store_for_the_same_account_only() {
    let route: Route = Arc::new(|_m, _p, _i, _b| response("404 Not Found", &[], "{}"));
    let server = fixture(route).await;
    let api_account = account("a");
    let api = NativeApi::new(stub(api_account), api_account, format!("http://{}", server.addr)).unwrap();
    let control = NativeControl::new(api.clone(), config(format!("http://{}", server.addr), std::env::temp_dir().join("hfdrive-raw-cache-c")));
    let raw = control.open_raw_store(api_account, bucket()).unwrap();
    assert_eq!(raw.bucket(), &bucket());
    let foreign = account("b");
    assert!(matches!(control.open_raw_store(foreign, bucket()), Err(NativeError::IdentityMismatch)));
}

#[tokio::test]
async fn exact_raw_keys_are_used_verbatim_and_resumes_reject_mismatched_checkpoints() {
    // Only a single binding dispatch is expected; anything else is a 404.
    let route: Route = Arc::new(|method, path, _index, _body| {
        if method == "POST" && path.ends_with("/batch") {
            return response("200 OK", &[], r#"{"success":true,"processed":1,"succeeded":1,"failed":[]}"#);
        }
        response("404 Not Found", &[], "{}")
    });
    let server = fixture(route).await;
    let api_account = account("raw-resume");
    let api = NativeApi::new(stub(api_account), api_account, format!("http://{}", server.addr)).unwrap();
    let raw = NativeRawStore::new(
        api,
        api_account,
        bucket(),
        config(format!("http://{}", server.addr), std::env::temp_dir().join("hfdrive-raw-cache-r")),
    )
    .unwrap();
    let lease = raw.capture_lease().unwrap();
    let cancel = CancellationToken::new();

    let raw_key = key("hfdrive-imports/00112233-4455-4677-8899-aabbccddeeff/docs/hello.txt");
    let sha256 = Sha256Digest::of(b"fixture");

    // Exact-key CAS resume binds without re-ingesting or re-uploading.
    let checkpoint = cas_checkpoint(raw_key.as_str(), 7, sha256);
    let bound = raw.resume_raw_committed(&lease, &raw_key, &checkpoint).unwrap()
        .bind(&cancel).await.unwrap();
    assert_eq!(bound.key, raw_key);
    assert_eq!(bound.size, 7);
    assert_eq!(bound.sha256, sha256);
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);

    // A checkpoint recorded for another exact key is never rebound here.
    let other = key("hfdrive-imports/00112233-4455-4677-8899-aabbccddeeff/other.txt");
    let foreign = cas_checkpoint(other.as_str(), 7, sha256);
    assert!(matches!(
        raw.resume_raw_committed(&lease, &raw_key, &foreign),
        Err(NativeError::SourceChanged)
    ));
    // A malformed checkpoint target is likewise refused.
    let malformed = cas_checkpoint("not/a/valid/../key", 7, sha256);
    assert!(matches!(
        raw.resume_raw_committed(&lease, &raw_key, &malformed),
        Err(NativeError::SourceChanged)
    ));
}

#[tokio::test]
async fn resuming_before_the_key_is_bound_uses_the_exact_raw_key() {
    // The binding call must address the raw key exactly; the fixture records
    // the dispatched body so the key cannot drift to any managed shape.
    let bodies = Arc::new(Mutex::new(Vec::<String>::new()));
    let recorded = bodies.clone();
    let route: Route = Arc::new(move |method, path, _index, body| {
        if method == "POST" && path.ends_with("/batch") {
            recorded.lock().unwrap().push(body.to_owned());
            return response("200 OK", &[], r#"{"success":true,"processed":1,"succeeded":1,"failed":[]}"#);
        }
        response("404 Not Found", &[], "{}")
    });
    let server = fixture(route).await;
    let api_account = account("raw-bind");
    let api = NativeApi::new(stub(api_account), api_account, format!("http://{}", server.addr)).unwrap();
    let raw = NativeRawStore::new(
        api,
        api_account,
        bucket(),
        config(format!("http://{}", server.addr), std::env::temp_dir().join("hfdrive-raw-cache-b")),
    )
    .unwrap();
    let lease = raw.capture_lease().unwrap();
    let cancel = CancellationToken::new();

    let raw_key = key("hfdrive-imports/00112233-4455-4677-8899-aabbccddeeff/photos/img.png");
    let checkpoint = cas_checkpoint(raw_key.as_str(), 3, Sha256Digest::of(b"png"));
    let bound = raw.resume_raw_committed(&lease, &raw_key, &checkpoint).unwrap()
        .bind(&cancel).await.unwrap();
    assert_eq!(bound.key, raw_key);
    let dispatched = bodies.lock().unwrap().clone();
    assert_eq!(dispatched.len(), 1);
    assert!(dispatched[0].contains(r#""path":"hfdrive-imports/00112233-4455-4677-8899-aabbccddeeff/photos/img.png""#),
        "binding must address the exact raw key, dispatched: {}", dispatched[0]);
    assert!(!dispatched[0].contains("HEAD"), "raw imports never touch managed HEAD");
}

#[tokio::test]
async fn vanished_snapshot_source_demands_recapture_before_any_dispatch() {
    let route: Route = Arc::new(|_m, _p, _i, _b| response("404 Not Found", &[], "{}"));
    let server = fixture(route).await;
    let api_account = account("raw-recapture");
    let api = NativeApi::new(stub(api_account), api_account, format!("http://{}", server.addr)).unwrap();
    let raw = NativeRawStore::new(
        api,
        api_account,
        bucket(),
        config(format!("http://{}", server.addr), std::env::temp_dir().join("hfdrive-raw-cache-v")),
    )
    .unwrap();
    let lease = raw.capture_lease().unwrap();

    let (path, sha256) = staged_file("vanished", b"fixture");
    let snapshot = hfdrive_core::storage::StableSnapshot {
        snapshot_id: hfdrive_core::ids::SnapshotId::new(),
        upload_id: hfdrive_core::ids::UploadId::new(),
        path,
        size: 7,
        sha256,
    };
    std::fs::remove_file(&snapshot.path).unwrap();
    let error = raw
        .begin_raw_upload(
            &lease,
            key("hfdrive-imports/00112233-4455-4677-8899-aabbccddeeff/a.txt"),
            UploadSource::Snapshot(snapshot),
        )
        .err()
        .expect("vanished staged source must be refused before any dispatch");
    assert!(matches!(error, NativeError::SourceChanged));
    assert_eq!(server.requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn drifted_snapshot_source_demands_recapture_and_never_binds() {
    let route: Route = Arc::new(|_m, _p, _i, _b| response("404 Not Found", &[], "{}"));
    let server = fixture(route).await;
    let api_account = account("raw-drift");
    let api = NativeApi::new(stub(api_account), api_account, format!("http://{}", server.addr)).unwrap();
    let raw = NativeRawStore::new(
        api,
        api_account,
        bucket(),
        config(format!("http://{}", server.addr), std::env::temp_dir().join("hfdrive-raw-cache-d")),
    )
    .unwrap();
    let lease = raw.capture_lease().unwrap();

    // Capture record says 7 bytes; the staged file now holds more. The size
    // check refuses the source before any network work: a changed source is a
    // recapture demand, never a blind upload or a rebind.
    let (path, sha256) = staged_file("drift", b"fixture");
    let snapshot = hfdrive_core::storage::StableSnapshot {
        snapshot_id: hfdrive_core::ids::SnapshotId::new(),
        upload_id: hfdrive_core::ids::UploadId::new(),
        path: path.clone(),
        size: 7,
        sha256,
    };
    std::fs::write(&path, b"fixture-longer").unwrap();
    let error = raw
        .begin_raw_upload(
            &lease,
            key("hfdrive-imports/00112233-4455-4677-8899-aabbccddeeff/b.txt"),
            UploadSource::Snapshot(snapshot),
        )
        .err()
        .expect("drifted staged source must be refused before any dispatch");
    assert!(matches!(error, NativeError::SourceChanged));
    std::fs::remove_file(&path).unwrap();
}

#[tokio::test]
async fn occupant_metadata_reports_absent_and_present_raw_keys() {
    let route: Route = Arc::new(move |method, path, _index, body| {
        if method == "POST" && path.ends_with("/paths-info") {
            // Only the occupied key is reported; the absent key is reconciled
            // as missing by the store (never as a deletion decision).
            assert!(body.contains("present.txt"));
            return response(
                "200 OK",
                &[],
                r#"[{"path":"hfdrive-imports/00112233-4455-4677-8899-aabbccddeeff/present.txt","type":"file","size":7,"xetHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]"#,
            );
        }
        if method == "HEAD" && path.contains("present.txt") {
            // Per-key native metadata is a HEAD: size from Content-Length,
            // Xet identity from x-xet-hash (never a body).
            return response(
                "200 OK",
                &[
                    ("Content-Length", "7"),
                    ("x-xet-hash", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                ],
                "",
            );
        }
        response("404 Not Found", &[], "{}")
    });
    let server = fixture(route).await;
    let api_account = account("raw-occupant");
    let api = NativeApi::new(stub(api_account), api_account, format!("http://{}", server.addr)).unwrap();
    let raw = NativeRawStore::new(
        api,
        api_account,
        bucket(),
        config(format!("http://{}", server.addr), std::env::temp_dir().join("hfdrive-raw-cache-o")),
    )
    .unwrap();
    let lease = raw.capture_lease().unwrap();
    let cancel = CancellationToken::new();

    let present = key("hfdrive-imports/00112233-4455-4677-8899-aabbccddeeff/present.txt");
    let absent = key("hfdrive-imports/00112233-4455-4677-8899-aabbccddeeff/absent.txt");
    let report = raw.paths_info(&lease, &[present.clone(), absent.clone()], &cancel).await.unwrap();
    assert_eq!(report.found.len(), 1);
    assert_eq!(report.found[0].key, present);
    assert_eq!(report.found[0].size, 7);
    assert_eq!(report.missing, vec![absent.clone()]);

    // Single-key metadata agrees with the batch view: an existing key is
    // resumable only when durable same-import evidence matches its live size
    // and Xet identity; any other occupant parks/fails and is never rebound.
    let metadata = raw.file_metadata(&lease, &present, &cancel).await.unwrap().expect("occupant");
    assert_eq!(metadata.size, 7);
    let id = metadata.require_xet().expect("raw import objects must carry a Xet identity");
    assert_eq!(id.as_str(), "aa".repeat(32));
    assert!(raw.file_metadata(&lease, &absent, &cancel).await.unwrap().is_none());
}

#[tokio::test]
async fn raw_import_never_addresses_a_managed_head_or_derives_managed_keys() {
    let bodies = Arc::new(Mutex::new(Vec::<String>::new()));
    let recorded = bodies.clone();
    let route: Route = Arc::new(move |method, path, _index, body| {
        if method == "POST" && path.ends_with("/batch") {
            recorded.lock().unwrap().push(body.to_owned());
            return response("200 OK", &[], r#"{"success":true,"processed":1,"succeeded":1,"failed":[]}"#);
        }
        response("404 Not Found", &[], "{}")
    });
    let server = fixture(route).await;
    let api_account = account("raw-no-managed");
    let api = NativeApi::new(stub(api_account), api_account, format!("http://{}", server.addr)).unwrap();
    let raw = NativeRawStore::new(
        api,
        api_account,
        bucket(),
        config(format!("http://{}", server.addr), std::env::temp_dir().join("hfdrive-raw-cache-n")),
    )
    .unwrap();
    let lease = raw.capture_lease().unwrap();
    let cancel = CancellationToken::new();

    // Two imports under distinct prefixes may target the same basename: the
    // exact raw keys differ because the import id is part of the key.
    let a = key("hfdrive-imports/11111111-1111-4111-8111-111111111111/hello.txt");
    let b = key("hfdrive-imports/22222222-2222-4222-8222-222222222222/hello.txt");
    for raw_key in [&a, &b] {
        let checkpoint = cas_checkpoint(raw_key.as_str(), 1, Sha256Digest::of(b"x"));
        let bound = raw.resume_raw_committed(&lease, raw_key, &checkpoint).unwrap()
            .bind(&cancel).await.unwrap();
        assert_eq!(&bound.key, raw_key);
    }
    let dispatched = bodies.lock().unwrap().clone();
    assert_eq!(dispatched.len(), 2);
    for body in &dispatched {
        assert!(body.contains("hfdrive-imports/"));
        assert!(!body.contains("/objects/"), "raw keys must not be rewritten to managed objects/: {body}");
        assert!(!body.contains("HEAD"), "raw imports must never touch managed HEAD: {body}");
    }
}
