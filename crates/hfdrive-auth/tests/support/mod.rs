//! Deterministic local fixture provider for hfdrive-auth tests.
//!
//! Serves OIDC discovery, JWKS, token (code + refresh grants), userinfo and
//! device authorization on `127.0.0.1`. ID tokens are signed with the
//! RFC 7515 example RSA key so tests exercise the real RS256 verification
//! path. Test marker values never appear in logs or artifacts.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use openidconnect::core::{CoreGenderClaim, CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey};
use openidconnect::{IdToken, IdTokenClaims, JsonWebKeyId, JsonWebKeySet, PrivateSigningKey};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use hfdrive_auth::identity::ExtraClaims;

/// RFC 7515 appendix B example RSA private key (public test fixture).
pub const TEST_RSA_PRIV_KEY_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEowIBAAKCAQEAn4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8/KuKPEHLd4\n\
rHVTeT+O+XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz/AJmSCpMaJMRBSFKrKb2wqVwG\n\
U/NsYOYL+QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj+oBHqFEHYpP\n\
e7Tpe+OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzw\n\
OHrtIQbS0FVbb9k3+tVTU4fg/3L/vniUFAKwuCLqKnS2BYwdq/mzSnbLY7h/qixo\n\
R7jig3//kRhuaxwUkRz5iaiQkqgc5gHdrNP5zwIDAQABAoIBAG1lAvQfhBUSKPJK\n\
Rn4dGbshj7zDSr2FjbQf4pIh/ZNtHk/jtavyO/HomZKV8V0NFExLNi7DUUvvLiW7\n\
0PgNYq5MDEjJCtSd10xoHa4QpLvYEZXWO7DQPwCmRofkOutf+NqyDS0QnvFvp2d+\n\
Lov6jn5C5yvUFgw6qWiLAPmzMFlkgxbtjFAWMJB0zBMy2BqjntOJ6KnqtYRMQUxw\n\
TgXZDF4rhYVKtQVOpfg6hIlsaoPNrF7dofizJ099OOgDmCaEYqM++bUlEHxgrIVk\n\
wZz+bg43dfJCocr9O5YX0iXaz3TOT5cpdtYbBX+C/5hwrqBWru4HbD3xz8cY1TnD\n\
qQa0M8ECgYEA3Slxg/DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex/fp7AZ/9\n\
nRaO7HX/+SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr/WCsmGpeNqQn\n\
ev1T7IyEsnh8UMt+n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0kCgYEAuKE2\n\
dh+cTf6ERF4k4e/jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR/cu0Dm1MZwW\n\
mtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoB\n\
vyY898EXvRD+hdqRxHlSqAZ192zB3pVFJ0s7pFcCgYAHw9W9eS8muPYv4ZhDu/fL\n\
2vorDmD1JqFcHCxZTOnX1NWWAj5hXzmrU0hvWvFC0P4ixddHf5Nqd6+5E9G3k4E5\n\
2IwZCnylu3bqCWNh8pT8T3Gf5FQsfPT5530T2BcsoPhUaeCnP499D+rb2mTnFYeg\n\
mnTT1B/Ue8KGLFFfn16GKQKBgAiw5gxnbocpXPaO6/OKxFFZ+6c0OjxfN2PogWce\n\
TU/k6ZzmShdaRKwDFXisxRJeNQ5Rx6qgS0jNFtbDhW8E8WFmQ5urCOqIOYk28EBi\n\
At4JySm4v+5P7yYBh8B8YD2l9j57z/s8hJAxEbn/q8uHP2ddQqvQKgtsni+pHSk9\n\
XGBfAoGBANz4qr10DdM8DHhPrAb2YItvPVz/VwkBd1Vqj8zCpyIEKe/07oKOvjWQ\n\
SgkLDH9x2hBgY01SbP43CvPk0V72invu2TGkI/FXwXWJLLG7tDSgw4YyfhrYrHmg\n\
1Vre3XB9HH8MYBVB6UIexaAq4xSeoemRKTBesZro7OKjKT8/GmiO\n\
-----END RSA PRIVATE KEY-----";

/// How the fixture signs ID tokens for adversarial cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IdTokenMode {
    #[default]
    Valid,
    Omitted,
    Expired,
    WrongIssuer,
    WrongAudience,
    MissingNonce,
    WrongNonce,
    BadSignature,
}

#[derive(Default)]
pub struct Controls {
    pub subject: String,
    pub username: Option<String>,
    pub orgs: Vec<Value>,
    pub granted_scope: Option<Option<String>>,
    pub token_fail: bool,
    pub id_token_nonce: Option<String>,
    pub id_token_mode: IdTokenMode,
    pub refresh_rotates: bool,
    pub expires_in: u64,
    pub device_pending_polls: u32,
    pub device_error: Option<String>,
    pub device_interval: u64,
    pub userinfo_subject: Option<String>,
    pub refresh_gate: Option<Arc<ResponseGate>>,
}

impl Controls {
    pub fn user(username: &str) -> Self {
        Self {
            subject: "subject-1".to_owned(),
            username: Some(username.to_owned()),
            granted_scope: Some(Some(
                "openid profile read-memberships read-repos write-repos manage-repos".to_owned(),
            )),
            refresh_rotates: true,
            expires_in: 3600,
            device_interval: 1,
            ..Self::default()
        }
    }
}

#[derive(Default)]
pub struct ResponseGate {
    pub reached: tokio::sync::Notify,
    pub release: tokio::sync::Notify,
}

#[derive(Default)]
pub struct Counters {
    pub token_requests: AtomicUsize,
    pub refresh_requests: AtomicUsize,
    pub code_exchanges: AtomicUsize,
    pub device_requests: AtomicUsize,
    pub device_polls: AtomicUsize,
}

pub struct Fixture {
    pub base: String,
    pub issuer: String,
    pub client_id: String,
    pub controls: Arc<Mutex<Controls>>,
    pub counters: Arc<Counters>,
}

fn signing_key() -> CoreRsaPrivateSigningKey {
    CoreRsaPrivateSigningKey::from_pem(
        TEST_RSA_PRIV_KEY_PEM,
        Some(JsonWebKeyId::new("test-key".to_owned())),
    )
    .expect("test RSA key parses")
}

pub fn jwks_json() -> String {
    let key = signing_key();
    let set = JsonWebKeySet::new(vec![key.as_verification_key()]);
    serde_json::to_string(&set).expect("jwks serialize")
}

/// The fixture's ID-token type (HF extra claims, RS256).
pub type TestIdToken = IdToken<
    ExtraClaims,
    CoreGenderClaim,
    openidconnect::core::CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

/// Build a signed (or deliberately invalid) ID token for the fixture.
pub fn build_id_token(controls: &Controls, client_id: &str, issuer: &str) -> Option<String> {
    if controls.id_token_mode == IdTokenMode::Omitted {
        return None;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    let mode = controls.id_token_mode;
    let exp = if mode == IdTokenMode::Expired { now - 3600 } else { now + 3600 };
    let iss = if mode == IdTokenMode::WrongIssuer {
        "https://evil.example".to_owned()
    } else {
        issuer.to_owned()
    };
    let aud = if mode == IdTokenMode::WrongAudience {
        "some-other-client".to_owned()
    } else {
        client_id.to_owned()
    };
    let nonce = match mode {
        IdTokenMode::MissingNonce => Value::Null,
        IdTokenMode::WrongNonce => json!("wrong-nonce-value"),
        _ => match &controls.id_token_nonce {
            Some(n) => json!(n),
            None => Value::Null,
        },
    };
    let claims_json = json!({
        "iss": iss,
        "sub": controls.subject,
        "aud": aud,
        "exp": exp,
        "iat": now - 10,
        "nonce": nonce,
        "role": "admin",
        "orgs": controls.orgs,
    });
    let claims: IdTokenClaims<ExtraClaims, CoreGenderClaim> =
        serde_json::from_value(claims_json).expect("claims parse");
    let key = signing_key();
    let token: TestIdToken = IdToken::new(
        claims,
        &key,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .expect("sign id token");
    let text = token.to_string();
    if mode == IdTokenMode::BadSignature {
        // Deterministic tampering: flip the first base64url char of the
        // signature segment.
        let mut parts: Vec<String> = text.split('.').map(str::to_owned).collect();
        let sig = parts.pop().expect("jwt has signature");
        let flipped = if sig.starts_with('A') { format!("B{}", &sig[1..]) } else { format!("A{}", &sig[1..]) };
        parts.push(flipped);
        Some(parts.join("."))
    } else {
        Some(text)
    }
}

fn token_response(
    c: &Controls,
    counters: &Counters,
    client_id: &str,
    issuer: &str,
    rotate_refresh: bool,
) -> Value {
    let mut response = json!({
        "access_token": format!("access-{}", counters.token_requests.load(Ordering::SeqCst)),
        "token_type": "Bearer",
        "expires_in": if c.expires_in == 0 { 3600 } else { c.expires_in },
    });
    if rotate_refresh {
        response["refresh_token"] =
            json!(format!("refresh-{}", counters.token_requests.load(Ordering::SeqCst)));
    }
    if let Some(scope) = &c.granted_scope {
        if let Some(scope) = scope {
            response["scope"] = json!(scope);
        }
    }
    if let Some(id_token) = build_id_token(c, client_id, issuer) {
        response["id_token"] = json!(id_token);
    }
    response
}

impl Fixture {
    pub async fn start(controls: Controls) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("fixture bind");
        let addr = listener.local_addr().expect("fixture addr");
        let base = format!("http://127.0.0.1:{}", addr.port());
        let controls = Arc::new(Mutex::new(controls));
        let counters = Arc::new(Counters::default());
        let issuer = base.clone();
        let client_id = "test-client".to_owned();
        {
            let controls = controls.clone();
            let counters = counters.clone();
            let issuer = issuer.clone();
            let client_id = client_id.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else { break };
                    let controls = controls.clone();
                    let counters = counters.clone();
                    let issuer = issuer.clone();
                    let client_id = client_id.clone();
                    tokio::spawn(async move {
                        let _ = handle(stream, controls, counters, issuer, client_id).await;
                    });
                }
            });
        }
        Fixture {
            base,
            issuer,
            client_id,
            controls,
            counters,
        }
    }

    pub fn discovery_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.base)
    }
}

async fn handle(
    mut stream: tokio::net::TcpStream,
    controls: Arc<Mutex<Controls>>,
    counters: Arc<Counters>,
    issuer: String,
    client_id: String,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    let head_end;
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            head_end = pos + 4;
            break;
        }
        if buf.len() > 64 * 1024 {
            return Ok(());
        }
    }
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("").to_owned();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let content_length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }

    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("").to_owned();
    let target = parts.next().unwrap_or("").to_owned();
    let path = target.split_once('?').map_or(target.as_str(), |(path, _)| path);

    let response_body = match (method.as_str(), path) {
        ("GET", "/.well-known/openid-configuration") => {
            let device_endpoint = format!("{}/device", issuer);
            json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{}/authorize", issuer),
                "token_endpoint": format!("{}/token", issuer),
                "userinfo_endpoint": format!("{}/userinfo", issuer),
                "jwks_uri": format!("{}/jwks", issuer),
                "device_authorization_endpoint": device_endpoint,
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            })
            .to_string()
        }
        ("GET", "/jwks") => jwks_json(),
        ("POST", "/token") => {
            let form = parse_form(&body);
            let grant = form.get("grant_type").map(String::as_str).unwrap_or("").to_owned();
            let is_refresh = grant == "refresh_token";
            let is_device = grant.contains("device_code");
            if is_refresh {
                counters.refresh_requests.fetch_add(1, Ordering::SeqCst);
                let gate = controls.lock().unwrap().refresh_gate.clone();
                if let Some(gate) = gate {
                    gate.reached.notify_one();
                    gate.release.notified().await;
                }
            } else if is_device {
                counters.device_polls.fetch_add(1, Ordering::SeqCst);
            } else {
                counters.code_exchanges.fetch_add(1, Ordering::SeqCst);
            }
            counters.token_requests.fetch_add(1, Ordering::SeqCst);
            let c = controls.lock().unwrap();
            if is_device {
                if let Some(error) = &c.device_error {
                    json!({ "error": error }).to_string()
                } else if counters.device_polls.load(Ordering::SeqCst) as u32 <= c.device_pending_polls {
                    r#"{"error":"authorization_pending"}"#.to_owned()
                } else {
                    token_response(&c, &counters, &client_id, &issuer, true).to_string()
                }
            } else if c.token_fail {
                r#"{"error":"invalid_grant"}"#.to_owned()
            } else {
                let rotate = !is_refresh || c.refresh_rotates;
                token_response(&c, &counters, &client_id, &issuer, rotate).to_string()
            }
        }
        ("GET", "/userinfo") => {
            let c = controls.lock().unwrap();
            let mut response = json!({
                "sub": c.userinfo_subject.clone().unwrap_or_else(|| c.subject.clone()),
                "role": "admin",
                "orgs": c.orgs,
            });
            if let Some(username) = &c.username {
                response["preferred_username"] = json!(username);
            }
            response.to_string()
        }
        ("POST", "/device") => {
            counters.device_requests.fetch_add(1, Ordering::SeqCst);
            let c = controls.lock().unwrap();
            json!({
                "device_code": "device-code-1",
                "user_code": "ABCD-EFGH",
                "verification_uri": format!("{}/device", issuer),
                "expires_in": 600,
                "interval": c.device_interval.max(1),
            })
            .to_string()
        }
        _ => r#"{"error":"not_found"}"#.to_owned(),
    };

    // The /token route returns JSON errors with 200/400 depending on content.
    let status = if response_body.contains("\"error\"") && path == "/token" {
        "400 Bad Request"
    } else {
        "200 OK"
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response_body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(response_body.as_bytes()).await?;
    stream.flush().await
}

fn parse_form(body: &[u8]) -> HashMap<String, String> {
    let text = String::from_utf8_lossy(body);
    text.split('&')
        .filter_map(|part| {
            let (k, v) = part.split_once('=')?;
            Some((percent_decode(k), percent_decode(v)))
        })
        .collect()
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Extract `key=value` pairs from an authorization URL's query string.
pub fn query_pairs(url: &str) -> HashMap<String, String> {
    let query = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    query
        .split('&')
        .filter_map(|part| {
            let (k, v) = part.split_once('=')?;
            Some((percent_decode(k), percent_decode(v)))
        })
        .collect()
}

/// Send an arbitrary raw request to the callback redirect's authority.
pub async fn raw_request(redirect_uri: &str, raw: &str) -> String {
    let rest = redirect_uri.trim_start_matches("http://");
    let authority = rest.split('/').next().unwrap_or(rest);
    let mut stream = tokio::net::TcpStream::connect(authority)
        .await
        .expect("raw connect");
    stream.write_all(raw.as_bytes()).await.expect("raw write");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response).await;
    String::from_utf8_lossy(&response).into_owned()
}

/// Raw callback GET against the loopback redirect; returns the response text.
pub async fn callback_request(redirect_uri: &str, query: &str, host: Option<&str>) -> String {
    let rest = redirect_uri.trim_start_matches("http://");
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let host_header = host.unwrap_or(authority);
    let request = format!(
        "GET {path}?{query} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n"
    );
    let Ok(mut stream) = tokio::net::TcpStream::connect(authority).await else {
        return String::new();
    };
    stream.write_all(request.as_bytes()).await.expect("callback write");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response).await;
    String::from_utf8_lossy(&response).into_owned()
}
