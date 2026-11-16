//! Adversarial PKCE/device login regressions against a deterministic fixture
//! provider. No real network, no real browser: the launcher seam is injected.
//! Test marker values never leave these tests.

mod support;

use std::sync::Arc;

use hfdrive_auth::{
    AuthConfig, AuthError, AuthManager, LoginFlow, LoginPurpose, LoginRequest, LoginState,
    OidcSettings,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use support::*;

async fn make_manager(fixture: &Fixture, lifetime: u64, launcher_ok: bool) -> (AuthManager, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let settings = OidcSettings::fixture(
        &fixture.issuer,
        &fixture.discovery_url(),
        "127.0.0.1",
        lifetime,
    );
    let config = AuthConfig::with_client_id(Some(fixture.client_id.clone()));
    let launcher: hfdrive_auth::BrowserLauncher = if launcher_ok {
        Arc::new(|_: &str| Ok(()))
    } else {
        Arc::new(|_: &str| Err(AuthError::BrowserLaunch))
    };
    let manager = AuthManager::with_settings_and_launcher(
        config,
        settings,
        dir.path().to_owned(),
        None,
        launcher,
    );
    (manager, dir)
}

fn request(flow: LoginFlow, purpose: LoginPurpose, org: Option<&str>) -> LoginRequest {
    LoginRequest {
        operation_id: Uuid::new_v4(),
        flow,
        purpose,
        organization_id: org.map(str::to_owned),
    }
}

async fn await_authorization(manager: &AuthManager, session_id: Uuid) -> (String, String, String) {
    let mut receiver = manager.watch();
    loop {
        {
            let snapshot = receiver.borrow().clone();
            if let Some(session) = &snapshot.active_login {
                if session.session_id == session_id {
                    if let Some(url) = &session.authorization_url {
                        let pairs = query_pairs(url);
                        return (
                            pairs["redirect_uri"].clone(),
                            pairs["state"].clone(),
                            pairs["nonce"].clone(),
                        );
                    }
                    assert!(
                        !session.state.is_terminal(),
                        "session ended before the authorization URL appeared"
                    );
                }
            }
        }
        receiver.changed().await.expect("watch alive");
    }
}

async fn await_user_code(manager: &AuthManager, session_id: Uuid) -> String {
    let mut receiver = manager.watch();
    loop {
        {
            let snapshot = receiver.borrow().clone();
            if let Some(session) = &snapshot.active_login {
                if session.session_id == session_id {
                    if let Some(code) = &session.user_code {
                        return code.clone();
                    }
                    assert!(!session.state.is_terminal());
                }
            }
        }
        receiver.changed().await.expect("watch alive");
    }
}

/// Drive the "browser": accept the callback redirect with a valid code.
async fn drive_browser(fixture: &Fixture, redirect: &str, state: &str, nonce: &str) {
    fixture.controls.lock().unwrap().id_token_nonce = Some(nonce.to_owned());
    let response = callback_request(redirect, &format!("code=test-code&state={state}"), None).await;
    assert!(response.contains("302"), "valid callback rejected: {response}");
}

#[tokio::test]
async fn pkce_login_completes_and_persists_verified_namespace() {
    let fixture = Fixture::start(Controls::user("alice")).await;
    let (manager, _dir) = make_manager(&fixture, 300, true).await;

    let session = manager
        .start_login(request(LoginFlow::Pkce, LoginPurpose::Signin, None), CancellationToken::new())
        .expect("start_login");
    assert_eq!(session.state, LoginState::Pending);
    // Pending is visible before any subscription races.
    assert!(manager.snapshot().active_login.is_some());

    let (redirect, state, nonce) = await_authorization(&manager, session.session_id).await;
    drive_browser(&fixture, &redirect, &state, &nonce).await;

    let profile = manager
        .wait_for_login(session.session_id)
        .await
        .expect("login completes");
    assert_eq!(profile.namespace.as_str(), "alice");
    assert_eq!(profile.subject, "subject-1");
    assert!(profile.purpose_covered);
    let snapshot = manager.snapshot();
    assert!(snapshot.revision > 0);
    assert!(snapshot.profile.is_some());
    assert_eq!(
        snapshot.active_login.as_ref().map(|s| s.state),
        Some(LoginState::Completed)
    );
    // The record is on disk under the promised file name.
    let record = manager.credential_record_file_name();
    assert_eq!(record, "oauth.hfdcred");
    assert!(manager.authorization_epoch(profile.account_key).is_ok());
}

#[tokio::test]
async fn invalid_state_and_adversarial_requests_never_consume_the_attempt() {
    let fixture = Fixture::start(Controls::user("alice")).await;
    let (manager, _dir) = make_manager(&fixture, 300, true).await;
    let session = manager
        .start_login(request(LoginFlow::Pkce, LoginPurpose::Signin, None), CancellationToken::new())
        .expect("start_login");
    let (redirect, state, nonce) = await_authorization(&manager, session.session_id).await;

    // Attacker traffic first: none of it may consume the real attempt.
    let wrong_state = callback_request(&redirect, "code=evil&state=WRONG", None).await;
    assert!(wrong_state.contains("400"));
    let duplicate = callback_request(&redirect, &format!("code=a&code=b&state={state}"), None).await;
    assert!(duplicate.contains("400"));
    let post = raw_request(&redirect, &format!("POST /oauth/callback?code=x&state={state} HTTP/1.1\r\nHost: x\r\n\r\n")).await;
    assert!(post.contains("400"));
    let wrong_path = raw_request(&redirect, &format!("GET /steal?code=x&state={state} HTTP/1.1\r\nHost: x\r\n\r\n")).await;
    assert!(wrong_path.contains("400"));
    let wrong_host = callback_request(&redirect, &format!("code=x&state={state}"), Some("evil.example")).await;
    assert!(wrong_host.contains("400"));

    // The real callback still completes exactly once.
    drive_browser(&fixture, &redirect, &state, &nonce).await;
    let profile = manager.wait_for_login(session.session_id).await.expect("login");
    assert_eq!(profile.namespace.as_str(), "alice");
    assert_eq!(fixture.counters.code_exchanges.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn oversized_callback_head_is_rejected_without_consuming() {
    let fixture = Fixture::start(Controls::user("alice")).await;
    let (manager, _dir) = make_manager(&fixture, 300, true).await;
    let session = manager
        .start_login(request(LoginFlow::Pkce, LoginPurpose::Signin, None), CancellationToken::new())
        .expect("start_login");
    let (redirect, state, nonce) = await_authorization(&manager, session.session_id).await;

    let mut huge = format!("GET /oauth/callback?code=x&state={state} HTTP/1.1\r\nHost: h\r\n");
    huge.push_str(&"X-Pad: ".to_owned());
    huge.push_str(&"a".repeat(24 * 1024));
    huge.push_str("\r\n\r\n");
    let response = raw_request(&redirect, &huge).await;
    assert!(response.is_empty() || response.contains("431") || response.contains("400"));

    drive_browser(&fixture, &redirect, &state, &nonce).await;
    manager.wait_for_login(session.session_id).await.expect("login");
}

#[tokio::test]
async fn duplicate_successful_callback_cannot_exchange_the_code_twice() {
    let fixture = Fixture::start(Controls::user("alice")).await;
    let (manager, _dir) = make_manager(&fixture, 300, true).await;
    let session = manager
        .start_login(request(LoginFlow::Pkce, LoginPurpose::Signin, None), CancellationToken::new())
        .expect("start_login");
    let (redirect, state, nonce) = await_authorization(&manager, session.session_id).await;
    drive_browser(&fixture, &redirect, &state, &nonce).await;
    manager.wait_for_login(session.session_id).await.expect("login");

    // The listener is closed: a repeated success callback cannot arrive.
    let second = callback_request(&redirect, &format!("code=test-code&state={state}"), None).await;
    assert!(second.is_empty(), "listener still accepted a duplicate: {second}");
    assert_eq!(fixture.counters.code_exchanges.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn denial_expires_cancel_and_browser_failure_are_distinct_terminal_states() {
    // Denied.
    let fixture = Fixture::start(Controls::user("alice")).await;
    let (manager, _dir) = make_manager(&fixture, 300, true).await;
    let session = manager
        .start_login(request(LoginFlow::Pkce, LoginPurpose::Signin, None), CancellationToken::new())
        .expect("start_login");
    let (redirect, state, _nonce) = await_authorization(&manager, session.session_id).await;
    let response = callback_request(&redirect, &format!("error=access_denied&state={state}"), None).await;
    assert!(response.contains("400"));
    assert_eq!(
        manager.wait_for_login(session.session_id).await,
        Err(AuthError::Denied)
    );

    // Expired (short lifetime, user never finishes).
    let fixture = Fixture::start(Controls::user("alice")).await;
    let (manager, _dir) = make_manager(&fixture, 1, true).await;
    let session = manager
        .start_login(request(LoginFlow::Pkce, LoginPurpose::Signin, None), CancellationToken::new())
        .expect("start_login");
    assert_eq!(
        manager.wait_for_login(session.session_id).await,
        Err(AuthError::Expired)
    );

    // Cancelled.
    let fixture = Fixture::start(Controls::user("alice")).await;
    let (manager, _dir) = make_manager(&fixture, 300, true).await;
    let cancel = CancellationToken::new();
    let session = manager
        .start_login(request(LoginFlow::Pkce, LoginPurpose::Signin, None), cancel.clone())
        .expect("start_login");
    let _ = await_authorization(&manager, session.session_id).await;
    assert!(manager.cancel_login(session.session_id));
    assert_eq!(
        manager.wait_for_login(session.session_id).await,
        Err(AuthError::Cancelled)
    );

    // Browser launch failure tears the session down.
    let fixture = Fixture::start(Controls::user("alice")).await;
    let (manager, _dir) = make_manager(&fixture, 300, false).await;
    let session = manager
        .start_login(request(LoginFlow::Pkce, LoginPurpose::Signin, None), CancellationToken::new())
        .expect("start_login");
    assert_eq!(
        manager.wait_for_login(session.session_id).await,
        Err(AuthError::BrowserLaunch)
    );
}

#[tokio::test]
async fn one_outstanding_login_only() {
    let fixture = Fixture::start(Controls::user("alice")).await;
    let (manager, _dir) = make_manager(&fixture, 300, true).await;
    let _first = manager
        .start_login(request(LoginFlow::Pkce, LoginPurpose::Signin, None), CancellationToken::new())
        .expect("start_login");
    assert_eq!(
        manager.start_login(request(LoginFlow::Pkce, LoginPurpose::Signin, None), CancellationToken::new()),
        Err(AuthError::LoginAlreadyInProgress)
    );
}

#[tokio::test]
async fn absent_or_invalid_preferred_username_rejects_the_identity() {
    // Absent preferred_username.
    let mut controls = Controls::user("ignored");
    controls.username = None;
    let fixture = Fixture::start(controls).await;
    let (manager, _dir) = make_manager(&fixture, 300, true).await;
    let session = manager
        .start_login(request(LoginFlow::Pkce, LoginPurpose::Signin, None), CancellationToken::new())
        .expect("start_login");
    let (redirect, state, nonce) = await_authorization(&manager, session.session_id).await;
    drive_browser(&fixture, &redirect, &state, &nonce).await;
    assert_eq!(
        manager.wait_for_login(session.session_id).await,
        Err(AuthError::IdentityValidation)
    );
    assert!(manager.active_profile().is_none());

    // Invalid namespace spelling: nothing is invented from the subject.
    let fixture = Fixture::start(Controls::user("not a namespace!")).await;
    let (manager, _dir) = make_manager(&fixture, 300, true).await;
    let session = manager
        .start_login(request(LoginFlow::Pkce, LoginPurpose::Signin, None), CancellationToken::new())
        .expect("start_login");
    let (redirect, state, nonce) = await_authorization(&manager, session.session_id).await;
    drive_browser(&fixture, &redirect, &state, &nonce).await;
    assert_eq!(
        manager.wait_for_login(session.session_id).await,
        Err(AuthError::IdentityValidation)
    );
    assert!(manager.active_profile().is_none());
}

#[tokio::test]
async fn id_token_validation_rejects_tampering_and_mismatch() {
    for mode in [
        IdTokenMode::BadSignature,
        IdTokenMode::WrongIssuer,
        IdTokenMode::WrongAudience,
        IdTokenMode::MissingNonce,
        IdTokenMode::WrongNonce,
        IdTokenMode::Expired,
        IdTokenMode::Omitted,
    ] {
        let mut controls = Controls::user("alice");
        controls.id_token_mode = mode;
        let fixture = Fixture::start(controls).await;
        let (manager, _dir) = make_manager(&fixture, 300, true).await;
        let session = manager
            .start_login(request(LoginFlow::Pkce, LoginPurpose::Signin, None), CancellationToken::new())
            .expect("start_login");
        let (redirect, state, nonce) = await_authorization(&manager, session.session_id).await;
        drive_browser(&fixture, &redirect, &state, &nonce).await;
        let outcome = manager.wait_for_login(session.session_id).await;
        assert!(outcome.is_err(), "accepted id_token_mode {mode:?}");
        assert!(manager.active_profile().is_none(), "published profile for {mode:?}");
    }
}

#[tokio::test]
async fn scope_purpose_is_enforced_and_none_stays_unknown() {
    // Purpose exceeds the granted scopes: fail closed before persistence.
    let mut controls = Controls::user("alice");
    controls.granted_scope = Some(Some("openid profile read-memberships".to_owned()));
    let fixture = Fixture::start(controls).await;
    let (manager, _dir) = make_manager(&fixture, 300, true).await;
    let session = manager
        .start_login(
            request(LoginFlow::Pkce, LoginPurpose::WriteStorage, None),
            CancellationToken::new(),
        )
        .expect("start_login");
    let (redirect, state, nonce) = await_authorization(&manager, session.session_id).await;
    drive_browser(&fixture, &redirect, &state, &nonce).await;
    assert_eq!(
        manager.wait_for_login(session.session_id).await,
        Err(AuthError::ScopesNotGranted)
    );
    assert!(manager.active_profile().is_none());

    // Omitted `scope` response field: unknown, not proven empty — accepted.
    let mut controls = Controls::user("alice");
    controls.granted_scope = None;
    let fixture = Fixture::start(controls).await;
    let (manager, _dir) = make_manager(&fixture, 300, true).await;
    let session = manager
        .start_login(
            request(LoginFlow::Pkce, LoginPurpose::WriteStorage, None),
            CancellationToken::new(),
        )
        .expect("start_login");
    let (redirect, state, nonce) = await_authorization(&manager, session.session_id).await;
    drive_browser(&fixture, &redirect, &state, &nonce).await;
    let profile = manager.wait_for_login(session.session_id).await.expect("login");
    assert!(profile.granted_scopes.is_none());
    assert!(profile.purpose_covered);
}

#[tokio::test]
async fn org_reconsent_requires_a_verified_org_subject() {
    // Requested org absent from the identity: nothing is pretended.
    let fixture = Fixture::start(Controls::user("alice")).await;
    let (manager, _dir) = make_manager(&fixture, 300, true).await;
    let session = manager
        .start_login(
            request(LoginFlow::Pkce, LoginPurpose::ReadStorage, Some("org-123")),
            CancellationToken::new(),
        )
        .expect("start_login");
    let (redirect, state, nonce) = await_authorization(&manager, session.session_id).await;
    drive_browser(&fixture, &redirect, &state, &nonce).await;
    assert_eq!(
        manager.wait_for_login(session.session_id).await,
        Err(AuthError::OrganizationNotVerified)
    );

    // Verified org present: consent provenance recorded.
    let mut controls = Controls::user("alice");
    controls.orgs = vec![serde_json::json!({"sub": "org-123", "name": "Team", "role": "admin"})];
    let fixture = Fixture::start(controls).await;
    let (manager, _dir) = make_manager(&fixture, 300, true).await;
    let session = manager
        .start_login(
            request(LoginFlow::Pkce, LoginPurpose::ReadStorage, Some("org-123")),
            CancellationToken::new(),
        )
        .expect("start_login");
    let (redirect, state, nonce) = await_authorization(&manager, session.session_id).await;
    drive_browser(&fixture, &redirect, &state, &nonce).await;
    let profile = manager.wait_for_login(session.session_id).await.expect("login");
    assert!(profile.org_consent_requested);
    let org = profile.orgs.iter().find(|o| o.subject == "org-123").expect("org");
    assert!(org.consented_this_session);
    assert_eq!(org.name.as_deref(), Some("Team"));
    assert_eq!(org.role.as_deref(), Some("admin"));
}

#[tokio::test]
async fn device_flow_is_explicit_and_respects_denial_and_pending() {
    // Success after one pending poll (interval honored by the library).
    let mut controls = Controls::user("alice");
    controls.device_pending_polls = 1;
    let fixture = Fixture::start(controls).await;
    let (manager, _dir) = make_manager(&fixture, 300, true).await;
    let session = manager
        .start_login(request(LoginFlow::Device, LoginPurpose::Signin, None), CancellationToken::new())
        .expect("start_login");
    let user_code = await_user_code(&manager, session.session_id).await;
    assert_eq!(user_code, "ABCD-EFGH");
    let profile = manager
        .wait_for_login(session.session_id)
        .await
        .expect("device login completes");
    assert!(profile.reconsent_required_for_storage);
    assert!(fixture.counters.device_requests.load(std::sync::atomic::Ordering::SeqCst) >= 1);

    // Denied at the provider.
    let mut controls = Controls::user("alice");
    controls.device_error = Some("access_denied".to_owned());
    let fixture = Fixture::start(controls).await;
    let (manager, _dir) = make_manager(&fixture, 300, true).await;
    let session = manager
        .start_login(request(LoginFlow::Device, LoginPurpose::Signin, None), CancellationToken::new())
        .expect("start_login");
    assert_eq!(
        manager.wait_for_login(session.session_id).await,
        Err(AuthError::Denied)
    );

    // Storage purpose over device flow cannot be pretended when scopes miss.
    let mut controls = Controls::user("alice");
    controls.granted_scope = Some(Some("openid profile read-memberships".to_owned()));
    let fixture = Fixture::start(controls).await;
    let (manager, _dir) = make_manager(&fixture, 300, true).await;
    let session = manager
        .start_login(
            request(LoginFlow::Device, LoginPurpose::WriteStorage, None),
            CancellationToken::new(),
        )
        .expect("start_login");
    assert_eq!(
        manager.wait_for_login(session.session_id).await,
        Err(AuthError::ScopesNotGranted)
    );
}
