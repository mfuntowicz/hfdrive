//! Credential-rotation and authorization-epoch regressions: single-flight
//! refresh, refresh-token retention, `invalid_grant` fail-closed behavior and
//! the epoch/generation distinction.

mod support;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use hfdrive_auth::{
    AuthConfig, AuthError, AuthManager, LoginFlow, LoginPurpose, LoginRequest, OidcSettings,
    TokenSource,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use support::*;

async fn signed_in_manager(fixture: &Fixture) -> (AuthManager, tempfile::TempDir, hfdrive_core::ids::AccountKey) {
    let dir = tempfile::tempdir().expect("tempdir");
    let settings = OidcSettings::fixture(&fixture.issuer, &fixture.discovery_url(), "127.0.0.1", 300);
    let config = AuthConfig::with_client_id(Some(fixture.client_id.clone()));
    let manager = AuthManager::with_settings_and_launcher(
        config,
        settings,
        dir.path().to_owned(),
        None,
        Arc::new(|_: &str| Ok(())),
    );
    let session = manager
        .start_login(
            LoginRequest {
                operation_id: Uuid::new_v4(),
                flow: LoginFlow::Pkce,
                purpose: LoginPurpose::Signin,
                organization_id: None,
            },
            CancellationToken::new(),
        )
        .expect("start_login");
    let (redirect, state, nonce) = await_authorization(&manager, session.session_id).await;
    fixture.controls.lock().unwrap().id_token_nonce = Some(nonce.clone());
    let response = callback_request(&redirect, &format!("code=test-code&state={state}"), None).await;
    assert!(response.contains("302"));
    let profile = manager.wait_for_login(session.session_id).await.expect("login");
    (manager, dir, profile.account_key)
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
                    assert!(!session.state.is_terminal());
                }
            }
        }
        receiver.changed().await.expect("watch alive");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_is_singleflight_and_rotations_persist_before_exposure() {
    let fixture = Fixture::start(Controls::user("alice")).await;
    let (manager, _dir, account) = signed_in_manager(&fixture).await;

    let first = manager.access_token(account).await.expect("cached token");
    let first_generation = first.generation();
    let first_secret = first.as_str().to_owned();

    // Concurrent 401 retries share exactly one refresh.
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let manager = manager.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            manager.refresh_after_unauthorized(account, first_generation).await
        }));
    }
    let mut refreshed = Vec::new();
    for handle in handles {
        refreshed.push(handle.await.unwrap().expect("refresh"));
    }
    assert_eq!(refreshed[0].as_str(), refreshed[1].as_str());
    assert_ne!(refreshed[0].as_str(), first_secret);
    assert!(refreshed[0].generation() > first_generation);
    assert_eq!(
        fixture.counters.refresh_requests.load(Ordering::SeqCst),
        1,
        "refresh must be single-flight"
    );

    // The rotated record was persisted before the token was exposed.
    let record = hfdrive_auth::AccountCredentialStore::open(
        hfdrive_auth::store::account_credentials_dir(_dir.path(), account),
        account,
    )
    .expect("store")
    .load()
    .expect("record");
    assert_eq!(record.generation, refreshed[0].generation());
    assert!(record.refresh_token.as_deref().expect("refresh token").starts_with("refresh-"));
}

#[tokio::test]
async fn omitted_refresh_rotation_retains_the_previous_refresh_token() {
    let mut controls = Controls::user("alice");
    controls.refresh_rotates = false;
    let fixture = Fixture::start(controls).await;
    let (manager, _dir, account) = signed_in_manager(&fixture).await;

    let first = manager.access_token(account).await.expect("cached");
    let record_before = hfdrive_auth::AccountCredentialStore::open(
        hfdrive_auth::store::account_credentials_dir(_dir.path(), account),
        account,
    )
    .expect("store")
    .load()
    .expect("record");
    let original_refresh = record_before.refresh_token.clone().expect("refresh token");

    let rotated = manager
        .refresh_after_unauthorized(account, first.generation())
        .await
        .expect("refresh");
    assert!(rotated.generation() > first.generation());
    let record = hfdrive_auth::AccountCredentialStore::open(
        hfdrive_auth::store::account_credentials_dir(_dir.path(), account),
        account,
    )
    .expect("store")
    .load()
    .expect("record");
    assert_eq!(
        record.refresh_token.as_deref(),
        Some(original_refresh.as_str()),
        "rotation without a replacement must retain the previous refresh token"
    );
}

#[tokio::test]
async fn invalid_grant_fails_closed_without_a_retry_loop() {
    let fixture = Fixture::start(Controls::user("alice")).await;
    let (manager, _dir, account) = signed_in_manager(&fixture).await;
    let first = manager.access_token(account).await.expect("cached");

    fixture.controls.lock().unwrap().token_fail = true;
    assert!(matches!(
        manager.refresh_after_unauthorized(account, first.generation()).await,
        Err(hfdrive_auth::AuthorizationError::NeedsSignIn)
    ));
    // No retry loop: exactly one refresh attempt.
    assert_eq!(fixture.counters.refresh_requests.load(Ordering::SeqCst), 1);
    // The account is now fail-closed: no token, no lease.
    assert!(matches!(
        manager.access_token(account).await,
        Err(hfdrive_auth::AuthorizationError::NeedsSignIn)
    ));
    assert!(manager.authorization_lease(account).is_err());
}

#[tokio::test]
async fn credential_generation_rotates_but_the_epoch_survives_refresh() {
    let fixture = Fixture::start(Controls::user("alice")).await;
    let (manager, _dir, account) = signed_in_manager(&fixture).await;

    let lease_before = manager.authorization_lease(account).expect("lease");
    let epoch_before = manager.authorization_epoch(account).expect("epoch");

    let first = manager.access_token(account).await.expect("cached");
    let rotated = manager
        .refresh_after_unauthorized(account, first.generation())
        .await
        .expect("refresh");

    // Credential generation moved; the authorization epoch did not.
    assert!(rotated.generation() > first.generation());
    assert_eq!(manager.authorization_epoch(account).expect("epoch"), epoch_before);
    lease_before.check().expect("lease survives token rotation");
}

#[tokio::test]
async fn sign_out_revokes_leases_and_blocks_late_login_activation() {
    let fixture = Fixture::start(Controls::user("alice")).await;
    let (manager, _dir, account) = signed_in_manager(&fixture).await;
    let lease = manager.authorization_lease(account).expect("lease");

    // Start a fresh login, then sign out before the callback arrives.
    let session = manager
        .start_login(
            LoginRequest {
                operation_id: Uuid::new_v4(),
                flow: LoginFlow::Pkce,
                purpose: LoginPurpose::Signin,
                organization_id: None,
            },
            CancellationToken::new(),
        )
        .expect("start_login");
    let (redirect, state, nonce) = await_authorization(&manager, session.session_id).await;

    manager.sign_out().await.expect("sign_out");

    // The pending login was cancelled; a late callback cannot activate it.
    assert_eq!(
        manager.wait_for_login(session.session_id).await,
        Err(AuthError::Cancelled)
    );
    let late = callback_request(&redirect, &format!("code=test-code&state={state}"), None).await;
    assert!(late.is_empty(), "callback still reachable after sign-out: {late}");
    fixture.controls.lock().unwrap().id_token_nonce = Some(nonce);
    assert!(manager.active_profile().is_none());
    assert_eq!(lease.check(), Err(hfdrive_auth::AuthorizationError::NeedsSignIn));
    assert!(matches!(
        manager.access_token(account).await,
        Err(hfdrive_auth::AuthorizationError::NeedsSignIn)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_response_after_logout_cannot_recreate_credentials() {
    let fixture = Fixture::start(Controls::user("alice")).await;
    let (manager, directory, account) = signed_in_manager(&fixture).await;
    let token = manager.access_token(account).await.unwrap();
    let gate = Arc::new(ResponseGate::default());
    fixture.controls.lock().unwrap().refresh_gate = Some(gate.clone());
    let refreshing = manager.clone();
    let refresh = tokio::spawn(async move {
        refreshing.refresh_after_unauthorized(account, token.generation()).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), gate.reached.notified())
        .await.expect("fixture refresh barrier");
    manager.sign_out().await.unwrap();
    let record = hfdrive_auth::store::account_credentials_dir(directory.path(), account)
        .join(manager.credential_record_file_name());
    assert!(!record.exists());
    gate.release.notify_one();
    assert!(refresh.await.unwrap().is_err(), "a revoked refresh must not expose a token");
    assert!(!record.exists(), "a late refresh must not recreate the deleted credential record");
    assert!(manager.active_profile().is_none());
    assert_eq!(manager.snapshot().last_error, None, "successful logout is SignedOut, not NeedsSignIn");
}

#[tokio::test]
async fn logout_without_an_account_cancels_the_first_pending_login() {
    let fixture = Fixture::start(Controls::user("alice")).await;
    let directory = tempfile::tempdir().unwrap();
    let manager = AuthManager::with_settings_and_launcher(
        AuthConfig::with_client_id(Some(fixture.client_id.clone())),
        OidcSettings::fixture(&fixture.issuer, &fixture.discovery_url(), "127.0.0.1", 300),
        directory.path().to_owned(), None, Arc::new(|_: &str| Ok(())),
    );
    let login = manager.start_login(LoginRequest {
        operation_id: Uuid::new_v4(), flow: LoginFlow::Pkce,
        purpose: LoginPurpose::Signin, organization_id: None,
    }, CancellationToken::new()).unwrap();
    let _ = await_authorization(&manager, login.session_id).await;
    manager.sign_out().await.unwrap();
    assert_eq!(manager.wait_for_login(login.session_id).await, Err(AuthError::Cancelled));
    assert!(manager.active_profile().is_none());
    assert_eq!(manager.snapshot().last_error, None);
}

#[tokio::test]
async fn login_after_logout_never_reuses_a_cached_credential_generation() {
    let fixture = Fixture::start(Controls::user("alice")).await;
    let (manager, _directory, account) = signed_in_manager(&fixture).await;
    let old_token = manager.access_token(account).await.unwrap();
    let old_epoch = manager.authorization_epoch(account).unwrap();
    manager.sign_out().await.unwrap();
    let login = manager.start_login(LoginRequest {
        operation_id: Uuid::new_v4(), flow: LoginFlow::Pkce,
        purpose: LoginPurpose::Signin, organization_id: None,
    }, CancellationToken::new()).unwrap();
    let (redirect, state, nonce) = await_authorization(&manager, login.session_id).await;
    fixture.controls.lock().unwrap().id_token_nonce = Some(nonce);
    let _ = callback_request(&redirect, &format!("code=test-code&state={state}"), None).await;
    assert_eq!(manager.wait_for_login(login.session_id).await.unwrap().account_key, account);
    let new_token = manager.access_token(account).await.unwrap();
    assert!(new_token.generation() > old_token.generation());
    assert!(manager.authorization_epoch(account).unwrap() > old_epoch);
    assert!(new_token.as_str() != old_token.as_str(), "fresh authorization must replace the bearer");
}

#[tokio::test]
async fn changed_refresh_grants_revoke_old_leases_and_restore_the_new_epoch() {
    let fixture = Fixture::start(Controls::user("alice")).await;
    let (manager, directory, account) = signed_in_manager(&fixture).await;
    let old_token = manager.access_token(account).await.unwrap();
    let old_lease = manager.authorization_lease(account).unwrap();
    {
        let mut controls = fixture.controls.lock().unwrap();
        controls.id_token_mode = IdTokenMode::Omitted;
        controls.username = Some("alice-renamed".into());
        controls.granted_scope = Some(Some("openid profile read-memberships read-repos".into()));
    }
    let _ = manager.refresh_after_unauthorized(account, old_token.generation()).await.unwrap();
    let profile = manager.active_profile().unwrap();
    assert_eq!(profile.namespace.as_str(), "alice-renamed");
    assert!(!profile.granted_scopes.as_ref().unwrap().iter().any(|scope| scope == "write-repos"));
    assert_eq!(old_lease.check(), Err(hfdrive_auth::AuthorizationError::NeedsSignIn));
    let epoch = manager.authorization_epoch(account).unwrap();
    let restored = AuthManager::with_settings_and_launcher(
        AuthConfig::with_client_id(Some(fixture.client_id.clone())),
        OidcSettings::fixture(&fixture.issuer, &fixture.discovery_url(), "127.0.0.1", 300),
        directory.path().to_owned(), Some(account), Arc::new(|_: &str| Ok(())),
    );
    assert_eq!(restored.authorization_epoch(account).unwrap(), epoch);
    assert_eq!(restored.active_profile().unwrap().namespace.as_str(), "alice-renamed");
}

#[tokio::test]
async fn refresh_without_id_token_still_rejects_a_changed_userinfo_subject() {
    let fixture = Fixture::start(Controls::user("alice")).await;
    let (manager, directory, account) = signed_in_manager(&fixture).await;
    let old_token = manager.access_token(account).await.unwrap();
    let lease = manager.authorization_lease(account).unwrap();
    {
        let mut controls = fixture.controls.lock().unwrap();
        controls.id_token_mode = IdTokenMode::Omitted;
        controls.userinfo_subject = Some("different-subject".into());
    }
    assert!(manager.refresh_after_unauthorized(account, old_token.generation()).await.is_err());
    assert_eq!(lease.check(), Err(hfdrive_auth::AuthorizationError::NeedsSignIn));
    assert_eq!(manager.snapshot().last_error, Some(AuthError::NeedsSignIn));
    let saved = hfdrive_auth::AccountCredentialStore::open(
        hfdrive_auth::store::account_credentials_dir(directory.path(), account), account,
    ).unwrap().load().unwrap();
    assert_eq!(saved.generation, old_token.generation(), "rejected identity must not replace credentials");
    assert_eq!(saved.subject, "subject-1");
}
