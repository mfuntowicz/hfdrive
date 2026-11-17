//! Restoration, record-reference truthfulness and Debug redaction.

mod support;

use std::sync::Arc;

use hfdrive_auth::{
    AuthConfig, AuthError, AuthManager, LoginFlow, LoginPurpose, LoginRequest, LoginSession,
    LoginState, OidcSettings,
};
use hfdrive_core::ids::AccountKey;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use support::*;

async fn signed_in(fixture: &Fixture, dir: &std::path::Path) -> (AuthManager, AccountKey) {
    let settings = OidcSettings::fixture(&fixture.issuer, &fixture.discovery_url(), "127.0.0.1", 300);
    let config = AuthConfig::with_client_id(Some(fixture.client_id.clone()));
    let manager = AuthManager::with_settings_and_launcher(
        config,
        settings,
        dir.to_owned(),
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
    fixture.controls.lock().unwrap().id_token_nonce = Some(nonce);
    let response = callback_request(&redirect, &format!("code=test-code&state={state}"), None).await;
    assert!(response.contains("302"));
    let profile = manager.wait_for_login(session.session_id).await.expect("login");
    (manager, profile.account_key)
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

#[tokio::test]
async fn explicit_account_restoration_rebuilds_the_verified_profile() {
    let fixture = Fixture::start(Controls::user("alice")).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (_manager, account) = signed_in(&fixture, dir.path()).await;
    drop(_manager);

    // The parent supplies the explicitly selected AccountKey; no scanning.
    let restored = AuthManager::with_settings_and_launcher(
        AuthConfig::with_client_id(Some(fixture.client_id.clone())),
        OidcSettings::fixture(&fixture.issuer, &fixture.discovery_url(), "127.0.0.1", 300),
        dir.path().to_owned(),
        Some(account),
        Arc::new(|_: &str| Ok(())),
    );
    let profile = restored.active_profile().expect("restored profile");
    assert_eq!(profile.account_key, account);
    assert_eq!(profile.namespace.as_str(), "alice");
    assert_eq!(profile.subject, "subject-1");
    restored.authorization_epoch(account).expect("epoch");
    assert_eq!(restored.credential_record_file_name(), "oauth.hfdcred");
}

#[tokio::test]
async fn missing_record_restores_to_needs_sign_in() {
    let fixture = Fixture::start(Controls::user("alice")).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let account = AccountKey::from_subject(&fixture.issuer, "subject-never-seen");
    let restored = AuthManager::with_settings_and_launcher(
        AuthConfig::with_client_id(Some(fixture.client_id.clone())),
        OidcSettings::fixture(&fixture.issuer, &fixture.discovery_url(), "127.0.0.1", 300),
        dir.path().to_owned(),
        Some(account),
        Arc::new(|_: &str| Ok(())),
    );
    assert!(restored.active_profile().is_none());
    assert_eq!(restored.snapshot().last_error, Some(AuthError::NeedsSignIn));
}

#[tokio::test]
async fn credential_record_file_name_matches_the_file_on_disk() {
    let fixture = Fixture::start(Controls::user("alice")).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (manager, account) = signed_in(&fixture, dir.path()).await;

    let credentials_dir = hfdrive_auth::store::account_credentials_dir(dir.path(), account);
    let mut on_disk: Vec<String> = std::fs::read_dir(&credentials_dir)
        .expect("credentials dir")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    on_disk.sort();
    assert_eq!(
        on_disk,
        vec!["oauth-refresh-fence.hfdcred".to_owned(), "oauth.hfdcred".to_owned()],
        "the refresh fence and credential must use their real record file names"
    );
    assert!(on_disk.iter().any(|name| name.as_str() == manager.credential_record_file_name()));
}

#[test]
fn login_session_debug_redacts_url_and_user_code() {
    let session = LoginSession {
        session_id: Uuid::new_v4(),
        flow: LoginFlow::Pkce,
        purpose: LoginPurpose::Signin,
        state: LoginState::Pending,
        expires_at_unix: 2_000_000_000,
        authorization_url: Some("https://huggingface.co/oauth/authorize?state=MARKER_STATE&nonce=MARKER_NONCE".to_owned()),
        user_code: Some("MARKER-CODE".to_owned()),
        verification_uri: Some("https://huggingface.co/device?code=MARKER-CODE".to_owned()),
        error: None,
    };
    let output = format!("{session:?}");
    assert!(!output.contains("MARKER_STATE"));
    assert!(!output.contains("MARKER_NONCE"));
    assert!(!output.contains("MARKER-CODE"));
    // The non-secret metadata remains visible for diagnostics.
    assert!(output.contains("session_id"));
    assert!(output.contains("Pending"));
}

#[tokio::test]
async fn snapshot_debug_and_error_paths_leak_no_secret_markers() {
    let fixture = Fixture::start(Controls::user("alice")).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (manager, _account) = signed_in(&fixture, dir.path()).await;
    let snapshot = manager.snapshot();
    let output = format!("{snapshot:?}");
    assert!(!output.contains("test-code"));
    assert!(!output.contains("access-"));
    assert!(!output.contains("refresh-"));
    // A failed login must not leak code/verifier values through errors.
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
    fixture.controls.lock().unwrap().id_token_nonce = Some(nonce);
    fixture.controls.lock().unwrap().id_token_mode = IdTokenMode::BadSignature;
    let _ = callback_request(&redirect, &format!("code=MARKER-SECRET-CODE&state={state}"), None).await;
    let outcome = manager.wait_for_login(session.session_id).await;
    assert!(outcome.is_err());
    let output = format!("{} {:?}", manager.snapshot().revision, outcome);
    assert!(!output.contains("MARKER-SECRET-CODE"));
}
