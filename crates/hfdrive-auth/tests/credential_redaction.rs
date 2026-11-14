use hfdrive_auth::{AuthorizationAuthority, SecretAccessToken};
use hfdrive_core::ids::AccountKey;
use zeroize::Zeroizing;

#[test]
fn token_debug_output_cannot_disclose_credential_marker() {
    let marker = "HFDRIVE_TEST_TOKEN_MUST_NOT_APPEAR";
    let token = SecretAccessToken::new(
        Zeroizing::new(marker.to_owned()),
        AccountKey::from_subject("https://huggingface.co", "fixture-subject"),
        7,
        2_000_000_000,
    );
    let output = format!("{token:?}");
    assert!(!output.contains(marker));
}

#[test]
fn authority_requires_an_account_and_leaks_no_token_material() {
    let account = AccountKey::from_subject("https://huggingface.co", "fixture-subject");
    let authority = AuthorizationAuthority::new(account, 3);
    assert_eq!(authority.account(), account);
    let lease = authority.activate().unwrap();
    assert_eq!(lease.account(), account);
    let output = format!("{authority:?} {lease:?}");
    assert!(!output.contains("fixture-subject"));
}
