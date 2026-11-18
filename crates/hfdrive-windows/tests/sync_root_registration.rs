//! Deterministic tests for the Windows name rules and stable registration
//! identities. Pure data; no OS mutation.

use hfdrive_core::ids::ConnectionId;
use hfdrive_windows::cfapi::{
    sync_root_id, CfError, HardlinkPolicy, HydrationModifiers, HydrationPolicy, PopulationPolicy,
    HFDRIVE_PROVIDER_GUID, SYNC_POLICY, SYNC_ROOT_ID_MAX_LEN,
};
use hfdrive_windows::filesystem::names::{
    decode_component, validate_component, windows_case_equivalent, windows_exact_equal,
    NameCheckError,
};

#[test]
fn portable_component_rules_are_enforced() {
    assert_eq!(validate_component("report.txt"), Ok(()));
    assert_eq!(validate_component("résumé"), Ok(()));
    assert_eq!(validate_component("報告"), Ok(()));
    assert!(validate_component("").is_err());
    assert!(validate_component("a.").is_err());
    assert!(validate_component("a ").is_err());
    assert!(validate_component("a/b").is_err());
    assert!(validate_component("a\\b").is_err());
    assert!(validate_component("a:b").is_err());
    assert!(validate_component("CON").is_err());
    assert!(validate_component("nul.txt").is_err());
    assert!(validate_component("Lpt\u{b9}.txt").is_err(), "superscript digits");
}

#[test]
fn wide_decoding_is_strict() {
    assert_eq!(decode_component(&[b'o' as u16, b'k' as u16]).unwrap(), "ok");
    assert_eq!(
        decode_component(&[b'a' as u16, 0]),
        Err(NameCheckError::ControlCharacter),
        "embedded NUL is rejected"
    );
    assert!(decode_component(&[0xD83D]).is_err(), "unpaired surrogate");
}

#[test]
fn windows_case_comparison_matches_ordinal_semantics() {
    assert!(windows_case_equivalent("Report.txt", "REPORT.TXT"));
    assert!(!windows_case_equivalent("Report.txt", "Report.txu"));
    assert!(windows_exact_equal("Report.txt", "Report.txt"));
    assert!(!windows_exact_equal("Report.txt", "report.txt"));
}

#[test]
fn provider_guid_is_frozen_for_the_product() {
    assert_eq!(
        HFDRIVE_PROVIDER_GUID.to_string(),
        "f727443d-0db5-4746-a08f-16afb2d2f289"
    );
}

#[test]
fn sync_root_ids_are_stable_and_bounded() {
    let connection = ConnectionId::new();
    let id = sync_root_id("S-1-5-21-1-2-3-1001", connection).expect("id");
    assert_eq!(id, format!("HFDrive!S-1-5-21-1-2-3-1001!{connection}"));
    assert!(id.len() <= SYNC_ROOT_ID_MAX_LEN);

    let long_sid = format!("S-1-5-21-{}", "1".repeat(200));
    assert!(matches!(
        sync_root_id(&long_sid, connection),
        Err(CfError::SyncRootIdTooLong { .. })
    ));
    assert!(sync_root_id("", connection).is_err());
    assert!(sync_root_id("bad!sid", connection).is_err());
}

#[test]
fn registration_policy_is_frozen_to_the_supported_combination() {
    assert_eq!(SYNC_POLICY.hydration, HydrationPolicy::Partial);
    assert_eq!(SYNC_POLICY.hydration_modifiers, HydrationModifiers::None);
    assert_eq!(SYNC_POLICY.population, PopulationPolicy::Full);
    assert_eq!(SYNC_POLICY.hardlinks, HardlinkPolicy::None);
}

#[test]
fn candidate_registration_does_not_require_enumerating_deleted_roots() {
    use hfdrive_windows::cfapi::{register_sync_root, unregister_sync_root, RegistrationInfo};
    use hfdrive_windows::filesystem::validate::{validate_sync_root, RootContext};

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("candidate");
    std::fs::create_dir(&root).unwrap();
    let validated = validate_sync_root(
        &root,
        &RootContext {
            state_dir: directory.path().join("state"),
            configured_roots: Vec::new(),
            existing_sync_root_id: None,
        },
    )
    .unwrap();
    let connection = ConnectionId::new();
    register_sync_root(
        &validated,
        "S-1-5-21-1-2-3-1001",
        &RegistrationInfo {
            connection,
            display_name: "HF Drive registration test".to_owned(),
            icon_resource: "@HFDrive,-101".to_owned(),
            version: "0.1.0".to_owned(),
        },
    )
    .unwrap();
    unregister_sync_root("S-1-5-21-1-2-3-1001", connection).unwrap();
}
