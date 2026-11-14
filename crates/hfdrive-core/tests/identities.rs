use hfdrive_core::ids::{AccountKey, ItemId};

#[test]
fn account_directory_cannot_be_selected_by_a_renamed_namespace() {
    let original = AccountKey::from_subject("https://huggingface.co", "stable-subject");
    assert_eq!(original, AccountKey::from_subject("https://huggingface.co", "stable-subject"));
    assert_ne!(original, AccountKey::from_subject("https://huggingface.co", "different-subject"));
    assert_ne!(original, AccountKey::from_subject("https://another-issuer.example", "stable-subject"));
    assert_eq!(original, original.to_string().parse().unwrap());
    assert!("../credentials".parse::<AccountKey>().is_err());
}

#[test]
fn remote_identifier_has_one_nonzero_path_safe_spelling() {
    let id = ItemId::new();
    let spelling = id.to_string();
    assert_eq!(id, spelling.parse().unwrap());
    assert!("00000000-0000-0000-0000-000000000000".parse::<ItemId>().is_err());
    assert!("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA".parse::<ItemId>().is_err());
    assert!(spelling.replace('-', "").parse::<ItemId>().is_err());
    assert!(format!("../{spelling}").parse::<ItemId>().is_err());
}
