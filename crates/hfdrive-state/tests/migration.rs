//! Migration and database-identity gates: fresh creation is distinct from an
//! unknown preexisting file; newer/foreign/corrupt databases are refused and
//! preserved exactly; forward migrations take an online backup first.

mod common;

use common::*;
use hfdrive_state::{StateError, StatePaths, StateStore};
use rusqlite::Connection;

const CONTROL_APPLICATION_ID: i64 = 0x4846_4443;
const ACCOUNT_APPLICATION_ID: i64 = 0x4846_4441;

fn user_version(path: &std::path::Path) -> u32 {
    let conn = Connection::open(path).unwrap();
    conn.pragma_query_value(None, "user_version", |row| row.get(0)).unwrap()
}

fn application_id(path: &std::path::Path) -> i64 {
    let conn = Connection::open(path).unwrap();
    conn.pragma_query_value(None, "application_id", |row| row.get(0)).unwrap()
}

#[tokio::test]
async fn fresh_creation_sets_schema_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let key = account_key();

    let store = StateStore::open(paths.clone()).await.unwrap();
    store.record_account(account_record(key)).await.unwrap();
    let account = store.open_account(key).await.unwrap();
    // Touch the account database so it is created.
    account.list_connections().await.unwrap();

    let control = paths.control_database();
    assert!(control.exists());
    assert_eq!(application_id(&control), CONTROL_APPLICATION_ID);
    assert_eq!(user_version(&control), 2);

    let account_db = paths.account(key).database();
    assert!(account_db.exists());
    assert_eq!(application_id(&account_db), ACCOUNT_APPLICATION_ID);
    assert_eq!(user_version(&account_db), 2);
    store.close().await.unwrap();
}

#[tokio::test]
async fn unknown_preexisting_file_is_refused_and_preserved() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let control = paths.control_database();
    std::fs::create_dir_all(control.parent().unwrap()).unwrap();
    let garbage = b"this is not a sqlite database file at all........";
    std::fs::write(&control, garbage).unwrap();

    let error = StateStore::open(paths).await.err().expect("corrupt state must be refused");
    assert!(
        matches!(error, StateError::Corrupt { .. }),
        "garbage file must be reported as corrupt, found {error:?}"
    );
    assert_eq!(std::fs::read(&control).unwrap(), garbage, "the refused file must be preserved byte-for-byte");
}

#[tokio::test]
async fn foreign_sqlite_database_is_refused_and_preserved() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let control = paths.control_database();
    std::fs::create_dir_all(control.parent().unwrap()).unwrap();
    {
        let conn = Connection::open(&control).unwrap();
        conn.execute_batch("CREATE TABLE foreign_data (x TEXT); INSERT INTO foreign_data VALUES ('keep-me');")
            .unwrap();
    }
    let before = std::fs::read(&control).unwrap();

    let error = StateStore::open(paths).await.err().expect("foreign state must be refused");
    assert!(
        matches!(error, StateError::NotAnHfDriveDatabase { .. }),
        "a foreign SQLite database must be refused, found {error:?}"
    );
    assert_eq!(std::fs::read(&control).unwrap(), before, "the foreign file must be preserved");
    // And the foreign data is still readable.
    let conn = Connection::open(&control).unwrap();
    let value: String = conn
        .query_row("SELECT x FROM foreign_data", [], |row| row.get(0))
        .unwrap();
    assert_eq!(value, "keep-me");
}

#[tokio::test]
async fn newer_schema_is_refused_and_preserved() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let key = account_key();
    {
        let store = StateStore::open(paths.clone()).await.unwrap();
        store.record_account(account_record(key)).await.unwrap();
        store.close().await.unwrap();
    }
    let control = paths.control_database();
    {
        let conn = Connection::open(&control).unwrap();
        conn.pragma_update(None, "user_version", 3).unwrap();
    }

    let error = StateStore::open(paths).await.err().expect("newer state must be refused");
    assert!(
        matches!(error, StateError::SchemaTooNew { found: 3, supported: 2 }),
        "newer schema must be refused, found {error:?}"
    );
    assert_eq!(user_version(&control), 3, "the newer database must be left untouched");
}

#[tokio::test]
async fn forward_migration_backs_up_before_upgrading() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let control = paths.control_database();
    std::fs::create_dir_all(control.parent().unwrap()).unwrap();
    {
        // A legacy v0 HF Drive control database: correct identity, old schema.
        let conn = Connection::open(&control).unwrap();
        conn.pragma_update(None, "application_id", CONTROL_APPLICATION_ID).unwrap();
        conn.pragma_update(None, "user_version", 0).unwrap();
        conn.execute_batch("CREATE TABLE legacy_rows (x TEXT); INSERT INTO legacy_rows VALUES ('still-here');")
            .unwrap();
    }

    let store = StateStore::open(paths.clone()).await.unwrap();
    assert_eq!(user_version(&control), 2, "migration must land on the supported version");

    // The online backup created before the forward migration exists and holds
    // the pre-migration contents.
    let backup = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("control.sqlite3.") && n.ends_with(".bak"))
        })
        .expect("a timestamped backup must exist before a forward migration");
    let backup_conn = Connection::open(&backup).unwrap();
    let value: String = backup_conn
        .query_row("SELECT x FROM legacy_rows", [], |row| row.get(0))
        .unwrap();
    assert_eq!(value, "still-here");
    drop(backup_conn);

    // The migrated database keeps legacy data and gained the new schema.
    let conn = Connection::open(&control).unwrap();
    let value: String = conn
        .query_row("SELECT x FROM legacy_rows", [], |row| row.get(0))
        .unwrap();
    assert_eq!(value, "still-here");
    let tables: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'operation_ledger'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tables, 1, "the v1 schema must be applied");
    drop(conn);
    store.close().await.unwrap();
}

#[tokio::test]
async fn corrupt_database_is_refused_and_preserved() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let key = account_key();
    {
        let store = StateStore::open(paths.clone()).await.unwrap();
        store.record_account(account_record(key)).await.unwrap();
        store.close().await.unwrap();
    }
    let control = paths.control_database();
    // Truncate the file below the schema pages: the header reads but the
    // database is damaged.
    let file = std::fs::OpenOptions::new().write(true).open(&control).unwrap();
    file.set_len(256).unwrap();
    drop(file);
    let damaged = std::fs::read(&control).unwrap();

    let error = StateStore::open(paths).await.err().expect("damaged state must be refused");
    assert!(
        matches!(error, StateError::Corrupt { .. } | StateError::Database(_)),
        "a damaged database must be refused, found {error:?}"
    );
    assert_eq!(
        std::fs::read(&control).unwrap(),
        damaged,
        "the damaged file must be preserved for recovery, never recreated"
    );
}
