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
    assert_eq!(user_version(&account_db), 5);
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

/// A real v2 account database (the schema this build must upgrade) migrates to
/// the current version with a pre-migration backup: work evidence, snapshot operation
/// bindings and the paging indexes appear, and the v2 rows keep working.
#[tokio::test]
async fn v2_account_database_migrates_to_current_with_backup() {
    use hfdrive_core::ids::{ConnectionId, SnapshotId, WorkspaceId};

    let tmp = tempfile::tempdir().unwrap();
    let paths = StatePaths::new(tmp.path().to_path_buf());
    let key = account_key();

    // The control database is created fresh; the account database is built by
    // hand at exactly schema version 2 with real v2 rows.
    let store = StateStore::open(paths.clone()).await.unwrap();
    store.record_account(account_record(key)).await.unwrap();
    let account_db = paths.account(key).database();
    std::fs::create_dir_all(account_db.parent().unwrap()).unwrap();
    let connection_id = ConnectionId::new();
    let snapshot_id = SnapshotId::new();
    {
        let conn = Connection::open(&account_db).unwrap();
        conn.pragma_update(None, "application_id", ACCOUNT_APPLICATION_ID).unwrap();
        conn.execute_batch(include_str!("../migrations/0001.sql")).unwrap();
        conn.execute_batch(include_str!("../migrations/0002.sql")).unwrap();
        conn.pragma_update(None, "user_version", 2).unwrap();
        conn.execute(
            "INSERT INTO connections
               (connection_id, account_key, workspace_id, owner_kind, owner_id, owner_namespace,
                bucket_id, bucket_name, prefix, root_path, schema_version, mode, config_json,
                created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, 'personal', 'owner-1', 'test-user', 'bucket-1', 'bucket-test-1',
                     'hfdrive/ws', 'C:\\root', 1, 'writable', '{}', 1000, 1000)",
            rusqlite::params![
                connection_id.as_bytes().as_slice(),
                key.as_bytes().as_slice(),
                WorkspaceId::new().as_bytes().as_slice(),
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO snapshots (connection_id, snapshot_id, path, size, sha256, status, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, 'C:\\staging\\snap', NULL, NULL, 'capturing', 1000, 1000)",
            rusqlite::params![connection_id.as_bytes().as_slice(), snapshot_id.as_bytes().as_slice()],
        )
        .unwrap();
        assert!(
            conn.prepare("SELECT operation_id FROM snapshots").is_err(),
            "a real v2 database has no snapshots.operation_id column yet"
        );
    }

    // Touching the account database runs the forward migration.
    let account = store.open_account(key).await.unwrap();
    let snapshots = account.list_snapshots(connection_id).await.unwrap();
    store.close().await.unwrap();

    assert_eq!(user_version(&account_db), 5, "the account database must land on the current schema");
    let conn = Connection::open(&account_db).unwrap();
    for table in ["work_errors"] {
        let found: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(found, 1, "{table} must exist after the migration");
    }
    for index in ["items_by_version", "outbox_work_page", "local_actions_work_page", "transfers_work_page"] {
        let found: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
                [index],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(found, 1, "{index} must exist after the migration");
    }
    drop(conn);

    // The v2 snapshot row survives with the new column unbound.
    assert_eq!(snapshots.len(), 1, "the v2 row must survive the migration");
    assert_eq!(snapshots[0].snapshot_id, snapshot_id);
    assert_eq!(snapshots[0].operation_id, None);

    // The pre-migration backup exists and predates the new schema.
    let backup = std::fs::read_dir(account_db.parent().unwrap())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("state.sqlite3.") && n.ends_with(".bak"))
        })
        .expect("a timestamped backup must exist before the forward migration");
    let backup_conn = Connection::open(&backup).unwrap();
    assert!(
        backup_conn
            .prepare("SELECT operation_id FROM snapshots")
            .is_err(),
        "the backup must be the pre-migration v2 database"
    );
    let rows: i64 = backup_conn
        .query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 1, "the backup must hold the pre-migration data");
}
