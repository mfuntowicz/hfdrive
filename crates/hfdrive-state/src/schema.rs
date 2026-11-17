//! Schema identity and forward-only migrations.
//!
//! A database is opened in three distinct situations: fresh creation (we won
//! the exclusive create), a known HF Drive database (matching application id,
//! schema at or below the supported version), and everything else (foreign or
//! newer files), which is refused without touching the file. Corruption and
//! unreadability are reported and never "repaired" by recreation; the file and
//! its WAL are preserved exactly as found.

use crate::error::StateError;
use rusqlite::{Connection, OpenFlags, backup::Backup, wal::CheckpointMode};
use std::{
    fs::{self, OpenOptions},
    path::Path,
    time::Duration,
};

pub const CONTROL_SCHEMA_VERSION: u32 = 2;
pub const ACCOUNT_SCHEMA_VERSION: u32 = 6;

const CONTROL_APPLICATION_ID: i64 = 0x4846_4443; // "HFDC"
const ACCOUNT_APPLICATION_ID: i64 = 0x4846_4441; // "HFDA"

const CONTROL_MIGRATIONS: &[(u32, &str)] = &[
    (1, include_str!("../migrations/control/0001.sql")),
    (2, include_str!("../migrations/control/0002.sql")),
];
const ACCOUNT_MIGRATIONS: &[(u32, &str)] = &[
    (1, include_str!("../migrations/0001.sql")),
    (2, include_str!("../migrations/0002.sql")),
    (3, include_str!("../migrations/0003.sql")),
    (4, include_str!("../migrations/0004.sql")),
    (5, include_str!("../migrations/0005.sql")),
    (6, include_str!("../migrations/0006.sql")),
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DatabaseKind {
    Control,
    Account,
}

impl DatabaseKind {
    fn application_id(self) -> i64 {
        match self {
            Self::Control => CONTROL_APPLICATION_ID,
            Self::Account => ACCOUNT_APPLICATION_ID,
        }
    }
    fn supported_version(self) -> u32 {
        match self {
            Self::Control => CONTROL_SCHEMA_VERSION,
            Self::Account => ACCOUNT_SCHEMA_VERSION,
        }
    }
    fn migrations(self) -> &'static [(u32, &'static str)] {
        match self {
            Self::Control => CONTROL_MIGRATIONS,
            Self::Account => ACCOUNT_MIGRATIONS,
        }
    }
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn checked_i64(value: u64) -> Result<i64, StateError> {
    i64::try_from(value).map_err(|_| StateError::IntegerOutOfRange { value })
}

/// Opens or creates a database at `path` and brings it to the supported schema
/// version. Fresh creation is decided by an exclusive `create_new` probe, so an
/// unknown preexisting file is never silently adopted as fresh and a failed
/// open never replaces it.
pub(crate) fn open_database(path: &Path, kind: DatabaseKind) -> Result<Connection, StateError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let fresh = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(_created) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(StateError::Io(error)),
    };
    // The file is now known to exist; open it without CREATE so a missing file
    // can never be recreated behind our back.
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(classify_open)?;
    if fresh {
        initialize(&conn, kind)?;
    } else {
        verify_identity(&conn, path, kind)?;
        quick_check(&conn)?;
        migrate(&conn, path, kind)?;
    }
    Ok(conn)
}

/// Full corruption check for preexisting databases. A damaged file is refused
/// and preserved; the state layer never recreates it.
fn quick_check(conn: &Connection) -> Result<(), StateError> {
    let report: String = match conn.query_row("PRAGMA quick_check(1)", [], |row| row.get(0)) {
        Ok(value) => value,
        Err(error) => return Err(map_corruption(error)),
    };
    if report == "ok" {
        Ok(())
    } else {
        Err(StateError::Corrupt { detail: report })
    }
}

fn classify_open(error: rusqlite::Error) -> StateError {
    if let rusqlite::Error::SqliteFailure(_, Some(message)) = &error {
        if message.contains("not a database") || message.contains("file is encrypted") {
            return StateError::Corrupt { detail: message.clone() };
        }
    }
    StateError::Database(error)
}

fn initialize(conn: &Connection, kind: DatabaseKind) -> Result<(), StateError> {
    apply_pragmas(conn)?;
    // Identity and schema land in one transaction: a crash can never leave a
    // database that claims our identity without our schema.
    let tx = conn.unchecked_transaction()?;
    tx.pragma_update(None, "application_id", kind.application_id())?;
    for (version, sql) in kind.migrations() {
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", *version)?;
    }
    tx.commit()?;
    Ok(())
}

fn verify_identity(conn: &Connection, path: &Path, kind: DatabaseKind) -> Result<(), StateError> {
    let application_id: i64 = match conn.pragma_query_value(None, "application_id", |row| row.get(0)) {
        Ok(value) => value,
        Err(error) => return Err(map_corruption(error)),
    };
    if application_id != kind.application_id() {
        return Err(StateError::NotAnHfDriveDatabase { path: path.to_owned() });
    }
    let version: u32 = match conn.pragma_query_value(None, "user_version", |row| row.get(0)) {
        Ok(value) => value,
        Err(error) => return Err(map_corruption(error)),
    };
    if version > kind.supported_version() {
        return Err(StateError::SchemaTooNew { found: version, supported: kind.supported_version() });
    }
    // Version 0 means "identified but not yet migrated"; any other version must
    // be one this build knows how to continue from.
    if version != 0 && !kind.migrations().iter().any(|(v, _)| *v == version) {
        return Err(StateError::SchemaUnsupported { found: version, supported: kind.supported_version() });
    }
    Ok(())
}

fn apply_pragmas(conn: &Connection) -> Result<(), StateError> {
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    // WAL is persistent and set once per database; synchronous=FULL makes every
    // committed transaction durable.
    conn.execute_batch("PRAGMA journal_mode = WAL;")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    Ok(())
}

/// Runs every pending forward migration. Before any forward migration the
/// current database is copied to a timestamped backup using SQLite's online
/// backup API, so a WAL-consistent recovery copy always exists.
fn migrate(conn: &Connection, path: &Path, kind: DatabaseKind) -> Result<(), StateError> {
    apply_pragmas(conn)?;
    let current: u32 = match conn.pragma_query_value(None, "user_version", |row| row.get(0)) {
        Ok(value) => value,
        Err(error) => return Err(map_corruption(error)),
    };
    if current == kind.supported_version() {
        return Ok(());
    }
    let pending: Vec<&(u32, &str)> = kind
        .migrations()
        .iter()
        .filter(|(version, _)| *version > current)
        .collect();
    if pending.is_empty() {
        return Err(StateError::SchemaUnsupported { found: current, supported: kind.supported_version() });
    }
    backup_before_migration(path, kind)?;
    for (version, sql) in pending {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", *version)?;
        tx.commit()?;
    }
    Ok(())
}

fn backup_before_migration(path: &Path, kind: DatabaseKind) -> Result<(), StateError> {
    let stamp = now_ms();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "database".to_owned());
    let backup_path = path.with_file_name(format!("{name}.{stamp}.v{}.bak", kind.supported_version()));
    let mut target = Connection::open(&backup_path)?;
    {
        let source = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(classify_open)?;
        let backup = Backup::new(&source, &mut target)?;
        backup.run_to_completion(100, Duration::from_millis(1), None)?;
    }
    target.close().map_err(|(_, error)| StateError::Database(error))?;
    Ok(())
}

/// Checkpoints the WAL into the main database file so a clean shutdown leaves a
/// fully durable single-file state.
pub(crate) fn checkpoint(conn: &Connection) -> Result<(), StateError> {
    conn.wal_checkpoint_v2(None::<&str>, CheckpointMode::TRUNCATE)?;
    Ok(())
}

/// SQLite reports a corrupt or truncated file at open/read time. Map those
/// reports so callers stop mutating state while the file stays preserved.
pub(crate) fn map_corruption(error: rusqlite::Error) -> StateError {
    if let rusqlite::Error::SqliteFailure(_, Some(message)) = &error {
        if message.contains("not a database") || message.contains("malformed") || message.contains("encrypted") {
            return StateError::Corrupt { detail: message.clone() };
        }
    }
    StateError::Database(error)
}
