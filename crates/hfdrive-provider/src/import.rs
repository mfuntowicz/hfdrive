//! One-shot raw bucket imports initiated by Explorer. No managed workspace,
//! catalog, HEAD, S3 payload path, or synchronization watcher is involved.

use crate::{operations::error, Provider};
use hfdrive_core::raw_keys::{self, RawKeyEmptyDirectory, RawKeyFile, RawKeySource};
use hfdrive_core::storage::{BucketName, RelativeKey, Sha256Digest, StableSnapshot};
use hfdrive_hf::{BoundObject, CasCommitCheckpoint, IngestionCheckpoint, NativeApi, NativeConfig, NativeError, NativeRawStore, UploadSource};
use hfdrive_protocol as wire;
use hfdrive_windows::filesystem::{capture_snapshot, query_file_state, replace_file, scan_metadata, MetadataEntry, ScanBudget, VisitFlow};
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use tokio_util::sync::CancellationToken;

const MAX_SOURCES: usize = 100;
const MAX_FILES: usize = 10_000;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_JOURNAL_BYTES: usize = MAX_REQUEST_BYTES * 16;
const RECEIPT_PAGE_SIZE: usize = 200;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum ImportFileState {
    Planned,
    Captured,
    Ingested,
    Committed,
    Bound,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ImportFile {
    source: String,
    root_qualifier: Option<String>,
    relative_path: String,
    key: String,
    staged_path: PathBuf,
    snapshot_id: hfdrive_core::ids::SnapshotId,
    upload_id: hfdrive_core::ids::UploadId,
    size: u64,
    sha256: Sha256Digest,
    state: ImportFileState,
    ingestion: Option<IngestionCheckpoint>,
    cas: Option<CasCommitCheckpoint>,
    bound: Option<BoundObject>,
}

impl ImportFile {
    fn snapshot(&self) -> StableSnapshot {
        StableSnapshot {
            snapshot_id: self.snapshot_id,
            upload_id: self.upload_id,
            path: self.staged_path.clone(),
            size: self.size,
            sha256: self.sha256,
        }
    }

    fn source_path(&self) -> PathBuf {
        if self.relative_path.is_empty() {
            PathBuf::from(&self.source)
        } else {
            Path::new(&self.source).join(self.relative_path.replace('/', "\\"))
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ImportJournal {
    format: u8,
    operation_id: uuid::Uuid,
    import_id: uuid::Uuid,
    target: wire::ImportTarget,
    sources: Vec<String>,
    files: Vec<ImportFile>,
    empty_directories: Vec<RawKeyEmptyDirectory>,
}

#[derive(Debug, thiserror::Error)]
enum ImportError {
    #[error("invalid import request: {0}")]
    Invalid(String),
    #[error("import source is not supported: {0}")]
    Source(String),
    #[error("import destination already contains a different object")]
    Occupant,
    #[error("native storage operation failed: {0}")]
    Native(#[from] NativeError),
    #[error("filesystem operation failed: {0}")]
    Fs(#[from] hfdrive_windows::filesystem::FsError),
    #[error("scheduler admission failed: {0}")]
    Schedule(#[from] crate::scheduler::ScheduleError),
    #[error("journal operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("journal serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

fn invalid(detail: impl Into<String>) -> ImportError {
    ImportError::Invalid(detail.into())
}

fn detailed_error(code: wire::ProtocolErrorCode, message: String) -> wire::ProtocolError {
    wire::ProtocolError { code, message, retry_after_ms: None }
}

fn map_error(error_value: ImportError) -> wire::ProtocolError {
    match error_value {
        ImportError::Invalid(detail) => detailed_error(wire::ProtocolErrorCode::InvalidRequest, detail),
        ImportError::Source(detail) => detailed_error(wire::ProtocolErrorCode::LocalRootInvalid, detail),
        ImportError::Occupant => error(wire::ProtocolErrorCode::Conflict, "The import destination contains a different or uncertain occupant; no object was rebound"),
        ImportError::Native(native) => crate::storage::native_failure(native),
        ImportError::Fs(fs) => detailed_error(wire::ProtocolErrorCode::LocalRootInvalid, fs.to_string()),
        ImportError::Schedule(schedule) => match schedule {
            crate::scheduler::ScheduleError::Busy => error(wire::ProtocolErrorCode::Busy, "The provider's upload capacity is occupied"),
            crate::scheduler::ScheduleError::Cancelled => error(wire::ProtocolErrorCode::Cancelled, "The import was cancelled; accepted work is retained"),
            crate::scheduler::ScheduleError::Paused | crate::scheduler::ScheduleError::Metered | crate::scheduler::ScheduleError::Offline => {
                error(wire::ProtocolErrorCode::Busy, "Import scheduling is paused or unavailable")
            }
            crate::scheduler::ScheduleError::DiskFull | crate::scheduler::ScheduleError::ReservationTooLarge => {
                error(wire::ProtocolErrorCode::DiskFull, "The import staging reservation cannot be satisfied")
            }
        },
        ImportError::Io(io) => detailed_error(wire::ProtocolErrorCode::Internal, io.to_string()),
        ImportError::Json(json) => detailed_error(wire::ProtocolErrorCode::Internal, json.to_string()),
    }
}

fn write_journal(directory: &Path, journal: &ImportJournal) -> Result<(), ImportError> {
    std::fs::create_dir_all(directory)?;
    let bytes = serde_json::to_vec(journal)?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(invalid("import journal exceeds its durable bound"));
    }
    let temporary = directory.join("journal.tmp");
    let mut file = std::fs::File::create(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    replace_file(&temporary, &directory.join("journal.json")).map_err(|error| std::io::Error::other(error.to_string()))?;
    Ok(())
}

fn load_journal(directory: &Path, request: &wire::ImportRequest) -> Result<ImportJournal, ImportError> {
    let file = std::fs::File::open(directory.join("journal.json"))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_JOURNAL_BYTES as u64 {
        return Err(invalid("import journal exceeds its durable bound"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_JOURNAL_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(invalid("import journal exceeds its durable bound"));
    }
    let journal: ImportJournal = serde_json::from_slice(&bytes)?;
    if journal.format != 1 || journal.operation_id != request.operation_id || journal.import_id != request.import_id
        || journal.target != request.target || journal.sources != request.sources
    {
        return Err(invalid("import journal identity does not match the request"));
    }
    Ok(journal)
}

fn validate_journal(journal: &mut ImportJournal, directory: &Path, request: &wire::ImportRequest) -> Result<(), ImportError> {
    let import_id = request.import_id.to_string();
    let sources = &journal.sources;
    for file in &mut journal.files {
        if !sources.contains(&file.source) {
            return Err(invalid("journal file does not belong to a selected source root"));
        }
        let root = file.root_qualifier.as_deref().ok_or_else(|| invalid("journal file lacks its root qualifier"))?;
        let suffix = if file.relative_path.is_empty() {
            root.to_owned()
        } else {
            format!("{root}/{}", file.relative_path)
        };
        let expected = raw_keys::import_key(&import_id, &suffix)
            .map_err(|_| invalid("journal contains an invalid source-to-key mapping"))?;
        if file.key != expected.as_str() {
            return Err(invalid("journal key does not match its source and root qualifier"));
        }
        file.staged_path = directory.join(format!("{}.snap", file.snapshot_id));
    }
    Ok(())
}

fn journal_directory(provider: &Provider, account_key: hfdrive_core::ids::AccountKey, import_id: uuid::Uuid) -> Result<PathBuf, ImportError> {
    let workspace = hfdrive_core::ids::WorkspaceId::from_uuid(import_id).map_err(|_| invalid("import id must be nonzero"))?;
    Ok(provider.paths.account(account_key).drive(workspace).snapshots())
}

/// A same-operation retry is an explicit request to reconcile an interrupted
/// import. A missing journal proves execution had not reached the first upload;
/// an existing journal must prove every resumable source/key/staging mapping.
pub(crate) fn validate_import_resume(provider: &Provider, request: &wire::ImportRequest) -> Result<(), wire::ProtocolError> {
    if request.sources.is_empty() || request.sources.len() > MAX_SOURCES {
        return Err(map_error(invalid("select between 1 and 100 source roots")));
    }
    for source in &request.sources {
        validate_source_path(Path::new(source)).map_err(map_error)?;
    }
    let profile = provider.current_account().map_err(|error| ImportError::Invalid(error.message)).map_err(map_error)?;
    let directory = journal_directory(provider, profile.account_key, request.import_id).map_err(map_error)?;
    if !directory.join("journal.json").exists() {
        return Ok(());
    }
    let mut journal = load_journal(&directory, request).map_err(map_error)?;
    validate_journal(&mut journal, &directory, request).map_err(map_error)
}

fn validate_source_path(path: &Path) -> Result<(), ImportError> {
    if !path.is_absolute() || path.as_os_str().encode_wide().count() >= 32_767 {
        return Err(ImportError::Source("source path must be absolute and shorter than 32767 UTF-16 units".to_owned()));
    }
    Ok(())
}

fn source_path_is_supported(path: &Path) -> Result<(), ImportError> {
    validate_source_path(path)?;
    let state = query_file_state(path)?;
    if state.identity.is_reparse_point() {
        return Err(ImportError::Source("reparse points are not imported".to_owned()));
    }
    if state.identity.is_encrypted() {
        return Err(ImportError::Source("EFS-encrypted content is not imported".to_owned()));
    }
    if state.identity.has_multiple_links() {
        return Err(ImportError::Source("multiply linked files are not imported".to_owned()));
    }
    Ok(())
}

fn plan_sources(request: &wire::ImportRequest, cancel: &CancellationToken) -> Result<raw_keys::RawKeyPlan, ImportError> {
    if request.sources.is_empty() || request.sources.len() > MAX_SOURCES {
        return Err(invalid("select between 1 and 100 source roots"));
    }
    let mut entries = Vec::new();
    for source in &request.sources {
        if cancel.is_cancelled() {
            return Err(crate::scheduler::ScheduleError::Cancelled.into());
        }
        let path = Path::new(source);
        source_path_is_supported(path)?;
        let metadata = query_file_state(path)?;
        let is_directory = metadata.identity.attributes & 0x10 != 0;
        entries.push(RawKeySource {
            source: source.clone(),
            is_dir: is_directory,
            relative_path: String::new(),
        });
        if !is_directory {
            continue;
        }
        let scan_cancel = AtomicBool::new(false);
        let mut callback_error: Option<ImportError> = None;
        let report = scan_metadata(path, &ScanBudget { max_entries: MAX_FILES + 1, max_depth: 512 }, &scan_cancel, &mut |entry: &MetadataEntry| {
            if cancel.is_cancelled() {
                callback_error = Some(crate::scheduler::ScheduleError::Cancelled.into());
                return VisitFlow::Stop;
            }
            if entry.identity.is_reparse_point() || entry.identity.is_encrypted() || entry.identity.has_multiple_links() {
                callback_error = Some(ImportError::Source("reparse, encrypted, or multiply linked content is not imported".to_owned()));
                return VisitFlow::Stop;
            }
            entries.push(RawKeySource {
                source: source.clone(),
                is_dir: entry.is_directory,
                relative_path: entry.relative_path.to_string_lossy().replace('\\', "/"),
            });
            VisitFlow::Continue
        })?;
        if let Some(error) = callback_error {
            return Err(error);
        }
        if !report.complete || report.overflow || !report.denied.is_empty() {
            return Err(ImportError::Source("the selected folder could not be enumerated completely".to_owned()));
        }
        // A source that disappears between the root query and enumeration is
        // rejected rather than being treated as an empty directory.
        if entries.is_empty() {
            return Err(ImportError::Source("the selected folder is unavailable".to_owned()));
        }
        // Keep the report local: it proves the source enumeration completed,
        // not that a deletion or empty directory should be inferred remotely.
    }
    if cancel.is_cancelled() {
        return Err(crate::scheduler::ScheduleError::Cancelled.into());
    }
    raw_keys::plan_raw_keys_with_limit(&request.import_id.to_string(), &entries, MAX_FILES)
        .map_err(|error| ImportError::Source(error.to_string()))
}

fn new_journal(request: &wire::ImportRequest, plan: raw_keys::RawKeyPlan, directory: PathBuf) -> ImportJournal {
    let files = plan.files.into_iter().map(|file: RawKeyFile| {
        let snapshot_id = hfdrive_core::ids::SnapshotId::new();
        let upload_id = hfdrive_core::ids::UploadId::new();
        ImportFile {
            source: file.source,
            root_qualifier: file.root_qualifier,
            relative_path: file.relative_path,
            key: file.key,
            staged_path: directory.join(format!("{snapshot_id}.snap")),
            snapshot_id,
            upload_id,
            size: 0,
            sha256: Sha256Digest::of(b""),
            state: ImportFileState::Planned,
            ingestion: None,
            cas: None,
            bound: None,
        }
    }).collect();
    ImportJournal {
        format: 1,
        operation_id: request.operation_id,
        import_id: request.import_id,
        target: request.target.clone(),
        sources: request.sources.clone(),
        files,
        empty_directories: plan.empty_directories,
    }
}

async fn capture_file(provider: &Provider, file: &mut ImportFile, import_id: uuid::Uuid, cancel: &CancellationToken) -> Result<(), ImportError> {
    let source = file.source_path();
    source_path_is_supported(&source)?;
    let state = query_file_state(&source)?;
    let _reservation = provider.scheduler.reserve_staging(crate::scheduler::WorkClass::LocalEdit, import_id, &source, state.size, cancel).await?;
    let staging = file.staged_path.clone();
    let snapshot_id = file.snapshot_id;
    let captured = tokio::task::spawn_blocking(move || capture_snapshot(&source, &staging, snapshot_id, None))
        .await
        .map_err(|error| std::io::Error::other(error.to_string()))??;
    file.staged_path = captured.staged_path;
    file.size = captured.size;
    file.sha256 = captured.sha256;
    file.state = ImportFileState::Captured;
    Ok(())
}

async fn bind_file(
    store: &NativeRawStore<crate::tokens::DurableTokens>,
    lease: &hfdrive_hf::NativeLease,
    file: &mut ImportFile,
    cancel: &CancellationToken,
) -> Result<BoundObject, ImportError> {
    let key = RelativeKey::new(file.key.clone()).map_err(|_| invalid("invalid raw key in journal"))?;
    if let Some(metadata) = store.file_metadata(lease, &key, cancel).await? {
        let expected = file.cas.as_ref().map(|checkpoint| &checkpoint.xet_file_id)
            .or_else(|| file.bound.as_ref().map(|bound| &bound.xet_file_id))
            .ok_or_else(|| invalid("missing binding evidence"))?;
        if metadata.size != file.size || metadata.xet_file_id.as_ref() != Some(expected) {
            return Err(ImportError::Occupant);
        }
        let bound = BoundObject { key, xet_file_id: expected.clone(), size: file.size, sha256: file.sha256 };
        file.bound = Some(bound.clone());
        file.state = ImportFileState::Bound;
        return Ok(bound);
    }
    let checkpoint = file.cas.clone().ok_or_else(|| invalid("missing CAS checkpoint"))?;
    let bound = store.resume_raw_committed(lease, &key, &checkpoint)?.bind(cancel).await?;
    file.bound = Some(bound.clone());
    file.state = ImportFileState::Bound;
    Ok(bound)
}

async fn execute_import(provider: &Provider, request: &wire::ImportRequest) -> Result<ImportJournal, ImportError> {
    if request.sources.is_empty() || request.sources.len() > MAX_SOURCES {
        return Err(invalid("select between 1 and 100 source roots"));
    }
    for source in &request.sources {
        validate_source_path(Path::new(source))?;
    }
    let profile = provider.current_account().map_err(|error| ImportError::Invalid(error.message))?;
    let control = provider.native_control(profile.account_key);
    let target = &request.target;
    let owner_id = hfdrive_core::storage::OwnerId::new(target.owner_id.clone()).map_err(|_| invalid("invalid owner id"))?;
    let owner_kind = match target.owner_kind {
        wire::OwnerKind::Personal => hfdrive_core::storage::OwnerKind::Personal,
        wire::OwnerKind::Organization => hfdrive_core::storage::OwnerKind::Organization,
    };
    let namespace = hfdrive_core::storage::Namespace::new(target.owner_namespace.clone()).map_err(|_| invalid("invalid owner namespace"))?;
    let locator = hfdrive_hf::OwnerLocator { owner_id, owner_kind, claimed_namespace: Some(namespace) };
    let cancel = &provider.operations.cancellation;
    let owner = control.verify_owner(&control.capture_lease()?, &locator, cancel).await?;
    let bucket_name = BucketName::new(target.bucket_name.clone()).map_err(|_| invalid("invalid bucket name"))?;
    let bucket_id = hfdrive_core::storage::BucketId::new(target.bucket_id.clone()).map_err(|_| invalid("invalid bucket id"))?;
    let summary = control.resolve_bucket(&control.capture_lease()?, &owner.owner_ref(), &bucket_name, Some(&bucket_id), cancel)
        .await?.ok_or_else(|| invalid("the selected bucket no longer exists or its identity changed"))?;
    let expected_private = match target.visibility {
        wire::Visibility::Private => true,
        wire::Visibility::Public => false,
    };
    if summary.private != expected_private {
        return Err(invalid("the selected bucket visibility changed; refresh the destination list"));
    }
    let workspace = hfdrive_core::ids::WorkspaceId::from_uuid(request.import_id).map_err(|_| invalid("import id must be nonzero"))?;
    let config = NativeConfig {
        endpoint: "https://huggingface.co".to_owned(),
        xet_cache_dir: provider.paths.account(profile.account_key).drive(workspace).xet_cache(),
        ..Default::default()
    };
    let api = NativeApi::new_with_budget(
        provider.tokens.clone(),
        profile.account_key,
        config.endpoint.clone(),
        provider.scheduler.wire_budget().clone(),
    ).map_err(|_| invalid("could not construct the native import client"))?;
    let store = NativeRawStore::new(api, profile.account_key, summary.binding.clone(), config)?;
    let lease = store.capture_lease()?;
    store.check_native_write(&lease, cancel).await?;

    let directory = provider.paths.account(profile.account_key).drive(workspace).snapshots();
    let mut journal = if directory.join("journal.json").exists() {
        load_journal(&directory, request)?
    } else {
        let plan_request = request.clone();
        let plan_cancel = cancel.clone();
        let plan = tokio::task::spawn_blocking(move || plan_sources(&plan_request, &plan_cancel))
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))??;
        let journal = new_journal(request, plan, directory.clone());
        write_journal(&directory, &journal)?;
        journal
    };
    // Revalidate the exact persisted source->key map before any upload. A
    // journal cannot escape its selected roots, import prefix, or staging dir.
    validate_journal(&mut journal, &directory, request)?;

    for index in 0..journal.files.len() {
        if journal.files[index].state == ImportFileState::Bound {
            let _ = bind_file(&store, &lease, &mut journal.files[index], cancel).await?;
            continue;
        }
        if journal.files[index].state == ImportFileState::Planned {
            capture_file(provider, &mut journal.files[index], request.import_id, cancel).await?;
            write_journal(&directory, &journal)?;
        }
        let _upload = provider.scheduler.acquire_upload(crate::scheduler::WorkClass::LocalEdit, request.import_id, cancel).await?;
        if journal.files[index].state == ImportFileState::Captured {
            let ingested = {
                let file = &mut journal.files[index];
                let staged = store.begin_raw_upload(&lease, RelativeKey::new(file.key.clone()).map_err(|_| invalid("invalid raw key in journal"))?, UploadSource::Snapshot(file.snapshot()))?;
                let (ingested, checkpoint) = staged.ingest(cancel).await?;
                file.ingestion = Some(checkpoint);
                file.state = ImportFileState::Ingested;
                ingested
            };
            write_journal(&directory, &journal)?;
            let (committed, checkpoint) = ingested.commit_cas(cancel).await?;
            journal.files[index].cas = Some(checkpoint);
            journal.files[index].state = ImportFileState::Committed;
            write_journal(&directory, &journal)?;
            let _ = committed;
        } else if journal.files[index].state == ImportFileState::Ingested {
            let checkpoint = {
                let file = &mut journal.files[index];
                let staged = store.begin_raw_upload(&lease, RelativeKey::new(file.key.clone()).map_err(|_| invalid("invalid raw key in journal"))?, UploadSource::Snapshot(file.snapshot()))?;
                let (ingested, _) = staged.ingest(cancel).await?;
                let (_, checkpoint) = ingested.commit_cas(cancel).await?;
                checkpoint
            };
            journal.files[index].cas = Some(checkpoint);
            journal.files[index].state = ImportFileState::Committed;
            write_journal(&directory, &journal)?;
        }
        let _ = bind_file(&store, &lease, &mut journal.files[index], cancel).await?;
        write_journal(&directory, &journal)?;
    }
    Ok(journal)
}

fn result_from_journal(journal: &ImportJournal) -> Result<wire::ImportResult, ImportError> {
    let mut files = Vec::with_capacity(journal.files.len());
    let mut total_bytes = 0u64;
    for file in &journal.files {
        let bound = file.bound.as_ref().ok_or_else(|| invalid("an imported file lacks a bound receipt"))?;
        total_bytes = total_bytes.checked_add(bound.size)
            .ok_or_else(|| invalid("import byte total exceeds u64"))?;
        files.push(wire::ImportFileResult {
            key: bound.key.to_string(),
            size: bound.size,
            sha256: bound.sha256.to_string(),
            xet_file_id: bound.xet_file_id.to_string(),
        });
    }
    Ok(wire::ImportResult {
        import_id: journal.import_id,
        prefix: format!("hfdrive-imports/{}", journal.import_id),
        files,
        file_count: journal.files.len() as u32,
        total_bytes,
        empty_directory_count: u32::try_from(journal.empty_directories.len())
            .map_err(|_| invalid("too many empty directories in import journal"))?,
        next_cursor: None,
    })
}

/// Return one bounded receipt page. Continuations slice a completed result;
/// they never start another mutation or upload.
pub(crate) fn page_import_result(result: wire::ImportResult, cursor: Option<&str>) -> Result<wire::ImportResult, wire::ProtocolError> {
    page_import_result_ref(&result, cursor)
}

pub(crate) fn page_import_result_ref(result: &wire::ImportResult, cursor: Option<&str>) -> Result<wire::ImportResult, wire::ProtocolError> {
    let start = match cursor {
        None => 0,
        Some(value) => {
            let prefix = format!("import-files-v1:{}:", result.import_id);
            let raw = value.strip_prefix(&prefix).ok_or_else(|| error(wire::ProtocolErrorCode::InvalidRequest, "Invalid import receipt cursor"))?;
            raw.parse::<usize>().map_err(|_| error(wire::ProtocolErrorCode::InvalidRequest, "Invalid import receipt cursor"))?
        }
    };
    if start > result.files.len() {
        return Err(error(wire::ProtocolErrorCode::InvalidRequest, "Import receipt cursor exceeds the result"));
    }
    let total = result.files.len();
    let end = start.saturating_add(RECEIPT_PAGE_SIZE).min(total);
    Ok(wire::ImportResult {
        import_id: result.import_id,
        prefix: result.prefix.clone(),
        files: result.files[start..end].to_vec(),
        next_cursor: (end < total).then(|| format!("import-files-v1:{}:{end}", result.import_id)),
        file_count: result.file_count,
        total_bytes: result.total_bytes,
        empty_directory_count: result.empty_directory_count,
    })
}

impl Provider {
    pub(crate) async fn import(&self, request: wire::ImportRequest) -> Result<wire::ImportResult, wire::ProtocolError> {
        let result = execute_import(self, &request).await.map_err(map_error)?;
        result_from_journal(&result).map_err(map_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal_fixture(import_id: uuid::Uuid) -> (wire::ImportRequest, ImportJournal) {
        let request = wire::ImportRequest {
            operation_id: uuid::Uuid::new_v4(),
            import_id,
            target: wire::ImportTarget {
                owner_kind: wire::OwnerKind::Personal,
                owner_id: "owner".to_owned(),
                owner_namespace: "alice".to_owned(),
                bucket_id: "bucket".to_owned(),
                bucket_name: "data".to_owned(),
                visibility: wire::Visibility::Private,
            },
            sources: vec![r"C:\root".to_owned()],
            files_cursor: None,
        };
        let key = raw_keys::import_key(&import_id.to_string(), "root/docs/a.txt").unwrap().as_str().to_owned();
        let file = ImportFile {
            source: r"C:\root".to_owned(),
            root_qualifier: Some("root".to_owned()),
            relative_path: "docs/a.txt".to_owned(),
            key,
            staged_path: PathBuf::from(r"C:\untrusted\snapshot.snap"),
            snapshot_id: hfdrive_core::ids::SnapshotId::new(),
            upload_id: hfdrive_core::ids::UploadId::new(),
            size: 0,
            sha256: Sha256Digest::of(b""),
            state: ImportFileState::Planned,
            ingestion: None,
            cas: None,
            bound: None,
        };
        let journal = ImportJournal {
            format: 1,
            operation_id: request.operation_id,
            import_id,
            target: request.target.clone(),
            sources: request.sources.clone(),
            files: vec![file],
            empty_directories: Vec::new(),
        };
        (request, journal)
    }

    #[test]
    fn cancelled_planning_stops_before_source_io() {
        let (request, _) = journal_fixture(uuid::Uuid::new_v4());
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(matches!(plan_sources(&request, &cancel), Err(ImportError::Schedule(crate::scheduler::ScheduleError::Cancelled))));
    }

    #[test]
    fn journal_validation_rejects_mapping_and_staging_tampering() {
        let import_id = uuid::Uuid::new_v4();
        let (request, mut journal) = journal_fixture(import_id);
        let directory = Path::new(r"C:\staging");
        validate_journal(&mut journal, directory, &request).unwrap();
        assert_eq!(journal.files[0].staged_path, directory.join(format!("{}.snap", journal.files[0].snapshot_id)));

        let key = journal.files[0].key.clone();
        journal.files[0].key = raw_keys::import_key(&import_id.to_string(), "root/other.txt").unwrap().as_str().to_owned();
        assert!(validate_journal(&mut journal, directory, &request).is_err());
        journal.files[0].key = key;
        journal.files[0].relative_path = "../escape.txt".to_owned();
        assert!(validate_journal(&mut journal, directory, &request).is_err());
        journal.files[0].relative_path = "docs/a.txt".to_owned();
        journal.files[0].source = r"C:\other".to_owned();
        assert!(validate_journal(&mut journal, directory, &request).is_err());
    }

    #[test]
    fn receipt_pages_are_bounded_and_self_describing() {
        let import_id = uuid::Uuid::new_v4();
        let result = wire::ImportResult {
            import_id,
            prefix: format!("hfdrive-imports/{import_id}"),
            files: (0..205).map(|index| wire::ImportFileResult {
                key: format!("hfdrive-imports/{import_id}/file-{index}.txt"),
                size: 7,
                sha256: "ab".repeat(32),
                xet_file_id: "cd".repeat(32),
            }).collect(),
            file_count: 205,
            total_bytes: 1435,
            empty_directory_count: 2,
            next_cursor: None,
        };
        let first = page_import_result(result.clone(), None).unwrap();
        assert_eq!(first.files.len(), 200);
        assert_eq!(first.file_count, 205);
        assert_eq!(first.total_bytes, 1435);
        let cursor = first.next_cursor.clone().unwrap();
        let second = page_import_result(result, Some(&cursor)).unwrap();
        assert_eq!(second.files.len(), 5);
        assert_eq!(second.next_cursor, None);
        assert_eq!(second.import_id, import_id);
        assert_eq!(second.empty_directory_count, 2);
    }
}
