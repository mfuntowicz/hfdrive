use hfdrive_protocol::{ImportRequest, ImportTarget};
use hfdrive_windows::ownership::default_state_root;
use std::io::Read;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
const MAX_SOURCES: usize = 100;
const MAX_PATH_CHARS: usize = 32_767;

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ShellImportRequest {
    format: u8,
    operation_id: Uuid,
    import_id: Uuid,
    target: ImportTarget,
    sources: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ImportRequestError {
    #[error("request file is missing or exceeds 1 MiB")]
    FileSize,
    #[error("request format is unsupported")]
    Format,
    #[error("operation and import identifiers must be distinct nonzero UUIDs")]
    Identifiers,
    #[error("an import request selects between 1 and 100 source roots")]
    SourceCount,
    #[error("source path must be absolute Windows syntax, shorter than 32767 UTF-16 units, and contain no control characters")]
    SourcePath,
    #[error("import target identity is incomplete")]
    Target,
    #[error("request file could not be read: {0}")]
    Io(#[from] std::io::Error),
    #[error("request state root could not be resolved: {0}")]
    State(#[from] hfdrive_windows::OwnershipError),
    #[error("request JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
}

fn request_path(request: Uuid) -> Result<PathBuf, ImportRequestError> {
    let root = default_state_root().map_err(ImportRequestError::State)?;
    Ok(root.join("shell").join("requests").join(format!("{request}.json")))
}

fn nonempty(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control)
}

pub fn load_request(request: Uuid) -> Result<ImportRequest, ImportRequestError> {
    load_request_path(&request_path(request)?)
}

fn validate_source(source: &str) -> Result<(), ImportRequestError> {
    if source.is_empty() || source.chars().any(char::is_control)
        || source.encode_utf16().count() >= MAX_PATH_CHARS
    {
        return Err(ImportRequestError::SourcePath);
    }
    let mut path = source;
    if let Some(extended) = path.strip_prefix(r"\\?\") {
        if let Some(unc) = extended.strip_prefix(r"UNC\") {
            let mut components = unc.split('\\');
            if components.next().unwrap_or_default().is_empty()
                || components.next().unwrap_or_default().is_empty()
            {
                return Err(ImportRequestError::SourcePath);
            }
            return Ok(());
        }
        path = extended;
    }
    let bytes = path.as_bytes();
    let drive_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\';
    if !drive_absolute && !bytes.starts_with(br"\\") {
        return Err(ImportRequestError::SourcePath);
    }
    Ok(())
}

fn load_request_path(path: &Path) -> Result<ImportRequest, ImportRequestError> {
    let file = std::fs::File::open(path).map_err(|_| ImportRequestError::FileSize)?;
    let metadata = file.metadata().map_err(|_| ImportRequestError::FileSize)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_REQUEST_BYTES {
        return Err(ImportRequestError::FileSize);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_REQUEST_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(ImportRequestError::FileSize);
    }
    let shell: ShellImportRequest = serde_json::from_slice(&bytes)?;
    if shell.format != 1 {
        return Err(ImportRequestError::Format);
    }
    if shell.operation_id.is_nil() || shell.import_id.is_nil() || shell.operation_id == shell.import_id {
        return Err(ImportRequestError::Identifiers);
    }
    if shell.sources.is_empty() || shell.sources.len() > MAX_SOURCES {
        return Err(ImportRequestError::SourceCount);
    }
    for source in &shell.sources {
        validate_source(source)?;
    }
    let target = &shell.target;
    if !nonempty(&target.owner_id) || !nonempty(&target.owner_namespace)
        || !nonempty(&target.bucket_id) || !nonempty(&target.bucket_name)
    {
        return Err(ImportRequestError::Target);
    }
    Ok(ImportRequest {
        operation_id: shell.operation_id,
        import_id: shell.import_id,
        target: shell.target,
        sources: shell.sources,
        files_cursor: None,
    })
}

pub fn remove_completed_request(request: Uuid) -> Result<(), ImportRequestError> {
    let path = request_path(request)?;
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ImportRequestError::Io(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPERATION: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
    const IMPORT: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn document(operation: &str, import: &str, sources: &[&str]) -> String {
        let encoded = sources.iter().map(|source| format!("\"{}\"", source.replace('\\', "\\\\"))).collect::<Vec<_>>().join(",");
        format!(
            "{{\"format\":1,\"operation_id\":\"{operation}\",\"import_id\":\"{import}\",\"target\":{{\"owner_kind\":\"personal\",\"owner_id\":\"owner\",\"owner_namespace\":\"alice\",\"bucket_id\":\"bucket\",\"bucket_name\":\"data\",\"visibility\":\"private\"}},\"sources\":[{encoded}]}}"
        )
    }

    #[test]
    fn valid_request_maps_to_typed_import() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("request.json");
        std::fs::write(&path, document(OPERATION, IMPORT, &["C:\\\\fixture\\\\hello.txt"])).unwrap();
        let request = load_request_path(&path).unwrap();
        assert_eq!(request.operation_id.to_string(), OPERATION);
        assert_eq!(request.import_id.to_string(), IMPORT);
        assert_eq!(request.sources.len(), 1);
        assert_eq!(request.target.bucket_name, "data");
    }

    #[test]
    fn invalid_ids_sources_and_target_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("request.json");
        std::fs::write(&path, document(IMPORT, IMPORT, &["C:\\\\fixture\\\\hello.txt"])).unwrap();
        assert!(matches!(load_request_path(&path), Err(ImportRequestError::Identifiers)));
        std::fs::write(&path, document(OPERATION, IMPORT, &["relative.txt"])).unwrap();
        assert!(matches!(load_request_path(&path), Err(ImportRequestError::SourcePath)));
        std::fs::write(&path, document(OPERATION, IMPORT, &[])).unwrap();
        assert!(matches!(load_request_path(&path), Err(ImportRequestError::SourceCount)));
        std::fs::write(&path, document(OPERATION, OPERATION, &["C:\\\\fixture\\\\hello.txt"])).unwrap();
        assert!(matches!(load_request_path(&path), Err(ImportRequestError::Identifiers)));
    }

    #[test]
    fn source_paths_use_the_shell_windows_grammar() {
        assert!(validate_source(r"C:\fixture\hello.txt").is_ok());
        assert!(validate_source(r"\\?\C:\fixture\hello.txt").is_ok());
        assert!(validate_source(r"\\?\UNC\server\share\hello.txt").is_ok());
        assert!(validate_source(r"C:/fixture/hello.txt").is_err());
        assert!(validate_source(r"\\?\UNC\server").is_err());
        assert!(validate_source(r"\relative-to-drive-root").is_err());
        assert!(validate_source(&format!(r"C:\{}", "x".repeat(MAX_PATH_CHARS))).is_err());
    }

    #[test]
    fn wrong_format_and_missing_file_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("request.json");
        std::fs::write(&path, document(OPERATION, IMPORT, &["C:\\\\fixture\\\\hello.txt"]).replace("\"format\":1", "\"format\":2")).unwrap();
        assert!(matches!(load_request_path(&path), Err(ImportRequestError::Format)));
        // A wrong format is rejected before any provider call.
        let missing = directory.path().join("missing.json");
        assert!(matches!(load_request_path(&missing), Err(ImportRequestError::FileSize)));
    }
}
