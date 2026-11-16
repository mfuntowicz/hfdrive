use hfdrive_protocol::{ImportTarget, Visibility};
use uuid::Uuid;

pub const MAX_JSON_BYTES: u64 = 1024 * 1024;
pub const MAX_SOURCES: usize = 100;
pub const MAX_PATH_CHARS: usize = 32_767;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportTargetDocument {
    pub format: u8,
    pub targets: Vec<ImportTarget>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ShellRequest {
    pub format: u8,
    pub operation_id: Uuid,
    pub import_id: Uuid,
    pub target: ImportTarget,
    pub sources: Vec<String>,
}

fn nonempty(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control)
}

pub fn validate_target(target: &ImportTarget) -> Result<(), String> {
    if !nonempty(&target.owner_id) || !nonempty(&target.owner_namespace)
        || !nonempty(&target.bucket_id) || !nonempty(&target.bucket_name)
    {
        return Err("target identity is incomplete".to_owned());
    }
    Ok(())
}

pub fn parse_targets(bytes: &[u8]) -> Result<Vec<ImportTarget>, String> {
    if bytes.len() as u64 > MAX_JSON_BYTES {
        return Err("target cache exceeds 1 MiB".to_owned());
    }
    let document: ImportTargetDocument = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if document.format != 1 {
        return Err("unsupported target-cache format".to_owned());
    }
    if document.targets.len() > 1000 {
        return Err("target cache contains too many targets".to_owned());
    }
    for target in &document.targets {
        validate_target(target)?;
    }
    Ok(document.targets)
}

pub fn child_title(target: &ImportTarget) -> String {
    let mut title = format!("{} — {}", target.bucket_name, target.owner_namespace);
    if matches!(target.visibility, Visibility::Public) {
        title.push_str(" (public)");
    }
    title
}

pub fn validate_source(source: &str) -> Result<(), String> {
    if source.is_empty() || source.chars().any(char::is_control) {
        return Err("source path is empty or contains a control character".to_owned());
    }
    if source.encode_utf16().count() >= MAX_PATH_CHARS {
        return Err("source path exceeds the Windows path bound".to_owned());
    }
    let mut path = source;
    if let Some(extended) = path.strip_prefix(r"\\?\") {
        if let Some(unc) = extended.strip_prefix(r"UNC\") {
            let mut components = unc.split('\\');
            let server = components.next().unwrap_or_default();
            let share = components.next().unwrap_or_default();
            if server.is_empty() || share.is_empty() {
                return Err("extended UNC source requires a server and share".to_owned());
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
    let unc = bytes.starts_with(br"\\");
    if !drive_absolute && !unc {
        return Err("source path must be drive-absolute or UNC".to_owned());
    }
    Ok(())
}

pub fn build_request_json(
    operation_id: Uuid,
    import_id: Uuid,
    target: &ImportTarget,
    sources: &[String],
) -> Result<String, String> {
    if operation_id.is_nil() || import_id.is_nil() || operation_id == import_id {
        return Err("operation and import identifiers must be distinct nonzero UUIDs".to_owned());
    }
    validate_target(target)?;
    if sources.is_empty() || sources.len() > MAX_SOURCES {
        return Err("an import request selects between 1 and 100 source roots".to_owned());
    }
    for source in sources {
        validate_source(source)?;
    }
    let json = serde_json::to_string(&ShellRequest {
        format: 1,
        operation_id,
        import_id,
        target: target.clone(),
        sources: sources.to_vec(),
    }).map_err(|error| error.to_string())?;
    if json.len() as u64 > MAX_JSON_BYTES {
        return Err("request payload exceeds 1 MiB".to_owned());
    }
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(visibility: Visibility) -> ImportTarget {
        ImportTarget {
            owner_kind: hfdrive_protocol::OwnerKind::Personal,
            owner_id: "owner".to_owned(),
            owner_namespace: "alice".to_owned(),
            bucket_id: "bucket".to_owned(),
            bucket_name: "data".to_owned(),
            visibility,
        }
    }

    #[test]
    fn target_document_is_strict_and_public_labels_are_explicit() {
        let document = ImportTargetDocument { format: 1, targets: vec![target(Visibility::Public)] };
        let bytes = serde_json::to_vec(&document).unwrap();
        let targets = parse_targets(&bytes).unwrap();
        assert_eq!(child_title(&targets[0]), "data — alice (public)");
        assert_eq!(parse_targets(b"{\"format\":2,\"targets\":[]}").unwrap_err(), "unsupported target-cache format");
    }

    #[test]
    fn request_validation_preserves_exact_target_and_paths() {
        let operation = Uuid::new_v4();
        let import = Uuid::new_v4();
        let target = target(Visibility::Private);
        let sources = vec!["C:\\\\fixture\\\\hello.txt".to_owned()];
        let json = build_request_json(operation, import, &target, &sources).unwrap();
        assert!(json.contains("\"format\":1"));
        assert!(json.contains("hello.txt"));
        assert!(build_request_json(operation, operation, &target, &sources).is_err());
        assert!(build_request_json(operation, import, &target, &[]).is_err());
        assert!(build_request_json(operation, import, &target, &["relative.txt".to_owned()]).is_err());
    }

    #[test]
    fn source_validation_requires_the_windows_absolute_path_grammar() {
        assert!(validate_source(r"C:\fixture\hello.txt").is_ok());
        assert!(validate_source(r"\\?\C:\fixture\hello.txt").is_ok());
        assert!(validate_source(r"\\?\UNC\server\share\hello.txt").is_ok());
        assert!(validate_source(r"C:/fixture/hello.txt").is_err());
        assert!(validate_source(r"\\?\UNC\server").is_err());
        assert!(validate_source(r"\\?\UNC\server\").is_err());
        assert!(validate_source(r"\relative-to-drive-root").is_err());
        assert!(validate_source(&format!(r"C:\{}", "x".repeat(MAX_PATH_CHARS))).is_err());
    }
}
