//! Redacted diagnostics export. Only derived state is archived: no credential
//! bytes, request bodies, database files, signed URLs, HTTP traces or file data.

use hfdrive_core::storage::Sha256Digest;
use hfdrive_protocol as wire;

use crate::{Provider, operations::error, storage::invalid};

impl Provider {
    pub(crate) async fn export_diagnostics(
        &self,
        request: wire::ExportDiagnosticsRequest,
    ) -> Result<wire::ExportDiagnosticsResult, wire::ProtocolError> {
        let destination = std::path::PathBuf::from(request.destination_path);
        if !destination.is_absolute() {
            return Err(invalid("Diagnostics destination must be an absolute path"));
        }
        let roots = self.state.reconcile_connections().await.map_err(crate::operations::state_error)?;
        let parent = destination.parent().ok_or_else(|| invalid("Diagnostics destination has no parent directory"))?;
        std::fs::create_dir_all(parent).map_err(|_| crate::operations::internal())?;
        let parent = std::fs::canonicalize(parent).map_err(|_| crate::operations::internal())?;
        let destination = parent.join(destination.file_name().ok_or_else(|| invalid("Diagnostics destination has no file name"))?);
        for record in roots {
            if let Ok(root) = std::fs::canonicalize(&record.root_path) {
                if path_within(&root, &destination) {
                    return Err(invalid("Diagnostics archives cannot be written inside a sync root"));
                }
            }
        }
        let connections = self.connection_statuses().await?;
        let account = self.status.borrow().account.clone();
        let pending = self.state.pending_external_operations().await.map_err(crate::operations::state_error)?;
        let global = self.state.settings("global".to_owned()).await.map_err(crate::operations::state_error)?;
        let account_json = serde_json::json!({
            "state": account.state,
            "namespace": account.profile.as_ref().map(|profile| profile.namespace.as_str()),
            "account_key": account.profile.as_ref().map(|profile| profile.account_key.to_string()),
            "last_error": account.last_error,
        });
        let connections_json = connections.iter().map(|status| {
            let mut status = status.clone();
            status.root_path = path_alias(&status.root_path);
            status
        }).collect::<Vec<_>>();
        let pending_json = pending.iter().map(|operation| serde_json::json!({
            "operation_id": operation.operation_id,
            "kind": operation.kind,
            "state": operation.state,
            "account_key": operation.account_key,
            "connection_id": operation.connection_id,
            "error_code": operation.error_code,
        })).collect::<Vec<_>>();
        let report = serde_json::json!({
            "schema": 1,
            "provider_version": env!("CARGO_PKG_VERSION"),
            "account": account_json,
            "connections": connections_json,
            "pending_external_operations": pending_json,
            "global_settings": global.map(|row| row.value_json),
        });
        let json = serde_json::to_vec_pretty(&report).map_err(|_| crate::operations::internal())?;
        let markdown = diagnostics_markdown(&report);
        let archive = zip_store(&[
            ("diagnostics.json", &json),
            ("diagnostics.md", markdown.as_bytes()),
        ]);
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&destination)
            .map_err(|_| error(wire::ProtocolErrorCode::Conflict, "Diagnostics destination already exists or cannot be created"))?;
        std::io::Write::write_all(&mut file, &archive).map_err(|_| crate::operations::internal())?;
        std::io::Write::flush(&mut file).map_err(|_| crate::operations::internal())?;
        Ok(wire::ExportDiagnosticsResult {
            archive_path: destination.to_str().ok_or_else(|| invalid("Diagnostics destination is not valid UTF-8"))?.to_owned(),
            redacted: true,
        })
    }
}

fn path_alias(path: &str) -> String {
    format!("path-{}", Sha256Digest::of(path.as_bytes()))
}

fn path_within(root: &std::path::Path, candidate: &std::path::Path) -> bool {
    let root = root.components().collect::<Vec<_>>();
    let candidate = candidate.components().collect::<Vec<_>>();
    root.len() <= candidate.len()
        && root.iter().zip(candidate.iter()).all(|(root, candidate)| {
            hfdrive_windows::filesystem::names::windows_case_equivalent(
                &root.as_os_str().to_string_lossy(),
                &candidate.as_os_str().to_string_lossy(),
            )
        })
}

fn diagnostics_markdown(report: &serde_json::Value) -> String {
    let mut out = "# HF Drive diagnostics (redacted)\n\n".to_owned();
    out.push_str(&format!("Provider version: {}\n\n", env!("CARGO_PKG_VERSION")));
    if let Some(account) = report.get("account") {
        out.push_str(&format!("Account: {:?}\n\n", account.get("state")));
    }
    if let Some(connections) = report.get("connections").and_then(serde_json::Value::as_array) {
        out.push_str(&format!("Connections: {}\n\n", connections.len()));
        for connection in connections {
            out.push_str(&format!(
                "- {}: state={:?}, capability={:?}, root={}\n",
                connection.get("connection_id").and_then(serde_json::Value::as_str).unwrap_or(""),
                connection.get("state"),
                connection.get("capability"),
                connection.get("root_path").and_then(serde_json::Value::as_str).unwrap_or("")
            ));
        }
    }
    if let Some(pending) = report.get("pending_external_operations").and_then(serde_json::Value::as_array) {
        out.push_str(&format!("\nPending external operations: {}\n", pending.len()));
    }
    out
}

fn zip_store(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut central = Vec::new();
    for (name, bytes) in entries {
        let offset = output.len() as u32;
        let crc = crc32(bytes);
        push_u32(&mut output, 0x0403_4b50);
        push_u16(&mut output, 20);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u32(&mut output, crc);
        push_u32(&mut output, bytes.len() as u32);
        push_u32(&mut output, bytes.len() as u32);
        push_u16(&mut output, name.len() as u16);
        push_u16(&mut output, 0);
        output.extend_from_slice(name.as_bytes());
        output.extend_from_slice(bytes);

        push_u32(&mut central, 0x0201_4b50);
        push_u16(&mut central, 20);
        push_u16(&mut central, 20);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u32(&mut central, crc);
        push_u32(&mut central, bytes.len() as u32);
        push_u32(&mut central, bytes.len() as u32);
        push_u16(&mut central, name.len() as u16);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u32(&mut central, 0);
        push_u32(&mut central, offset);
        central.extend_from_slice(name.as_bytes());
    }
    let central_offset = output.len() as u32;
    let central_size = central.len() as u32;
    output.extend_from_slice(&central);
    push_u32(&mut output, 0x0605_4b50);
    push_u16(&mut output, 0);
    push_u16(&mut output, 0);
    push_u16(&mut output, entries.len() as u16);
    push_u16(&mut output, entries.len() as u16);
    push_u32(&mut output, central_size);
    push_u32(&mut output, central_offset);
    push_u16(&mut output, 0);
    output
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_is_a_real_zip_and_crc_is_standard() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        let zip = zip_store(&[("diagnostics.json", b"{}")]);
        assert!(zip.starts_with(&[0x50, 0x4b, 0x03, 0x04]));
        let eocd = &zip[zip.len() - 22..];
        assert_eq!(&eocd[..4], &[0x50, 0x4b, 0x05, 0x06]);
        assert_eq!(u16::from_le_bytes([eocd[8], eocd[9]]), 1);
        assert_eq!(u16::from_le_bytes([eocd[10], eocd[11]]), 1);
    }
}
