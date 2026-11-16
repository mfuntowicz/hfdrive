//! Explorer import-target cache: real native write probes off the shell UI
//! thread, stable bucket identities, and atomic local JSON publication.

use crate::Provider;
use hfdrive_hf::{NativeControl, NativeError, OwnerRef};
use hfdrive_protocol as wire;
use hfdrive_windows::filesystem::replace_file;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

const CACHE_FILE: &str = "import-targets.json";
const MAX_TARGETS: usize = 1000;
const REFRESH_SECONDS: u64 = 60;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportTargetDocument {
    format: u8,
    targets: Vec<wire::ImportTarget>,
}

#[derive(Debug, thiserror::Error)]
enum ImportMenuError {
    #[error(transparent)]
    Native(#[from] NativeError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

fn cache_path(base: &Path) -> PathBuf {
    base.join("shell").join(CACHE_FILE)
}

fn write_target_cache(base: &Path, mut targets: Vec<wire::ImportTarget>) -> Result<(), ImportMenuError> {
    targets.sort_by(|left, right| {
        left.owner_namespace
            .to_lowercase()
            .cmp(&right.owner_namespace.to_lowercase())
            .then_with(|| left.bucket_name.to_lowercase().cmp(&right.bucket_name.to_lowercase()))
            .then_with(|| left.bucket_id.cmp(&right.bucket_id))
    });
    targets.truncate(MAX_TARGETS);
    let bytes = serde_json::to_vec(&ImportTargetDocument { format: 1, targets })?;
    if bytes.len() > 1024 * 1024 {
        return Err(ImportMenuError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "import target cache exceeds 1 MiB",
        )));
    }
    let directory = base.join("shell");
    std::fs::create_dir_all(&directory)?;
    let target = cache_path(base);
    let temporary = directory.join("import-targets.tmp");
    let mut file = std::fs::File::create(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    replace_file(&temporary, &target).map_err(|error| std::io::Error::other(error.to_string()))?;
    Ok(())
}

async fn refresh_targets(control: &NativeControl<crate::tokens::DurableTokens>, cancel: &CancellationToken) -> Result<Vec<wire::ImportTarget>, ImportMenuError> {
    let lease = control.capture_lease()?;
    let owners = control.whoami_owners(&lease, cancel).await?;
    let mut targets = Vec::new();
    for owner in owners {
        if owner.namespace.is_none() {
            continue;
        }
        let owner_ref = OwnerRef {
            owner_id: owner.owner_id.clone(),
            owner_kind: owner.owner_kind,
            owner_namespace: owner.namespace.clone().expect("namespace checked above"),
        };
        let buckets = control.list_buckets(&lease, &owner_ref, cancel).await?;
        for bucket in buckets {
            match control.check_native_write(&lease, &bucket.binding, cancel).await {
                Ok(()) => {}
                Err(NativeError::PermissionDenied) => continue,
                Err(error) => return Err(error.into()),
            }
            targets.push(wire::ImportTarget {
                owner_kind: match bucket.binding.owner_kind {
                    hfdrive_core::storage::OwnerKind::Personal => wire::OwnerKind::Personal,
                    hfdrive_core::storage::OwnerKind::Organization => wire::OwnerKind::Organization,
                },
                owner_id: bucket.binding.owner_id.as_str().to_owned(),
                owner_namespace: bucket.binding.owner_namespace.as_str().to_owned(),
                bucket_id: bucket.binding.bucket_id.as_str().to_owned(),
                bucket_name: bucket.binding.bucket_name.as_str().to_owned(),
                visibility: if bucket.private { wire::Visibility::Private } else { wire::Visibility::Public },
            });
            if targets.len() == MAX_TARGETS {
                return Ok(targets);
            }
        }
    }
    Ok(targets)
}

impl Provider {
    pub async fn import_menu_loop(self: Arc<Self>) {
        loop {
            if let Some(account_key) = self.auth.active_profile().map(|profile| profile.account_key) {
                let control = self.native_control(account_key);
                match refresh_targets(&control, &self.operations.cancellation).await {
                    Ok(targets) => {
                        if let Err(error) = write_target_cache(self.paths.base(), targets) {
                            tracing::warn!(error = %error, "import target cache write failed; preserving the previous cache");
                        }
                    }
                    Err(error) => tracing::warn!(error = %error, "import target cache refresh failed; preserving the previous cache"),
                }
            } else if let Err(error) = write_target_cache(self.paths.base(), Vec::new()) {
                tracing::warn!(error = %error, "import target cache could not be cleared without an active account");
            }
            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                _ = tokio::time::sleep(std::time::Duration::from_secs(REFRESH_SECONDS)) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(owner: &str, bucket: &str, id: &str) -> wire::ImportTarget {
        wire::ImportTarget {
            owner_kind: wire::OwnerKind::Personal,
            owner_id: format!("{owner}-id"),
            owner_namespace: owner.to_owned(),
            bucket_id: id.to_owned(),
            bucket_name: bucket.to_owned(),
            visibility: wire::Visibility::Private,
        }
    }

    #[test]
    fn cache_is_sorted_bounded_and_contains_no_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        let targets = vec![
            target("zoe", "z-bucket", "z"),
            target("alice", "z-bucket", "a2"),
            target("alice", "a-bucket", "a1"),
        ];
        write_target_cache(base, targets.clone()).unwrap();
        let bytes = std::fs::read(cache_path(base)).unwrap();
        let document: ImportTargetDocument = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(document.format, 1);
        assert_eq!(document.targets.len(), 3);
        assert_eq!(document.targets[0].bucket_name, "a-bucket");
        assert_eq!(document.targets[1].bucket_name, "z-bucket");
        assert_eq!(document.targets[2].owner_namespace, "zoe");
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("account_key"));
        assert!(!text.contains("token"));
        assert!(!text.contains("secret"));
        assert!(!base.join("shell").join("import-targets.tmp").exists());
    }

    #[test]
    fn target_cap_is_enforced() {
        let directory = tempfile::tempdir().unwrap();
        let targets = (0..MAX_TARGETS + 4)
            .map(|index| target("alice", &format!("bucket-{index:04}"), &format!("id-{index:04}")))
            .collect::<Vec<_>>();
        write_target_cache(directory.path(), targets).unwrap();
        let bytes = std::fs::read(cache_path(directory.path())).unwrap();
        let document: ImportTargetDocument = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(document.targets.len(), MAX_TARGETS);
    }
}
