//! `hf-xet` 1.8.1 session ownership: one persistent session per store, a
//! persistent per-bucket read group, per-upload write commits, and
//! bucket-specific `/xet-read-token` / `/xet-write-token` refresh URLs.
//!
//! Programmatic bounds only: this crate never touches process-global
//! environment variables to configure transfers.

use crate::NativeError;
use hfdrive_core::storage::BucketBinding;
use reqwest::header::HeaderMap;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use xet::xet_session::{
    Sha256Policy, XetDownloadStreamGroup, XetFileInfo, XetSession, XetSessionBuilder, XetUploadCommit,
};
use xet::XetError;

/// Transfer bounds applied to the Xet session. Defaults match the provider
/// scheduler's initial permits (2 uploads, 4 concurrent range reads, 8 metadata
/// requests are scheduled above this layer). The buffering bounds cap the SDK's
/// internal reconstruction/upload buffers; they are upper bounds for the SDK's
/// own allocations and are verified by measurement, not assumed to be the whole
/// process footprint.
#[derive(Clone, Copy, Debug)]
pub struct XetLimits {
    /// Adaptive concurrency is disabled by default: the provider owns pacing.
    pub adaptive_concurrency: bool,
    pub upload_concurrency: usize,
    pub download_concurrency: usize,
    pub max_concurrent_ingestions: usize,
    pub max_concurrent_downloads: usize,
    /// Maximum bytes read from one source file per ingestion pass (upload
    /// buffering bound).
    pub ingestion_block_bytes: u64,
    /// Per-active-download reconstruction buffer bound.
    pub download_buffer_bytes: u64,
    /// Per-file reconstruction buffer bound.
    pub download_buffer_per_file_bytes: u64,
    /// Ceiling for total reconstruction buffers across active downloads.
    pub max_download_buffer_bytes: u64,
}

impl Default for XetLimits {
    fn default() -> Self {
        Self {
            adaptive_concurrency: false,
            upload_concurrency: 2,
            download_concurrency: 4,
            max_concurrent_ingestions: 2,
            max_concurrent_downloads: 4,
            ingestion_block_bytes: 8 * 1024 * 1024,
            download_buffer_bytes: 4 * 1024 * 1024,
            download_buffer_per_file_bytes: 8 * 1024 * 1024,
            max_download_buffer_bytes: 64 * 1024 * 1024,
        }
    }
}

pub(crate) fn map_xet_error(error: XetError) -> NativeError {
    match &error {
        XetError::Authentication(_) => NativeError::PermissionDenied,
        XetError::UserCancelled(_) | XetError::Cancelled(_) | XetError::KeyboardInterrupt => NativeError::Cancelled,
        XetError::RateLimited(_) => NativeError::RateLimited { retry_after_seconds: None },
        XetError::NotFound(_) => NativeError::RemoteContentUnavailable,
        XetError::Network(_) | XetError::Timeout(_) | XetError::Io(_) => NativeError::Transport,
        XetError::DataIntegrity(_) => NativeError::InvalidResponse,
        XetError::Configuration(m) => NativeError::InvalidRequest { detail: NativeError::detail(m) },
        // InvalidTaskID/AlreadyCompleted/PreviousTaskError/TaskError/Internal/
        // WrongRuntimeMode and anything added later are transport-class faults
        // for this boundary; SDK text never crosses it.
        _ => NativeError::Transport,
    }
}

struct ReadGroup {
    generation: u64,
    group: XetDownloadStreamGroup,
}

struct XetInner {
    session: XetSession,
    read_groups: Mutex<HashMap<String, ReadGroup>>,
}

/// Persistent Xet store for one drive. The session and per-bucket read groups
/// outlive individual requests and are rebuilt only after credential
/// generation changes.
#[derive(Clone)]
pub(crate) struct XetStore {
    inner: Arc<XetInner>,
}

/// Adapter from the shared [`crate::wire_budget::WireBudget`] to the vendored
/// `xet-client` transport hook (see `vendor/xet-core/README.md`). Installed
/// once per process; every encoded CAS/dedup/range body byte passes through it.
struct XetTransportHook(crate::wire_budget::WireBudget);

impl xet_client::common::transport_budget::TransportBudgetHook for XetTransportHook {
    fn gate(
        &self,
        direction: xet_client::common::transport_budget::Direction,
        bytes: u64,
    ) -> xet_client::common::transport_budget::GateFuture {
        let direction = match direction {
            xet_client::common::transport_budget::Direction::Upload => crate::wire_budget::Direction::Upload,
            xet_client::common::transport_budget::Direction::Download => crate::wire_budget::Direction::Download,
        };
        Box::pin(self.0.gate(direction, bytes))
    }
}

impl XetStore {
    pub(crate) fn new(
        cache_dir: &std::path::Path,
        limits: XetLimits,
        budget: &crate::wire_budget::WireBudget,
    ) -> Result<Self, NativeError> {
        // The transport hook is process-global and must exist before any CAS
        // byte moves; the shared budget is the same instance for every store.
        xet_client::common::transport_budget::install_global_hook(std::sync::Arc::new(XetTransportHook(budget.clone())));

        let mut config = xet::xet_session::XetConfig::new();
        config.client.enable_adaptive_concurrency = limits.adaptive_concurrency;
        config.client.ac_max_upload_concurrency = limits.upload_concurrency;
        config.client.ac_max_download_concurrency = limits.download_concurrency;
        config.data.max_concurrent_file_ingestion = limits.max_concurrent_ingestions;
        config.data.max_concurrent_file_downloads = limits.max_concurrent_downloads;
        // Programmatic buffering bounds only; never process-global env vars.
        config.data.ingestion_block_size = limits.ingestion_block_bytes.into();
        config.reconstruction.download_buffer_size = limits.download_buffer_bytes.into();
        config.reconstruction.download_buffer_perfile_size = limits.download_buffer_per_file_bytes.into();
        config.reconstruction.download_buffer_limit = limits.max_download_buffer_bytes.into();

        let mut builder = XetSessionBuilder::new_with_config(config);
        if !cache_dir.as_os_str().is_empty() {
            builder = builder.with_cache_dir(cache_dir);
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            builder = builder.with_tokio_handle(handle);
        }
        let session = builder.build().map_err(map_xet_error)?;
        Ok(Self { inner: Arc::new(XetInner { session, read_groups: Mutex::new(HashMap::new()) }) })
    }

    /// The bucket's Xet read-token refresh route on the trusted HF API origin.
    pub(crate) fn read_token_url(endpoint: &str, binding: &BucketBinding) -> Result<String, NativeError> {
        token_url(endpoint, binding, "read")
    }

    /// The bucket's Xet write-token refresh route on the trusted HF API origin.
    pub(crate) fn write_token_url(endpoint: &str, binding: &BucketBinding) -> Result<String, NativeError> {
        token_url(endpoint, binding, "write")
    }

    /// Persistent bucket read group. Built with `with_token_refresh_url` to the
    /// bucket's `/xet-read-token`; rebuilt after credential generation changes
    /// so refreshes always carry current bearer credentials.
    pub(crate) async fn read_group(
        &self,
        binding: &BucketBinding,
        refresh_url: &str,
        bearer: HeaderMap,
        generation: u64,
    ) -> Result<XetDownloadStreamGroup, NativeError> {
        let key = format!("{}/{}", binding.owner_namespace.as_str(), binding.bucket_name.as_str());
        {
            let guard = self.inner.read_groups.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = guard.get(&key)
                && entry.generation == generation
            {
                return Ok(entry.group.clone());
            }
        }
        let builder = self
            .inner
            .session
            .new_download_stream_group()
            .map_err(map_xet_error)?
            .with_token_refresh_url(refresh_url, bearer);
        let group = builder.build().await.map_err(map_xet_error)?;
        let mut guard = self.inner.read_groups.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(key, ReadGroup { generation, group: group.clone() });
        Ok(group)
    }

    /// Fresh write commit for one staged upload, configured with the bucket's
    /// `/xet-write-token` refresh route. The SDK models upload authorization
    /// per commit; the persistent part is the session and the route binding.
    pub(crate) async fn write_commit(
        &self,
        refresh_url: &str,
        bearer: HeaderMap,
    ) -> Result<XetUploadCommit, NativeError> {
        let builder = self
            .inner
            .session
            .new_upload_commit()
            .map_err(map_xet_error)?
            .with_token_refresh_url(refresh_url, bearer);
        builder.build().await.map_err(map_xet_error)
    }
}

fn token_url(endpoint: &str, binding: &BucketBinding, kind: &str) -> Result<String, NativeError> {
    let url = crate::http::bucket_api_url(
        endpoint,
        binding.owner_namespace.as_str(),
        binding.bucket_name.as_str(),
        &[&format!("xet-{kind}-token")],
    )?;
    Ok(url.into())
}

/// File info for one immutable object: Xet Merkle hash plus exact size.
pub(crate) fn file_info(hash: &str, size: u64) -> XetFileInfo {
    XetFileInfo::new(hash.to_owned(), size)
}

/// SHA-256 policy that recomputes the digest from the ingested bytes so the
/// returned metadata can be verified against the capture-time claim.
pub(crate) const SHA256_RECOMPUTE: Sha256Policy = Sha256Policy::Compute;
