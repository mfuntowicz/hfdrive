use serde::{Deserialize, Serialize};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub upload_bytes_per_second: u64,
    pub download_bytes_per_second: u64,
    pub transfer_memory_bytes: u64,
    pub range_cache_bytes: u64,
    pub staging_admission_bytes: u64,
    pub minimum_free_bytes: u64,
    pub allow_background_on_metered: bool,
    pub start_at_login: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            upload_bytes_per_second: 0,
            download_bytes_per_second: 0,
            transfer_memory_bytes: 256 * MIB,
            range_cache_bytes: 512 * MIB,
            staging_admission_bytes: 10 * GIB,
            minimum_free_bytes: GIB,
            allow_background_on_metered: false,
            start_at_login: false,
        }
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum SettingsError {
    #[error("transfer memory must accommodate four reads and two uploads (at least 8 MiB)")]
    TransferMemory,
    #[error("storage budgets exceed the supported signed 64-bit range")]
    StorageRange,
}

impl Settings {
    pub fn validate(&self) -> Result<(), SettingsError> {
        if self.transfer_memory_bytes < 8 * MIB { return Err(SettingsError::TransferMemory); }
        if [self.transfer_memory_bytes, self.range_cache_bytes,
            self.staging_admission_bytes, self.minimum_free_bytes]
            .into_iter().any(|n| n > i64::MAX as u64) {
            return Err(SettingsError::StorageRange);
        }
        Ok(())
    }
}
