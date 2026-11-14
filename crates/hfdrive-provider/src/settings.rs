//! Global transfer/memory settings: one durable JSON object per scope, with
//! optimistic revision checking and live scheduler application after commit.
//! An empty patch returns the resolved settings and revision without mutation.

use hfdrive_protocol as wire;

use crate::{Provider, operations::error, scheduler::Scheduler, storage::invalid};

const UPLOAD: &str = "upload_bytes_per_second";
const DOWNLOAD: &str = "download_bytes_per_second";
const TRANSFER: &str = "transfer_memory_bytes";
const RANGE: &str = "range_cache_bytes";
const STAGING: &str = "staging_admission_bytes";
const MINIMUM_FREE: &str = "minimum_free_bytes";
const KEYS: [&str; 6] = [UPLOAD, DOWNLOAD, TRANSFER, RANGE, STAGING, MINIMUM_FREE];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LiveSettings {
    upload: u64,
    download: u64,
    transfer: u64,
    range: u64,
    staging: u64,
    minimum_free: u64,
}

impl Default for LiveSettings {
    fn default() -> Self {
        let config = crate::scheduler::SchedulerConfig::default();
        Self {
            upload: 0,
            download: 0,
            transfer: config.transfer_memory_bytes,
            range: config.range_cache_bytes,
            staging: config.staging_admission_bytes,
            minimum_free: config.minimum_free_bytes,
        }
    }
}

pub(crate) fn default_global_settings() -> serde_json::Value {
    let defaults = LiveSettings::default();
    serde_json::json!({
        "upload_bytes_per_second": defaults.upload,
        "download_bytes_per_second": defaults.download,
        "transfer_memory_bytes": defaults.transfer,
        "range_cache_bytes": defaults.range,
        "staging_admission_bytes": defaults.staging,
        "minimum_free_bytes": defaults.minimum_free,
    })
}

pub(crate) fn apply_global_settings(
    scheduler: &Scheduler,
    value: &serde_json::Value,
) -> Result<(), &'static str> {
    let live = live_settings(value)?;
    scheduler.set_transfer_rates(live.upload, live.download);
    scheduler.set_memory_limits(live.transfer, live.range, live.staging, live.minimum_free);
    Ok(())
}

fn live_settings(value: &serde_json::Value) -> Result<LiveSettings, &'static str> {
    let object = value.as_object().ok_or("global settings must be a JSON object")?;
    let mut live = LiveSettings::default();
    for (key, target) in [
        (UPLOAD, &mut live.upload),
        (DOWNLOAD, &mut live.download),
        (TRANSFER, &mut live.transfer),
        (RANGE, &mut live.range),
        (STAGING, &mut live.staging),
        (MINIMUM_FREE, &mut live.minimum_free),
    ] {
        if let Some(value) = object.get(key) {
            *target = value.as_u64().ok_or("settings values must be nonnegative u64 integers")?;
        }
    }
    Ok(live)
}

impl Provider {
    pub(crate) async fn update_settings(
        &self,
        request: wire::UpdateSettingsRequest,
    ) -> Result<wire::UpdateSettingsResult, wire::ProtocolError> {
        if request.scope_id != "global" {
            return Err(invalid("Transfer and memory settings are provider-wide; use the global scope"));
        }
        let current = self.state.settings("global".to_owned()).await.map_err(crate::operations::state_error)?;
        if request.settings.is_empty() {
            let (revision, value) = current
                .map(|row| (row.revision, row.value_json))
                .unwrap_or((0, default_global_settings()));
            let settings = value.as_object().ok_or_else(|| error(wire::ProtocolErrorCode::Conflict, "Stored global settings are not a JSON object"))?
                .iter()
                .map(|(key, value)| Ok(wire::SettingsEntry {
                    key: key.clone(),
                    value_json: serde_json::to_string(value).map_err(|_| crate::operations::internal())?,
                }))
                .collect::<Result<Vec<_>, wire::ProtocolError>>()?;
            return Ok(wire::UpdateSettingsResult { revision, settings });
        }
        let actual_revision = current.as_ref().map_or(0, |row| row.revision);
        if request.expected_revision != actual_revision {
            return Err(crate::operations::state_error(hfdrive_state::StateError::RevisionMismatch {
                expected: request.expected_revision,
                actual: actual_revision,
            }));
        }
        let mut object = current
            .map(|row| row.value_json)
            .unwrap_or_else(default_global_settings)
            .as_object()
            .cloned()
            .ok_or_else(|| error(wire::ProtocolErrorCode::Conflict, "Stored global settings are not a JSON object"))?;
        let mut seen = std::collections::BTreeSet::new();
        for patch in request.settings {
            if !KEYS.contains(&patch.key.as_str()) || !seen.insert(patch.key.clone()) {
                return Err(invalid("Unknown or duplicate settings key"));
            }
            match patch.value_json {
                None => {
                    object.remove(&patch.key);
                }
                Some(encoded) => {
                    let value: serde_json::Value = serde_json::from_str(&encoded)
                        .map_err(|_| invalid("Settings value is not valid JSON"))?;
                    if value.as_u64().is_none() {
                        return Err(invalid("Settings values must be nonnegative u64 integers"));
                    }
                    object.insert(patch.key, value);
                }
            }
        }
        let value = serde_json::Value::Object(object);
        live_settings(&value).map_err(|_| invalid("Global settings are invalid"))?;
        let stored = self.state.set_settings(
            "global".to_owned(),
            value.clone(),
            (actual_revision != 0).then_some(request.expected_revision),
        ).await.map_err(crate::operations::state_error)?;
        apply_global_settings(&self.scheduler, &value).map_err(|_| crate::operations::internal())?;
        let object = value.as_object().ok_or_else(crate::operations::internal)?;
        let settings = object.iter().map(|(key, value)| {
            Ok(wire::SettingsEntry {
                key: key.clone(),
                value_json: serde_json::to_string(value).map_err(|_| crate::operations::internal())?,
            })
        }).collect::<Result<Vec<_>, wire::ProtocolError>>()?;
        Ok(wire::UpdateSettingsResult { revision: stored.revision, settings })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_values_use_defaults_and_invalid_values_fail() {
        let defaults = live_settings(&default_global_settings()).unwrap();
        assert_eq!(live_settings(&serde_json::json!({})).unwrap(), defaults);
        assert_eq!(live_settings(&serde_json::json!({"upload_bytes_per_second": 42})).unwrap().upload, 42);
        assert!(live_settings(&serde_json::json!({"upload_bytes_per_second": -1})).is_err());
        assert!(live_settings(&serde_json::json!({"upload_bytes_per_second": "42"})).is_err());
    }

    #[tokio::test]
    async fn first_update_uses_revision_zero_and_rejects_stale_rewrite() {
        let provider = Provider::new(hfdrive_protocol::StatusSnapshot {
            sequence: 0,
            account: Default::default(),
            connections: Vec::new(),
        });
        let request = wire::UpdateSettingsRequest {
            operation_id: uuid::Uuid::new_v4(),
            scope_id: "global".to_owned(),
            expected_revision: 0,
            settings: vec![wire::SettingsPatch {
                key: "upload_bytes_per_second".to_owned(),
                value_json: Some("42".to_owned()),
            }],
        };
        let updated = provider.update_settings(request.clone()).await.unwrap();
        assert_eq!(updated.revision, 1);
        assert_eq!(updated.settings.iter().find(|entry| entry.key == "upload_bytes_per_second").unwrap().value_json, "42");
        let stored = provider.state.settings("global".to_owned()).await.unwrap().unwrap();
        assert_eq!(stored.revision, 1);
        assert_eq!(stored.value_json.get("upload_bytes_per_second").unwrap().as_u64(), Some(42));
        let discovered = provider.update_settings(wire::UpdateSettingsRequest {
            operation_id: uuid::Uuid::new_v4(),
            scope_id: "global".to_owned(),
            expected_revision: 0,
            settings: Vec::new(),
        }).await.unwrap();
        assert_eq!(discovered.revision, 1);
        assert!(discovered.settings.iter().any(|entry| entry.key == "upload_bytes_per_second" && entry.value_json == "42"));
        assert!(provider.update_settings(request).await.is_err());
    }
}
