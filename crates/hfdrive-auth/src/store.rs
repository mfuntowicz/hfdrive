//! DPAPI-protected per-account OAuth credential envelopes.
//!
//! Uses the one existing persistence convention
//! ([`hfdrive_windows::credentials::CredentialStore`]): user-scoped DPAPI,
//! user/SYSTEM-only DACL, atomic replace. The record name is the store's real
//! record name ([`AccountCredentialStore::record_name`]) and the on-disk file
//! name is exposed verbatim via
//! [`AccountCredentialStore::record_file_name`] — the durable `credential_ref`
//! must store that, not a fabricated string. The envelope JSON binds issuer +
//! subject and is serialized as UTF-8 before protection; token fields are
//! zeroized.

use hfdrive_core::ids::AccountKey;
use hfdrive_windows::credentials::{CredentialStore, RecordName, SecretBytes};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::error::AuthError;
use crate::identity::OrgCandidate;
use crate::login::{LoginFlow, LoginPurpose};

/// Schema identifier of the protected envelope.
pub const ENVELOPE_SCHEMA: u32 = 1;

/// The one OAuth credential record name per account (the store appends its
/// own file extension).
pub const OAUTH_RECORD_NAME: &str = "oauth";

/// Protected credential envelope for one account.
///
/// Serialized with `serde_json` and protected by user-scoped DPAPI before it
/// touches disk. Never logged, never serialized to IPC, never `Debug`-printed
/// with contents. Identity fields (`namespace`/`orgs`) are the verified
/// display identity recorded at login so restoration republishes the same
/// immutable snapshot without inventing anything.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialEnvelope {
    /// Envelope schema version.
    pub schema: u32,
    /// Exact issuer this record belongs to.
    pub issuer: String,
    /// Verified subject this record belongs to.
    pub subject: String,
    /// Verified canonical personal namespace (validated at build/restore).
    pub namespace: String,
    /// Validated display-only avatar URL (HTTPS `huggingface.co`/subdomain,
    /// no embedded credentials). `None` when unknown/rejected. `default` keeps
    /// records written before this field readable — absence restores as
    /// `None` and never fails the account. Never a credential; never logged.
    #[serde(default)]
    pub avatar_url: Option<String>,
    /// Verified organization display identity.
    pub orgs: Vec<OrgCandidate>,
    /// Granted scopes; `None` means unknown, never "proven empty".
    pub granted_scopes: Option<Vec<String>>,
    /// Purpose of the login session that issued/last rotated this record.
    pub covered_purpose: LoginPurpose,
    /// Flow of the login session that issued this record.
    pub login_flow: LoginFlow,
    /// Credential generation (monotonic per account; distinct from the
    /// authorization epoch).
    pub generation: u64,
    /// Durable authorization epoch; preserved across ordinary refresh/restoration.
    pub authorization_epoch: u64,
    /// Token lifetime in seconds as returned by the provider (used to
    /// recompute the proactive refresh deadline after restoration).
    pub lifetime_secs: u64,
    /// Access token expiry, seconds since the Unix epoch.
    pub expires_at: u64,
    /// Access token.
    pub access_token: String,
    /// Optional refresh token (absent for flows without refresh capability).
    pub refresh_token: Option<String>,
}

impl std::fmt::Debug for CredentialEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialEnvelope")
            .field("schema", &self.schema)
            .field("issuer", &self.issuer)
            .field("subject", &self.subject)
            .field("namespace", &self.namespace)
            .field("avatar_url", &self.avatar_url)
            .field("orgs", &self.orgs)
            .field("granted_scopes", &self.granted_scopes)
            .field("covered_purpose", &self.covered_purpose)
            .field("login_flow", &self.login_flow)
            .field("generation", &self.generation)
            .field("lifetime_secs", &self.lifetime_secs)
            .field("expires_at", &self.expires_at)
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl Drop for CredentialEnvelope {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

impl CredentialEnvelope {
    /// Wipe the secret fields in place.
    pub fn zeroize_secrets(&mut self) {
        use zeroize::Zeroize;
        self.access_token.zeroize();
        if let Some(t) = self.refresh_token.as_mut() {
            t.zeroize();
        }
    }
}

/// Per-account DPAPI-protected credential record store.
///
/// Record layout: `<state-base>/accounts/<account-key>/credentials/oauth.hfdcred`.
/// The parent directory is created and ACL'd by the existing credential store
/// implementation. DPAPI entropy binds the record to the account key (which
/// is itself `sha256(issuer + NUL + subject)`).
pub struct AccountCredentialStore {
    store: CredentialStore,
    account: AccountKey,
}

impl AccountCredentialStore {
    /// The real record name used by the underlying credential store.
    pub fn record_name() -> RecordName {
        RecordName::new(OAUTH_RECORD_NAME).expect("static record name is valid")
    }

    /// The actual on-disk file name of the OAuth credential record (record
    /// name plus the credential store's own extension). Store this as the
    /// durable `credential_ref`; it is computed from the store's convention,
    /// never fabricated.
    pub fn record_file_name() -> String {
        hfdrive_windows::credentials::record_file_name(&Self::record_name())
    }

    /// Open (and create/harden) the credential directory for one account.
    ///
    /// `credentials_dir` is `StatePaths::account(key).credentials()`.
    pub fn open(credentials_dir: PathBuf, account: AccountKey) -> Result<Self, AuthError> {
        let store = CredentialStore::open(credentials_dir).map_err(|_| AuthError::Persistence)?;
        Ok(Self { store, account })
    }

    /// Save the envelope, atomically and before any caller exposure.
    ///
    /// The new record replaces the old one only after the protected bytes
    /// were written and flushed; a crash leaves either the old or the new
    /// record, never a torn one. The envelope identity must hash to this
    /// store's account.
    pub fn save(&self, envelope: &CredentialEnvelope) -> Result<(), AuthError> {
        if AccountKey::from_subject(&envelope.issuer, &envelope.subject) != self.account {
            return Err(AuthError::Internal);
        }
        let name = Self::record_name();
        let plaintext = Zeroizing::new(
            serde_json::to_vec(envelope).map_err(|_| AuthError::Persistence)?,
        );
        let binding = self.entropy();
        let entropy = Some(binding.as_slice());
        self.store
            .save_record(&name, plaintext.as_slice(), entropy)
            .map_err(|_| AuthError::Persistence)
    }

    /// Load the envelope. [`AuthError::NeedsSignIn`] when no record exists;
    /// [`AuthError::CredentialRecordUnreadable`] when the record exists but
    /// cannot be protected for this user/binding (the file is preserved
    /// untouched). Identity agreement with the account is checked by the
    /// caller so a subject change can surface as
    /// [`AuthError::ExistingSessionPreserved`].
    pub fn load(&self) -> Result<CredentialEnvelope, AuthError> {
        let name = Self::record_name();
        let entropy = self.entropy();
        let plaintext: SecretBytes = match self.store.load_record(&name, Some(entropy.as_slice())) {
            Ok(p) => p,
            Err(hfdrive_windows::CredentialError::NotFound) => return Err(AuthError::NeedsSignIn),
            Err(_) => return Err(AuthError::CredentialRecordUnreadable),
        };
        let envelope: CredentialEnvelope =
            serde_json::from_slice(plaintext.expose()).map_err(|_| AuthError::CredentialRecordUnreadable)?;
        if envelope.schema != ENVELOPE_SCHEMA {
            return Err(AuthError::CredentialRecordUnreadable);
        }
        Ok(envelope)
    }

    /// Delete the record; `Ok(false)` when it was already absent.
    pub fn delete(&self) -> Result<bool, AuthError> {
        let name = Self::record_name();
        self.store.delete_record(&name).map_err(|_| AuthError::Persistence)
    }

    /// DPAPI entropy binding this record to the account key.
    fn entropy(&self) -> Vec<u8> {
        let mut entropy = Vec::with_capacity(b"HFDRIVE-OAUTH-ENVELOPE\0".len() + 32);
        entropy.extend_from_slice(b"HFDRIVE-OAUTH-ENVELOPE\0");
        entropy.extend_from_slice(self.account.as_bytes());
        entropy
    }
}

/// Store directory for one account under the shared state layout.
pub fn account_credentials_dir(state_base: &std::path::Path, account: AccountKey) -> PathBuf {
    hfdrive_state::StatePaths::new(state_base.to_owned())
        .account(account)
        .credentials()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record written before `avatar_url` existed must still restore, with
    /// the avatar absent rather than the account failing to load.
    #[test]
    fn envelopes_without_avatar_url_still_deserialize_as_none() {
        let old = br#"{
            "schema": 1,
            "issuer": "https://huggingface.co",
            "subject": "fixture-subject",
            "namespace": "fixture-person",
            "orgs": [],
            "granted_scopes": ["openid", "profile"],
            "covered_purpose": "write_storage",
            "login_flow": "pkce",
            "generation": 3,
            "authorization_epoch": 1,
            "lifetime_secs": 3600,
            "expires_at": 4000000000,
            "access_token": "fixture-access-token",
            "refresh_token": null
        }"#;
        let envelope: CredentialEnvelope =
            serde_json::from_slice(old).expect("pre-avatar envelope stays readable");
        assert_eq!(envelope.avatar_url, None);
        assert_eq!(envelope.subject, "fixture-subject");

        // A new record round-trips its validated avatar unchanged.
        let mut new = envelope;
        new.avatar_url =
            Some("https://cdn-avatars.huggingface.co/v1/production/uploads/a.jpeg".to_owned());
        let bytes = serde_json::to_vec(&new).expect("envelope serializes");
        let restored: CredentialEnvelope =
            serde_json::from_slice(&bytes).expect("envelope round-trips");
        assert_eq!(restored.avatar_url, new.avatar_url);
    }
}
