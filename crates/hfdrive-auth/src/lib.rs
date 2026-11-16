//! Provider-owned authorization lifetimes; UI/IPC never receive bearer tokens.
//!
//! # Layering
//!
//! * [`AuthorizationAuthority`]/[`AuthorizationLease`] — the authorization
//!   epoch: lease validity for dispatching remote mutations. Bound to one
//!   immutable [`AccountKey`](hfdrive_core::ids::AccountKey) so a lease can
//!   never authorize a different account's binding. Revocation closes before
//!   advancing; reactivation never revives an old lease.
//! * [`SecretAccessToken`] — zeroizing bearer token shared by credential
//!   generation ([`SecretAccessToken::generation`]). Credential generations
//!   rotate on refresh. Ordinary refresh preserves the authorization epoch;
//!   changed grants/identity revoke old leases, and logout can never be revived.
//! * [`TokenSource`] — the shared native-client boundary implemented by
//!   [`AuthManager`].
//! * [`AuthManager`] — OAuth public-client login (PKCE loopback + explicit
//!   device flow), strict OIDC validation, DPAPI-protected per-account
//!   credential persistence, single-flight refresh, verified identity
//!   snapshots and sign-out.
#![forbid(unsafe_code)]

use hfdrive_core::ids::AccountKey;
use std::{fmt, sync::{Arc, Mutex}};
use zeroize::Zeroizing;

pub mod config;
pub mod discovery;
pub mod error;
pub mod flows;
pub(crate) mod http;
pub mod identity;
pub mod login;
pub mod manager;
pub mod protocol;
pub mod store;

pub use config::{AuthConfig, OidcSettings, OAUTH_CLIENT_ID};
pub use error::AuthError;
pub use identity::{AccountProfile, AccountProfileSummary, OrgCandidate, VerifiedOrg};
pub use login::{LoginFlow, LoginPurpose, LoginRequest, LoginSession, LoginState};
pub use manager::{AuthManager, AuthSnapshot, BrowserLauncher};
pub use protocol::{CallbackCheck, CallbackError};
pub use store::{AccountCredentialStore, CredentialEnvelope};

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum AuthorizationError {
    #[error("sign-in is required")]
    NeedsSignIn,
    #[error("authorization state is unavailable")]
    Unavailable,
    #[error("authorization epoch exhausted; restart with preserved state")]
    EpochExhausted,
}

#[derive(Debug)]
struct EpochState {
    generation: u64,
    enabled: bool,
}

/// Only the account owner activates a generation after durable credential
/// save. One authority exists per account; its account identity is immutable
/// and lives outside the state lock.
#[derive(Debug)]
pub struct AuthorizationAuthority {
    account: AccountKey,
    state: Arc<Mutex<EpochState>>,
}

impl AuthorizationAuthority {
    /// Create the authority for one account at the given starting generation.
    /// The epoch starts disabled: nothing dispatches until the first
    /// successful durable credential save activates it.
    pub fn new(account: AccountKey, generation: u64) -> Self {
        Self {
            account,
            state: Arc::new(Mutex::new(EpochState { generation, enabled: false })),
        }
    }

    /// The account this authority (and every lease it issues) is bound to.
    pub const fn account(&self) -> AccountKey {
        self.account
    }

    pub fn activate(&self) -> Result<AuthorizationLease, AuthorizationError> {
        let mut state = self.state.lock().map_err(|_| AuthorizationError::Unavailable)?;
        state.enabled = false;
        state.generation = state.generation.checked_add(1).ok_or(AuthorizationError::EpochExhausted)?;
        state.enabled = true;
        Ok(AuthorizationLease {
            state: self.state.clone(),
            account: self.account,
            generation: state.generation,
        })
    }

    /// Revoke first (closing every live lease), then advance the epoch. No
    /// later activation can revive a lease issued before this call.
    pub fn revoke(&self) -> Result<u64, AuthorizationError> {
        let mut state = self.state.lock().map_err(|_| AuthorizationError::Unavailable)?;
        state.enabled = false;
        state.generation = state.generation.checked_add(1).ok_or(AuthorizationError::EpochExhausted)?;
        Ok(state.generation)
    }

    pub fn capture(&self) -> Result<AuthorizationLease, AuthorizationError> {
        let state = self.state.lock().map_err(|_| AuthorizationError::Unavailable)?;
        if !state.enabled {
            return Err(AuthorizationError::NeedsSignIn);
        }
        Ok(AuthorizationLease {
            state: self.state.clone(),
            account: self.account,
            generation: state.generation,
        })
    }

    /// The current epoch generation (whether or not it is enabled). This is
    /// the durable `auth_epoch` value — distinct from credential generations.
    pub fn current_epoch(&self) -> Result<u64, AuthorizationError> {
        let state = self.state.lock().map_err(|_| AuthorizationError::Unavailable)?;
        Ok(state.generation)
    }
}

/// A cloneable dispatch lease for one account's authorization epoch.
/// Callers check the lease immediately before dispatch **and** compare
/// [`lease.account()`](Self::account) with the resource binding's account key.
#[derive(Clone, Debug)]
pub struct AuthorizationLease {
    state: Arc<Mutex<EpochState>>,
    account: AccountKey,
    generation: u64,
}

impl AuthorizationLease {
    pub fn check(&self) -> Result<(), AuthorizationError> {
        let state = self.state.lock().map_err(|_| AuthorizationError::Unavailable)?;
        if !state.enabled || state.generation != self.generation {
            return Err(AuthorizationError::NeedsSignIn);
        }
        Ok(())
    }

    /// The account this lease is bound to. A lease can never authorize
    /// dispatches for a different account's resources.
    pub const fn account(&self) -> AccountKey {
        self.account
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

pub struct SecretAccessToken {
    token: Zeroizing<String>,
    account: AccountKey,
    generation: u64,
    expires_at: u64,
}

impl SecretAccessToken {
    pub fn new(token: Zeroizing<String>, account: AccountKey, generation: u64, expires_at: u64) -> Self {
        Self { token, account, generation, expires_at }
    }

    pub fn as_str(&self) -> &str {
        &self.token
    }

    pub const fn account(&self) -> AccountKey {
        self.account
    }

    /// Credential generation: rotates on every token issuance/refresh and is
    /// distinct from the authorization epoch.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

impl fmt::Debug for SecretAccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretAccessToken").field("token", &"[REDACTED]").finish_non_exhaustive()
    }
}

/// Shared native-client boundary. Credentials are shared by generation, never
/// copied per lookup. A rejected generation permits one serialized refresh;
/// concurrent callers reuse its replacement.
pub trait TokenSource: Send + Sync {
    fn access_token(&self, account: AccountKey)
        -> impl Future<Output = Result<Arc<SecretAccessToken>, AuthorizationError>> + Send;

    fn refresh_after_unauthorized(&self, account: AccountKey, rejected_generation: u64)
        -> impl Future<Output = Result<Arc<SecretAccessToken>, AuthorizationError>> + Send;

    fn authorization_lease(&self, account: AccountKey) -> Result<AuthorizationLease, AuthorizationError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> AccountKey {
        AccountKey::from_subject("https://huggingface.co", "fixture-subject")
    }

    #[test]
    fn revocation_invalidates_every_existing_lease_and_reconsent_cannot_revive_one() {
        let authority = AuthorizationAuthority::new(account(), 42);
        assert!(matches!(authority.capture(), Err(AuthorizationError::NeedsSignIn)));
        let old = authority.activate().unwrap();
        let second = authority.capture().unwrap();
        authority.revoke().unwrap();
        assert_eq!(old.check(), Err(AuthorizationError::NeedsSignIn));
        assert_eq!(second.check(), Err(AuthorizationError::NeedsSignIn));
        let current = authority.activate().unwrap();
        assert!(current.generation() > old.generation());
        current.check().unwrap();
        assert_eq!(old.check(), Err(AuthorizationError::NeedsSignIn));
    }

    #[test]
    fn exhausted_epoch_fails_closed() {
        let authority = AuthorizationAuthority::new(account(), u64::MAX - 1);
        let lease = authority.activate().unwrap();
        assert_eq!(authority.revoke(), Err(AuthorizationError::EpochExhausted));
        assert_eq!(lease.check(), Err(AuthorizationError::NeedsSignIn));
        assert!(matches!(authority.activate(), Err(AuthorizationError::EpochExhausted)));
    }

    #[test]
    fn lease_carries_its_account_identity() {
        let mine = account();
        let other = AccountKey::from_subject("https://huggingface.co", "someone-else");
        let authority = AuthorizationAuthority::new(mine, 0);
        let lease = authority.activate().unwrap();
        assert_eq!(lease.account(), mine);
        assert_eq!(authority.account(), mine);
        assert_ne!(lease.account(), other);
        // A lease for one account must not validate against a different
        // account's binding.
        assert!(lease.check().is_ok());
    }

    #[test]
    fn refresh_generation_never_changes_the_epoch() {
        let authority = AuthorizationAuthority::new(account(), 0);
        let lease = authority.activate().unwrap();
        let epoch_generation = lease.generation();
        // A credential rotation (token generation) is a different counter;
        // nothing here touches the authority.
        let token = SecretAccessToken::new(
            Zeroizing::new("t".to_owned()),
            account(),
            epoch_generation + 100,
            2_000_000_000,
        );
        assert_eq!(token.generation(), epoch_generation + 100);
        assert_eq!(lease.generation(), epoch_generation);
        lease.check().unwrap();
    }
}
