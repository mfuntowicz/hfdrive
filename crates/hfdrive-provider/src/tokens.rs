//! Native consumers cannot use a newly selected identity/epoch before its state commit.
use hfdrive_auth::{AuthManager, AuthorizationError, AuthorizationLease, SecretAccessToken, TokenSource};
use hfdrive_core::ids::AccountKey;
use std::sync::{Arc, Mutex};

pub(crate) struct DurableTokens {
    auth: AuthManager,
    admitted: Mutex<Option<(AccountKey, u64)>>,
}

impl DurableTokens {
    pub(crate) fn new(auth: AuthManager) -> Self { Self { auth, admitted: Mutex::new(None) } }

    pub(crate) fn admit(&self, account: AccountKey, epoch: u64) -> Result<(), AuthorizationError> {
        *self.admitted.lock().map_err(|_| AuthorizationError::Unavailable)? = Some((account, epoch));
        Ok(())
    }

    pub(crate) fn clear(&self) -> Result<(), AuthorizationError> {
        *self.admitted.lock().map_err(|_| AuthorizationError::Unavailable)? = None;
        Ok(())
    }
}

impl TokenSource for DurableTokens {
    async fn access_token(&self, account: AccountKey) -> Result<Arc<SecretAccessToken>, AuthorizationError> {
        let lease = self.authorization_lease(account)?;
        let token = self.auth.access_token(account).await?;
        lease.check()?;
        self.authorization_lease(account)?;
        Ok(token)
    }

    async fn refresh_after_unauthorized(&self, account: AccountKey, rejected_generation: u64) -> Result<Arc<SecretAccessToken>, AuthorizationError> {
        let lease = self.authorization_lease(account)?;
        let token = self.auth.refresh_after_unauthorized(account, rejected_generation).await?;
        lease.check()?;
        self.authorization_lease(account)?;
        Ok(token)
    }

    fn authorization_lease(&self, account: AccountKey) -> Result<AuthorizationLease, AuthorizationError> {
        let lease = self.auth.authorization_lease(account)?;
        let admitted = self.admitted.lock().map_err(|_| AuthorizationError::Unavailable)?;
        if *admitted != Some((account, lease.generation())) {
            return Err(AuthorizationError::Unavailable);
        }
        lease.check()?;
        Ok(lease)
    }
}
