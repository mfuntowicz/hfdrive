//! Account publication follows durable selection; credential material stays in the auth store.
use crate::{Provider, account, operations::{error, internal, state_error}};
use hfdrive_auth::{AccountCredentialStore, AuthError, AuthSnapshot, LoginFlow, LoginState};
use hfdrive_protocol::{self as wire, ProtocolError, ProtocolErrorCode};
use hfdrive_state::{AccountRecord, AccountStatus, CredentialRef};
use std::sync::Arc;

impl Provider {
    pub(crate) async fn synchronize_account(&self) -> Result<AuthSnapshot, ProtocolError> {
        let mut revision = self.account_revision.lock().await;
        let result = self.persist_account_snapshot(&mut revision).await;
        if result.is_err() { let _ = self.tokens.clear(); }
        result
    }

    async fn persist_account_snapshot(&self, persisted_revision: &mut u64) -> Result<AuthSnapshot, ProtocolError> {
        loop {
            let snapshot = self.auth.snapshot();
            if *persisted_revision == snapshot.revision { return Ok(snapshot); }
            let selected = self.state.selected_account().await.map_err(state_error)?;
            let needs_sign_in = snapshot.last_error.as_ref().is_some_and(AuthError::needs_sign_in);
            let mut public = account::status(&snapshot)?;
            let mut admitted = None;
            if let Some(profile) = &snapshot.profile {
                let epoch = self.auth.authorization_epoch(profile.account_key).map_err(account::failure)?;
                let status = if needs_sign_in { AccountStatus::NeedsSignIn } else { AccountStatus::Active };
                self.state.record_account(AccountRecord {
                    account_key: profile.account_key, issuer: profile.issuer.clone(), subject: profile.subject.clone(),
                    namespace: profile.namespace.as_str().to_owned(),
                    credential_ref: CredentialRef(self.auth.credential_record_file_name()), auth_epoch: epoch, status,
                }).await.map_err(state_error)?;
                if selected != Some(profile.account_key) {
                    if let Some(previous) = selected {
                        self.state.set_account_status(previous, AccountStatus::SignedOut).await.map_err(state_error)?;
                    }
                    self.state.select_account(profile.account_key).await.map_err(state_error)?;
                }
                if !needs_sign_in { admitted = Some((profile.account_key, epoch)); }
            } else if let Some(selected) = selected {
                // A retained selected record is not permission to restore a signed-out,
                // unreadable, unconfigured, or previously rejected credential envelope.
                self.state.set_account_status(selected, AccountStatus::NeedsSignIn).await.map_err(state_error)?;
                if snapshot.active_login.as_ref().is_none_or(|login| login.state != LoginState::Pending) {
                    public.state = wire::AuthenticationState::NeedsSignIn;
                    if public.last_error.is_none() { public.last_error = Some(account::failure(AuthError::NeedsSignIn)); }
                }
            }
            if self.auth.snapshot().revision != snapshot.revision { continue; }
            let persisted = self.state.selected_account().await.map_err(state_error)?;
            if persisted != snapshot.profile.as_ref().map(|profile| profile.account_key) { continue; }
            match admitted {
                Some((account, epoch)) => self.tokens.admit(account, epoch),
                None => self.tokens.clear(),
            }.map_err(|_| internal())?;
            self.publish_account(public)?;
            *persisted_revision = snapshot.revision;
            return Ok(snapshot);
        }
    }

    fn publish_account(&self, account: wire::AccountStatus) -> Result<(), ProtocolError> {
        let mut exhausted = false;
        self.status.send_if_modified(|snapshot| {
            if snapshot.account == account { return false; }
            let Some(sequence) = snapshot.sequence.checked_add(1) else { exhausted = true; return false; };
            snapshot.sequence = sequence;
            snapshot.account = account;
            true
        });
        if exhausted { Err(internal()) } else { Ok(()) }
    }

    pub async fn observe_accounts(self: Arc<Self>) {
        let mut receiver = self.auth.watch();
        loop {
            if let Err(error) = self.synchronize_account().await {
                let mut account = self.status.borrow().account.clone();
                account.state = wire::AuthenticationState::NeedsSignIn;
                account.last_error = Some(error);
                let _ = self.publish_account(account);
            } else if let Err(error) = self.restore_connections().await {
                let mut account = self.status.borrow().account.clone();
                account.last_error = Some(error);
                let _ = self.publish_account(account);
            }
            tokio::select! {
                _ = self.shutdown.cancelled() => return,
                changed = receiver.changed() => if changed.is_err() { return; },
            }
        }
    }

    pub(crate) async fn start_login(&self, request: wire::StartLoginRequest) -> Result<wire::StartLoginResult, ProtocolError> {
        let request = account::request(request)?;
        let session = {
            let _revision = self.account_revision.lock().await;
            if self.operations.cancellation.is_cancelled() {
                return Err(error(ProtocolErrorCode::Cancelled, "Provider is draining accepted work"));
            }
            self.auth.start_login(request, self.operations.cancellation.child_token()).map_err(account::failure)?
        };
        // Discovery and device authorization run after admission. A device-flow reply
        // must actually contain its code; returning the initial empty session deadlocks UI.
        let mut receiver = self.auth.watch();
        loop {
            let current = receiver.borrow_and_update().active_login.clone()
                .filter(|current| current.session_id == session.session_id)
                .ok_or_else(|| account::failure(AuthError::UnknownLoginSession))?;
            if let Some(error) = current.error { return Err(account::failure(error)); }
            let instructions_ready = match current.flow {
                LoginFlow::Pkce => current.authorization_url.is_some(),
                LoginFlow::Device => current.user_code.is_some() && current.verification_uri.is_some(),
            };
            if instructions_ready || current.state == LoginState::Completed {
                self.synchronize_account().await?;
                return account::login_result(&current);
            }
            if current.state.is_terminal() { return Err(account::failure(AuthError::Cancelled)); }
            tokio::select! {
                _ = self.operations.cancellation.cancelled() => {
                    self.auth.cancel_login(session.session_id);
                    return Err(account::failure(AuthError::Cancelled));
                }
                changed = receiver.changed() => if changed.is_err() { return Err(internal()); },
            }
        }
    }

    pub(crate) async fn cancel_login(&self, session_id: uuid::Uuid) -> Result<wire::CancelLoginResult, ProtocolError> {
        let cancelled = {
            let _revision = self.account_revision.lock().await;
            self.auth.cancel_login(session_id)
        };
        self.synchronize_account().await?;
        Ok(wire::CancelLoginResult { cancelled })
    }

    pub(crate) async fn sign_out(&self) -> Result<wire::SignOutResult, ProtocolError> {
        let mut revision = self.account_revision.lock().await;
        self.tokens.clear().map_err(|_| internal())?;
        // Stop all remote workers before credential revocation/removal. Their
        // registrations, snapshots and unsynchronized local work remain intact.
        let mut failure = if let Some(engine) = &self.engine {
            engine.disconnect_all().await.err().map(|_| internal())
        } else {
            None
        };
        *self.engine_account.lock().await = None;
        // Revoke memory first, even if SQLite or credential removal is unavailable.
        if let Some(error) = self.auth.sign_out().await.err().map(account::failure) {
            if failure.is_none() { failure = Some(error); }
        }
        let accounts = match self.state.list_accounts().await {
            Ok(accounts) => accounts,
            Err(error) => { failure = Some(state_error(error)); Vec::new() }
        };
        if let Err(error) = self.state.clear_selected_account().await { failure = Some(state_error(error)); }
        for account in &accounts {
            if let Err(error) = self.state.set_account_status(account.account_key, AccountStatus::SignedOut).await {
                failure = Some(state_error(error));
            }
        }
        // Also forget known, inactive accounts from earlier provider instances. Never
        // scan directories or let a database credential_ref choose an arbitrary file.
        let paths = self.paths.clone();
        let removed = tokio::task::spawn_blocking(move || {
            for account in accounts {
                let directory = paths.account(account.account_key).credentials();
                let path = directory.join(AccountCredentialStore::record_file_name());
                if path.try_exists().map_err(|_| AuthError::Persistence)? {
                    AccountCredentialStore::open(directory, account.account_key)?.delete()?;
                }
            }
            Ok::<(), AuthError>(())
        }).await.map_err(|_| internal()).and_then(|result| result.map_err(account::failure));
        if let Err(error) = removed { failure = Some(error); }
        if let Err(error) = self.persist_account_snapshot(&mut revision).await { failure = Some(error); }
        if let Some(error) = failure {
            let mut public = account::status(&self.auth.snapshot())?;
            public.last_error = Some(error.clone());
            self.publish_account(public)?;
            return Err(error);
        }
        Ok(wire::SignOutResult { signed_out: true })
    }
}
