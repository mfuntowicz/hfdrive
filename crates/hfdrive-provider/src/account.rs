//! Public account projections. Membership hints never authorize storage operations.
use hfdrive_auth::{AuthError, AuthSnapshot, LoginSession, LoginState};
use hfdrive_core::ids::AccountKey;
use hfdrive_protocol as wire;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub(crate) fn failure(error: AuthError) -> wire::ProtocolError {
    use wire::ProtocolErrorCode as Code;
    let code = match error {
        AuthError::OAuthClientNotConfigured => Code::OAuthClientNotConfigured,
        AuthError::LoginAlreadyInProgress | AuthError::SignOutInProgress => Code::Busy,
        AuthError::UnknownLoginSession => Code::NotFound,
        AuthError::Cancelled => Code::Cancelled,
        AuthError::Expired => Code::Timeout,
        AuthError::Denied | AuthError::CallbackInvalid | AuthError::OrganizationNotVerified
        | AuthError::ScopesNotGranted | AuthError::IdentityValidation => Code::PermissionDenied,
        AuthError::InvalidGrant | AuthError::NeedsSignIn | AuthError::CredentialRecordUnreadable
        | AuthError::ExistingSessionPreserved => Code::NeedsSignIn,
        AuthError::BrowserLaunch | AuthError::TokenEndpoint | AuthError::DeviceFlowUnavailable
        | AuthError::Persistence | AuthError::ProviderMetadata | AuthError::Internal => Code::Internal,
    };
    wire::ProtocolError { code, message: error.to_string(), retry_after_ms: None }
}

pub(crate) fn request(request: wire::StartLoginRequest) -> Result<hfdrive_auth::LoginRequest, wire::ProtocolError> {
    if request.operation_id.is_nil() {
        return Err(invalid("A nonzero operation identifier is required"));
    }
    Ok(hfdrive_auth::LoginRequest {
        operation_id: request.operation_id,
        flow: match request.flow {
            wire::LoginFlow::Pkce => hfdrive_auth::LoginFlow::Pkce,
            wire::LoginFlow::Device => hfdrive_auth::LoginFlow::Device,
        },
        purpose: match request.purpose {
            wire::LoginPurpose::Signin => hfdrive_auth::LoginPurpose::Signin,
            wire::LoginPurpose::ReadStorage => hfdrive_auth::LoginPurpose::ReadStorage,
            wire::LoginPurpose::WriteStorage => hfdrive_auth::LoginPurpose::WriteStorage,
            wire::LoginPurpose::CreateStorage => hfdrive_auth::LoginPurpose::CreateStorage,
        },
        organization_id: request.organization_id,
    })
}

fn flow(value: hfdrive_auth::LoginFlow) -> wire::LoginFlow {
    match value {
        hfdrive_auth::LoginFlow::Pkce => wire::LoginFlow::Pkce,
        hfdrive_auth::LoginFlow::Device => wire::LoginFlow::Device,
    }
}

fn purpose(value: hfdrive_auth::LoginPurpose) -> wire::LoginPurpose {
    match value {
        hfdrive_auth::LoginPurpose::Signin => wire::LoginPurpose::Signin,
        hfdrive_auth::LoginPurpose::ReadStorage => wire::LoginPurpose::ReadStorage,
        hfdrive_auth::LoginPurpose::WriteStorage => wire::LoginPurpose::WriteStorage,
        hfdrive_auth::LoginPurpose::CreateStorage => wire::LoginPurpose::CreateStorage,
    }
}

fn expires_at(session: &LoginSession) -> Result<String, wire::ProtocolError> {
    let seconds = i64::try_from(session.expires_at_unix).map_err(|_| failure(AuthError::Internal))?;
    OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|_| failure(AuthError::Internal))?
        .format(&Rfc3339)
        .map_err(|_| failure(AuthError::Internal))
}

/// Only the direct reply to an explicit login carries transient instructions.
/// This result must not be stored unprotected in the operation ledger or events.
pub(crate) fn login_result(session: &LoginSession) -> Result<wire::StartLoginResult, wire::ProtocolError> {
    Ok(wire::StartLoginResult {
        session_id: session.session_id,
        authorization_url: session.authorization_url.clone(),
        user_code: session.user_code.clone(),
        verification_uri: session.verification_uri.clone(),
        expires_at: expires_at(session)?,
    })
}

fn progress(session: &LoginSession) -> Result<wire::LoginProgress, wire::ProtocolError> {
    Ok(wire::LoginProgress {
        session_id: session.session_id,
        flow: flow(session.flow),
        purpose: purpose(session.purpose),
        phase: match session.state {
            LoginState::Pending => wire::LoginPhase::Pending,
            LoginState::Completed => wire::LoginPhase::Completed,
            LoginState::Cancelled => wire::LoginPhase::Cancelled,
            LoginState::Expired => wire::LoginPhase::Expired,
            LoginState::Denied => wire::LoginPhase::Denied,
            LoginState::Failed => wire::LoginPhase::Failed,
        },
        expires_at: expires_at(session)?,
    })
}

pub(crate) fn status(snapshot: &AuthSnapshot) -> Result<wire::AccountStatus, wire::ProtocolError> {
    let profile = snapshot.profile.as_ref().map(|profile| {
        wire::AccountProfile {
            account_key: profile.account_key.to_string(),
            issuer: profile.issuer.clone(),
            subject: profile.subject.clone(),
            namespace: profile.namespace.as_str().to_owned(),
            display_name: profile.namespace.as_str().to_owned(),
            granted_scopes: profile.granted_scopes.clone(),
        }
    });
    let login = snapshot.active_login.as_ref().map(progress).transpose()?;
    let state = if snapshot.last_error.as_ref().is_some_and(AuthError::needs_sign_in) {
        wire::AuthenticationState::NeedsSignIn
    } else if login.as_ref().is_some_and(|login| login.phase == wire::LoginPhase::Pending) {
        wire::AuthenticationState::SigningIn
    } else if profile.is_some() {
        wire::AuthenticationState::SignedIn
    } else {
        wire::AuthenticationState::SignedOut
    };
    Ok(wire::AccountStatus {
        state,
        profile,
        login,
        last_error: snapshot.last_error.clone().map(failure),
    })
}

fn invalid(message: &'static str) -> wire::ProtocolError {
    wire::ProtocolError { code: wire::ProtocolErrorCode::InvalidRequest, message: message.into(), retry_after_ms: None }
}

/// Pages only this verified snapshot. A cursor from another identity or revision cannot select it.
/// `resolved` is fresh authenticated whoami-v2 evidence, not OIDC membership identity.
pub(crate) fn owners(
    profile: &hfdrive_auth::AccountProfile,
    revision: u64,
    request: &wire::ListOwnersRequest,
    resolved: &[wire::Owner],
) -> Result<wire::ListOwnersResult, wire::ProtocolError> {
    if !(1..=200).contains(&request.limit) {
        return Err(invalid("Owner page size must be between 1 and 200"));
    }
    let start = if let Some(cursor) = &request.cursor {
        let mut fields = cursor.split(':');
        if fields.next() != Some("owners-v1") { return Err(invalid("Invalid owner continuation cursor")); }
        let account = fields.next().and_then(|value| value.parse::<AccountKey>().ok());
        let cursor_revision = fields.next().and_then(|value| value.parse::<u64>().ok());
        let start = fields.next().and_then(|value| value.parse::<usize>().ok());
        if fields.next().is_some() || account.is_none() || cursor_revision.is_none() || start.is_none() {
            return Err(invalid("Invalid owner continuation cursor"));
        }
        if account != Some(profile.account_key) || cursor_revision != Some(revision) {
            return Err(wire::ProtocolError {
                code: wire::ProtocolErrorCode::Conflict,
                message: "Owner identities changed; reload the first page".into(),
                retry_after_ms: None,
            });
        }
        start.ok_or_else(|| invalid("Invalid owner continuation cursor"))?
    } else { 0 };
    let total = resolved.len();
    if start > total { return Err(invalid("Owner continuation cursor exceeds the current listing")); }
    let end = start.saturating_add(request.limit as usize).min(total);
    let items = resolved.get(start..end).ok_or_else(|| invalid("Owner continuation cursor exceeds the current listing"))?.to_vec();
    Ok(wire::ListOwnersResult {
        items,
        next_cursor: (end < total).then(|| format!("owners-v1:{}:{revision}:{end}", profile.account_key)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hfdrive_core::storage::Namespace;

    fn profile(subject: &str) -> hfdrive_auth::AccountProfile {
        hfdrive_auth::AccountProfile {
            account_key: AccountKey::from_subject("https://huggingface.co", subject),
            issuer: "https://huggingface.co".into(),
            subject: subject.into(),
            namespace: Namespace::new("fixture-person".into()).unwrap(),
            orgs: vec![hfdrive_auth::VerifiedOrg {
                subject: "fixture-org".into(), name: None, role: Some("admin".into()),
                restrictions: vec!["resource-group-limited".into()], consented_this_session: false,
            }],
            granted_scopes: None,
            purpose_covered: false,
            org_consent_requested: false,
            reconsent_required_for_storage: true,
        }
    }

    #[test]
    fn owner_cursor_cannot_cross_accounts_or_identity_revisions() {
        let resolved = vec![
            wire::Owner { owner_kind: wire::OwnerKind::Personal, owner_id: "stable-person".into(), namespace: Some("fixture-person".into()), display_name: "fixture-person".into(), role: None, restrictions: Vec::new(), can_create: true },
            wire::Owner { owner_kind: wire::OwnerKind::Organization, owner_id: "stable-org".into(), namespace: None, display_name: "fixture-org".into(), role: None, restrictions: Vec::new(), can_create: false },
        ];
        let first = owners(&profile("person-a"), 7,
            &wire::ListOwnersRequest { cursor: None, limit: 1 }, &resolved).unwrap();
        let second = wire::ListOwnersRequest { cursor: first.next_cursor, limit: 1 };
        assert_eq!(owners(&profile("person-b"), 7, &second, &resolved).unwrap_err().code,
            wire::ProtocolErrorCode::Conflict);
        assert_eq!(owners(&profile("person-a"), 8, &second, &resolved).unwrap_err().code,
            wire::ProtocolErrorCode::Conflict);
        let page = owners(&profile("person-a"), 7, &second, &resolved).unwrap();
        assert_eq!(page.items[0].owner_id, "stable-org");
        assert_eq!(page.items[0].namespace, None);
        assert!(!page.items[0].can_create, "unresolved canonical namespaces cannot be used for creation");
        assert!(page.items[0].restrictions.is_empty());
    }

    #[test]
    fn unknown_grants_and_signin_required_survive_public_projection() {
        let snapshot = AuthSnapshot {
            revision: 1, profile: Some(profile("person-a")), active_login: None,
            last_error: Some(AuthError::NeedsSignIn),
        };
        let account = status(&snapshot).unwrap();
        assert_eq!(account.state, wire::AuthenticationState::NeedsSignIn);
        assert_eq!(account.profile.unwrap().granted_scopes, None);
    }
}
