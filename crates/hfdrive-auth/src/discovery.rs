//! Strict OIDC discovery and JWKS retrieval.
//!
//! Validation is fail-closed and covers the full trust chain before any
//! client is built:
//!
//! * issuer must equal the configured issuer (production: exactly
//!   `https://huggingface.co`);
//! * every endpoint (authorization, token, userinfo, JWKS) must be HTTPS on a
//!   trusted host with no embedded controls;
//! * `id_token_signing_alg_values_supported` must contain RS256;
//! * the JWKS must be non-empty and fetched from the discovered `jwks_uri`;
//! * redirects are never followed and response bodies are bounded.
//!
//! Discovered metadata is cached per manager instance; tests exercise the
//! same code path against a deterministic local fixture provider.

use openidconnect::core::{
    CoreAuthDisplay, CoreClientAuthMethod, CoreClaimName, CoreClaimType, CoreGrantType,
    CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm,
    CoreJsonWebKey, CoreResponseMode, CoreResponseType, CoreSubjectIdentifierType,
};
use openidconnect::{JsonWebKeySet, ProviderMetadata};
use serde::{Deserialize, Serialize};

use crate::config::OidcSettings;
use crate::error::AuthError;
use crate::http;

/// HF discovery extension field: RFC 8628 device authorization endpoint.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct HfProviderExtra {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) device_authorization_endpoint: Option<String>,
}

impl openidconnect::AdditionalProviderMetadata for HfProviderExtra {}

/// Provider metadata with the HF device-endpoint extension preserved.
pub(crate) type HfProviderMetadata = ProviderMetadata<
    HfProviderExtra,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

/// Discovered and strictly validated provider metadata.
pub(crate) struct Provider {
    pub(crate) metadata: HfProviderMetadata,
}

/// Fetch + validate discovery metadata and the JWKS.
pub(crate) async fn fetch_provider(
    settings: &OidcSettings,
    client: &reqwest::Client,
) -> Result<Provider, AuthError> {
    settings.validate_endpoint(&settings.discovery_url)?;
    let adapter = http::oidc_adapter!(client);

    let request = openidconnect::http::Request::builder()
        .method(openidconnect::http::Method::GET)
        .uri(settings.discovery_url.as_str())
        .header(openidconnect::http::header::ACCEPT, "application/json")
        .body(Vec::new())
        .map_err(|_| AuthError::ProviderMetadata)?;
    let response = http::send_bounded(client, request, http::MAX_OIDC_RESPONSE_BYTES)
        .await
        .map_err(|_| AuthError::ProviderMetadata)?;
    if response.status() != openidconnect::http::StatusCode::OK {
        return Err(AuthError::ProviderMetadata);
    }

    let mut metadata: HfProviderMetadata =
        serde_json::from_slice(response.body()).map_err(|_| AuthError::ProviderMetadata)?;

    // Issuer must match exactly what we configured.
    let issuer = metadata.issuer().as_str().to_owned();
    if issuer != settings.issuer {
        return Err(AuthError::ProviderMetadata);
    }
    settings.validate_issuer(&issuer)?;

    // Every endpoint we will ever contact must be trusted up front.
    settings.validate_endpoint(metadata.authorization_endpoint().as_str())?;
    let token_endpoint = metadata
        .token_endpoint()
        .ok_or(AuthError::ProviderMetadata)?;
    settings.validate_endpoint(token_endpoint.as_str())?;
    let userinfo_endpoint = metadata
        .userinfo_endpoint()
        .ok_or(AuthError::ProviderMetadata)?;
    settings.validate_endpoint(userinfo_endpoint.as_str())?;
    settings.validate_endpoint(metadata.jwks_uri().as_str())?;

    // RS256 must be advertised; verification is additionally restricted to
    // RS256 at token-validation time.
    if !metadata
        .id_token_signing_alg_values_supported()
        .iter()
        .any(|alg| *alg == CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256)
    {
        return Err(AuthError::ProviderMetadata);
    }

    // JWKS: fetched through the same bounded, redirect-free adapter.
    let jwks = JsonWebKeySet::<openidconnect::core::CoreJsonWebKey>::fetch_async(
        metadata.jwks_uri(),
        &adapter,
    )
    .await
    .map_err(|_| AuthError::ProviderMetadata)?;
    if jwks.keys().is_empty() {
        return Err(AuthError::ProviderMetadata);
    }
    // RS256 JWKS: every key must be an RSA signing key; symmetric or
    // elliptic-curve material is rejected outright.
    use openidconnect::JsonWebKey;
    for key in jwks.keys() {
        if *key.key_type() != openidconnect::core::CoreJsonWebKeyType::RSA {
            return Err(AuthError::ProviderMetadata);
        }
    }
    metadata = metadata.set_jwks(jwks);

    Ok(Provider { metadata })
}
