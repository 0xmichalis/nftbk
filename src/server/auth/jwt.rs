use josekit::jws::ES256;
use josekit::jwt::decode_with_verifier;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String, // subject (e.g., user DID)
    pub iss: String, // issuer
    pub aud: String, // audience (first entry if multiple)
    pub exp: u64,    // expiration (seconds since epoch)
}

/// Verify an ES256-signed JWT using a PEM-encoded verification key.
/// The token must match the expected issuer and contain the expected audience.
pub async fn verify_jwt(
    token: &str,
    verification_key_pem: &str,
    expected_issuer: &str,
    expected_audience: &str,
) -> Result<JwtClaims, String> {
    let verifier = ES256
        .verifier_from_pem(verification_key_pem.as_bytes())
        .map_err(|e| format!("Failed to create verifier: {e}"))?;
    let (payload, _header) = decode_with_verifier(token, &verifier)
        .map_err(|e| format!("JWT validation failed: {e}"))?;

    // Check issuer
    if payload.issuer() != Some(expected_issuer) {
        return Err("Invalid issuer".to_string());
    }

    // Check audience contains expected value
    if payload
        .audience()
        .map(|aud| !aud.contains(&expected_audience))
        .unwrap_or(true)
    {
        return Err("Invalid audience".to_string());
    }

    // Check expiration
    if let Some(exp) = payload.expires_at() {
        if exp < SystemTime::now() {
            return Err("JWT expired".to_string());
        }
    }

    let claims = JwtClaims {
        sub: payload.subject().unwrap_or_default().to_string(),
        iss: payload.issuer().unwrap_or_default().to_string(),
        aud: payload
            .audience()
            .and_then(|aud| aud.first().map(|s| (*s).to_string()))
            .unwrap_or_default(),
        exp: payload
            .expires_at()
            .map(|t| t.duration_since(UNIX_EPOCH).unwrap().as_secs())
            .unwrap_or(0),
    };

    Ok(claims)
}
