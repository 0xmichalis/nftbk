use josekit::jws::ES256;
use josekit::jwt::decode_with_verifier;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct PrivyClaims {
    pub sub: String, // user DID
    pub iss: String, // issuer
    pub aud: String, // audience
    pub exp: u64,    // expiration
}

pub async fn verify_privy_jwt(
    token: &str,
    verification_key: &str,
    app_id: &str,
) -> Result<PrivyClaims, String> {
    // Use ES256 verifier from PEM
    let verifier = ES256
        .verifier_from_pem(verification_key.as_bytes())
        .map_err(|e| format!("Failed to create verifier: {e}"))?;
    let (payload, _header) = decode_with_verifier(token, &verifier)
        .map_err(|e| format!("JWT validation failed: {e}"))?;
    // Check issuer
    if payload.issuer() != Some("privy.io") {
        return Err("Invalid issuer".to_string());
    }
    // Check audience
    if payload
        .audience()
        .map(|aud| !aud.contains(&app_id))
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
    let claims = PrivyClaims {
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
