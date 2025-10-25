use base64::Engine;
use josekit::jwk::Jwk;
use josekit::jws::alg::eddsa::EddsaJwsAlgorithm;
use josekit::jws::JwsHeader;
use josekit::jws::ES256;
use josekit::jwt::{decode_with_verifier, JwtPayload};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(serde::Deserialize, Clone, Debug)]
pub struct JwtCredential {
    pub issuer: String,
    pub audience: String,
    pub verification_key: String,
}

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

/// JWT claims structure for Coinbase CDP SDK authentication
#[derive(Debug, Serialize)]
struct CoinbaseClaims {
    /// Subject - the API key ID
    sub: String,
    aud: String,
    iss: String,
    /// Expiration time (Unix timestamp)
    ///
    exp: u64,
    uris: Vec<String>,
}

/// Convert CoinbaseClaims into a JwtPayload, setting standard and custom claims.
fn coinbase_claims_to_payload(
    claims: &CoinbaseClaims,
    now_unix: u64,
) -> Result<JwtPayload, String> {
    let mut payload = JwtPayload::new();
    // Standard claims
    payload.set_subject(&claims.sub);
    let exp_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(claims.exp);
    payload.set_expires_at(&exp_time);
    let iat_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(now_unix);
    payload.set_issued_at(&iat_time);
    payload.set_not_before(&iat_time);

    // Custom claims: iss, aud, uris
    let claims_json =
        serde_json::to_value(claims).map_err(|e| format!("Failed to serialize claims: {e}"))?;

    if let Some(iss) = claims_json.get("iss") {
        payload
            .set_claim("iss", Some(iss.clone()))
            .map_err(|e| format!("Failed to set iss claim: {e}"))?;
    }
    if let Some(aud) = claims_json.get("aud") {
        payload
            .set_claim("aud", Some(aud.clone()))
            .map_err(|e| format!("Failed to set aud claim: {e}"))?;
    }
    if let Some(uris) = claims_json.get("uris") {
        payload
            .set_claim("uris", Some(uris.clone()))
            .map_err(|e| format!("Failed to set uris claim: {e}"))?;
    }

    Ok(payload)
}

/// Generate a standard CDP JWS header with specified alg, JWT typ, kid and random nonce
fn generate_cdp_jwt_header(api_key_id: &str) -> JwsHeader {
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    header.set_algorithm("EdDSA");
    header.set_key_id(api_key_id);
    // Add a random nonce per CDP guidance to prevent replay
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    header.set_nonce(nonce);
    header
}

/// Build an Ed25519 OKP JWK from a base64-encoded 64-byte key (seed[32] + public[32])
fn build_ed25519_jwk_from_base64_seed_public(
    api_key_id: &str,
    key_b64: &str,
) -> Result<Jwk, String> {
    let decoded = match base64::engine::general_purpose::STANDARD.decode(key_b64.as_bytes()) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(
                "Invalid key: expected base64-encoded Ed25519 (64 bytes seed+public)".to_string(),
            );
        }
    };
    if decoded.len() != 64 {
        return Err("Invalid Ed25519 key length: expected 64 bytes (seed+public)".to_string());
    }
    let seed = &decoded[0..32];
    let public_key = &decoded[32..64];

    let mut jwk = Jwk::new("OKP");
    jwk.set_curve("Ed25519");
    jwk.set_algorithm("EdDSA");
    jwk.set_key_id(api_key_id.to_string());
    jwk.set_key_use("sig");
    jwk.set_key_operations(vec!["sign".to_string()]);
    let d_b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed);
    let x_b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key);
    jwk.set_parameter("d", Some(serde_json::Value::String(d_b64url)))
        .map_err(|e| e.to_string())?;
    jwk.set_parameter("x", Some(serde_json::Value::String(x_b64url)))
        .map_err(|e| e.to_string())?;
    Ok(jwk)
}

/// Generate a JWT token for Coinbase API authentication
///
/// This function creates a JWT assuming the API key is a Ed25519 key which is the default
/// algorithm for new API keys generated by CDP.
///
/// # Arguments
/// * `api_key_id` - The API key ID to use as the subject
/// * `api_key_secret` - The API key secret to use for signing
/// * `request_method` - The HTTP method (e.g., "GET", "POST")
/// * `request_host` - The host of the request (e.g., "api.cdp.coinbase.com")
/// * `request_path` - The path of the request (e.g., "/platform/v2/x402/verify")
/// * `expires_in` - Token expiration time in seconds (defaults to 120 if not specified)
///
/// # Returns
/// * `Ok(String)` - The generated JWT token
/// * `Err(String)` - If JWT generation fails
pub fn generate_cdp_jwt(
    api_key_id: &str,
    api_key_secret: &str,
    request_method: &str,
    request_host: &str,
    request_path: &str,
    expires_in: Option<u64>,
) -> Result<String, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    // Prepare claims
    let normalized_host = request_host
        .strip_prefix("https://")
        .or_else(|| request_host.strip_prefix("http://"))
        .unwrap_or(request_host);
    let combined_uri = format!("{} {}{}", request_method, normalized_host, request_path);
    let claims = CoinbaseClaims {
        sub: api_key_id.to_owned(),
        iss: "cdp".to_string(),
        aud: "cdp_service".to_owned(),
        exp: now + expires_in.unwrap_or(120),
        uris: vec![combined_uri],
    };

    // Create JWT payload
    let payload = coinbase_claims_to_payload(&claims, now)?;

    // Create JWT header
    let header = generate_cdp_jwt_header(api_key_id);

    // Create JWT signer
    let jwk = build_ed25519_jwk_from_base64_seed_public(api_key_id, api_key_secret)?;
    let signer = EddsaJwsAlgorithm::Eddsa
        .signer_from_jwk(&jwk)
        .map_err(|e| format!("Failed to create EdDSA signer: {e}"))?;

    // Generate JWT token
    let token = josekit::jwt::encode_with_signer(&payload, &header, &signer)
        .map_err(|e| format!("Failed to encode JWT: {e}"))?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs8::EncodePublicKey;
    use tokio_test::block_on;

    #[test]
    fn test_generate_cdp_jwt_ed25519_default_and_params() {
        use ed25519_dalek::{SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
        use rand_core::OsRng as EdOsRng;

        let signing_key = EdSigningKey::generate(&mut EdOsRng);
        let verifying_key: EdVerifyingKey = (&signing_key).into();
        let mut concat = Vec::with_capacity(64);
        concat.extend_from_slice(&signing_key.to_bytes());
        concat.extend_from_slice(verifying_key.as_bytes());
        let b64 = base64::engine::general_purpose::STANDARD.encode(concat);

        // default expiration
        let t1 = generate_cdp_jwt(
            "test_key_id",
            &b64,
            "GET",
            "https://api.cdp.coinbase.com",
            "/platform/v2/x402/verify",
            None,
        );
        assert!(t1.is_ok());
        assert_eq!(t1.unwrap().split('.').count(), 3);

        // custom params
        let t2 = generate_cdp_jwt(
            "my_api_key",
            &b64,
            "POST",
            "api.example.com",
            "/v1/endpoint",
            Some(300),
        );
        assert!(t2.is_ok());
    }

    #[test]
    fn test_generate_cdp_jwt_headers_and_claims_verified() {
        use base64::Engine;
        use ed25519_dalek::{SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
        use rand_core::OsRng as EdOsRng;

        // Generate keypair and the base64 seed+public secret
        let signing_key = EdSigningKey::generate(&mut EdOsRng);
        let verifying_key: EdVerifyingKey = (&signing_key).into();
        let mut concat = Vec::with_capacity(64);
        concat.extend_from_slice(&signing_key.to_bytes());
        concat.extend_from_slice(verifying_key.as_bytes());
        let secret_b64 = base64::engine::general_purpose::STANDARD.encode(concat);

        let api_key_id = "kid_123";
        let method = "GET";
        let host = "api.cdp.coinbase.com";
        let path = "/platform/v2/x402/supported";
        let token = generate_cdp_jwt(api_key_id, &secret_b64, method, host, path, Some(120))
            .expect("jwt generated");

        // Build a public JWK for verification
        let x_b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifying_key); // 32 bytes
        let mut pub_jwk = Jwk::new("OKP");
        pub_jwk.set_curve("Ed25519");
        pub_jwk.set_algorithm("EdDSA");
        pub_jwk.set_key_id(api_key_id.to_string());
        pub_jwk.set_key_use("sig");
        pub_jwk.set_key_operations(vec!["verify".to_string()]);
        pub_jwk
            .set_parameter("x", Some(serde_json::Value::String(x_b64url)))
            .unwrap();

        // Verify signature and decode
        let verifier = EddsaJwsAlgorithm::Eddsa
            .verifier_from_jwk(&pub_jwk)
            .expect("ed verifier");
        let (payload, header) =
            josekit::jwt::decode_with_verifier(&token, &verifier).expect("jwt verified");

        // Header checks
        assert_eq!(header.algorithm(), Some("EdDSA"));
        assert_eq!(header.key_id(), Some(api_key_id));
        assert!(header.nonce().is_some());

        // Payload checks
        assert_eq!(payload.subject(), Some(api_key_id));
        // Custom claims
        let iss = payload.claim("iss").and_then(|v| v.as_str());
        assert_eq!(iss, Some("cdp"));
        let aud = payload.claim("aud").and_then(|v| v.as_str());
        assert_eq!(aud, Some("cdp_service"));
        // uris array with exactly one value
        let uris = payload.claim("uris").and_then(|v| v.as_array());
        assert!(uris.is_some());
        let combined = format!("{} {}{}", method, host, path);
        assert_eq!(uris.unwrap().len(), 1);
        assert_eq!(uris.unwrap()[0].as_str(), Some(combined.as_str()));

        // Expiration sanity: exp > now
        let now = std::time::SystemTime::now();
        let now_secs = now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let exp = payload
            .expires_at()
            .expect("exp present")
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(exp > now_secs);
    }

    #[test]
    fn test_build_ed25519_jwk_invalid_base64() {
        let res = build_ed25519_jwk_from_base64_seed_public("kid", "@@@not-base64@@@");
        assert!(res.is_err());
        let msg = res.err().unwrap();
        assert!(msg.contains("base64-encoded Ed25519"));
    }

    #[test]
    fn test_build_ed25519_jwk_wrong_length() {
        // 32 bytes only
        let thirty_two = vec![1u8; 32];
        let b64 = base64::engine::general_purpose::STANDARD.encode(thirty_two);
        let res = build_ed25519_jwk_from_base64_seed_public("kid", &b64);
        assert!(res.is_err());
        let msg = res.err().unwrap();
        assert!(msg.contains("expected 64 bytes"));
    }

    #[test]
    fn test_generate_cdp_jwt_invalid_base64_secret() {
        let res = generate_cdp_jwt(
            "kid",
            "not_base64!!!",
            "GET",
            "api.cdp.coinbase.com",
            "/platform/v2/x402/supported",
            None,
        );
        assert!(res.is_err());
        let msg = res.err().unwrap();
        assert!(msg.contains("base64-encoded Ed25519"));
    }

    #[test]
    fn test_generate_cdp_jwt_secret_wrong_length() {
        // 48 bytes to trigger wrong length
        let forty_eight = vec![2u8; 48];
        let b64 = base64::engine::general_purpose::STANDARD.encode(forty_eight);
        let res = generate_cdp_jwt(
            "kid",
            &b64,
            "POST",
            "api.cdp.coinbase.com",
            "/platform/v2/x402/verify",
            Some(60),
        );
        assert!(res.is_err());
        let msg = res.err().unwrap();
        assert!(msg.contains("expected 64 bytes"));
    }

    #[test]
    fn test_verify_jwt_success_and_failures() {
        use p256::ecdsa::SigningKey;
        use pkcs8::EncodePrivateKey;
        use rand_core::OsRng;

        // Generate ES256 keypair for verification tests
        let signing_key = SigningKey::random(&mut OsRng);
        let private_pem = signing_key
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .expect("pem")
            .to_string();
        let public_pem = signing_key
            .verifying_key()
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .expect("pub pem");

        // Make a simple ES256 JWT to validate verify_jwt path
        let mut header = JwsHeader::new();
        header.set_algorithm("ES256");
        let mut payload = JwtPayload::new();
        payload.set_subject("subj");
        let now = std::time::SystemTime::now();
        payload.set_issued_at(&now);
        payload.set_not_before(&now);
        let exp = now + std::time::Duration::from_secs(60);
        payload.set_expires_at(&exp);
        payload
            .set_claim("iss", Some(serde_json::Value::String("issuer".into())))
            .unwrap();
        payload
            .set_claim("aud", Some(serde_json::Value::String("audience".into())))
            .unwrap();

        let signer = josekit::jws::ES256
            .signer_from_pem(private_pem.as_bytes())
            .expect("es256 signer");
        let token = josekit::jwt::encode_with_signer(&payload, &header, &signer).expect("encode");

        // Success case
        let ok = block_on(verify_jwt(&token, &public_pem, "issuer", "audience"));
        assert!(ok.is_ok());

        // Wrong issuer
        let bad_iss = block_on(verify_jwt(&token, &public_pem, "wrong", "audience"));
        assert!(bad_iss.is_err());

        // Wrong audience
        let bad_aud = block_on(verify_jwt(&token, &public_pem, "issuer", "wrong"));
        assert!(bad_aud.is_err());

        // Expired token
        let mut payload2 = JwtPayload::new();
        payload2.set_subject("subj");
        payload2.set_issued_at(&now);
        payload2.set_not_before(&now);
        let past = now - std::time::Duration::from_secs(10);
        payload2.set_expires_at(&past);
        payload2
            .set_claim("iss", Some(serde_json::Value::String("issuer".into())))
            .unwrap();
        payload2
            .set_claim("aud", Some(serde_json::Value::String("audience".into())))
            .unwrap();
        let token2 = josekit::jwt::encode_with_signer(&payload2, &header, &signer).expect("enc2");
        let expired = block_on(verify_jwt(&token2, &public_pem, "issuer", "audience"));
        assert!(expired.is_err());
    }
}
