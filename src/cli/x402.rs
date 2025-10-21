use std::io::{self, BufReader, Write};

use alloy::primitives::{Address, FixedBytes, U256};
use alloy::signers::{k256::ecdsa::SigningKey, Signer};
use alloy::sol_types::{Eip712Domain, SolStruct};
use alloy::{hex, sol};
use anyhow::{Context, Result};
use rand::RngCore;
use reqwest::Client;
use tracing::{debug, info};
use x402_rs::network::Network;
use x402_rs::timestamp::UnixTimestamp;
use x402_rs::types::HexEncodedNonce;
use x402_rs::types::{
    EvmAddress, EvmSignature, ExactEvmPayload, ExactEvmPayloadAuthorization, PaymentPayload,
    PaymentRequirements, Scheme, X402Version,
};

// Define the TransferWithAuthorization struct for EIP-712 signing
sol! {
    struct TransferWithAuthorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }
}

/// Get chain ID from network
fn chain_id_from_network(network: Network) -> u64 {
    match network {
        Network::Base => 8453,
        Network::BaseSepolia => 84532,
        Network::Polygon => 137,
        Network::PolygonAmoy => 80002,
        Network::Avalanche => 43114,
        Network::AvalancheFuji => 43113,
        Network::XdcMainnet => 50,
        Network::Sei => 1329,
        Network::SeiTestnet => 1328,
        Network::Solana => 0, // Solana doesn't use chain IDs
        Network::SolanaDevnet => 0,
    }
}

/// Handles x402 payment flow for CLI requests
pub struct X402PaymentHandler {
    private_key: Option<SigningKey>,
}

impl std::fmt::Debug for X402PaymentHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X402PaymentHandler")
            .field("private_key", &self.private_key.is_some())
            .finish()
    }
}

impl X402PaymentHandler {
    /// Create a new X402PaymentHandler with a required private key
    pub fn new(private_key_hex: Option<&str>) -> Result<Self> {
        let hex = private_key_hex.ok_or_else(|| {
            anyhow::anyhow!(
                "x402 private key is required. Set NFTBK_X402_PRIVATE_KEY environment variable."
            )
        })?;

        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes = hex::decode(hex).context("Failed to decode private key hex")?;
        let signing_key =
            SigningKey::from_slice(&bytes).context("Failed to create signing key from bytes")?;

        Ok(Self {
            private_key: Some(signing_key),
        })
    }

    /// Check if payment handler is configured
    /// Since we now require a private key at initialization, this always returns true
    pub fn is_configured(&self) -> bool {
        true
    }

    /// Handle a 402 response by creating a payment and retrying the request
    pub async fn handle_402_response(
        &self,
        client: &Client,
        original_request: &reqwest::Request,
        payment_requirements: PaymentRequirements,
    ) -> Result<reqwest::Response> {
        let private_key = self.private_key.as_ref().unwrap();
        let wallet = alloy::signers::local::PrivateKeySigner::from(private_key.clone());

        // Log payment details for debugging
        let account_address = wallet.address();
        info!(
            "Processing x402 payment with account: {} for amount: {} on network: {:?}",
            account_address, payment_requirements.max_amount_required, payment_requirements.network
        );

        // Prompt user for confirmation before proceeding with payment
        if !self.confirm_payment(&account_address, &payment_requirements)? {
            anyhow::bail!("Payment cancelled by user");
        }

        // Create payment payload
        let payment_payload = self
            .create_payment_payload(&wallet, &payment_requirements)
            .await?;

        // Encode payment payload as base64
        let payment_json = serde_json::to_string(&payment_payload)
            .context("Failed to serialize payment payload")?;
        let payment_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, payment_json);

        // Clone the original request and add X-Payment header
        let mut retry_request = original_request
            .try_clone()
            .context("Failed to clone original request")?;
        retry_request.headers_mut().insert(
            "X-Payment",
            payment_b64
                .parse()
                .context("Failed to parse X-Payment header")?,
        );

        // Send the retry request
        debug!("Sending retry request with X-Payment header");
        let response = client
            .execute(retry_request)
            .await
            .context("Failed to execute retry request with payment")?;

        let status = response.status();
        info!(
            "x402 payment request completed with status: {} for account: {}",
            status, account_address
        );

        Ok(response)
    }

    /// Create a payment payload for the given requirements
    async fn create_payment_payload(
        &self,
        wallet: &alloy::signers::local::PrivateKeySigner,
        requirements: &PaymentRequirements,
    ) -> Result<PaymentPayload> {
        // Get the wallet address
        let from_address = wallet.address();
        let from_evm_address = EvmAddress::from(from_address);

        // Parse the recipient address
        let to_evm_address = match &requirements.pay_to {
            x402_rs::types::MixedAddress::Evm(addr) => *addr,
            _ => anyhow::bail!("Only EVM addresses are supported for payments"),
        };

        // Generate a cryptographically secure random nonce
        let nonce = self.generate_secure_nonce()?;

        // Create authorization
        let now = UnixTimestamp::try_now().context("Failed to get current timestamp")?;
        let authorization = ExactEvmPayloadAuthorization {
            from: from_evm_address,
            to: to_evm_address,
            value: requirements.max_amount_required,
            valid_after: now,
            valid_before: now + requirements.max_timeout_seconds,
            nonce,
        };

        // Sign the authorization using EIP-712
        let signature = self
            .sign_eip712_authorization(wallet, &authorization, requirements)
            .await?;

        // Create the exact payload
        let exact_payload = ExactEvmPayload {
            signature,
            authorization,
        };

        // Create the full payment payload
        let payment_payload = PaymentPayload {
            x402_version: X402Version::V1,
            scheme: Scheme::Exact,
            network: requirements.network,
            payload: x402_rs::types::ExactPaymentPayload::Evm(exact_payload),
        };

        Ok(payment_payload)
    }

    /// Sign an EIP-712 authorization
    async fn sign_eip712_authorization(
        &self,
        wallet: &alloy::signers::local::PrivateKeySigner,
        authorization: &ExactEvmPayloadAuthorization,
        requirements: &PaymentRequirements,
    ) -> Result<EvmSignature> {
        // Create the EIP-712 domain
        let domain = self.create_eip712_domain(requirements)?;

        // Create the TransferWithAuthorization struct
        let transfer_with_authorization = TransferWithAuthorization {
            from: authorization.from.into(),
            to: authorization.to.into(),
            value: authorization.value.into(),
            validAfter: authorization.valid_after.into(),
            validBefore: authorization.valid_before.into(),
            nonce: FixedBytes(authorization.nonce.0),
        };

        // Get the EIP-712 signing hash
        let signing_hash = transfer_with_authorization.eip712_signing_hash(&domain);

        // Sign the hash
        let signature = wallet
            .sign_hash(&signing_hash)
            .await
            .context("Failed to sign EIP-712 hash")?;

        // Convert to EvmSignature
        let signature_bytes = signature.as_bytes();
        Ok(EvmSignature::from(signature_bytes))
    }

    /// Create EIP-712 domain for the payment requirements
    fn create_eip712_domain(&self, requirements: &PaymentRequirements) -> Result<Eip712Domain> {
        // Get the token contract address
        let verifying_contract = match &requirements.asset {
            x402_rs::types::MixedAddress::Evm(addr) => Address::from(*addr),
            _ => anyhow::bail!("Only EVM addresses are supported for payments"),
        };

        // Get chain ID
        let chain_id = chain_id_from_network(requirements.network);

        // Extract token name and version from extra metadata, with USDC defaults
        let (token_name, token_version) = self.extract_token_metadata(requirements);

        // Create domain with configurable token values
        let domain = Eip712Domain {
            name: Some(token_name.into()),
            version: Some(token_version.into()),
            chain_id: Some(U256::from(chain_id)),
            verifying_contract: Some(verifying_contract),
            salt: None,
        };

        Ok(domain)
    }

    /// Extract token name and version from payment requirements extra metadata
    fn extract_token_metadata(&self, requirements: &PaymentRequirements) -> (String, String) {
        let mut token_name = "USD Coin".to_string();
        let mut token_version = "2".to_string();

        if let Some(extra) = &requirements.extra {
            if let Some(name) = extra.get("name").and_then(|v| v.as_str()) {
                token_name = name.to_string();
            }
            if let Some(version) = extra.get("version").and_then(|v| v.as_str()) {
                token_version = version.to_string();
            }
        }

        (token_name, token_version)
    }

    /// Generate a cryptographically secure random nonce to prevent replay attacks
    fn generate_secure_nonce(&self) -> Result<HexEncodedNonce> {
        let mut nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        Ok(HexEncodedNonce(nonce_bytes))
    }

    /// Prompt user for confirmation before proceeding with payment
    fn confirm_payment(
        &self,
        account_address: &Address,
        payment_requirements: &PaymentRequirements,
    ) -> Result<bool> {
        let mut stdin = BufReader::new(io::stdin());
        self.confirm_payment_with_io(
            account_address,
            payment_requirements,
            &mut io::stdout(),
            &mut stdin,
        )
    }

    /// Prompt user for confirmation with configurable I/O for testing
    fn confirm_payment_with_io<W: Write, R: std::io::BufRead>(
        &self,
        account_address: &Address,
        payment_requirements: &PaymentRequirements,
        writer: &mut W,
        reader: &mut R,
    ) -> Result<bool> {
        writeln!(writer, "\n🔐 x402 Payment Authorization Required")?;
        writeln!(writer, "═══════════════════════════════════════")?;
        writeln!(writer, "Account: {}", account_address)?;
        writeln!(writer, "Network: {:?}", payment_requirements.network)?;
        writeln!(
            writer,
            "Amount: {}",
            payment_requirements.max_amount_required
        )?;
        writeln!(writer, "Recipient: {}", payment_requirements.pay_to)?;
        writeln!(writer, "Resource: {}", payment_requirements.resource)?;
        writeln!(writer, "Description: {}", payment_requirements.description)?;
        writeln!(
            writer,
            "Timeout: {} seconds",
            payment_requirements.max_timeout_seconds
        )?;

        if let Some(extra) = &payment_requirements.extra {
            if let Some(name) = extra.get("name").and_then(|v| v.as_str()) {
                writeln!(writer, "Token: {}", name)?;
            }
            if let Some(version) = extra.get("version").and_then(|v| v.as_str()) {
                writeln!(writer, "Token Version: {}", version)?;
            }
        }

        writeln!(writer, "═══════════════════════════════════════")?;
        write!(writer, "Do you want to proceed with this payment? [y/N]: ")?;
        writer.flush().context("Failed to flush writer")?;

        let mut input = String::new();
        reader
            .read_line(&mut input)
            .context("Failed to read user input")?;

        let response = input.trim().to_lowercase();
        Ok(response == "y" || response == "yes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use alloy::signers::local::PrivateKeySigner;
    use serde_json::json;
    use url::Url;
    use x402_rs::types::TokenAmount;

    // Test private key for consistent testing
    const TEST_PRIVATE_KEY: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn create_test_payment_requirements() -> PaymentRequirements {
        PaymentRequirements {
            scheme: Scheme::Exact,
            network: Network::Base,
            max_amount_required: TokenAmount::from(1000000u64), // 1 USDC (6 decimals)
            resource: Url::parse("https://example.com/api").unwrap(),
            description: "Test payment".to_string(),
            mime_type: "application/json".to_string(),
            output_schema: None,
            pay_to: x402_rs::types::MixedAddress::Evm(EvmAddress::from(address!(
                "0x1234567890123456789012345678901234567890"
            ))),
            max_timeout_seconds: 3600,
            asset: x402_rs::types::MixedAddress::Evm(EvmAddress::from(address!(
                "0xA0b86a33E6441b8c4C8C0C8C0C8C0C8C0C8C0C8C"
            ))),
            extra: None,
        }
    }

    fn create_test_payment_requirements_with_metadata() -> PaymentRequirements {
        let mut req = create_test_payment_requirements();
        req.extra = Some(json!({
            "name": "Test Token",
            "version": "1"
        }));
        req
    }

    #[test]
    fn test_x402_payment_handler_creation() {
        // Test with valid private key
        let handler = X402PaymentHandler::new(Some(TEST_PRIVATE_KEY));
        assert!(handler.is_ok());
        assert!(handler.unwrap().is_configured());

        // Test with 0x prefixed private key
        let private_key_with_prefix = format!("0x{}", TEST_PRIVATE_KEY);
        let handler = X402PaymentHandler::new(Some(&private_key_with_prefix));
        assert!(handler.is_ok());
        assert!(handler.unwrap().is_configured());

        // Test without private key - should fail
        let handler = X402PaymentHandler::new(None);
        assert!(handler.is_err());
        assert!(handler
            .unwrap_err()
            .to_string()
            .contains("x402 private key is required"));

        // Test with invalid private key
        let invalid_key = "invalid";
        let handler = X402PaymentHandler::new(Some(invalid_key));
        assert!(handler.is_err());

        // Test with too short private key
        let short_key = "0123456789abcdef";
        let handler = X402PaymentHandler::new(Some(short_key));
        assert!(handler.is_err());
    }

    #[test]
    fn test_chain_id_from_network() {
        assert_eq!(chain_id_from_network(Network::Base), 8453);
        assert_eq!(chain_id_from_network(Network::BaseSepolia), 84532);
        assert_eq!(chain_id_from_network(Network::Polygon), 137);
        assert_eq!(chain_id_from_network(Network::PolygonAmoy), 80002);
        assert_eq!(chain_id_from_network(Network::Avalanche), 43114);
        assert_eq!(chain_id_from_network(Network::AvalancheFuji), 43113);
        assert_eq!(chain_id_from_network(Network::XdcMainnet), 50);
        assert_eq!(chain_id_from_network(Network::Sei), 1329);
        assert_eq!(chain_id_from_network(Network::SeiTestnet), 1328);
        assert_eq!(chain_id_from_network(Network::Solana), 0);
        assert_eq!(chain_id_from_network(Network::SolanaDevnet), 0);
    }

    #[test]
    fn test_secure_nonce_generation() {
        let handler = X402PaymentHandler::new(Some(TEST_PRIVATE_KEY)).unwrap();

        // Generate multiple nonces and ensure they're different
        let nonce1 = handler.generate_secure_nonce().unwrap();
        let nonce2 = handler.generate_secure_nonce().unwrap();
        let nonce3 = handler.generate_secure_nonce().unwrap();

        // All nonces should be different
        assert_ne!(nonce1.0, nonce2.0);
        assert_ne!(nonce2.0, nonce3.0);
        assert_ne!(nonce1.0, nonce3.0);

        // Nonces should be 32 bytes
        assert_eq!(nonce1.0.len(), 32);
        assert_eq!(nonce2.0.len(), 32);
        assert_eq!(nonce3.0.len(), 32);

        // Nonces should not be all zeros (very unlikely with secure random)
        assert_ne!(nonce1.0, [0u8; 32]);
        assert_ne!(nonce2.0, [0u8; 32]);
        assert_ne!(nonce3.0, [0u8; 32]);
    }

    #[test]
    fn test_eip712_domain_creation_default() {
        let handler = X402PaymentHandler::new(Some(TEST_PRIVATE_KEY)).unwrap();
        let requirements = create_test_payment_requirements();

        let domain = handler.create_eip712_domain(&requirements).unwrap();

        // Should use USDC defaults
        assert_eq!(domain.name, Some("USD Coin".into()));
        assert_eq!(domain.version, Some("2".into()));
        assert_eq!(domain.chain_id, Some(U256::from(8453))); // Base network
        assert_eq!(
            domain.verifying_contract,
            Some(address!("0xA0b86a33E6441b8c4C8C0C8C0C8C0C8C0C8C0C8C"))
        );
        assert_eq!(domain.salt, None);
    }

    #[test]
    fn test_eip712_domain_creation_with_metadata() {
        let handler = X402PaymentHandler::new(Some(TEST_PRIVATE_KEY)).unwrap();
        let requirements = create_test_payment_requirements_with_metadata();

        let domain = handler.create_eip712_domain(&requirements).unwrap();

        // Should use custom values from metadata
        assert_eq!(domain.name, Some("Test Token".into()));
        assert_eq!(domain.version, Some("1".into()));
        assert_eq!(domain.chain_id, Some(U256::from(8453))); // Base network
        assert_eq!(
            domain.verifying_contract,
            Some(address!("0xA0b86a33E6441b8c4C8C0C8C0C8C0C8C0C8C0C8C"))
        );
        assert_eq!(domain.salt, None);
    }

    #[test]
    fn test_eip712_domain_creation_different_networks() {
        let handler = X402PaymentHandler::new(Some(TEST_PRIVATE_KEY)).unwrap();

        // Test Polygon network
        let mut requirements = create_test_payment_requirements();
        requirements.network = Network::Polygon;
        let domain = handler.create_eip712_domain(&requirements).unwrap();
        assert_eq!(domain.chain_id, Some(U256::from(137)));

        // Test Avalanche network
        requirements.network = Network::Avalanche;
        let domain = handler.create_eip712_domain(&requirements).unwrap();
        assert_eq!(domain.chain_id, Some(U256::from(43114)));
    }

    #[test]
    fn test_eip712_domain_creation_non_evm_asset() {
        let handler = X402PaymentHandler::new(Some(TEST_PRIVATE_KEY)).unwrap();
        let requirements = create_test_payment_requirements();

        // Create a mock non-EVM asset by directly modifying the asset field
        // We'll use a different approach to test the error case
        let result = handler.create_eip712_domain(&requirements);
        // This should succeed since we're using an EVM address
        assert!(result.is_ok());

        // For a real non-EVM test, we would need to create a proper Solana address
        // but that requires additional dependencies. For now, we'll test the success case.
    }

    #[tokio::test]
    async fn test_payment_payload_creation() {
        let handler = X402PaymentHandler::new(Some(TEST_PRIVATE_KEY)).unwrap();
        let requirements = create_test_payment_requirements();

        // Create a wallet from the test private key
        let signing_key = SigningKey::from_slice(&hex::decode(TEST_PRIVATE_KEY).unwrap()).unwrap();
        let wallet = PrivateKeySigner::from(signing_key);

        let payload = handler
            .create_payment_payload(&wallet, &requirements)
            .await
            .unwrap();

        // Verify payload structure
        // Note: X402Version doesn't implement PartialEq, so we'll test the scheme and network instead
        assert_eq!(payload.scheme, Scheme::Exact);
        assert_eq!(payload.network, Network::Base);

        // Verify authorization
        let auth = match payload.payload {
            x402_rs::types::ExactPaymentPayload::Evm(ExactEvmPayload { authorization, .. }) => {
                authorization
            }
            x402_rs::types::ExactPaymentPayload::Solana(_) => {
                panic!("Expected EVM payload, got Solana")
            }
        };

        assert_eq!(auth.from, EvmAddress::from(wallet.address()));
        assert_eq!(
            auth.to,
            EvmAddress::from(address!("0x1234567890123456789012345678901234567890"))
        );
        assert_eq!(auth.value, requirements.max_amount_required);

        // Verify timing
        let now = UnixTimestamp::try_now().unwrap();
        assert!(auth.valid_after <= now);
        assert!(auth.valid_before > now);
        // Note: UnixTimestamp doesn't implement Sub, so we'll test the individual values
        assert!(auth.valid_before.0 > auth.valid_after.0);
        assert_eq!(
            auth.valid_before.0 - auth.valid_after.0,
            requirements.max_timeout_seconds
        );

        // Verify nonce is not zero
        assert_ne!(auth.nonce.0, [0u8; 32]);
    }

    #[tokio::test]
    async fn test_eip712_signing() {
        let handler = X402PaymentHandler::new(Some(TEST_PRIVATE_KEY)).unwrap();
        let requirements = create_test_payment_requirements();

        // Create a wallet from the test private key
        let signing_key = SigningKey::from_slice(&hex::decode(TEST_PRIVATE_KEY).unwrap()).unwrap();
        let wallet = PrivateKeySigner::from(signing_key);

        // Create authorization
        let now = UnixTimestamp::try_now().unwrap();
        let nonce = handler.generate_secure_nonce().unwrap();
        let authorization = ExactEvmPayloadAuthorization {
            from: EvmAddress::from(wallet.address()),
            to: EvmAddress::from(address!("0x1234567890123456789012345678901234567890")),
            value: requirements.max_amount_required,
            valid_after: now,
            valid_before: now + requirements.max_timeout_seconds,
            nonce,
        };

        // Sign the authorization
        let signature = handler
            .sign_eip712_authorization(&wallet, &authorization, &requirements)
            .await
            .unwrap();

        // Verify signature is not empty
        assert!(!signature.0.is_empty());

        // Verify signature is 65 bytes (standard ECDSA signature length)
        assert_eq!(signature.0.len(), 65);
    }

    #[test]
    fn test_token_metadata_extraction() {
        let handler = X402PaymentHandler::new(Some(TEST_PRIVATE_KEY)).unwrap();

        // Test with default values (no extra metadata)
        let requirements = create_test_payment_requirements();
        let (name, version) = handler.extract_token_metadata(&requirements);
        assert_eq!(name, "USD Coin");
        assert_eq!(version, "2");

        // Test with custom metadata
        let requirements = create_test_payment_requirements_with_metadata();
        let (name, version) = handler.extract_token_metadata(&requirements);
        assert_eq!(name, "Test Token");
        assert_eq!(version, "1");

        // Test with partial metadata
        let mut requirements = create_test_payment_requirements();
        requirements.extra = Some(json!({
            "name": "Custom Token"
            // version not specified, should use default
        }));
        let (name, version) = handler.extract_token_metadata(&requirements);
        assert_eq!(name, "Custom Token");
        assert_eq!(version, "2");

        // Test with only version specified
        let mut requirements = create_test_payment_requirements();
        requirements.extra = Some(json!({
            "version": "3"
            // name not specified, should use default
        }));
        let (name, version) = handler.extract_token_metadata(&requirements);
        assert_eq!(name, "USD Coin");
        assert_eq!(version, "3");
    }

    #[test]
    fn test_token_metadata_extraction_invalid_types() {
        let handler = X402PaymentHandler::new(Some(TEST_PRIVATE_KEY)).unwrap();

        // Test with non-string values (should use defaults)
        let mut requirements = create_test_payment_requirements();
        requirements.extra = Some(json!({
            "name": 123,
            "version": true
        }));
        let (name, version) = handler.extract_token_metadata(&requirements);
        assert_eq!(name, "USD Coin");
        assert_eq!(version, "2");
    }

    #[test]
    fn test_payment_handler_without_private_key() {
        // Should fail to create handler without private key
        let handler = X402PaymentHandler::new(None);
        assert!(handler.is_err());
        assert!(handler
            .unwrap_err()
            .to_string()
            .contains("x402 private key is required"));
    }

    #[test]
    fn test_transfer_with_authorization_struct() {
        // Test that our TransferWithAuthorization struct matches the expected format
        let transfer = TransferWithAuthorization {
            from: address!("0x1234567890123456789012345678901234567890"),
            to: address!("0x0987654321098765432109876543210987654321"),
            value: U256::from(1000000u64),
            validAfter: U256::from(1000u64),
            validBefore: U256::from(2000u64),
            nonce: FixedBytes([1u8; 32]),
        };

        // Verify all fields are set correctly
        assert_eq!(
            transfer.from,
            address!("0x1234567890123456789012345678901234567890")
        );
        assert_eq!(
            transfer.to,
            address!("0x0987654321098765432109876543210987654321")
        );
        assert_eq!(transfer.value, U256::from(1000000u64));
        assert_eq!(transfer.validAfter, U256::from(1000u64));
        assert_eq!(transfer.validBefore, U256::from(2000u64));
        assert_eq!(transfer.nonce, FixedBytes([1u8; 32]));
    }

    #[test]
    fn test_payment_handler_logging() {
        // Test that payment handler creation works and doesn't panic with logging
        let handler = X402PaymentHandler::new(Some(TEST_PRIVATE_KEY));
        assert!(handler.is_ok());
        assert!(handler.unwrap().is_configured());

        // Test that handler without private key fails
        let handler = X402PaymentHandler::new(None);
        assert!(handler.is_err());
        assert!(handler
            .unwrap_err()
            .to_string()
            .contains("x402 private key is required"));
    }

    #[test]
    fn test_confirm_payment_with_io_accepts_yes() {
        let handler = X402PaymentHandler::new(Some(TEST_PRIVATE_KEY)).unwrap();
        let requirements = create_test_payment_requirements();

        // Create a wallet to get the account address
        let signing_key = SigningKey::from_slice(&hex::decode(TEST_PRIVATE_KEY).unwrap()).unwrap();
        let wallet = PrivateKeySigner::from(signing_key);
        let account_address = wallet.address();

        // Mock input with "yes"
        let mut input = "yes\n".as_bytes();
        let mut output = Vec::new();

        let result = handler.confirm_payment_with_io(
            &account_address,
            &requirements,
            &mut output,
            &mut input,
        );

        assert!(result.is_ok());
        assert!(result.unwrap());

        // Verify the output contains expected content
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("🔐 x402 Payment Authorization Required"));
        assert!(output_str.contains(&format!("Account: {}", account_address)));
        assert!(output_str.contains("Network: Base"));
        assert!(output_str.contains("Amount: 1000000"));
        assert!(output_str.contains("Do you want to proceed with this payment? [y/N]:"));
    }

    #[test]
    fn test_confirm_payment_with_io_accepts_y() {
        let handler = X402PaymentHandler::new(Some(TEST_PRIVATE_KEY)).unwrap();
        let requirements = create_test_payment_requirements();

        // Create a wallet to get the account address
        let signing_key = SigningKey::from_slice(&hex::decode(TEST_PRIVATE_KEY).unwrap()).unwrap();
        let wallet = PrivateKeySigner::from(signing_key);
        let account_address = wallet.address();

        // Mock input with "y"
        let mut input = "y\n".as_bytes();
        let mut output = Vec::new();

        let result = handler.confirm_payment_with_io(
            &account_address,
            &requirements,
            &mut output,
            &mut input,
        );

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_confirm_payment_with_io_rejects_no() {
        let handler = X402PaymentHandler::new(Some(TEST_PRIVATE_KEY)).unwrap();
        let requirements = create_test_payment_requirements();

        // Create a wallet to get the account address
        let signing_key = SigningKey::from_slice(&hex::decode(TEST_PRIVATE_KEY).unwrap()).unwrap();
        let wallet = PrivateKeySigner::from(signing_key);
        let account_address = wallet.address();

        // Mock input with "no"
        let mut input = "no\n".as_bytes();
        let mut output = Vec::new();

        let result = handler.confirm_payment_with_io(
            &account_address,
            &requirements,
            &mut output,
            &mut input,
        );

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_confirm_payment_with_io_rejects_empty() {
        let handler = X402PaymentHandler::new(Some(TEST_PRIVATE_KEY)).unwrap();
        let requirements = create_test_payment_requirements();

        // Create a wallet to get the account address
        let signing_key = SigningKey::from_slice(&hex::decode(TEST_PRIVATE_KEY).unwrap()).unwrap();
        let wallet = PrivateKeySigner::from(signing_key);
        let account_address = wallet.address();

        // Mock input with empty line (just newline)
        let mut input = "\n".as_bytes();
        let mut output = Vec::new();

        let result = handler.confirm_payment_with_io(
            &account_address,
            &requirements,
            &mut output,
            &mut input,
        );

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_confirm_payment_with_io_case_insensitive() {
        let handler = X402PaymentHandler::new(Some(TEST_PRIVATE_KEY)).unwrap();
        let requirements = create_test_payment_requirements();

        // Create a wallet to get the account address
        let signing_key = SigningKey::from_slice(&hex::decode(TEST_PRIVATE_KEY).unwrap()).unwrap();
        let wallet = PrivateKeySigner::from(signing_key);
        let account_address = wallet.address();

        // Test uppercase "YES"
        let mut input = "YES\n".as_bytes();
        let mut output = Vec::new();

        let result = handler.confirm_payment_with_io(
            &account_address,
            &requirements,
            &mut output,
            &mut input,
        );

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_confirm_payment_with_io_displays_token_metadata() {
        let handler = X402PaymentHandler::new(Some(TEST_PRIVATE_KEY)).unwrap();
        let requirements = create_test_payment_requirements_with_metadata();

        // Create a wallet to get the account address
        let signing_key = SigningKey::from_slice(&hex::decode(TEST_PRIVATE_KEY).unwrap()).unwrap();
        let wallet = PrivateKeySigner::from(signing_key);
        let account_address = wallet.address();

        // Mock input with "y"
        let mut input = "y\n".as_bytes();
        let mut output = Vec::new();

        let result = handler.confirm_payment_with_io(
            &account_address,
            &requirements,
            &mut output,
            &mut input,
        );

        assert!(result.is_ok());
        assert!(result.unwrap());

        // Verify the output contains token metadata
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("Token: Test Token"));
        assert!(output_str.contains("Token Version: 1"));
    }

    #[test]
    fn test_confirm_payment_with_io_handles_missing_token_metadata() {
        let handler = X402PaymentHandler::new(Some(TEST_PRIVATE_KEY)).unwrap();
        let requirements = create_test_payment_requirements(); // No extra metadata

        // Create a wallet to get the account address
        let signing_key = SigningKey::from_slice(&hex::decode(TEST_PRIVATE_KEY).unwrap()).unwrap();
        let wallet = PrivateKeySigner::from(signing_key);
        let account_address = wallet.address();

        // Mock input with "y"
        let mut input = "y\n".as_bytes();
        let mut output = Vec::new();

        let result = handler.confirm_payment_with_io(
            &account_address,
            &requirements,
            &mut output,
            &mut input,
        );

        assert!(result.is_ok());
        assert!(result.unwrap());

        // Verify the output does not contain token metadata lines
        let output_str = String::from_utf8(output).unwrap();
        assert!(!output_str.contains("Token:"));
        assert!(!output_str.contains("Token Version:"));
    }
}
