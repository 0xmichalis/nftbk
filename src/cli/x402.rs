use std::io::{self, BufReader, Write};

use alloy_primitives::hex;
use alloy_primitives::{Address, FixedBytes, U256};
use alloy_rpc_client::ClientBuilder;
use alloy_sol_types::sol;
use alloy_sol_types::{Eip712Domain, SolStruct};
use anyhow::{Context, Result};
use k256::ecdsa::SigningKey;
use rand::RngCore;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use x402_types::proto::v1::{self, PaymentRequirements};
use x402_types::timestamp::UnixTimestamp;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExactEvmPayloadAuthorization {
    from: Address,
    to: Address,
    value: String,
    valid_after: UnixTimestamp,
    valid_before: UnixTimestamp,
    nonce: FixedBytes<32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExactEvmPayload {
    signature: alloy_primitives::Bytes,
    authorization: ExactEvmPayloadAuthorization,
}

type PaymentPayload = v1::PaymentPayload<String, ExactEvmPayload>;

struct PaymentSigner(SigningKey);

impl From<SigningKey> for PaymentSigner {
    fn from(value: SigningKey) -> Self {
        Self(value)
    }
}

impl PaymentSigner {
    fn address(&self) -> Address {
        let public_key = self.0.verifying_key().to_sec1_point(false);
        let hash = alloy_primitives::keccak256(&public_key.as_bytes()[1..]);
        Address::from_slice(&hash[12..])
    }
}

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

// ERC20 token interface to query decimals
sol! {
    #[allow(missing_docs)]
    interface IERC20 {
        function decimals() external view returns (uint8);
    }
}

/// Get chain ID from network
fn chain_id_from_network(network: &str) -> Result<u64> {
    match network {
        "base" => Ok(8453),
        "base-sepolia" => Ok(84532),
        _ => anyhow::bail!(
            "Only Base and Base Sepolia networks are supported for chain id retrieval"
        ),
    }
}

/// Get RPC URL for network
fn get_rpc_url_for_network(network: &str) -> Result<&'static str> {
    match network {
        "base" => Ok("https://mainnet.base.org"),
        "base-sepolia" => Ok("https://sepolia.base.org"),
        _ => anyhow::bail!(
            "Only Base and Base Sepolia networks are supported for asset decimals queries"
        ),
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
        let wallet = PaymentSigner::from(private_key.clone());

        // Log payment details for debugging
        let account_address = wallet.address();
        info!(
            "Processing x402 payment with account: {} for amount: {} on network: {:?}",
            account_address, payment_requirements.max_amount_required, payment_requirements.network
        );

        // Prompt user for confirmation before proceeding with payment
        if !self
            .confirm_payment(&account_address, &payment_requirements)
            .await?
        {
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
        wallet: &PaymentSigner,
        requirements: &PaymentRequirements,
    ) -> Result<PaymentPayload> {
        // Get the wallet address
        let from_address = wallet.address();
        let from_evm_address = from_address;

        // Parse the recipient address
        let to_evm_address = requirements
            .pay_to
            .parse::<Address>()
            .context("Only EVM addresses are supported for payments")?;

        // Generate a cryptographically secure random nonce
        let nonce = self.generate_secure_nonce()?;

        // Create authorization
        let now = UnixTimestamp::now();
        let authorization = ExactEvmPayloadAuthorization {
            from: from_evm_address,
            to: to_evm_address,
            value: requirements.max_amount_required.clone(),
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
            x402_version: v1::X402Version1,
            scheme: "exact".into(),
            network: requirements.network.clone(),
            payload: exact_payload,
        };

        Ok(payment_payload)
    }

    /// Sign an EIP-712 authorization
    async fn sign_eip712_authorization(
        &self,
        wallet: &PaymentSigner,
        authorization: &ExactEvmPayloadAuthorization,
        requirements: &PaymentRequirements,
    ) -> Result<alloy_primitives::Bytes> {
        // Create the EIP-712 domain
        let domain = self.create_eip712_domain(requirements)?;

        // Create the TransferWithAuthorization struct
        let transfer_with_authorization = TransferWithAuthorization {
            from: authorization.from,
            to: authorization.to,
            value: U256::from_str_radix(&authorization.value, 10)
                .context("Invalid payment amount")?,
            validAfter: U256::from(authorization.valid_after.as_secs()),
            validBefore: U256::from(authorization.valid_before.as_secs()),
            nonce: authorization.nonce,
        };

        // Get the EIP-712 signing hash
        let signing_hash = transfer_with_authorization.eip712_signing_hash(&domain);

        // Sign the hash
        let (signature, recovery_id) = wallet.0.sign_prehash_recoverable(signing_hash.as_slice());
        let mut signature_bytes = signature.to_bytes().to_vec();
        signature_bytes.push(recovery_id.to_byte() + 27);
        Ok(signature_bytes.into())
    }

    /// Create EIP-712 domain for the payment requirements
    fn create_eip712_domain(&self, requirements: &PaymentRequirements) -> Result<Eip712Domain> {
        // Get the token contract address
        let verifying_contract = requirements
            .asset
            .parse::<Address>()
            .context("Only EVM addresses are supported for payments")?;

        // Get chain ID
        let chain_id = chain_id_from_network(&requirements.network)?;

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
    fn generate_secure_nonce(&self) -> Result<FixedBytes<32>> {
        let mut nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        Ok(FixedBytes(nonce_bytes))
    }

    /// Query asset decimals from the blockchain
    async fn query_asset_decimals(&self, requirements: &PaymentRequirements) -> Result<u8> {
        // Only support EVM addresses for now
        let asset_address = requirements
            .asset
            .parse::<Address>()
            .context("Only EVM addresses are supported for asset decimals queries")?;

        // Get RPC URL for the network
        let rpc_url = get_rpc_url_for_network(&requirements.network)?;

        // Create provider
        let provider = ClientBuilder::default()
            .connect(rpc_url)
            .await
            .context("Failed to connect to RPC provider")?;

        // Query decimals
        crate::chain::evm::call_contract(&provider, asset_address, IERC20::decimalsCall {})
            .await
            .context("Failed to query token decimals")
    }

    /// Format token amount with decimals for human-readable display
    fn format_token_amount(amount: &str, decimals: u8) -> Result<String> {
        let amount_u256 = U256::from_str_radix(amount, 10)?;
        let divisor = U256::from(10).pow(U256::from(decimals));

        let whole_part = amount_u256 / divisor;
        let fractional_part = amount_u256 % divisor;

        Ok(if fractional_part == U256::ZERO {
            format!("{}", whole_part)
        } else {
            // Format fractional part with proper padding
            let fractional_str = format!("{:0width$}", fractional_part, width = decimals as usize);
            // Remove trailing zeros
            let fractional_trimmed = fractional_str.trim_end_matches('0');

            if fractional_trimmed.is_empty() {
                format!("{}", whole_part)
            } else {
                format!("{}.{}", whole_part, fractional_trimmed)
            }
        })
    }

    /// Prompt user for confirmation before proceeding with payment
    async fn confirm_payment(
        &self,
        account_address: &Address,
        payment_requirements: &PaymentRequirements,
    ) -> Result<bool> {
        let decimals = self.query_asset_decimals(payment_requirements).await;
        let mut stdin = BufReader::new(io::stdin());
        self.confirm_payment_with_io(
            account_address,
            payment_requirements,
            decimals,
            &mut io::stdout(),
            &mut stdin,
        )
        .await
    }

    /// Prompt user for confirmation with configurable I/O for testing
    async fn confirm_payment_with_io<W: Write, R: std::io::BufRead>(
        &self,
        account_address: &Address,
        payment_requirements: &PaymentRequirements,
        decimals: Result<u8>,
        writer: &mut W,
        reader: &mut R,
    ) -> Result<bool> {
        writeln!(writer, "\n🔐 x402 Payment Authorization Required")?;
        writeln!(writer, "═══════════════════════════════════════")?;
        writeln!(writer, "Account: {}", account_address)?;
        writeln!(writer, "Network: {:?}", payment_requirements.network)?;

        // Query asset decimals and display human-readable amount
        match decimals {
            Ok(decimals) => {
                let human_readable_amount =
                    Self::format_token_amount(&payment_requirements.max_amount_required, decimals)?;
                writeln!(
                    writer,
                    "Amount: {} (raw: {})",
                    human_readable_amount, payment_requirements.max_amount_required
                )?;
            }
            Err(e) => {
                // Fallback to raw amount if decimals query fails
                writeln!(
                    writer,
                    "Amount: {} (failed to query decimals: {})",
                    payment_requirements.max_amount_required, e
                )?;
            }
        }

        // Display token metadata if available
        if let Some(extra) = &payment_requirements.extra {
            if let Some(name) = extra.get("name").and_then(|v| v.as_str()) {
                writeln!(writer, "Token: {}", name)?;
            }
            if let Some(version) = extra.get("version").and_then(|v| v.as_str()) {
                writeln!(writer, "Token Version: {}", version)?;
            }
        }

        writeln!(writer, "Recipient: {}", payment_requirements.pay_to)?;
        writeln!(writer, "Resource: {}", payment_requirements.resource)?;
        writeln!(writer, "Description: {}", payment_requirements.description)?;
        writeln!(
            writer,
            "Timeout: {} seconds",
            payment_requirements.max_timeout_seconds
        )?;

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
mod new_tests {
    use super::*;

    #[test]
    fn rejects_missing_invalid_and_zero_private_keys() {
        for key in [
            None,
            Some("no-hex"),
            Some("00"),
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
        ] {
            assert!(X402PaymentHandler::new(key).is_err());
        }
    }
}

#[cfg(test)]
mod create_payment_payload_tests {
    use super::*;
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use serde_json::json;

    #[tokio::test]
    async fn signs_recoverable_erc3009_authorization_with_the_expected_domain() {
        let handler = X402PaymentHandler::new(Some(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ))
        .unwrap();
        let wallet = PaymentSigner::from(handler.private_key.clone().unwrap());
        let requirements = PaymentRequirements {
            scheme: "exact".into(),
            network: "base".into(),
            max_amount_required: "1234567".into(),
            resource: "https://example.com/v2/backups".into(),
            description: "Snapshot".into(),
            mime_type: "application/json".into(),
            output_schema: None,
            pay_to: "0x1234567890123456789012345678901234567890".into(),
            max_timeout_seconds: 300,
            asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into(),
            extra: Some(json!({"name":"USD Coin","version":"2"})),
        };
        let payload = handler
            .create_payment_payload(&wallet, &requirements)
            .await
            .unwrap();
        let authorization = &payload.payload.authorization;
        assert_eq!(authorization.from, wallet.address());
        assert_eq!(authorization.to.to_string(), requirements.pay_to);
        assert_eq!(authorization.value, "1234567");
        assert_eq!(
            authorization.valid_before.as_secs() - authorization.valid_after.as_secs(),
            300
        );
        assert_ne!(authorization.nonce, FixedBytes::ZERO);
        let transfer = TransferWithAuthorization {
            from: authorization.from,
            to: authorization.to,
            value: U256::from(1_234_567),
            validAfter: U256::from(authorization.valid_after.as_secs()),
            validBefore: U256::from(authorization.valid_before.as_secs()),
            nonce: authorization.nonce,
        };
        let domain = Eip712Domain {
            name: Some("USD Coin".into()),
            version: Some("2".into()),
            chain_id: Some(U256::from(8453)),
            verifying_contract: Some(requirements.asset.parse().unwrap()),
            salt: None,
        };
        let signature = &payload.payload.signature;
        assert_eq!(signature.len(), 65);
        let recovered = VerifyingKey::recover_from_prehash(
            transfer.eip712_signing_hash(&domain).as_slice(),
            &Signature::from_slice(&signature[..64]).unwrap(),
            RecoveryId::from_byte(signature[64] - 27).unwrap(),
        )
        .unwrap();
        assert_eq!(&recovered, wallet.0.verifying_key());
        let wire = serde_json::to_value(&payload).unwrap();
        assert_eq!(wire["x402Version"], 1);
        assert_eq!(wire["network"], "base");
        assert_eq!(wire["scheme"], "exact");
        assert_eq!(wire["payload"]["authorization"]["value"], "1234567");
        let _: v1::PaymentPayload = serde_json::from_value(wire).unwrap();
    }
}

#[cfg(test)]
mod format_token_amount_tests {
    use super::*;

    #[test]
    fn formats_atomic_units_without_losing_precision() {
        for (atomic, decimals, expected) in [
            ("0", 6, "0"),
            ("1000000", 6, "1"),
            ("1234500", 6, "1.2345"),
            ("1", 6, "0.000001"),
            ("100", 0, "100"),
        ] {
            assert_eq!(
                X402PaymentHandler::format_token_amount(atomic, decimals).unwrap(),
                expected
            );
        }
        assert!(X402PaymentHandler::format_token_amount("invalid", 6).is_err());
    }
}

#[cfg(test)]
mod chain_id_from_network_tests {
    use super::*;

    #[test]
    fn restricts_payments_to_supported_networks() {
        assert_eq!(chain_id_from_network("base").unwrap(), 8453);
        assert_eq!(chain_id_from_network("base-sepolia").unwrap(), 84532);
        assert!(chain_id_from_network("polygon").is_err());
    }
}
