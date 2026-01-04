use axum::http::HeaderMap;
use tracing::warn;
use url::Url;
use x402_axum::layer::X402Error;
use x402_rs::types::TokenAmount;

use crate::server::x402::X402Config;
use crate::server::AppState;

/// Parse a price string (e.g., "0.1069") directly to microdollars (u64)
/// without using floating-point arithmetic to avoid precision loss.
/// USDC has 6 decimal places, so we multiply by 1_000_000.
pub fn parse_usdc_price_to_wei(price_str: &str) -> Result<u64, String> {
    let price_str = price_str.trim();
    if price_str.is_empty() {
        return Err("Price string is empty".to_string());
    }

    let parts: Vec<&str> = price_str.split('.').collect();
    if parts.len() > 2 {
        return Err("Invalid price format: multiple decimal points".to_string());
    }

    let whole_part = parts[0]
        .parse::<u64>()
        .map_err(|e| format!("Failed to parse whole part '{}': {}", parts[0], e))?;

    let fractional_part = if parts.len() == 2 {
        let frac_str = parts[1];
        if frac_str.is_empty() {
            0
        } else if frac_str.len() > 6 {
            return Err(format!(
                "Price has more than 6 decimal places: {}",
                frac_str.len()
            ));
        } else {
            let frac_value = frac_str
                .parse::<u64>()
                .map_err(|e| format!("Failed to parse fractional part '{}': {}", frac_str, e))?;
            // Scale fractional part to microdollars by multiplying by 10^(6 - len)
            // e.g., "1069" (4 digits) -> 1069 * 10^2 = 106900
            let scale = 6 - frac_str.len();
            frac_value
                .checked_mul(10_u64.pow(scale as u32))
                .ok_or_else(|| "Fractional part too large, would overflow".to_string())?
        }
    } else {
        0
    };

    let microdollars = whole_part
        .checked_mul(1_000_000)
        .and_then(|w| w.checked_add(fractional_part))
        .ok_or_else(|| "Price value too large, would overflow".to_string())?;

    Ok(microdollars)
}

async fn compute_dynamic_price_impl(
    state: AppState,
    config: X402Config,
    quote_id: Option<String>,
) -> Result<TokenAmount, X402Error> {
    let quote_id = quote_id.ok_or_else(|| {
        X402Error::verification_failed("X-Quote-Id header is required".to_string(), Vec::new())
    })?;

    let mut cache = state.quote_cache.lock().await;
    let price_opt = cache
        .get(&quote_id)
        .ok_or_else(|| {
            X402Error::verification_failed(
                format!("Quote {quote_id} not found in cache"),
                Vec::new(),
            )
        })?
        .price;

    let price_wei = price_opt.ok_or_else(|| {
        X402Error::verification_failed(
            format!("Quote {quote_id} exists but has no price set"),
            Vec::new(),
        )
    })?;

    drop(cache);

    // Validate the price tag
    let _price_tag = config
        .usdc_price_tag_for_token_amount(price_wei)
        .map_err(|e| {
            let error_msg = format!(
                "Failed to build price tag from amount '{}': {}",
                price_wei, e
            );
            warn!("{}", error_msg);
            X402Error::verification_failed(error_msg, Vec::new())
        })?;

    let token_amount = TokenAmount::from(price_wei);

    Ok(token_amount)
}

pub fn create_dynamic_price_callback(
    state: AppState,
    config: X402Config,
) -> Box<x402_axum::layer::DynamicPriceCallback> {
    Box::new(
        move |headers: &HeaderMap, _uri: &axum::http::Uri, _base_url: &Url| {
            let state = state.clone();
            let config = config.clone();
            let quote_id = headers
                .get("X-Quote-Id")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            Box::pin(compute_dynamic_price_impl(state, config, quote_id))
        },
    )
}

#[cfg(test)]
mod parse_usdc_price_to_wei_tests {
    use super::*;

    #[test]
    fn test_parse_whole_number() {
        assert_eq!(parse_usdc_price_to_wei("0"), Ok(0));
        assert_eq!(parse_usdc_price_to_wei("1"), Ok(1_000_000));
        assert_eq!(parse_usdc_price_to_wei("10"), Ok(10_000_000));
        assert_eq!(parse_usdc_price_to_wei("100"), Ok(100_000_000));
    }

    #[test]
    fn test_parse_with_decimal_places() {
        assert_eq!(parse_usdc_price_to_wei("0.1"), Ok(100_000));
        assert_eq!(parse_usdc_price_to_wei("0.01"), Ok(10_000));
        assert_eq!(parse_usdc_price_to_wei("0.001"), Ok(1_000));
        assert_eq!(parse_usdc_price_to_wei("0.0001"), Ok(100));
        assert_eq!(parse_usdc_price_to_wei("0.00001"), Ok(10));
        assert_eq!(parse_usdc_price_to_wei("0.000001"), Ok(1));
    }

    #[test]
    fn test_parse_with_partial_decimal_places() {
        assert_eq!(parse_usdc_price_to_wei("0.1069"), Ok(106_900));
        assert_eq!(parse_usdc_price_to_wei("1.5"), Ok(1_500_000));
        assert_eq!(parse_usdc_price_to_wei("10.25"), Ok(10_250_000));
        assert_eq!(parse_usdc_price_to_wei("100.123456"), Ok(100_123_456));
    }

    #[test]
    fn test_parse_with_whitespace() {
        assert_eq!(parse_usdc_price_to_wei(" 0.1 "), Ok(100_000));
        assert_eq!(parse_usdc_price_to_wei("1.5 "), Ok(1_500_000));
        assert_eq!(parse_usdc_price_to_wei(" 10"), Ok(10_000_000));
    }

    #[test]
    fn test_parse_large_values() {
        assert_eq!(parse_usdc_price_to_wei("1000"), Ok(1_000_000_000));
        assert_eq!(parse_usdc_price_to_wei("10000"), Ok(10_000_000_000));
        assert_eq!(parse_usdc_price_to_wei("100000"), Ok(100_000_000_000));
    }

    #[test]
    fn test_parse_empty_string() {
        let result = parse_usdc_price_to_wei("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Price string is empty"));
    }

    #[test]
    fn test_parse_whitespace_only() {
        let result = parse_usdc_price_to_wei("   ");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Price string is empty"));
    }

    #[test]
    fn test_parse_multiple_decimal_points() {
        let result = parse_usdc_price_to_wei("1.2.3");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Invalid price format: multiple decimal points"));
    }

    #[test]
    fn test_parse_too_many_decimal_places() {
        let result = parse_usdc_price_to_wei("0.1234567");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Price has more than 6 decimal places"));
    }

    #[test]
    fn test_parse_exactly_six_decimal_places() {
        assert_eq!(parse_usdc_price_to_wei("0.123456"), Ok(123_456));
        assert_eq!(parse_usdc_price_to_wei("1.123456"), Ok(1_123_456));
    }

    #[test]
    fn test_parse_invalid_characters() {
        let result = parse_usdc_price_to_wei("abc");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse whole part"));

        let result = parse_usdc_price_to_wei("1.abc");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Failed to parse fractional part"));
    }

    #[test]
    fn test_parse_negative_number() {
        let result = parse_usdc_price_to_wei("-1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse whole part"));
    }

    #[test]
    fn test_parse_decimal_point_only() {
        let result = parse_usdc_price_to_wei(".");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_leading_decimal_point() {
        let result = parse_usdc_price_to_wei(".5");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse whole part"));
    }

    #[test]
    fn test_parse_trailing_decimal_point() {
        let result = parse_usdc_price_to_wei("5.");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 5_000_000);
    }

    #[test]
    fn test_parse_edge_case_zero_with_decimal() {
        assert_eq!(parse_usdc_price_to_wei("0.0"), Ok(0));
        assert_eq!(parse_usdc_price_to_wei("0.00"), Ok(0));
        assert_eq!(parse_usdc_price_to_wei("0.000000"), Ok(0));
    }

    #[test]
    fn test_parse_very_small_amounts() {
        assert_eq!(parse_usdc_price_to_wei("0.000001"), Ok(1));
        assert_eq!(parse_usdc_price_to_wei("0.000010"), Ok(10));
        assert_eq!(parse_usdc_price_to_wei("0.000100"), Ok(100));
    }

    #[test]
    fn test_parse_common_price_examples() {
        assert_eq!(parse_usdc_price_to_wei("0.01"), Ok(10_000));
        assert_eq!(parse_usdc_price_to_wei("0.1"), Ok(100_000));
        assert_eq!(parse_usdc_price_to_wei("1.0"), Ok(1_000_000));
        assert_eq!(parse_usdc_price_to_wei("10.50"), Ok(10_500_000));
    }
}
