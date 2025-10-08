use rand::{thread_rng, Rng};
use std::time::Duration;
use tokio::time::sleep;
use tracing::warn;

fn calculate_retry_delay(attempt: u32) -> Duration {
    let base_delay = 2u64.pow(attempt).min(30);
    let jitter: u64 = thread_rng().gen_range(0..500);
    Duration::from_secs(base_delay) + Duration::from_millis(jitter)
}

pub(crate) async fn retry_operation<T>(
    operation: impl Fn() -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = (anyhow::Result<T>, Option<reqwest::StatusCode>)>
                + Send,
        >,
    >,
    max_retries: u32,
    should_retry: impl Fn(&anyhow::Error, Option<reqwest::StatusCode>) -> bool,
    context: &str,
) -> anyhow::Result<T> {
    let mut attempt = 0;
    loop {
        let (result, status) = operation().await;
        if result.is_ok() {
            return result;
        }

        let error = result.as_ref().err().unwrap();
        if !should_retry(error, status) {
            return result;
        }

        if attempt >= max_retries {
            return result;
        }
        attempt += 1;
        let delay = calculate_retry_delay(attempt);
        warn!(
            "Retriable error for {}, retrying in {:?} (attempt {}/{})",
            context, delay, attempt, max_retries
        );
        sleep(delay).await;
    }
}

pub(crate) fn should_retry(error: &anyhow::Error, status: Option<reqwest::StatusCode>) -> bool {
    const RETRIABLE_ERRORS: [&str; 2] = [
        "end of file before message length reached",
        "tcp connect error",
    ];

    let err_str = format!("{error}");
    let is_streaming_error = RETRIABLE_ERRORS
        .iter()
        .any(|substr| err_str.contains(substr));

    let is_http_error = if let Some(status_code) = status {
        status_code.is_server_error() || status_code.as_u16() == 429
    } else {
        false
    };

    is_streaming_error || is_http_error
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_retry_delay_monotonic() {
        let d1 = calculate_retry_delay(1);
        let d2 = calculate_retry_delay(2);
        let d3 = calculate_retry_delay(3);
        assert!(d2 > d1);
        assert!(d3 > d2);
    }

    #[test]
    fn test_should_retry_logic() {
        assert!(should_retry(
            &anyhow::anyhow!("test"),
            Some(reqwest::StatusCode::from_u16(500).unwrap())
        ));
        assert!(should_retry(
            &anyhow::anyhow!("test"),
            Some(reqwest::StatusCode::from_u16(429).unwrap())
        ));
        assert!(!should_retry(
            &anyhow::anyhow!("test"),
            Some(reqwest::StatusCode::from_u16(404).unwrap())
        ));

        assert!(should_retry(
            &anyhow::anyhow!("end of file before message length reached"),
            None
        ));
        assert!(should_retry(&anyhow::anyhow!("tcp connect error"), None));
        assert!(!should_retry(&anyhow::anyhow!("some other error"), None));
    }
}
