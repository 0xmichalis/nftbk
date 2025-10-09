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

    mod retry_operation_tests {
        use super::*;
        use std::sync::{
            atomic::{AtomicU32, Ordering},
            Arc,
        };
        use tokio::task::yield_now;
        use tokio::time::{advance, Duration as TokioDuration};

        async fn advance_n(n: usize) {
            for _ in 0..n {
                advance(TokioDuration::from_secs(60)).await;
                yield_now().await;
            }
        }

        #[tokio::test(start_paused = true, flavor = "current_thread")]
        async fn success_on_first_try() {
            let attempts = Arc::new(AtomicU32::new(0));
            let op_attempts = attempts.clone();
            let fut = retry_operation(
                move || {
                    let op_attempts = op_attempts.clone();
                    Box::pin(async move {
                        op_attempts.fetch_add(1, Ordering::SeqCst);
                        (Ok::<_, anyhow::Error>(42u32), None)
                    })
                },
                3,
                should_retry,
                "ctx",
            );

            let res = fut.await.unwrap();
            assert_eq!(res, 42);
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
        }

        #[tokio::test(start_paused = true, flavor = "current_thread")]
        async fn non_retriable_error_returns_immediately() {
            let attempts = Arc::new(AtomicU32::new(0));
            let op_attempts = attempts.clone();
            let fut = retry_operation(
                move || {
                    let op_attempts = op_attempts.clone();
                    Box::pin(async move {
                        op_attempts.fetch_add(1, Ordering::SeqCst);
                        (
                            Err::<u32, anyhow::Error>(anyhow::anyhow!("bad request")),
                            Some(reqwest::StatusCode::BAD_REQUEST),
                        )
                    })
                },
                5,
                should_retry,
                "ctx",
            );

            let err = fut.await.expect_err("should error");
            assert!(format!("{err}").contains("bad request"));
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
        }

        #[tokio::test(start_paused = true, flavor = "current_thread")]
        async fn retries_until_max_and_fails() {
            let attempts = Arc::new(AtomicU32::new(0));
            let op_attempts = attempts.clone();
            let handle = tokio::spawn(retry_operation(
                move || {
                    let op_attempts = op_attempts.clone();
                    Box::pin(async move {
                        op_attempts.fetch_add(1, Ordering::SeqCst);
                        (
                            Err::<u8, anyhow::Error>(anyhow::anyhow!("server error")),
                            Some(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
                        )
                    })
                },
                2,
                should_retry,
                "ctx",
            ));

            // Two sleeps expected before giving up (max_retries = 2)
            advance_n(2).await;
            let res = handle.await.unwrap();
            assert!(res.is_err());
            assert_eq!(attempts.load(Ordering::SeqCst), 3);
        }

        #[tokio::test(start_paused = true, flavor = "current_thread")]
        async fn eventual_success_after_retries() {
            let attempts = Arc::new(AtomicU32::new(0));
            let op_attempts = attempts.clone();
            let fail_times = 2u32;
            let handle = tokio::spawn(retry_operation(
                move || {
                    let op_attempts = op_attempts.clone();
                    Box::pin(async move {
                        let n = op_attempts.fetch_add(1, Ordering::SeqCst);
                        if n < fail_times {
                            (
                                Err::<String, anyhow::Error>(anyhow::anyhow!("temporary")),
                                Some(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
                            )
                        } else {
                            (Ok::<_, anyhow::Error>("ok".to_string()), None)
                        }
                    })
                },
                5,
                should_retry,
                "ctx",
            ));

            // Expect two sleeps before success
            advance_n(2).await;
            let res = handle.await.unwrap().unwrap();
            assert_eq!(res, "ok");
            assert_eq!(attempts.load(Ordering::SeqCst), 3);
        }

        #[tokio::test(start_paused = true, flavor = "current_thread")]
        async fn http_429_is_retriable() {
            let attempts = Arc::new(AtomicU32::new(0));
            let op_attempts = attempts.clone();
            let handle = tokio::spawn(retry_operation(
                move || {
                    let op_attempts = op_attempts.clone();
                    Box::pin(async move {
                        let n = op_attempts.fetch_add(1, Ordering::SeqCst);
                        if n == 0 {
                            (
                                Err::<i32, anyhow::Error>(anyhow::anyhow!("rate limited")),
                                Some(reqwest::StatusCode::TOO_MANY_REQUESTS),
                            )
                        } else {
                            (Ok::<_, anyhow::Error>(7i32), None)
                        }
                    })
                },
                3,
                should_retry,
                "ctx",
            ));

            advance_n(1).await;
            let res = handle.await.unwrap().unwrap();
            assert_eq!(res, 7);
            assert_eq!(attempts.load(Ordering::SeqCst), 2);
        }

        #[tokio::test(start_paused = true, flavor = "current_thread")]
        async fn streaming_error_is_retriable() {
            let attempts = Arc::new(AtomicU32::new(0));
            let op_attempts = attempts.clone();
            let handle = tokio::spawn(retry_operation(
                move || {
                    let op_attempts = op_attempts.clone();
                    Box::pin(async move {
                        let n = op_attempts.fetch_add(1, Ordering::SeqCst);
                        if n == 0 {
                            (
                                Err::<String, anyhow::Error>(anyhow::anyhow!("tcp connect error")),
                                None,
                            )
                        } else {
                            (Ok::<_, anyhow::Error>("done".to_string()), None)
                        }
                    })
                },
                3,
                should_retry,
                "ctx",
            ));

            advance_n(1).await;
            let res = handle.await.unwrap().unwrap();
            assert_eq!(res, "done");
            assert_eq!(attempts.load(Ordering::SeqCst), 2);
        }
    }
}
