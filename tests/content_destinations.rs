use nftbk::httpclient::HttpClient;
use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn production_client_rejects_initial_private_destinations() {
    let internal = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("internal secret"))
        .mount(&internal)
        .await;
    let client = HttpClient::new().with_max_retries(0);
    for host in ["127.0.0.1", "2130706433", "[::1]", "[::ffff:127.0.0.1]"] {
        let url = internal.uri().replace("127.0.0.1", host);
        assert_eq!(
            client.fetch(&url).await.unwrap_err().to_string(),
            "Content URL must use HTTP(S) and a public destination"
        );
    }
    assert!(client
        .fetch(&internal.uri().replace("127.0.0.1", "localhost"))
        .await
        .is_err());
    assert_eq!(internal.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn production_raw_croquet_requests_reject_private_destinations() {
    let internal = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("internal secret"))
        .mount(&internal)
        .await;
    let output = tempfile::TempDir::new().unwrap();
    let result = nftbk::content::extra::croquet::fetch_croquet_challenge(
        output.path(),
        "0xabc",
        "25811853076941608055270457512038717433705462539422789705262203111341130500763",
        Some(&internal.uri()),
    )
    .await;

    assert_eq!(
        result.unwrap_err().to_string(),
        "Content URL must use HTTP(S) and a public destination"
    );
    assert_eq!(internal.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn production_client_ignores_environment_proxies() {
    if std::env::var_os("NFTBK_PROXY_TEST_CHILD").is_some() {
        assert!(HttpClient::new()
            .with_max_retries(0)
            .fetch("http://content.invalid/")
            .await
            .is_err());
        return;
    }

    let proxy = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("proxy bypass"))
        .mount(&proxy)
        .await;
    let proxy_url = proxy.uri();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "production_client_ignores_environment_proxies",
                "--nocapture",
            ])
            .env("NFTBK_PROXY_TEST_CHILD", "1")
            .env("HTTP_PROXY", &proxy_url)
            .env("http_proxy", &proxy_url)
            .env("ALL_PROXY", &proxy_url)
            .env("all_proxy", &proxy_url)
            .env("NO_PROXY", "")
            .env("no_proxy", "")
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(proxy.received_requests().await.unwrap().len(), 0);
}
