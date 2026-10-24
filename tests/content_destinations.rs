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
