//! Explicitly opt-in PostgreSQL integration tests. Unit tests mock Database.
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use alloy::sol_types::SolValue;
use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use base64::Engine;
use serde_json::{json, Value};
use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, PgConnection, PgPool};
use tower::ServiceExt;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use nftbk::model::*;
use nftbk::server::database::r#trait::{Create, Creation, Database, DatabaseError, Progress};
use nftbk::server::database::Db;
use nftbk::server::router::build_router;
use nftbk::server::storage::BlobStore;
use nftbk::server::{workers, AppState};
use nftbk::ChainConfig;

struct TestDatabase {
    admin: PgPool,
    name: String,
    db: Db,
}
impl TestDatabase {
    async fn new(legacy: bool) -> Self {
        let url = std::env::var("NFTBK_INTEGRATION_DATABASE_URL")
            .expect("Set NFTBK_INTEGRATION_DATABASE_URL to the isolated validation database");
        let options: PgConnectOptions = url.parse().unwrap();
        assert_eq!(
            options.get_database(),
            Some("nftbk_v2"),
            "Integration tests require the dedicated nftbk_v2 database"
        );
        let admin = PgPool::connect_with(options.clone()).await.unwrap();
        let name = format!("nftbk_v2_test_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&admin)
            .await
            .unwrap();
        if legacy {
            let mut connection = PgConnection::connect_with(&options.clone().database(&name))
                .await
                .unwrap();
            sqlx::raw_sql(include_str!("../migrations/001_initial_schema.sql"))
                .execute(&mut connection)
                .await
                .unwrap();
            sqlx::raw_sql("INSERT INTO backup_tasks(task_id,requestor,nft_count,storage_mode) VALUES('legacy-task','alice',2,'full'); INSERT INTO archive_requests(task_id,archive_format,status) VALUES('legacy-task','zip','done'); INSERT INTO pin_requests(task_id,status) VALUES('legacy-task','done'); INSERT INTO tokens(task_id,chain,contract_address,token_id) VALUES('legacy-task','ethereum','0x00000000000000000000000000000000000000AB','1'),('legacy-task','tezos','KT1DmEFfeqEC3nEx6bpWKqjNY8FF8RFrR3Gc','2'); INSERT INTO pins(token_id,task_id,provider_type,provider_url,cid,request_id,pin_status) VALUES(1,'legacy-task','pinata','https://provider.example','QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG','remote-1','pinned');").execute(&mut connection).await.unwrap();
        }
        let pool = PgPool::connect_with(options.database(&name)).await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        Self {
            admin,
            name,
            db: Db::from_pool(pool).configure(1024, 0),
        }
    }
    async fn close(self) {
        self.db.pool.close().await;
        sqlx::query(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .execute(&self.admin)
            .await
            .unwrap();
        self.admin.close().await;
    }
}
fn nft() -> Nft {
    Nft {
        chain_id: "eip155:1".into(),
        contract_address: "0x00000000000000000000000000000000000000ab".into(),
        token_id: "42".into(),
    }
}
fn specification() -> Specification {
    Specification {
        nfts: vec![nft()],
        outputs: vec![OutputRequest::Archive {
            format: ArchiveFormat::Zip,
            retention_days: Some(3),
        }],
    }
}
fn state(db: &Db, base: &std::path::Path, rpc: &str) -> AppState {
    AppState {
        db: Arc::new(db.clone()),
        chain_config: Arc::new(ChainConfig(std::collections::HashMap::from([(
            "eip155:1".into(),
            rpc.into(),
        )]))),
        storage: BlobStore::new(base),
        providers: Arc::new(ProviderMap::new()),
        jwt_credentials: Arc::new(vec![]),
        auth_token: None,
        download_key: Arc::new([7u8; 32]),
        shutdown_flag: Arc::new(AtomicBool::new(false)),
        x402_config: None,
        retention_days: 3,
        max_content_request_retries: 0,
        unsafe_skip_checksum_check: false,
        pricing_version: "test".into(),
    }
}
async fn request(
    app: &axum::Router,
    method: Method,
    path: &str,
    body: Value,
    key: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(key) = key {
        request = request.header("idempotency-key", key);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 32 * 1024 * 1024)
        .await
        .unwrap();
    (status, headers, bytes.to_vec())
}

#[tokio::test]
#[ignore = "Requires isolated PostgreSQL; run with NFTBK_INTEGRATION_DATABASE_URL"]
async fn migrates_legacy_records_without_losing_locations_or_ipfs_coverage() {
    let database = TestDatabase::new(true).await;
    let owner = database
        .db
        .owner(&Principal {
            issuer: "legacy".into(),
            subject: "alice".into(),
        })
        .await
        .unwrap();
    let page = database
        .db
        .list(Resource::Backup, &owner, &Default::default())
        .await
        .unwrap();
    assert_eq!(page.data.len(), 1);
    let backup: Backup = serde_json::from_value(page.data[0].clone()).unwrap();
    assert_ne!(backup.id, "legacy-task");
    assert_eq!(backup.provenance, "legacy");
    assert_eq!(backup.nft_count, 2);
    assert_eq!(
        database
            .db
            .archive_storage(&owner, &backup.archives[0].id)
            .await
            .unwrap(),
        "nftbk-legacy-task.zip"
    );
    assert_eq!(backup.pin_sets[0].eligible_nft_count, 1);
    assert_eq!(backup.pin_sets[0].protected_nft_count, 1);
    assert_eq!(backup.pin_sets[0].skipped_nft_count, 1);
    let items = database
        .db
        .list(
            Resource::Item,
            &owner,
            &nftbk::server::database::r#trait::Page {
                backup_id: Some(backup.id),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let chains: std::collections::BTreeSet<&str> = items
        .data
        .iter()
        .map(|i| i["chain_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        chains,
        std::collections::BTreeSet::from(["eip155:1", "tezos:NetXdQprcVkpaWU"])
    );
    database.close().await;
}

#[tokio::test]
#[ignore = "Requires isolated PostgreSQL; run with NFTBK_INTEGRATION_DATABASE_URL"]
async fn captures_original_metadata_and_runs_independent_archive_and_download_lifecycles() {
    let database = TestDatabase::new(false).await;
    let directory = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    let original = "{\n  \"name\": \"Raw metadata\", \"unmodeled\": {\"preserve\": true},\n \"image\": \"data:image/png;base64,iVBORw0KGgo=\"\n}".to_string();
    let uri = format!(
        "data:application/json;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(original.as_bytes())
    );
    let encoded = format!("0x{}", hex::encode(uri.abi_encode()));
    Mock::given(method("POST"))
        .and(path("/rpc"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"jsonrpc":"2.0","id":0,"result":encoded})),
        )
        .mount(&server)
        .await;
    let state = state(
        &database.db,
        directory.path(),
        &format!("{}/rpc", server.uri()),
    );
    let app = build_router(state.clone());
    let payload = json!({"nfts":[nft()],"outputs":[{"type":"archive","format":"zip"}]});
    let (status, headers, body) = request(
        &app,
        Method::POST,
        "/v2/backups",
        payload.clone(),
        Some("request-1"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: Backup = serde_json::from_slice(&body).unwrap();
    assert_eq!(headers["location"], format!("/v2/backups/{}", created.id));
    let (_, _, replay) = request(
        &app,
        Method::POST,
        "/v2/backups",
        payload.clone(),
        Some("request-1"),
    )
    .await;
    assert_eq!(
        serde_json::from_slice::<Backup>(&replay).unwrap().id,
        created.id
    );
    let mut changed = payload.clone();
    changed["outputs"][0]["format"] = json!("tar.gz");
    assert_eq!(
        request(
            &app,
            Method::POST,
            "/v2/backups",
            changed,
            Some("request-1")
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let capture = database.db.claim().await.unwrap().unwrap();
    assert_eq!(capture.operation.kind, "capture");
    workers::execute(&state, &capture).await.unwrap();
    let archive = database.db.claim().await.unwrap().unwrap();
    assert_eq!(archive.operation.kind, "archive");
    workers::execute(&state, &archive).await.unwrap();
    let (status, _, body) = request(
        &app,
        Method::GET,
        &format!("/v2/backups/{}", created.id),
        Value::Null,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let captured: Backup = serde_json::from_slice(&body).unwrap();
    assert_eq!(captured.state, State::Ready);
    assert_eq!(captured.archives[0].state, State::Ready);
    let manifest: Manifest = serde_json::from_slice(
        &state
            .storage
            .read(captured.manifest_sha256.as_ref().unwrap())
            .await
            .unwrap(),
    )
    .unwrap();
    let raw = state
        .storage
        .read(manifest.items[0].metadata_sha256.as_ref().unwrap())
        .await
        .unwrap();
    assert_eq!(raw, original.as_bytes());
    let archive_id = &captured.archives[0].id;
    let (status, _, body) = request(
        &app,
        Method::POST,
        &format!("/v2/archives/{archive_id}/download-links"),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let link: Value = serde_json::from_slice(&body).unwrap();
    let url = link["url"].as_str().unwrap();
    let response = app
        .clone()
        .oneshot(Request::builder().uri(url).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let archive_bytes = to_bytes(response.into_body(), 32 * 1024 * 1024)
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(url)
                .header("Range", "bytes=5-12")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        to_bytes(response.into_body(), 100).await.unwrap().as_ref(),
        &archive_bytes[5..13]
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::HEAD)
                .uri(url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(to_bytes(response.into_body(), 100)
        .await
        .unwrap()
        .is_empty());
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(archive_bytes)).unwrap();
    let mut archived_metadata = Vec::new();
    std::io::Read::read_to_end(
        &mut zip
            .by_name(&format!("{}/metadata.json", nft().directory()))
            .unwrap(),
        &mut archived_metadata,
    )
    .unwrap();
    assert_eq!(archived_metadata, original.as_bytes());
    assert_eq!(
        request(
            &app,
            Method::DELETE,
            &format!("/v2/archives/{archive_id}"),
            json!({}),
            None
        )
        .await
        .0,
        StatusCode::ACCEPTED
    );
    let deletion = database.db.claim().await.unwrap().unwrap();
    workers::execute(&state, &deletion).await.unwrap();
    let owner = database
        .db
        .owner(&Principal {
            issuer: "nftbk:local".into(),
            subject: "local".into(),
        })
        .await
        .unwrap();
    let backup: Backup = serde_json::from_value(
        database
            .db
            .get(Resource::Backup, &owner, &created.id)
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(backup.state, State::Ready);
    assert_eq!(backup.archives[0].state, State::Deleted);
    let (_, _, fresh) = request(
        &app,
        Method::POST,
        "/v2/backups",
        payload,
        Some("request-2"),
    )
    .await;
    assert_ne!(
        serde_json::from_slice::<Backup>(&fresh).unwrap().id,
        created.id
    );
    drop(state);
    drop(app);
    database.close().await;
}

#[tokio::test]
#[ignore = "Requires isolated PostgreSQL; run with NFTBK_INTEGRATION_DATABASE_URL"]
async fn fences_stale_workers_and_scopes_resource_reads_to_the_owner() {
    let database = TestDatabase::new(false).await;
    let owner = database
        .db
        .owner(&Principal {
            issuer: "issuer-a".into(),
            subject: "same-subject".into(),
        })
        .await
        .unwrap();
    let other = database
        .db
        .owner(&Principal {
            issuer: "issuer-b".into(),
            subject: "same-subject".into(),
        })
        .await
        .unwrap();
    assert_ne!(owner, other);
    let specification = specification();
    let created = database
        .db
        .create(Create {
            owner_id: owner.clone(),
            key: "lease-test".into(),
            payload_hash: specification.hash(),
            resource: Resource::Backup,
            creation: Creation::Backup {
                specification,
                quote_id: None,
                pricing_version: None,
                provider_ids: vec![],
            },
        })
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap();
    assert!(database
        .db
        .get(Resource::Backup, &other, id)
        .await
        .unwrap()
        .is_none());
    let first = database.db.claim().await.unwrap().unwrap();
    sqlx::query(
        "UPDATE operations SET lease_until=now()-interval '1 second' WHERE id=$1::text::uuid",
    )
    .bind(&first.operation.id)
    .execute(&database.db.pool)
    .await
    .unwrap();
    database.db.maintenance().await.unwrap();
    let second = database.db.claim().await.unwrap().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let storage = BlobStore::new(directory.path());
    let abandoned = storage.stage(&first).await.unwrap();
    let active = storage.stage(&second).await.unwrap();
    storage.cleanup_staging(&database.db).await.unwrap();
    assert!(!abandoned.exists());
    assert!(active.exists());
    assert_eq!(first.operation.id, second.operation.id);
    assert_ne!(first.lease_token, second.lease_token);
    assert!(matches!(
        database
            .db
            .progress(
                &first,
                Progress::Captured {
                    manifest_sha256: "0".repeat(64),
                    state: State::Ready
                }
            )
            .await,
        Err(DatabaseError::LostLease)
    ));
    assert_eq!(
        database
            .db
            .attempts(&owner, &second.operation.id)
            .await
            .unwrap()
            .len(),
        2
    );
    database.close().await;
}

async fn create_for_owner(
    db: &Db,
    owner: &str,
    specification: Specification,
    providers: Vec<String>,
) -> Backup {
    let value = db
        .create(Create {
            owner_id: owner.into(),
            key: Uuid::new_v4().to_string(),
            payload_hash: specification.hash(),
            resource: Resource::Backup,
            creation: Creation::Backup {
                specification,
                quote_id: None,
                pricing_version: None,
                provider_ids: providers,
            },
        })
        .await
        .unwrap();
    serde_json::from_value(value).unwrap()
}

async fn complete_capture(db: &Db, cids: &[Option<&str>]) {
    let claim = db.claim().await.unwrap().unwrap();
    assert_eq!(claim.operation.kind, "capture");
    let context = db.context(&claim).await.unwrap();
    let mut items: Vec<Item> = serde_json::from_value(context["items"].clone()).unwrap();
    for (item, cid) in items.iter_mut().zip(cids) {
        item.state = State::Ready;
        if let Some(cid) = cid {
            item.assets.push(Asset {
                id: Uuid::new_v4().to_string(),
                item_id: item.id.clone(),
                role: "image".into(),
                source_uri: Some(format!("ipfs://{cid}")),
                filename: None,
                fallback_filename: None,
                observed_at: Some(chrono::Utc::now()),
                path: format!("{}/image", item.nft.directory()),
                sha256: None,
                cid: Some((*cid).into()),
                size_bytes: Some(10),
                state: State::Ready,
                error: None,
            });
        }
    }
    db.progress(&claim, Progress::Items(items)).await.unwrap();
    db.progress(
        &claim,
        Progress::Captured {
            manifest_sha256: "0".repeat(64),
            state: State::Ready,
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "Requires isolated PostgreSQL; run with NFTBK_INTEGRATION_DATABASE_URL"]
async fn shares_pins_and_unpins_only_the_last_reference_with_truthful_filtered_counts() {
    use nftbk::ipfs::pinning_service::IpfsPinningClient;
    use nftbk::server::database::r#trait::Page;

    let database = TestDatabase::new(false).await;
    let directory = tempfile::tempdir().unwrap();
    let provider = MockServer::start().await;
    let cid = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";
    let observed = json!({"requestid":"remote-1","status":"pinned","created":"2026-01-01T00:00:00Z","pin":{"cid":cid}});
    Mock::given(method("POST"))
        .and(path("/pins"))
        .respond_with(ResponseTemplate::new(200).set_body_json(observed.clone()))
        .expect(1)
        .mount(&provider)
        .await;
    Mock::given(method("GET"))
        .and(path("/pins/remote-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(observed))
        .mount(&provider)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/pins/remote-1"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&provider)
        .await;
    let provider_id = database
        .db
        .register_provider("test", "pinning-service", &provider.uri(), None, false)
        .await
        .unwrap();
    let mut state = state(&database.db, directory.path(), "https://rpc.example");
    Arc::make_mut(&mut state.providers).insert(
        provider_id.clone(),
        Arc::new(IpfsPinningClient::new(provider.uri(), None)),
    );
    let owner = database
        .db
        .owner(&Principal {
            issuer: "nftbk:local".into(),
            subject: "local".into(),
        })
        .await
        .unwrap();
    let mut second_nft = nft();
    second_nft.token_id = "43".into();
    let specification = Specification {
        nfts: vec![nft(), second_nft],
        outputs: vec![OutputRequest::Ipfs],
    };
    let mut backups = vec![];
    for _ in 0..2 {
        let backup = create_for_owner(
            &database.db,
            &owner,
            specification.clone(),
            vec![provider_id.clone()],
        )
        .await;
        complete_capture(&database.db, &[Some(cid), None]).await;
        let pin = database.db.claim().await.unwrap().unwrap();
        workers::execute(&state, &pin).await.unwrap();
        let set: PinSet = serde_json::from_value(
            database
                .db
                .get(Resource::PinSet, &owner, &backup.pin_sets[0].id)
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            (
                set.requested_nft_count,
                set.eligible_nft_count,
                set.protected_nft_count,
                set.skipped_nft_count
            ),
            (2, 1, 1, 1)
        );
        assert_eq!(set.state, State::Partial);
        let eligible = database
            .db
            .list(
                Resource::Item,
                &owner,
                &Page {
                    backup_id: Some(backup.id.clone()),
                    ipfs_only: Some(true),
                    limit: Some(1),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(eligible.data.len(), 1);
        assert_eq!(eligible.next_cursor, None);
        backups.push(backup);
    }
    let pins = database
        .db
        .list(
            Resource::Pin,
            &owner,
            &Page {
                chain_id: Some("eip155:1".into()),
                contract_address: Some(nft().contract_address),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(pins.data.len(), 1);
    for (index, backup) in backups.into_iter().enumerate() {
        let operation = database
            .db
            .delete(Resource::PinSet, &owner, &backup.pin_sets[0].id)
            .await
            .unwrap();
        let deletion = database.db.claim().await.unwrap().unwrap();
        assert_eq!(deletion.operation.id, operation.id);
        workers::execute(&state, &deletion).await.unwrap();
        let deletes = provider
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method.as_str() == "DELETE")
            .count();
        assert_eq!(deletes, index);
    }
    database.close().await;
}

#[tokio::test]
#[ignore = "Requires isolated PostgreSQL; run with NFTBK_INTEGRATION_DATABASE_URL"]
async fn retry_creates_a_readable_attempt_and_deletion_failures_retain_history() {
    let database = TestDatabase::new(false).await;
    let directory = tempfile::tempdir().unwrap();
    let state = state(&database.db, directory.path(), "https://rpc.example");
    let owner = database
        .db
        .owner(&Principal {
            issuer: "nftbk:local".into(),
            subject: "local".into(),
        })
        .await
        .unwrap();
    let backup = create_for_owner(&database.db, &owner, specification(), vec![]).await;
    complete_capture(&database.db, &[None]).await;
    let archive = database.db.claim().await.unwrap().unwrap();
    database
        .db
        .progress(
            &archive,
            Progress::Failed(nftbk::server::snapshot::failure(
                "disk_full",
                "Not enough disk space",
            )),
        )
        .await
        .unwrap();
    let app = build_router(state);
    let (status, headers, body) = request(
        &app,
        Method::POST,
        &format!("/v2/operations/{}/attempts", archive.operation.id),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let attempt: Attempt = serde_json::from_slice(&body).unwrap();
    assert_eq!(attempt.number, 2);
    assert_eq!(attempt.started_at, None);
    let (status, _, stored) = request(
        &app,
        Method::GET,
        headers["location"].to_str().unwrap(),
        Value::Null,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&stored).unwrap(),
        serde_json::from_slice::<Value>(&body).unwrap()
    );
    let resumed = database.db.claim().await.unwrap().unwrap();
    assert_eq!(resumed.operation.attempts, 2);
    let attempts = database
        .db
        .attempts(&owner, &archive.operation.id)
        .await
        .unwrap();
    assert!(attempts[1].started_at.is_some());
    assert_eq!(attempts[0].error.as_ref().unwrap().code, "disk_full");
    database
        .db
        .progress(
            &resumed,
            Progress::Failed(nftbk::server::snapshot::failure("disk_full", "Still full")),
        )
        .await
        .unwrap();
    let deletion = database
        .db
        .delete(Resource::Archive, &owner, &backup.archives[0].id)
        .await
        .unwrap();
    let claim = database.db.claim().await.unwrap().unwrap();
    assert_eq!(claim.operation.id, deletion.id);
    database
        .db
        .progress(
            &claim,
            Progress::Failed(nftbk::server::snapshot::failure(
                "cleanup_failed",
                "File removal failed",
            )),
        )
        .await
        .unwrap();
    let output: Archive = serde_json::from_value(
        database
            .db
            .get(Resource::Archive, &owner, &backup.archives[0].id)
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(output.state, State::Deleting);
    assert_eq!(output.deleted_at, None);
    assert!(output.deletion_requested_at.is_some());
    assert_eq!(
        database
            .db
            .delete(Resource::Archive, &owner, &output.id)
            .await
            .unwrap()
            .id,
        deletion.id
    );
    database.db.retry(&owner, &deletion.id).await.unwrap();
    let retry = database.db.claim().await.unwrap().unwrap();
    database
        .db
        .progress(&retry, Progress::Deleted)
        .await
        .unwrap();
    let output: Archive = serde_json::from_value(
        database
            .db
            .get(Resource::Archive, &owner, &output.id)
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(output.state, State::Deleted);
    assert!(output.deleted_at.is_some());
    database.close().await;
}

#[tokio::test]
#[ignore = "Requires isolated PostgreSQL; run with NFTBK_INTEGRATION_DATABASE_URL"]
async fn binds_quotes_and_payments_and_never_reuses_an_ambiguous_authorization() {
    use nftbk::server::database::r#trait::{PaymentUpdate, QuoteTerms};
    let database = TestDatabase::new(false).await;
    let owner = database
        .db
        .owner(&Principal {
            issuer: "issuer".into(),
            subject: "alice".into(),
        })
        .await
        .unwrap();
    let spec = specification();
    let quote = database
        .db
        .create(Create {
            owner_id: owner.clone(),
            key: "quote".into(),
            payload_hash: spec.hash(),
            resource: Resource::Quote,
            creation: Creation::Quote {
                specification: spec.clone(),
                backup_id: None,
                terms: QuoteTerms {
                    asset_symbol: "USDC".into(),
                    chain_id: "eip155:84532".into(),
                    asset_address: "0xasset".into(),
                    asset_decimals: 6,
                    pricing_version: "policy-2".into(),
                    lifetime_seconds: 300,
                },
            },
        })
        .await
        .unwrap();
    let claim = database.db.claim().await.unwrap().unwrap();
    database
        .db
        .progress(
            &claim,
            Progress::Quoted {
                plan: vec![],
                amount_atomic: "123".into(),
                estimated_size_bytes: 100,
                lifetime_seconds: 300,
            },
        )
        .await
        .unwrap();
    let creation = |key: &str, specification: Specification, version: &str| Create {
        owner_id: owner.clone(),
        key: key.into(),
        payload_hash: specification.hash(),
        resource: Resource::Backup,
        creation: Creation::Backup {
            specification,
            quote_id: Some(quote["id"].as_str().unwrap().into()),
            pricing_version: Some(version.into()),
            provider_ids: vec![],
        },
    };
    let mut wrong = spec.clone();
    wrong.outputs = vec![OutputRequest::Ipfs];
    assert!(matches!(
        database
            .db
            .create(creation("wrong-output", wrong, "policy-2"))
            .await,
        Err(DatabaseError::Conflict(_))
    ));
    assert!(matches!(
        database
            .db
            .create(creation("wrong-policy", spec.clone(), "policy-3"))
            .await,
        Err(DatabaseError::Conflict(_))
    ));
    let backup = database
        .db
        .create(creation("payment", spec.clone(), "policy-2"))
        .await
        .unwrap();
    let id = backup["id"].as_str().unwrap();
    assert_eq!(backup["state"], "awaiting_payment");
    assert!(database.db.claim().await.unwrap().is_none());
    let proof = PaymentUpdate::Begin {
        proof_hash: "proof".into(),
        settle_request: json!({"proof":"durably stored"}),
    };
    database
        .db
        .payment(Resource::Backup, &owner, id, Some(proof.clone()))
        .await
        .unwrap();
    assert!(matches!(
        database
            .db
            .payment(Resource::Backup, &owner, id, Some(proof.clone()))
            .await,
        Err(DatabaseError::Conflict(_))
    ));
    assert!(matches!(
        database.db.delete(Resource::Backup, &owner, id).await,
        Err(DatabaseError::Conflict(_))
    ));
    database
        .db
        .payment(
            Resource::Backup,
            &owner,
            id,
            Some(PaymentUpdate::Failed {
                detail: "Connection closed".into(),
                ambiguous: true,
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        database
            .db
            .payment(Resource::Backup, &owner, id, None)
            .await
            .unwrap()
            .unwrap()["state"],
        "reconciliation_required"
    );
    assert!(matches!(
        database
            .db
            .payment(Resource::Backup, &owner, id, Some(proof.clone()))
            .await,
        Err(DatabaseError::Conflict(_))
    ));
    let second = database
        .db
        .create(creation("other-request", spec, "policy-2"))
        .await
        .unwrap();
    assert!(matches!(
        database
            .db
            .payment(
                Resource::Backup,
                &owner,
                second["id"].as_str().unwrap(),
                Some(proof)
            )
            .await,
        Err(DatabaseError::Conflict(_))
    ));
    database
        .db
        .payment(
            Resource::Backup,
            &owner,
            id,
            Some(PaymentUpdate::Settled(
                json!({"success":true,"transaction":"verified-tx"}),
            )),
        )
        .await
        .unwrap();
    assert_eq!(
        database
            .db
            .get(Resource::Backup, &owner, id)
            .await
            .unwrap()
            .unwrap()["state"],
        "queued"
    );
    assert_eq!(
        database.db.claim().await.unwrap().unwrap().operation.kind,
        "capture"
    );
    database.close().await;
}

#[tokio::test]
#[ignore = "Requires isolated PostgreSQL; run with NFTBK_INTEGRATION_DATABASE_URL"]
async fn a_paid_snapshot_reuses_the_raw_metadata_observed_by_its_quote() {
    use nftbk::server::database::r#trait::PaymentUpdate;
    use nftbk::server::{
        billing,
        x402::{PricingRaw, X402Config, X402ConfigRaw, X402FacilitatorConfigRaw},
    };

    let database = TestDatabase::new(false).await;
    let directory = tempfile::tempdir().unwrap();
    let rpc = MockServer::start().await;
    let original = br#"{ "name":"Quoted observation", "additional": {"preserved":true} }"#;
    let uri = format!(
        "data:application/json;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(original)
    );
    Mock::given(method("POST"))
        .and(path("/rpc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"jsonrpc":"2.0","id":0,"result":format!("0x{}",hex::encode(uri.abi_encode()))}),
        ))
        .expect(1)
        .mount(&rpc)
        .await;
    let mut state = state(
        &database.db,
        directory.path(),
        &format!("{}/rpc", rpc.uri()),
    );
    state.x402_config = Some(
        X402Config::compile(X402ConfigRaw {
            asset_symbol: "USDC".into(),
            base_url: "https://nftbk.example".into(),
            recipient_address: "0x0000000000000000000000000000000000000002".into(),
            max_timeout_seconds: 300,
            facilitator: X402FacilitatorConfigRaw {
                url: rpc.uri(),
                network: "eip155:84532".into(),
                api_key_id_env: None,
                api_key_secret_env: None,
            },
            pricing: PricingRaw {
                archive_price_per_gb: Some("0.05".into()),
                pin_price_per_gb: None,
            },
        })
        .unwrap(),
    );
    let owner = database
        .db
        .owner(&Principal {
            issuer: "nftbk:local".into(),
            subject: "local".into(),
        })
        .await
        .unwrap();
    let spec = specification();
    let quote = database
        .db
        .create(Create {
            owner_id: owner.clone(),
            key: "quoted-raw".into(),
            payload_hash: spec.hash(),
            resource: Resource::Quote,
            creation: Creation::Quote {
                specification: spec.clone(),
                terms: billing::terms(&state).unwrap(),
                backup_id: None,
            },
        })
        .await
        .unwrap();
    let quote_claim = database.db.claim().await.unwrap().unwrap();
    workers::execute(&state, &quote_claim).await.unwrap();
    let ready: Quote = serde_json::from_value(
        database
            .db
            .get(Resource::Quote, &owner, quote["id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(ready.state, "ready");
    assert_eq!(ready.amount_atomic.as_deref(), Some("1"));
    let app = build_router(state.clone());
    let (status, _, _) = request(
        &app,
        Method::POST,
        "/v2/backups",
        json!({"nfts":spec.nfts,"outputs":spec.outputs,"quote_id":ready.id}),
        Some("quoted-creation"),
    )
    .await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    assert!(database.db.claim().await.unwrap().is_none());
    let backups = database
        .db
        .list(Resource::Backup, &owner, &Default::default())
        .await
        .unwrap();
    let id = backups.data[0]["id"].as_str().unwrap();
    database
        .db
        .payment(
            Resource::Backup,
            &owner,
            id,
            Some(PaymentUpdate::Settled(
                json!({"success":true,"transaction":"fixture"}),
            )),
        )
        .await
        .unwrap();
    let capture = database.db.claim().await.unwrap().unwrap();
    workers::execute(&state, &capture).await.unwrap();
    let items = database
        .db
        .list(
            Resource::Item,
            &owner,
            &nftbk::server::database::r#trait::Page {
                backup_id: Some(id.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let digest = items.data[0]["metadata_sha256"].as_str().unwrap();
    assert_eq!(state.storage.read(digest).await.unwrap(), original);
    assert_eq!(rpc.received_requests().await.unwrap().len(), 1);
    database.close().await;
}

#[tokio::test]
#[ignore = "Requires isolated PostgreSQL; run with NFTBK_INTEGRATION_DATABASE_URL"]
async fn an_old_garbage_collector_cannot_delete_a_reused_digest() {
    let database = TestDatabase::new(false).await;
    let directory = tempfile::tempdir().unwrap();
    let state = state(&database.db, directory.path(), "https://rpc.example");
    let owner = database
        .db
        .owner(&Principal {
            issuer: "issuer".into(),
            subject: "alice".into(),
        })
        .await
        .unwrap();
    let backup = create_for_owner(&database.db, &owner, specification(), vec![]).await;
    let capture = database.db.claim().await.unwrap().unwrap();
    let source = state
        .storage
        .put(&database.db, &capture, b"source inventory")
        .await
        .unwrap();
    database
        .db
        .progress(
            &capture,
            Progress::Captured {
                manifest_sha256: source.sha256.clone(),
                state: State::Ready,
            },
        )
        .await
        .unwrap();
    let archive = database.db.claim().await.unwrap().unwrap();
    let artifact = state
        .storage
        .put(&database.db, &archive, b"reusable artifact")
        .await
        .unwrap();
    database
        .db
        .progress(&archive, Progress::Archived(artifact.clone()))
        .await
        .unwrap();
    database
        .db
        .delete(Resource::Archive, &owner, &backup.archives[0].id)
        .await
        .unwrap();
    let deletion = database.db.claim().await.unwrap().unwrap();
    workers::execute(&state, &deletion).await.unwrap();
    let garbage = database.db.garbage(None).await.unwrap();
    assert_eq!(garbage.len(), 1);
    assert_eq!(garbage[0].sha256, artifact.sha256);
    state
        .storage
        .collect(&database.db, &garbage[0])
        .await
        .unwrap();
    assert!(!state.storage.blob_path(&artifact.sha256).unwrap().exists());
    create_for_owner(&database.db, &owner, specification(), vec![]).await;
    let fresh = database.db.claim().await.unwrap().unwrap();
    state
        .storage
        .put(&database.db, &fresh, b"reusable artifact")
        .await
        .unwrap();
    state
        .storage
        .collect(&database.db, &garbage[0])
        .await
        .unwrap();
    assert_eq!(
        state.storage.read(&artifact.sha256).await.unwrap(),
        b"reusable artifact"
    );
    assert_eq!(
        state.storage.read(&source.sha256).await.unwrap(),
        b"source inventory"
    );
    assert!(database.db.garbage(None).await.unwrap().is_empty());
    database.close().await;
}

#[tokio::test]
#[ignore = "Requires isolated PostgreSQL; run with NFTBK_INTEGRATION_DATABASE_URL"]
async fn expires_unpaid_reservations_without_releasing_uncertain_settlements() {
    use nftbk::server::database::r#trait::{PaymentUpdate, QuoteTerms};
    let database = TestDatabase::new(false).await;
    let owner = database
        .db
        .owner(&Principal {
            issuer: "issuer".into(),
            subject: "alice".into(),
        })
        .await
        .unwrap();
    let spec = specification();
    let quote = database
        .db
        .create(Create {
            owner_id: owner.clone(),
            key: "quote-expiry".into(),
            payload_hash: spec.hash(),
            resource: Resource::Quote,
            creation: Creation::Quote {
                specification: spec.clone(),
                backup_id: None,
                terms: QuoteTerms {
                    asset_symbol: "USDC".into(),
                    chain_id: "eip155:84532".into(),
                    asset_address: "0xasset".into(),
                    asset_decimals: 6,
                    pricing_version: "test".into(),
                    lifetime_seconds: 300,
                },
            },
        })
        .await
        .unwrap();
    let quote_claim = database.db.claim().await.unwrap().unwrap();
    database
        .db
        .progress(
            &quote_claim,
            Progress::Quoted {
                plan: vec![],
                amount_atomic: "123".into(),
                estimated_size_bytes: 100,
                lifetime_seconds: 300,
            },
        )
        .await
        .unwrap();
    let mut ids = vec![];
    for key in ["abandoned", "unknown"] {
        let created = database
            .db
            .create(Create {
                owner_id: owner.clone(),
                key: key.into(),
                payload_hash: spec.hash(),
                resource: Resource::Backup,
                creation: Creation::Backup {
                    specification: spec.clone(),
                    quote_id: Some(quote["id"].as_str().unwrap().into()),
                    pricing_version: Some("test".into()),
                    provider_ids: vec![],
                },
            })
            .await
            .unwrap();
        ids.push(created["id"].as_str().unwrap().to_string());
    }
    database
        .db
        .payment(
            Resource::Backup,
            &owner,
            &ids[1],
            Some(PaymentUpdate::Begin {
                proof_hash: "unknown-outcome".into(),
                settle_request: json!({}),
            }),
        )
        .await
        .unwrap();
    database
        .db
        .payment(
            Resource::Backup,
            &owner,
            &ids[1],
            Some(PaymentUpdate::Failed {
                detail: "No response".into(),
                ambiguous: true,
            }),
        )
        .await
        .unwrap();
    sqlx::query("UPDATE quotes SET expires_at=now()-interval '1 second' WHERE id=$1::text::uuid")
        .bind(quote["id"].as_str().unwrap())
        .execute(&database.db.pool)
        .await
        .unwrap();
    database.db.maintenance().await.unwrap();
    let abandoned = database
        .db
        .get(Resource::Backup, &owner, &ids[0])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(abandoned["state"], "deleting");
    assert_eq!(
        database
            .db
            .get(Resource::Backup, &owner, &ids[1])
            .await
            .unwrap()
            .unwrap()["state"],
        "awaiting_payment"
    );
    assert!(matches!(
        database
            .db
            .payment(
                Resource::Backup,
                &owner,
                &ids[0],
                Some(PaymentUpdate::Begin {
                    proof_hash: "new-proof".into(),
                    settle_request: json!({})
                })
            )
            .await,
        Err(DatabaseError::Conflict(_))
    ));
    let deletion = database.db.claim().await.unwrap().unwrap();
    assert_eq!(deletion.operation.kind, "delete_backup");
    assert_eq!(deletion.operation.target_id, ids[0]);
    database.close().await;
}
