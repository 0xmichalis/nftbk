use std::time::Duration;

use base64::Engine;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgConnection, PgPool, Postgres, QueryBuilder, Row};
use uuid::Uuid;

use crate::server::model::*;
use r#trait::*;

#[cfg(test)]
pub mod mock;
pub mod r#trait;

#[derive(Clone)]
pub struct Db {
    pub pool: PgPool,
    queue_capacity: usize,
    pin_check_interval_seconds: u64,
}

fn uuid() -> String {
    Uuid::new_v4().to_string()
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
    serde_json::from_value(value).map_err(|e| DatabaseError::Invalid(e.to_string()))
}
fn view(resource: Resource) -> &'static str {
    match resource {
        Resource::Backup => "api_backups",
        Resource::Archive => "api_archives",
        Resource::PinSet => "api_pin_sets",
        Resource::Quote => "api_quotes",
        Resource::Operation => "api_operations",
        Resource::Item => "api_items",
        Resource::Pin => "api_pins",
    }
}
async fn document(
    connection: &mut PgConnection,
    resource: Resource,
    owner: &str,
    id: &str,
) -> Result<Option<Value>> {
    let query = format!(
        "SELECT document FROM {} WHERE owner_id=$1::text::uuid AND id=$2::text::uuid",
        view(resource)
    );
    Ok(sqlx::query_scalar(&query)
        .bind(owner)
        .bind(id)
        .fetch_optional(connection)
        .await?)
}
async fn fence(connection: &mut PgConnection, claim: &Claim) -> Result<()> {
    let active: Option<String> = sqlx::query_scalar("SELECT id::text FROM operations WHERE id=$1::text::uuid AND lease_token=$2::text::uuid AND state='running' AND lease_until>now() FOR UPDATE")
        .bind(&claim.operation.id).bind(&claim.lease_token).fetch_optional(connection).await?;
    if active.is_none() {
        return Err(DatabaseError::LostLease);
    }
    Ok(())
}
async fn insert_operation(
    connection: &mut PgConnection,
    owner: &str,
    kind: &str,
    target: &str,
    state: &str,
) -> Result<String> {
    let column = match kind {
        "capture" | "delete_backup" => "backup_id",
        "archive" | "delete_archive" => "archive_id",
        "pin" | "delete_pin_set" => "pin_set_id",
        "quote" => "quote_id",
        _ => return Err(DatabaseError::Invalid("Unknown operation kind".into())),
    };
    let id = uuid();
    sqlx::query(&format!("INSERT INTO operations(id,owner_id,kind,{column},state) VALUES($1::text::uuid,$2::text::uuid,$3,$4::text::uuid,$5)"))
        .bind(&id).bind(owner).bind(kind).bind(target).bind(state).execute(connection).await?;
    Ok(id)
}

impl Db {
    pub fn from_pool(pool: PgPool) -> Self {
        Self {
            pool,
            queue_capacity: 1024,
            pin_check_interval_seconds: 3600,
        }
    }

    pub fn configure(mut self, queue_capacity: usize, pin_check_interval_seconds: u64) -> Self {
        self.queue_capacity = queue_capacity;
        self.pin_check_interval_seconds = pin_check_interval_seconds;
        self
    }

    pub async fn new(url: &str, max_connections: u32) -> anyhow::Result<Self> {
        let mut last_error = None;
        for _ in 0..10 {
            match PgPoolOptions::new()
                .max_connections(max_connections.max(4))
                .connect(url)
                .await
            {
                Ok(pool) => {
                    sqlx::migrate!("./migrations").run(&pool).await?;
                    return Ok(Self::from_pool(pool));
                }
                Err(error) => {
                    last_error = Some(error);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
        Err(last_error.expect("connection attempted").into())
    }

    pub async fn register_provider(
        &self,
        key: &str,
        provider_type: &str,
        url: &str,
        credential_reference: Option<&str>,
        adopt_legacy: bool,
    ) -> Result<String> {
        if adopt_legacy {
            sqlx::query("UPDATE provider_instances SET instance_key=$1,credential_reference=$2 WHERE instance_key=$3 AND NOT EXISTS(SELECT 1 FROM provider_instances WHERE instance_key=$1)")
                .bind(key).bind(credential_reference).bind(format!("legacy:{provider_type}:{url}")).execute(&self.pool).await?;
        }
        Ok(sqlx::query_scalar("INSERT INTO provider_instances(instance_key,provider_type,provider_url,credential_reference) VALUES($1,$2,$3,$4) ON CONFLICT(instance_key) DO UPDATE SET provider_url=EXCLUDED.provider_url,credential_reference=EXCLUDED.credential_reference RETURNING id::text")
            .bind(key).bind(provider_type).bind(url).bind(credential_reference).fetch_one(&self.pool).await?)
    }

    pub async fn signing_key(&self) -> Result<Vec<u8>> {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Ok(sqlx::query_scalar("INSERT INTO service_keys(name,key) VALUES('download',$1) ON CONFLICT(name) DO UPDATE SET name=EXCLUDED.name RETURNING key")
            .bind(key.as_slice()).fetch_one(&self.pool).await?)
    }

    pub async fn adopt_legacy_issuer(&self, issuer: &str) -> Result<()> {
        sqlx::query("UPDATE principals SET issuer=$1 WHERE issuer='legacy'")
            .bind(issuer)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl Database for Db {
    async fn owner(&self, principal: &Principal) -> Result<String> {
        Ok(sqlx::query_scalar("INSERT INTO principals(issuer,subject) VALUES($1,$2) ON CONFLICT(issuer,subject) DO UPDATE SET issuer=EXCLUDED.issuer RETURNING id::text")
            .bind(&principal.issuer).bind(&principal.subject).fetch_one(&self.pool).await?)
    }

    async fn archive_storage(&self, owner: &str, id: &str) -> Result<String> {
        sqlx::query_scalar("SELECT storage_key FROM archives WHERE id=$1::text::uuid AND owner_id=$2::text::uuid AND storage_key IS NOT NULL").bind(id).bind(owner).fetch_optional(&self.pool).await?.ok_or(DatabaseError::NotFound)
    }
    async fn get(&self, resource: Resource, owner: &str, id: &str) -> Result<Option<Value>> {
        document(&mut *self.pool.acquire().await?, resource, owner, id).await
    }

    async fn list(
        &self,
        resource: Resource,
        owner: &str,
        page: &Page,
    ) -> Result<Collection<Value>> {
        let limit = page.limit.unwrap_or(50).clamp(1, 100) as usize;
        let mut query = QueryBuilder::<Postgres>::new(format!(
            "SELECT document,created_at,id::text AS cursor_id FROM {} WHERE owner_id=",
            view(resource)
        ));
        query.push_bind(owner).push("::text::uuid");
        for (key, value) in [
            ("state", &page.state),
            ("chain_id", &page.chain_id),
            ("contract_address", &page.contract_address),
            ("token_id", &page.token_id),
            ("cid", &page.cid),
            ("backup_id", &page.backup_id),
        ] {
            if let Some(value) = value {
                if matches!(resource, Resource::Pin)
                    && matches!(key, "chain_id" | "contract_address" | "token_id")
                {
                    continue;
                }
                query
                    .push(" AND document->>")
                    .push_bind(key)
                    .push("=")
                    .push_bind(value);
            }
        }
        if matches!(resource, Resource::Pin)
            && [
                page.chain_id.as_ref(),
                page.contract_address.as_ref(),
                page.token_id.as_ref(),
            ]
            .iter()
            .any(|x| x.is_some())
        {
            query.push(" AND EXISTS(SELECT 1 FROM pin_memberships m JOIN backup_items i ON i.id=m.item_id JOIN pin_sets ps ON ps.id=m.pin_set_id WHERE m.pin_id=api_pins.id AND ps.owner_id=api_pins.owner_id");
            for (column, value) in [
                ("i.chain_id", &page.chain_id),
                ("i.contract_address", &page.contract_address),
                ("i.token_id", &page.token_id),
            ] {
                if let Some(value) = value {
                    query.push(" AND ").push(column).push("=").push_bind(value);
                }
            }
            query.push(")");
        }
        if matches!(resource, Resource::Item) && page.ipfs_only == Some(true) {
            query.push(
                " AND EXISTS(SELECT 1 FROM item_assets a WHERE a.item_id=api_items.id AND a.cid IS NOT NULL)",
            );
        }
        if let Some(pin_set_id) = &page.pin_set_id {
            query
                .push(" AND id IN(SELECT pin_id FROM pin_memberships WHERE pin_set_id=")
                .push_bind(pin_set_id)
                .push("::text::uuid)");
        }
        if let Some(cursor) = &page.cursor {
            let (created_at, id) = decode_cursor(cursor)?;
            query
                .push(" AND (created_at,id)<(")
                .push_bind(created_at)
                .push(",")
                .push_bind(id)
                .push("::text::uuid)");
        }
        query
            .push(" ORDER BY created_at DESC,id DESC LIMIT ")
            .push_bind((limit + 1) as i64);
        let rows = query.build().fetch_all(&self.pool).await?;
        let next_cursor = if rows.len() > limit {
            let row = &rows[limit - 1];
            Some(encode_cursor(row.get("created_at"), row.get("cursor_id")))
        } else {
            None
        };
        Ok(Collection {
            data: rows
                .into_iter()
                .take(limit)
                .map(|r| r.get("document"))
                .collect(),
            next_cursor,
        })
    }

    async fn create(&self, request: Create) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT id FROM principals WHERE id=$1::text::uuid FOR UPDATE")
            .bind(&request.owner_id)
            .execute(&mut *tx)
            .await?;
        let endpoint = request.resource.collection();
        if let Some(row)=sqlx::query("SELECT payload_hash,resource_id::text AS resource_id FROM idempotency_keys WHERE owner_id=$1::text::uuid AND endpoint=$2 AND key=$3")
            .bind(&request.owner_id).bind(endpoint).bind(&request.key).fetch_optional(&mut *tx).await? {
            if row.get::<String,_>("payload_hash")!=request.payload_hash { return Err(DatabaseError::Conflict("Idempotency-Key was already used with a different payload".into())); }
            let result=document(&mut tx,request.resource,&request.owner_id,&row.get::<String,_>("resource_id")).await?.ok_or(DatabaseError::NotFound)?;
            tx.commit().await?; return Ok(result);
        }
        sqlx::query("SELECT pg_advisory_xact_lock(881002)")
            .execute(&mut *tx)
            .await?;
        let pending: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM operations WHERE state IN('awaiting_payment','queued','running')",
        )
        .fetch_one(&mut *tx)
        .await?;
        let added = match &request.creation {
            Creation::Backup { specification, .. } => 1 + specification.outputs.len(),
            _ => 1,
        };
        if pending as usize + added > self.queue_capacity {
            return Err(DatabaseError::Capacity);
        }
        let id = uuid();
        match request.creation {
            Creation::Backup {
                specification,
                quote_id,
                pricing_version,
                provider_ids,
            } => {
                let mut plan = Vec::new();
                let state = if let Some(version) = pricing_version {
                    let quote_id = quote_id
                        .as_deref()
                        .ok_or_else(|| DatabaseError::Invalid("quote_id is required".into()))?;
                    let quote=sqlx::query("SELECT specification_hash,pricing_version,state,expires_at,plan,source_backup_id::text AS source_backup_id FROM quotes WHERE id=$1::text::uuid AND owner_id=$2::text::uuid FOR UPDATE")
                        .bind(quote_id).bind(&request.owner_id).fetch_optional(&mut *tx).await?.ok_or(DatabaseError::NotFound)?;
                    if quote.get::<Option<String>, _>("source_backup_id").is_some()
                        || quote.get::<String, _>("state") != "ready"
                        || quote.get::<DateTime<Utc>, _>("expires_at") <= Utc::now()
                        || quote.get::<String, _>("specification_hash") != specification.hash()
                        || quote.get::<String, _>("pricing_version") != version
                    {
                        return Err(DatabaseError::Conflict("Quote is expired, incomplete, or belongs to a different specification or pricing policy".into()));
                    }
                    plan = decode(quote.get("plan"))?;
                    "awaiting_payment"
                } else {
                    "queued"
                };
                sqlx::query("INSERT INTO backups(id,owner_id,state,specification,specification_hash) VALUES($1::text::uuid,$2::text::uuid,$3,$4,$5)")
                    .bind(&id).bind(&request.owner_id).bind(state).bind(json!(specification)).bind(specification.hash()).execute(&mut *tx).await?;
                for nft in &specification.nfts {
                    let planned: Option<&Item> = plan.iter().find(|i: &&Item| i.nft == *nft);
                    let item_id = uuid();
                    sqlx::query("INSERT INTO backup_items(id,backup_id,chain_id,contract_address,token_id,metadata_uri,metadata_sha256,observed_at,block_reference) VALUES($1::text::uuid,$2::text::uuid,$3,$4,$5,$6,$7,$8,$9)")
                        .bind(&item_id).bind(&id).bind(&nft.chain_id).bind(&nft.contract_address).bind(&nft.token_id)
                        .bind(planned.and_then(|i|i.metadata_uri.as_deref())).bind(planned.and_then(|i|i.metadata_sha256.as_deref())).bind(planned.and_then(|i|i.observed_at)).bind(planned.and_then(|i|i.block_reference.as_deref())).execute(&mut *tx).await?;
                    if let Some(item) = planned {
                        for asset in &item.assets {
                            let mut copied = asset.clone();
                            copied.id = uuid();
                            copied.item_id = item_id.clone();
                            save_asset(&mut tx, &item_id, &copied).await?;
                        }
                    }
                }
                insert_operation(&mut tx, &request.owner_id, "capture", &id, state).await?;
                for output in specification.outputs {
                    insert_output(
                        &mut tx,
                        &request.owner_id,
                        &id,
                        &uuid(),
                        output,
                        &provider_ids,
                        state,
                    )
                    .await?;
                }
                if let Some(quote_id) = quote_id.filter(|_| state == "awaiting_payment") {
                    sqlx::query("INSERT INTO payments(backup_id,quote_id) VALUES($1::text::uuid,$2::text::uuid)").bind(&id).bind(quote_id).execute(&mut *tx).await?;
                }
            }
            Creation::Quote {
                specification,
                terms,
                backup_id,
            } => {
                sqlx::query("INSERT INTO quotes(id,owner_id,specification,specification_hash,pricing_version,state,asset_symbol,chain_id,asset_address,asset_decimals,expires_at,source_backup_id) VALUES($1::text::uuid,$2::text::uuid,$3,$4,$5,'calculating',$6,$7,$8,$9,now()+make_interval(secs=>$10::double precision),$11::text::uuid)")
                    .bind(&id).bind(&request.owner_id).bind(json!(specification)).bind(specification.hash()).bind(terms.pricing_version).bind(terms.asset_symbol).bind(terms.chain_id).bind(terms.asset_address).bind(i16::from(terms.asset_decimals)).bind(f64::from(terms.lifetime_seconds)).bind(backup_id).execute(&mut *tx).await?;
                insert_operation(&mut tx, &request.owner_id, "quote", &id, "queued").await?;
            }
            Creation::Output {
                backup_id,
                output,
                provider_ids,
                quote_id,
                pricing_version,
                specification_hash,
            } => {
                let backup = document(&mut tx, Resource::Backup, &request.owner_id, &backup_id)
                    .await?
                    .ok_or(DatabaseError::NotFound)?;
                if !matches!(backup["state"].as_str(), Some("ready" | "partial")) {
                    return Err(DatabaseError::Conflict(
                        "Backup must be captured before adding outputs".into(),
                    ));
                }
                let state = if let Some(version) = pricing_version {
                    let quote_id = quote_id
                        .as_deref()
                        .ok_or_else(|| DatabaseError::Invalid("quote_id is required".into()))?;
                    let hash=sqlx::query_scalar::<_,String>("SELECT specification_hash FROM quotes WHERE id=$1::text::uuid AND owner_id=$2::text::uuid AND source_backup_id=$3::text::uuid AND state='ready' AND expires_at>now() AND pricing_version=$4 FOR UPDATE").bind(quote_id).bind(&request.owner_id).bind(&backup_id).bind(version).fetch_optional(&mut *tx).await?.ok_or_else(||DatabaseError::Conflict("Valid output quote is required".into()))?;
                    if hash != specification_hash {
                        return Err(DatabaseError::Conflict(
                            "Quote belongs to a different output specification".into(),
                        ));
                    }
                    "awaiting_payment"
                } else {
                    "queued"
                };
                insert_output(
                    &mut tx,
                    &request.owner_id,
                    &backup_id,
                    &id,
                    output,
                    &provider_ids,
                    state,
                )
                .await?;
                if state == "awaiting_payment" {
                    let column = match request.resource {
                        Resource::Archive => "archive_id",
                        Resource::PinSet => "pin_set_id",
                        _ => return Err(DatabaseError::Invalid("Invalid output resource".into())),
                    };
                    sqlx::query(&format!("INSERT INTO payments({column},quote_id) VALUES($1::text::uuid,$2::text::uuid)")).bind(&id).bind(quote_id).execute(&mut *tx).await?;
                }
            }
        }
        sqlx::query("INSERT INTO idempotency_keys(owner_id,endpoint,key,payload_hash,resource_id) VALUES($1::text::uuid,$2,$3,$4,$5::text::uuid)")
            .bind(&request.owner_id).bind(endpoint).bind(request.key).bind(request.payload_hash).bind(&id).execute(&mut *tx).await?;
        let result = document(&mut tx, request.resource, &request.owner_id, &id)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        tx.commit().await?;
        Ok(result)
    }

    async fn delete(&self, resource: Resource, owner: &str, id: &str) -> Result<Operation> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT id FROM principals WHERE id=$1::text::uuid FOR UPDATE")
            .bind(owner)
            .execute(&mut *tx)
            .await?;
        let target = document(&mut tx, resource, owner, id)
            .await?
            .ok_or(DatabaseError::NotFound)?;
        let (kind, column) = match resource {
            Resource::Backup => ("delete_backup", "backup_id"),
            Resource::Archive => ("delete_archive", "archive_id"),
            Resource::PinSet => ("delete_pin_set", "pin_set_id"),
            _ => return Err(DatabaseError::Invalid("Resource cannot be deleted".into())),
        };
        if let Some(op_id)=sqlx::query_scalar::<_,String>(&format!("SELECT id::text FROM operations WHERE {column}=$1::text::uuid AND kind=$2 ORDER BY created_at DESC LIMIT 1")).bind(id).bind(kind).fetch_optional(&mut *tx).await? {
            let result=decode(document(&mut tx,Resource::Operation,owner,&op_id).await?.ok_or(DatabaseError::NotFound)?)?;
            tx.commit().await?;return Ok(result);
        }
        let active = sqlx::query(&format!(
            "SELECT state FROM operations WHERE {column}=$1::text::uuid ORDER BY id FOR UPDATE"
        ))
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
        if active
            .iter()
            .any(|r| matches!(r.get::<String, _>("state").as_str(), "queued" | "running"))
            || matches!(target["state"].as_str(), Some("queued" | "running"))
        {
            return Err(DatabaseError::Conflict(
                "Wait for the active operation to finish before deleting this resource".into(),
            ));
        }
        let settling: bool = sqlx::query_scalar(&format!("SELECT EXISTS(SELECT 1 FROM payments p WHERE (p.{column}=$1::text::uuid{} ) AND p.state IN('settling','reconciliation_required'))",if matches!(resource,Resource::Backup) { " OR p.archive_id IN(SELECT id FROM archives WHERE backup_id=$1::text::uuid) OR p.pin_set_id IN(SELECT id FROM pin_sets WHERE backup_id=$1::text::uuid)" } else { "" })).bind(id).fetch_one(&mut *tx).await?;
        if settling {
            return Err(DatabaseError::Conflict(
                "Payment settlement must be reconciled before deletion".into(),
            ));
        }
        sqlx::query(&format!("UPDATE operations SET state='failed',error=$2,updated_at=now() WHERE {column}=$1::text::uuid AND state='awaiting_payment'")).bind(id).bind(json!({"code":"cancelled","message":"Resource deleted before payment","retryable":false})).execute(&mut *tx).await?;
        if matches!(resource, Resource::Backup) {
            let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM archives WHERE backup_id=$1::text::uuid AND state IN('queued','running','deleting') UNION ALL SELECT 1 FROM pin_sets WHERE backup_id=$1::text::uuid AND state IN('queued','running','deleting'))").bind(id).fetch_one(&mut *tx).await?;
            if active {
                return Err(DatabaseError::Conflict(
                    "An output operation is active".into(),
                ));
            }
        }
        sqlx::query(&format!("UPDATE {} SET state='deleting',deletion_requested_at=COALESCE(deletion_requested_at,now()) WHERE id=$1::text::uuid",resource.table())).bind(id).execute(&mut *tx).await?;
        let op_id = insert_operation(&mut tx, owner, kind, id, "queued").await?;
        let result = decode(
            document(&mut tx, Resource::Operation, owner, &op_id)
                .await?
                .ok_or(DatabaseError::NotFound)?,
        )?;
        tx.commit().await?;
        Ok(result)
    }

    async fn retry(&self, owner: &str, id: &str) -> Result<Attempt> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT id FROM principals WHERE id=$1::text::uuid FOR UPDATE")
            .bind(owner)
            .execute(&mut *tx)
            .await?;
        let row=sqlx::query("SELECT kind,COALESCE(backup_id,archive_id,pin_set_id,quote_id)::text AS target,state FROM operations WHERE id=$1::text::uuid AND owner_id=$2::text::uuid FOR UPDATE").bind(id).bind(owner).fetch_optional(&mut *tx).await?.ok_or(DatabaseError::NotFound)?;
        if row.get::<String, _>("state") != "failed" {
            return Err(DatabaseError::Conflict(
                "Only a failed operation can be retried".into(),
            ));
        }
        let kind = row.get::<String, _>("kind");
        let table = match kind.as_str() {
            "capture" | "delete_backup" => "backups",
            "archive" | "delete_archive" => "archives",
            "pin" | "delete_pin_set" => "pin_sets",
            "quote" => "quotes",
            _ => return Err(DatabaseError::Invalid("Invalid operation".into())),
        };
        let target: String = row.get("target");
        let state = if kind.starts_with("delete_") {
            "deleting"
        } else if kind == "quote" {
            "calculating"
        } else {
            "queued"
        };
        let active:bool=sqlx::query_scalar(&format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE id=$1::text::uuid AND state IN('deleting','deleted','expired'))")).bind(&target).fetch_one(&mut *tx).await?;
        if active && !kind.starts_with("delete_") {
            return Err(DatabaseError::Conflict(
                "The target is deleting, deleted or expired; create a new output or quote".into(),
            ));
        }
        if matches!(kind.as_str(), "archive" | "pin") {
            let ready: bool = sqlx::query_scalar(&format!("SELECT EXISTS(SELECT 1 FROM {table} r JOIN backups b ON b.id=r.backup_id WHERE r.id=$1::text::uuid AND b.state IN('ready','partial'))")).bind(&target).fetch_one(&mut *tx).await?;
            if !ready {
                return Err(DatabaseError::Conflict(
                    "Retry the snapshot capture operation before retrying this output".into(),
                ));
            }
        }
        sqlx::query(&format!(
            "UPDATE {table} SET state=$2 WHERE id=$1::text::uuid"
        ))
        .bind(&target)
        .bind(state)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE operations SET state='queued',available_at=now(),updated_at=now(),error=NULL WHERE id=$1::text::uuid").bind(id).execute(&mut *tx).await?;
        let value: Value = sqlx::query_scalar("INSERT INTO operation_attempts(operation_id,number) SELECT id,attempts+1 FROM operations WHERE id=$1::text::uuid RETURNING jsonb_build_object('number',number,'requested_at',requested_at,'started_at',started_at,'finished_at',finished_at,'error',error)").bind(id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        decode(value)
    }

    async fn attempts(&self, owner: &str, id: &str) -> Result<Vec<Attempt>> {
        if self.get(Resource::Operation, owner, id).await?.is_none() {
            return Err(DatabaseError::NotFound);
        }
        let rows:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('number',number,'requested_at',requested_at,'started_at',started_at,'finished_at',finished_at,'error',error) FROM operation_attempts WHERE operation_id=$1::text::uuid ORDER BY number").bind(id).fetch_all(&self.pool).await?;
        rows.into_iter().map(decode).collect()
    }

    async fn claim(&self) -> Result<Option<Claim>> {
        let mut tx = self.pool.begin().await?;
        let row=sqlx::query("SELECT o.id::text AS id,o.owner_id::text AS owner_id FROM operations o WHERE o.state='queued' AND o.available_at<=now() AND (o.kind NOT IN('archive','pin') OR EXISTS(SELECT 1 FROM backups b WHERE b.state IN('ready','partial') AND b.id=COALESCE((SELECT backup_id FROM archives WHERE id=o.archive_id),(SELECT backup_id FROM pin_sets WHERE id=o.pin_set_id)))) ORDER BY o.available_at,o.created_at,o.id FOR UPDATE OF o SKIP LOCKED LIMIT 1").fetch_optional(&mut *tx).await?;
        let Some(row) = row else { return Ok(None) };
        let id: String = row.get("id");
        let owner: String = row.get("owner_id");
        let lease_token = uuid();
        sqlx::query("UPDATE operations SET state='running',attempts=CASE WHEN EXISTS(SELECT 1 FROM operation_attempts a WHERE a.operation_id=operations.id AND a.number=operations.attempts AND a.finished_at IS NULL) THEN attempts ELSE attempts+1 END,lease_token=$2::text::uuid,lease_until=now()+interval '90 seconds',updated_at=now() WHERE id=$1::text::uuid").bind(&id).bind(&lease_token).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO operation_attempts(operation_id,number,lease_token,started_at) SELECT id,attempts,lease_token,now() FROM operations WHERE id=$1::text::uuid ON CONFLICT(operation_id,number) DO UPDATE SET lease_token=EXCLUDED.lease_token,started_at=COALESCE(operation_attempts.started_at,EXCLUDED.started_at)").bind(&id).execute(&mut *tx).await?;
        let operation: Operation = decode(
            document(&mut tx, Resource::Operation, &owner, &id)
                .await?
                .ok_or(DatabaseError::NotFound)?,
        )?;
        let target_table = match operation.kind.as_str() {
            "capture" => Some("backups"),
            "archive" => Some("archives"),
            "pin" => Some("pin_sets"),
            _ => None,
        };
        if let Some(table) = target_table {
            sqlx::query(&format!(
                "UPDATE {table} SET state='running' WHERE id=$1::text::uuid AND state='queued'"
            ))
            .bind(&operation.target_id)
            .execute(&mut *tx)
            .await?;
        }
        let specification:Option<Value>=sqlx::query_scalar("SELECT COALESCE(q.specification,b.specification) FROM operations o LEFT JOIN backups b ON b.id=COALESCE(o.backup_id,(SELECT backup_id FROM archives WHERE id=o.archive_id),(SELECT backup_id FROM pin_sets WHERE id=o.pin_set_id)) LEFT JOIN quotes q ON q.id=o.quote_id WHERE o.id=$1::text::uuid").bind(&id).fetch_one(&mut *tx).await?;
        let plan:Option<Value>=sqlx::query_scalar("SELECT q.plan FROM operations o JOIN quotes q ON q.id=o.quote_id WHERE o.id=$1::text::uuid").bind(&id).fetch_optional(&mut *tx).await?;
        tx.commit().await?;
        Ok(Some(Claim {
            operation,
            owner_id: owner,
            lease_token,
            specification: specification.map(decode).transpose()?,
            plan: decode(plan.unwrap_or_else(|| json!([])))?,
        }))
    }

    async fn heartbeat(&self, claim: &Claim) -> Result<bool> {
        Ok(sqlx::query("UPDATE operations SET lease_until=now()+interval '90 seconds',updated_at=now() WHERE id=$1::text::uuid AND lease_token=$2::text::uuid AND state='running' AND lease_until>now()")
            .bind(&claim.operation.id).bind(&claim.lease_token).execute(&self.pool).await?.rows_affected()==1)
    }

    async fn context(&self, claim: &Claim) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        fence(&mut tx, claim).await?;
        let row=sqlx::query("SELECT COALESCE(o.backup_id,a.backup_id,ps.backup_id,q.source_backup_id)::text AS backup_id,a.storage_key,a.retention_days,to_jsonb(ps.provider_ids) AS provider_ids FROM operations o LEFT JOIN archives a ON a.id=o.archive_id LEFT JOIN pin_sets ps ON ps.id=o.pin_set_id LEFT JOIN quotes q ON q.id=o.quote_id WHERE o.id=$1::text::uuid").bind(&claim.operation.id).fetch_one(&mut *tx).await?;
        let backup_id: Option<String> = row.get("backup_id");
        let items: Vec<Value> = if let Some(id) = &backup_id {
            sqlx::query_scalar(
                "SELECT document FROM api_items WHERE backup_id=$1::text::uuid ORDER BY id",
            )
            .bind(id)
            .fetch_all(&mut *tx)
            .await?
        } else {
            vec![]
        };
        let pins:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(p)-'error' FROM provider_pins p JOIN pin_memberships m ON m.pin_id=p.id WHERE m.pin_set_id=$1::text::uuid ORDER BY p.id").bind(&claim.operation.target_id).fetch_all(&mut *tx).await?;
        let archive = if claim.operation.kind.ends_with("archive") {
            document(
                &mut tx,
                Resource::Archive,
                &claim.owner_id,
                &claim.operation.target_id,
            )
            .await?
        } else {
            None
        };
        let pin_set = if matches!(claim.operation.kind.as_str(), "pin" | "delete_pin_set") {
            document(
                &mut tx,
                Resource::PinSet,
                &claim.owner_id,
                &claim.operation.target_id,
            )
            .await?
        } else {
            None
        };
        let result = json!({"backup_id":backup_id,"items":items,"pins":pins,"archive":archive,"pin_set":pin_set,"storage_key":row.get::<Option<String>,_>("storage_key"),"retention_days":row.get::<Option<i32>,_>("retention_days"),"provider_ids":row.get::<Option<Value>,_>("provider_ids")});
        tx.commit().await?;
        Ok(result)
    }

    async fn progress(&self, claim: &Claim, progress: Progress) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        fence(&mut tx, claim).await?;
        let mut finish = true;
        let mut failure = None;
        match progress {
            Progress::Items(items) => {
                for item in items {
                    sqlx::query("UPDATE backup_items SET state=$3,metadata_uri=$4,metadata_sha256=$5,observed_at=$6,block_reference=$7,error=$8 WHERE id=$1::text::uuid AND backup_id=$2::text::uuid")
                        .bind(&item.id).bind(&item.backup_id).bind(state_name(&item.state)).bind(&item.metadata_uri).bind(&item.metadata_sha256).bind(item.observed_at).bind(&item.block_reference).bind(json!(item.error)).execute(&mut *tx).await?;
                    sqlx::query("DELETE FROM item_assets WHERE item_id=$1::text::uuid")
                        .bind(&item.id)
                        .execute(&mut *tx)
                        .await?;
                    for asset in item.assets {
                        save_asset(&mut tx, &item.id, &asset).await?;
                    }
                }
                finish = false;
            }
            Progress::Captured {
                manifest_sha256,
                state,
            } => {
                sqlx::query("UPDATE backups SET state=$2,manifest_sha256=$3,updated_at=now() WHERE id=$1::text::uuid").bind(&claim.operation.target_id).bind(state_name(&state)).bind(manifest_sha256).execute(&mut *tx).await?;
            }
            Progress::Archived(blob) => {
                sqlx::query("UPDATE archives SET state=CASE WHEN EXISTS(SELECT 1 FROM backup_items i WHERE i.backup_id=archives.backup_id AND i.state IN('failed','partial','unsupported')) THEN 'partial' ELSE 'ready' END,sha256=$2,storage_key=$3,size_bytes=$4,expires_at=now()+make_interval(days=>retention_days),error=NULL WHERE id=$1::text::uuid")
                    .bind(&claim.operation.target_id).bind(blob.sha256).bind(blob.storage_key).bind(to_i64(blob.size_bytes)?).execute(&mut *tx).await?;
            }
            Progress::Quoted {
                plan,
                amount_atomic,
                estimated_size_bytes,
                lifetime_seconds,
            } => {
                sqlx::query("UPDATE quotes SET state='ready',plan=$2,amount_atomic=$3::text::numeric,estimated_size_bytes=$4,expires_at=now()+make_interval(secs=>$5::double precision),error=NULL WHERE id=$1::text::uuid")
                    .bind(&claim.operation.target_id).bind(json!(plan)).bind(amount_atomic).bind(to_i64(estimated_size_bytes)?).bind(f64::from(lifetime_seconds)).execute(&mut *tx).await?;
            }
            Progress::Pinned { state } => {
                sqlx::query("UPDATE pin_sets SET state=$2,error=NULL WHERE id=$1::text::uuid")
                    .bind(&claim.operation.target_id)
                    .bind(state_name(&state))
                    .execute(&mut *tx)
                    .await?;
            }
            Progress::Deleted => {
                let table = match claim.operation.kind.as_str() {
                    "delete_backup" => "backups",
                    "delete_archive" => "archives",
                    "delete_pin_set" => "pin_sets",
                    _ => return Err(DatabaseError::Invalid("Not a deletion operation".into())),
                };
                let state = if table == "archives" {
                    "CASE WHEN deletion_requested_at IS NULL AND expires_at<=now() THEN 'expired' ELSE 'deleted' END"
                } else {
                    "'deleted'"
                };
                sqlx::query(&format!(
                    "UPDATE {table} SET state={state},deleted_at=now() WHERE id=$1::text::uuid"
                ))
                .bind(&claim.operation.target_id)
                .execute(&mut *tx)
                .await?;
            }
            Progress::Failed(error) => {
                failure = Some(json!(error));
                let table = match claim.operation.kind.as_str() {
                    "capture" | "delete_backup" => "backups",
                    "archive" | "delete_archive" => "archives",
                    "pin" | "delete_pin_set" => "pin_sets",
                    "quote" => "quotes",
                    _ => return Err(DatabaseError::Invalid("Unknown operation".into())),
                };
                let target_state = if claim.operation.kind.starts_with("delete_") {
                    "deleting"
                } else {
                    "failed"
                };
                if table == "backups" {
                    sqlx::query(
                        "UPDATE backups SET state=$2,updated_at=now() WHERE id=$1::text::uuid",
                    )
                    .bind(&claim.operation.target_id)
                    .bind(target_state)
                    .execute(&mut *tx)
                    .await?;
                } else {
                    sqlx::query(&format!(
                        "UPDATE {table} SET state=$2,error=$3 WHERE id=$1::text::uuid"
                    ))
                    .bind(&claim.operation.target_id)
                    .bind(target_state)
                    .bind(&failure)
                    .execute(&mut *tx)
                    .await?;
                }
            }
            Progress::Deferred => {
                if claim.operation.kind == "pin" {
                    sqlx::query("UPDATE pin_sets SET state='running' WHERE id=$1::text::uuid")
                        .bind(&claim.operation.target_id)
                        .execute(&mut *tx)
                        .await?;
                }
                sqlx::query("UPDATE operations SET state='queued',available_at=now()+interval '5 seconds',lease_until=NULL,lease_token=NULL,updated_at=now() WHERE id=$1::text::uuid").bind(&claim.operation.id).execute(&mut *tx).await?;
                finish = false;
            }
        }
        if finish {
            sqlx::query("UPDATE operations SET state=$2,error=$3,updated_at=now(),lease_until=NULL,lease_token=NULL WHERE id=$1::text::uuid").bind(&claim.operation.id).bind(if failure.is_some(){"failed"}else{"succeeded"}).bind(&failure).execute(&mut *tx).await?;
            sqlx::query("UPDATE operation_attempts SET finished_at=now(),error=$3 WHERE operation_id=$1::text::uuid AND number=$2").bind(&claim.operation.id).bind(claim.operation.attempts as i32).bind(&failure).execute(&mut *tx).await?;
            sqlx::query(
                "INSERT INTO operation_events(operation_id,event) VALUES($1::text::uuid,$2)",
            )
            .bind(&claim.operation.id)
            .bind(json!({"state":if failure.is_some(){"failed"}else{"succeeded"},"error":failure}))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn put_blob(&self, claim: &Claim, blob: &Blob) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        fence(&mut tx, claim).await?;
        let inserted:Option<String>=sqlx::query_scalar("INSERT INTO blobs(sha256,size_bytes,storage_key) VALUES($1,$2,$3) ON CONFLICT(sha256) DO UPDATE SET deleted_at=NULL,state='ready' WHERE blobs.state<>'deleting' RETURNING sha256")
            .bind(&blob.sha256).bind(to_i64(blob.size_bytes)?).bind(&blob.storage_key).fetch_optional(&mut *tx).await?;
        if inserted.is_none() {
            return Err(DatabaseError::Conflict(
                "Blob cleanup is in progress; retry the operation".into(),
            ));
        }
        sqlx::query("INSERT INTO blob_leases(sha256,operation_id) VALUES($1,$2::text::uuid) ON CONFLICT DO NOTHING").bind(&blob.sha256).bind(&claim.operation.id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn reserve_pin(
        &self,
        claim: &Claim,
        asset: &Asset,
        provider: &str,
    ) -> Result<ManagedPin> {
        let cid = asset
            .cid
            .as_deref()
            .ok_or_else(|| DatabaseError::Invalid("Asset has no CID".into()))?;
        let mut tx = self.pool.begin().await?;
        fence(&mut tx, claim).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("{provider}:{cid}"))
            .execute(&mut *tx)
            .await?;
        let pin_id=if let Some(id)=sqlx::query_scalar::<_,String>("SELECT id::text FROM provider_pins WHERE provider_id=$1::text::uuid AND cid=$2 AND state IN('queued','pinning','pinned','reconciliation_required') ORDER BY CASE state WHEN 'pinned' THEN 0 ELSE 1 END,created_at,id FOR UPDATE LIMIT 1").bind(provider).bind(cid).fetch_optional(&mut *tx).await? { id }else{
            let id=uuid();
            sqlx::query("INSERT INTO provider_pins(id,provider_id,cid,state,operation_id) VALUES($1::text::uuid,$2::text::uuid,$3,'queued',$4::text::uuid)").bind(&id).bind(provider).bind(cid).bind(&claim.operation.id).execute(&mut *tx).await?;id
        };
        sqlx::query("INSERT INTO pin_memberships(pin_set_id,backup_id,item_id,asset_id,pin_id) SELECT $1::text::uuid,i.backup_id,i.id,$2::text::uuid,$3::text::uuid FROM backup_items i WHERE i.id=$4::text::uuid ON CONFLICT DO NOTHING")
            .bind(&claim.operation.target_id).bind(&asset.id).bind(&pin_id).bind(&asset.item_id).execute(&mut *tx).await?;
        let value: Value =
            sqlx::query_scalar("SELECT to_jsonb(p) FROM provider_pins p WHERE id=$1::text::uuid")
                .bind(&pin_id)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        decode(value)
    }

    async fn update_pin(&self, claim: &Claim, update: PinUpdate) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        fence(&mut tx, claim).await?;
        match update {
            PinUpdate::Submitting { pin_id } => {
                let changed = sqlx::query("UPDATE provider_pins SET state='pinning',submitted_at=now(),updated_at=now() WHERE id=$1::text::uuid AND submitted_at IS NULL AND operation_id=$2::text::uuid").bind(pin_id).bind(&claim.operation.id).execute(&mut *tx).await?.rows_affected();
                if changed != 1 {
                    return Err(DatabaseError::Conflict(
                        "Pin submission has already started".into(),
                    ));
                }
            }
            PinUpdate::Observed {
                pin_id,
                request_id,
                state,
            } => {
                sqlx::query("UPDATE provider_pins SET request_id=$2,state=$3,updated_at=now(),error=NULL WHERE id=$1::text::uuid AND state<>'deleted'").bind(pin_id).bind(request_id).bind(state).execute(&mut *tx).await?;
            }
            PinUpdate::Failed {
                pin_id,
                failure,
                ambiguous,
            } => {
                sqlx::query("UPDATE provider_pins SET state=$2,error=$3,updated_at=now() WHERE id=$1::text::uuid").bind(pin_id).bind(if ambiguous{"reconciliation_required"}else{"failed"}).bind(json!(failure)).execute(&mut *tx).await?;
            }
            PinUpdate::Deleted { pin_id } => {
                sqlx::query("UPDATE provider_pins SET state='deleted',updated_at=now(),error=NULL WHERE id=$1::text::uuid AND NOT EXISTS(SELECT 1 FROM pin_memberships WHERE pin_id=provider_pins.id)").bind(pin_id).execute(&mut *tx).await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    async fn release_pins(&self, claim: &Claim) -> Result<Vec<ManagedPin>> {
        let mut tx = self.pool.begin().await?;
        fence(&mut tx, claim).await?;
        let ids: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT pin_id::text FROM pin_memberships WHERE pin_set_id=$1::text::uuid",
        )
        .bind(&claim.operation.target_id)
        .fetch_all(&mut *tx)
        .await?;
        sqlx::query("SELECT id FROM provider_pins WHERE id IN(SELECT x::uuid FROM unnest($1::text[]) x) ORDER BY id FOR UPDATE").bind(&ids).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM pin_memberships WHERE pin_set_id=$1::text::uuid")
            .bind(&claim.operation.target_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO pin_deletions(operation_id,pin_id) SELECT $1::text::uuid,p.id FROM provider_pins p WHERE p.id IN(SELECT x::uuid FROM unnest($2::text[]) x) AND NOT EXISTS(SELECT 1 FROM pin_memberships WHERE pin_id=p.id) ON CONFLICT DO NOTHING").bind(&claim.operation.id).bind(&ids).execute(&mut *tx).await?;
        sqlx::query("UPDATE provider_pins SET state='deleting',updated_at=now() WHERE id IN(SELECT pin_id FROM pin_deletions WHERE operation_id=$1::text::uuid) AND state<>'deleted' AND NOT EXISTS(SELECT 1 FROM pin_memberships WHERE pin_id=provider_pins.id)").bind(&claim.operation.id).execute(&mut *tx).await?;
        let rows:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(p) FROM provider_pins p JOIN pin_deletions d ON d.pin_id=p.id WHERE d.operation_id=$1::text::uuid AND p.state<>'deleted' ORDER BY p.id").bind(&claim.operation.id).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        rows.into_iter().map(decode).collect()
    }

    async fn payment(
        &self,
        resource: Resource,
        owner: &str,
        target_id: &str,
        update: Option<PaymentUpdate>,
    ) -> Result<Option<Value>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT id FROM principals WHERE id=$1::text::uuid FOR UPDATE")
            .bind(owner)
            .execute(&mut *tx)
            .await?;
        let (table, column) = match resource {
            Resource::Backup => ("backups", "backup_id"),
            Resource::Archive => ("archives", "archive_id"),
            Resource::PinSet => ("pin_sets", "pin_set_id"),
            _ => return Err(DatabaseError::Invalid("Resource is not payable".into())),
        };
        let parent_state = if matches!(resource, Resource::Backup) {
            "r.state"
        } else {
            "(SELECT b.state FROM backups b WHERE b.id=r.backup_id)"
        };
        let payment=sqlx::query(&format!("SELECT p.id::text AS id,p.state,r.state AS target_state,{parent_state} AS parent_state,p.settle_request,p.settlement FROM payments p JOIN {table} r ON r.id=p.{column} WHERE r.id=$1::text::uuid AND r.owner_id=$2::text::uuid FOR UPDATE OF p")).bind(target_id).bind(owner).fetch_optional(&mut *tx).await?;
        let Some(payment) = payment else {
            return Ok(None);
        };
        let id: String = payment.get("id");
        if matches!(
            update,
            Some(PaymentUpdate::Begin { .. } | PaymentUpdate::Settled(_))
        ) && matches!(
            payment.get::<String, _>("parent_state").as_str(),
            "deleting" | "deleted"
        ) {
            return Err(DatabaseError::Conflict(
                "Snapshot deletion has already started".into(),
            ));
        }
        match update {
            None => {}
            Some(PaymentUpdate::Begin {
                proof_hash,
                settle_request,
            }) => {
                if payment.get::<String, _>("target_state") != "awaiting_payment" {
                    return Err(DatabaseError::Conflict(
                        "Resource is no longer payable".into(),
                    ));
                }
                if !matches!(
                    payment.get::<String, _>("state").as_str(),
                    "pending" | "failed"
                ) {
                    return Err(DatabaseError::Conflict(
                        "Settlement is already in progress or requires reconciliation".into(),
                    ));
                }
                let changed=sqlx::query("UPDATE payments SET state='settling',proof_hash=$2,settle_request=$3,updated_at=now() WHERE id=$1::text::uuid").bind(&id).bind(proof_hash).bind(settle_request).execute(&mut *tx).await;
                match changed {
                    Ok(_) => {}
                    Err(error)
                        if error.as_database_error().and_then(|e| e.code()).as_deref()
                            == Some("23505") =>
                    {
                        return Err(DatabaseError::Conflict(
                            "Payment authorization was already used for another request".into(),
                        ))
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Some(PaymentUpdate::Settled(settlement)) => {
                if payment.get::<String, _>("target_state") != "awaiting_payment"
                    && payment.get::<String, _>("state") != "paid"
                {
                    return Err(DatabaseError::Conflict(
                        "Resource is no longer payable".into(),
                    ));
                }
                sqlx::query("UPDATE payments SET state='paid',settlement=$2,updated_at=now() WHERE id=$1::text::uuid").bind(&id).bind(settlement).execute(&mut *tx).await?;
                sqlx::query(&format!("UPDATE {table} SET state='queued' WHERE id=$1::text::uuid AND state='awaiting_payment'")).bind(target_id).execute(&mut *tx).await?;
                sqlx::query(&format!("UPDATE operations SET state='queued',updated_at=now() WHERE state='awaiting_payment' AND {column}=$1::text::uuid")).bind(target_id).execute(&mut *tx).await?;
                if matches!(resource, Resource::Backup) {
                    sqlx::query("UPDATE archives SET state='queued' WHERE backup_id=$1::text::uuid AND state='awaiting_payment'").bind(target_id).execute(&mut *tx).await?;
                    sqlx::query("UPDATE pin_sets SET state='queued' WHERE backup_id=$1::text::uuid AND state='awaiting_payment'").bind(target_id).execute(&mut *tx).await?;
                    sqlx::query("UPDATE operations SET state='queued',updated_at=now() WHERE state='awaiting_payment' AND (archive_id IN(SELECT id FROM archives WHERE backup_id=$1::text::uuid) OR pin_set_id IN(SELECT id FROM pin_sets WHERE backup_id=$1::text::uuid))").bind(target_id).execute(&mut *tx).await?;
                }
            }
            Some(PaymentUpdate::Failed { detail, ambiguous }) => {
                sqlx::query("UPDATE payments SET state=$2,settlement=$3,updated_at=now() WHERE id=$1::text::uuid").bind(&id).bind(if ambiguous{"reconciliation_required"}else{"failed"}).bind(json!({"error":detail})).execute(&mut *tx).await?;
            }
        }
        let result =
            sqlx::query_scalar("SELECT to_jsonb(p) FROM payments p WHERE id=$1::text::uuid")
                .bind(&id)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(Some(result))
    }

    async fn maintenance(&self) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("WITH expired AS(UPDATE operations SET state='queued',available_at=now(),lease_token=NULL,lease_until=NULL,updated_at=now() WHERE state='running' AND lease_until<=now() RETURNING id,attempts) UPDATE operation_attempts a SET finished_at=now(),error=$1 FROM expired e WHERE a.operation_id=e.id AND a.number=e.attempts")
            .bind(json!({"code":"lease_expired","message":"Worker lease expired; operation will resume","retryable":true})).execute(&mut *tx).await?;
        sqlx::query("UPDATE payments SET state='reconciliation_required',updated_at=now() WHERE state='settling' AND updated_at<now()-interval '5 minutes'").execute(&mut *tx).await?;
        sqlx::query(
            "UPDATE quotes SET state='expired' WHERE expires_at<=now() AND state<>'expired'",
        )
        .execute(&mut *tx)
        .await?;
        let expired=sqlx::query("SELECT id::text AS id,owner_id::text AS owner_id FROM archives WHERE state IN('ready','partial') AND expires_at<=now() FOR UPDATE SKIP LOCKED").fetch_all(&mut *tx).await?;
        for row in expired {
            let id: String = row.get("id");
            sqlx::query("UPDATE archives SET state='expired' WHERE id=$1::text::uuid")
                .bind(&id)
                .execute(&mut *tx)
                .await?;
            insert_operation(
                &mut tx,
                &row.get::<String, _>("owner_id"),
                "delete_archive",
                &id,
                "queued",
            )
            .await?;
        }
        let blocked = json!({"code":"capture_failed","message":"Snapshot capture failed; retry its operation before retrying this output","retryable":true});
        sqlx::query("UPDATE operations o SET state='failed',error=$1,updated_at=now() WHERE o.state='queued' AND o.kind IN('archive','pin') AND EXISTS(SELECT 1 FROM backups b WHERE b.state='failed' AND b.id=COALESCE((SELECT backup_id FROM archives WHERE id=o.archive_id),(SELECT backup_id FROM pin_sets WHERE id=o.pin_set_id)))").bind(&blocked).execute(&mut *tx).await?;
        sqlx::query("UPDATE archives a SET state='failed',error=$1 WHERE a.state='queued' AND EXISTS(SELECT 1 FROM backups b WHERE b.id=a.backup_id AND b.state='failed')").bind(&blocked).execute(&mut *tx).await?;
        sqlx::query("UPDATE pin_sets p SET state='failed',error=$1 WHERE p.state='queued' AND EXISTS(SELECT 1 FROM backups b WHERE b.id=p.backup_id AND b.state='failed')").bind(&blocked).execute(&mut *tx).await?;
        if self.pin_check_interval_seconds > 0 {
            sqlx::query("UPDATE operations o SET state='queued',available_at=now(),updated_at=now() FROM pin_sets p WHERE o.pin_set_id=p.id AND o.kind='pin' AND o.state='succeeded' AND p.state IN('ready','partial') AND o.updated_at < now()-make_interval(secs=>$1::double precision)").bind(self.pin_check_interval_seconds as f64).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        let abandoned=sqlx::query("SELECT b.owner_id::text AS owner_id,COALESCE(p.backup_id,p.archive_id,p.pin_set_id)::text AS target_id,CASE WHEN p.backup_id IS NOT NULL THEN 'backup' WHEN p.archive_id IS NOT NULL THEN 'archive' ELSE 'pin_set' END AS resource FROM payments p JOIN quotes q ON q.id=p.quote_id LEFT JOIN archives a ON a.id=p.archive_id LEFT JOIN pin_sets ps ON ps.id=p.pin_set_id JOIN backups b ON b.id=COALESCE(p.backup_id,a.backup_id,ps.backup_id) WHERE q.expires_at<=now() AND p.state IN('pending','failed') AND CASE WHEN p.backup_id IS NOT NULL THEN b.state WHEN p.archive_id IS NOT NULL THEN a.state ELSE ps.state END='awaiting_payment' LIMIT 100").fetch_all(&self.pool).await?;
        for row in abandoned {
            let resource = match row.get::<String, _>("resource").as_str() {
                "backup" => Resource::Backup,
                "archive" => Resource::Archive,
                _ => Resource::PinSet,
            };
            match self
                .delete(
                    resource,
                    &row.get::<String, _>("owner_id"),
                    &row.get::<String, _>("target_id"),
                )
                .await
            {
                Ok(_) | Err(DatabaseError::Conflict(_)) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    async fn active_leases(&self) -> Result<Vec<(String, String)>> {
        Ok(sqlx::query_as("SELECT id::text,lease_token::text FROM operations WHERE state='running' AND lease_until>now()").fetch_all(&self.pool).await?)
    }
    async fn blob_deleting(&self, sha256: &str) -> Result<bool> {
        Ok(sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM blobs WHERE sha256=$1 AND state='deleting')",
        )
        .bind(sha256)
        .fetch_one(&self.pool)
        .await?)
    }

    async fn garbage(&self, finished: Option<&str>) -> Result<Vec<Blob>> {
        if let Some(sha256) = finished {
            sqlx::query("UPDATE blobs SET state='deleted',deleted_at=now() WHERE sha256=$1 AND state='deleting'").bind(sha256).execute(&self.pool).await?;
        }
        let rows:Vec<Value>=sqlx::query_scalar("WITH candidates AS(SELECT bl.sha256 FROM blobs bl WHERE bl.state='ready' AND NOT EXISTS(SELECT 1 FROM blob_leases l JOIN operations o ON o.id=l.operation_id LEFT JOIN quotes q ON q.id=o.quote_id WHERE l.sha256=bl.sha256 AND (o.state IN('awaiting_payment','queued','running') OR q.expires_at>now())) AND NOT EXISTS(SELECT 1 FROM backup_items i JOIN backups b ON b.id=i.backup_id WHERE i.metadata_sha256=bl.sha256 AND b.state<>'deleted') AND NOT EXISTS(SELECT 1 FROM item_assets a JOIN backup_items i ON i.id=a.item_id JOIN backups b ON b.id=i.backup_id WHERE a.sha256=bl.sha256 AND b.state<>'deleted') AND NOT EXISTS(SELECT 1 FROM archives a WHERE a.sha256=bl.sha256 AND a.state NOT IN('deleted','expired')) AND NOT EXISTS(SELECT 1 FROM backups b WHERE b.manifest_sha256=bl.sha256 AND b.state<>'deleted') ORDER BY bl.created_at FOR UPDATE OF bl SKIP LOCKED LIMIT 100), marked AS(UPDATE blobs SET state='deleting' WHERE sha256 IN(SELECT sha256 FROM candidates) RETURNING sha256,size_bytes,storage_key) SELECT jsonb_build_object('sha256',sha256,'size_bytes',size_bytes,'storage_key',storage_key) FROM marked UNION ALL SELECT jsonb_build_object('sha256',sha256,'size_bytes',size_bytes,'storage_key',storage_key) FROM blobs WHERE state='deleting' LIMIT 100").fetch_all(&self.pool).await?;
        rows.into_iter().map(decode).collect()
    }
}

pub fn state_name(state: &State) -> &'static str {
    match state {
        State::AwaitingPayment => "awaiting_payment",
        State::Queued => "queued",
        State::Running => "running",
        State::Ready => "ready",
        State::Partial => "partial",
        State::Failed => "failed",
        State::Deleting => "deleting",
        State::Deleted => "deleted",
        State::Expired => "expired",
        State::Unsupported => "unsupported",
    }
}
fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| DatabaseError::Invalid("Byte count exceeds supported range".into()))
}

async fn insert_output(
    connection: &mut PgConnection,
    owner: &str,
    backup_id: &str,
    id: &str,
    output: OutputRequest,
    providers: &[String],
    state: &str,
) -> Result<()> {
    match output {
        OutputRequest::Archive {
            format,
            retention_days,
        } => {
            sqlx::query("INSERT INTO archives(id,backup_id,owner_id,state,format,retention_days) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,$4,$5,$6)")
                .bind(id).bind(backup_id).bind(owner).bind(state).bind(format.as_str()).bind(retention_days.unwrap_or(3) as i32).execute(&mut *connection).await?;
            insert_operation(connection, owner, "archive", id, state).await?;
        }
        OutputRequest::Ipfs => {
            sqlx::query("INSERT INTO pin_sets(id,backup_id,owner_id,state,provider_ids) VALUES($1::text::uuid,$2::text::uuid,$3::text::uuid,$4,ARRAY(SELECT x::uuid FROM unnest($5::text[]) x))")
                .bind(id).bind(backup_id).bind(owner).bind(state).bind(providers).execute(&mut *connection).await?;
            insert_operation(connection, owner, "pin", id, state).await?;
        }
    }
    Ok(())
}

async fn save_asset(connection: &mut PgConnection, item_id: &str, asset: &Asset) -> Result<()> {
    sqlx::query("INSERT INTO item_assets(id,item_id,role,source_uri,path,sha256,cid,size_bytes,state,error,filename,fallback_filename,observed_at) VALUES($1::text::uuid,$2::text::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(item_id,path) DO UPDATE SET sha256=EXCLUDED.sha256,size_bytes=EXCLUDED.size_bytes,state=EXCLUDED.state,error=EXCLUDED.error")
        .bind(&asset.id).bind(item_id).bind(&asset.role).bind(&asset.source_uri).bind(&asset.path).bind(&asset.sha256).bind(&asset.cid).bind(asset.size_bytes.map(to_i64).transpose()?).bind(state_name(&asset.state)).bind(json!(asset.error)).bind(&asset.filename).bind(&asset.fallback_filename).bind(asset.observed_at).execute(connection).await?;
    Ok(())
}

pub fn encode_cursor(created_at: DateTime<Utc>, id: String) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json!([created_at, id]).to_string())
}
pub fn decode_cursor(cursor: &str) -> Result<(DateTime<Utc>, String)> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| DatabaseError::Invalid("Invalid cursor".into()))?;
    let decoded: (DateTime<Utc>, String) = serde_json::from_slice(&bytes)
        .map_err(|_| DatabaseError::Invalid("Invalid cursor".into()))?;
    Uuid::parse_str(&decoded.1).map_err(|_| DatabaseError::Invalid("Invalid cursor".into()))?;
    Ok(decoded)
}

#[cfg(test)]
mod decode_cursor_tests {
    use super::*;
    #[test]
    fn round_trips_and_rejects_untrusted_cursors() {
        let timestamp = DateTime::parse_from_rfc3339("2026-10-24T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let id = "11111111-1111-4111-8111-111111111111".to_string();
        assert_eq!(
            decode_cursor(&encode_cursor(timestamp, id.clone())).unwrap(),
            (timestamp, id)
        );
        assert!(decode_cursor("invalid").is_err());
    }
}
