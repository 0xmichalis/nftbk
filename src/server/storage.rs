use std::path::{Component, Path, PathBuf};

use anyhow::{ensure, Context, Result};
use base64::Engine;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::server::database::r#trait::{Blob, Database};
use crate::server::hashing::compute_file_sha256;
use crate::server::model::Claim;

#[derive(Clone)]
pub struct BlobStore {
    base: PathBuf,
}

impl BlobStore {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }
    pub fn path(&self, key: &str) -> Result<PathBuf> {
        ensure!(
            !key.is_empty()
                && Path::new(key)
                    .components()
                    .all(|c| matches!(c, Component::Normal(_))),
            "Invalid storage key"
        );
        Ok(self.base.join(key))
    }
    pub fn blob_path(&self, sha256: &str) -> Result<PathBuf> {
        ensure!(
            sha256.len() == 64 && sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid content digest"
        );
        self.path(&format!("blobs/{sha256}"))
    }
    async fn lock(&self, digest: &str) -> Result<std::fs::File> {
        self.blob_path(digest)?;
        let path = self.path(&format!("locks/{digest}"))?;
        fs::create_dir_all(path.parent().context("Lock directory missing")?).await?;
        tokio::task::spawn_blocking(move || {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)?;
            fs2::FileExt::lock_exclusive(&file)?;
            Ok::<_, std::io::Error>(file)
        })
        .await?
        .map_err(Into::into)
    }
    pub async fn collect(&self, db: &dyn Database, blob: &Blob) -> Result<()> {
        let _lock = self.lock(&blob.sha256).await?;
        // Other collectors may have finished and a new snapshot may have reused this digest.
        if db.blob_deleting(&blob.sha256).await? {
            self.remove(&blob.storage_key).await?;
            db.garbage(Some(&blob.sha256)).await?;
        }
        Ok(())
    }
    pub async fn put(&self, db: &dyn Database, claim: &Claim, bytes: &[u8]) -> Result<Blob> {
        let sha256 = format!("{:x}", Sha256::digest(bytes));
        let blob = Blob {
            storage_key: format!("blobs/{sha256}"),
            sha256,
            size_bytes: bytes.len() as u64,
        };
        let _lock = self.lock(&blob.sha256).await?;
        db.put_blob(claim, &blob).await?;
        let path = self.path(&blob.storage_key)?;
        fs::create_dir_all(path.parent().context("Blob directory missing")?).await?;
        let temporary = self.stage(claim).await?.join(Uuid::new_v4().to_string());
        let mut file = fs::File::create(&temporary).await?;
        file.write_all(bytes).await?;
        file.sync_all().await?;
        fs::rename(&temporary, &path).await?;
        fs::File::open(path.parent().context("Blob directory missing")?)
            .await?
            .sync_all()
            .await?;
        Ok(blob)
    }
    pub async fn import(&self, db: &dyn Database, claim: &Claim, path: &Path) -> Result<Blob> {
        let sha256 = compute_file_sha256(path).await?;
        let blob = Blob {
            storage_key: format!("blobs/{sha256}"),
            sha256,
            size_bytes: fs::metadata(path).await?.len(),
        };
        let _lock = self.lock(&blob.sha256).await?;
        db.put_blob(claim, &blob).await?;
        let target = self.path(&blob.storage_key)?;
        fs::create_dir_all(target.parent().context("Blob directory missing")?).await?;
        let temporary = self.stage(claim).await?.join(Uuid::new_v4().to_string());
        fs::copy(path, &temporary).await?;
        fs::File::open(&temporary).await?.sync_all().await?;
        fs::rename(temporary, &target).await?;
        fs::File::open(target.parent().context("Blob directory missing")?)
            .await?
            .sync_all()
            .await?;
        Ok(blob)
    }
    pub async fn stage(&self, claim: &Claim) -> Result<PathBuf> {
        let path = self.path(&format!(
            "staging/{}/{}",
            claim.operation.id, claim.lease_token
        ))?;
        fs::create_dir_all(&path).await?;
        Ok(path)
    }
    pub async fn cleanup_staging(&self, db: &dyn Database) -> Result<()> {
        let root = self.path("staging")?;
        let mut operations = match fs::read_dir(&root).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let mut candidates = Vec::new();
        while let Some(operation) = operations.next_entry().await? {
            let id = operation.file_name().to_string_lossy().into_owned();
            if Uuid::parse_str(&id).is_err() || !operation.file_type().await?.is_dir() {
                continue;
            }
            let mut leases = fs::read_dir(operation.path()).await?;
            while let Some(lease) = leases.next_entry().await? {
                let token = lease.file_name().to_string_lossy().into_owned();
                if Uuid::parse_str(&token).is_ok() && lease.file_type().await?.is_dir() {
                    candidates.push((id.clone(), token, lease.path()));
                }
            }
        }
        // List paths before reading leases: a new worker cannot appear in the candidate set later.
        let active: std::collections::HashSet<_> = db.active_leases().await?.into_iter().collect();
        for (id, token, path) in candidates {
            if !active.contains(&(id, token)) {
                fs::remove_dir_all(&path).await.or_else(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        Ok(())
                    } else {
                        Err(e)
                    }
                })?;
                if let Some(parent) = path.parent() {
                    fs::remove_dir(parent).await.ok();
                }
            }
        }
        Ok(())
    }
    pub async fn read(&self, sha256: &str) -> Result<Vec<u8>> {
        Ok(fs::read(self.blob_path(sha256)?).await?)
    }
    pub async fn remove(&self, key: &str) -> Result<()> {
        match fs::remove_file(self.path(key)?).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DownloadGrant {
    pub archive_id: String,
    pub owner_id: String,
    pub expires_at: DateTime<Utc>,
}

fn signature(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts a 256-bit key");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

pub fn sign_download(key: &[u8; 32], grant: &DownloadGrant) -> Result<String> {
    let payload =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(grant)?);
    let signed =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature(key, payload.as_bytes()));
    Ok(format!("{payload}.{signed}"))
}
pub fn verify_download(key: &[u8; 32], token: &str, archive_id: &str) -> Result<DownloadGrant> {
    let (payload, signed) = token.split_once('.').context("Invalid download grant")?;
    let signed = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(signed)?;
    ensure!(
        signed.len() == 32
            && bool::from(signature(key, payload.as_bytes()).as_slice().ct_eq(&signed)),
        "Invalid download grant"
    );
    let grant: DownloadGrant =
        serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload)?)?;
    ensure!(
        grant.archive_id == archive_id && grant.expires_at > Utc::now(),
        "Expired or mismatched download grant"
    );
    Ok(grant)
}

#[cfg(test)]
mod signature_tests {
    use super::*;
    #[test]
    fn matches_an_independently_computed_hmac_vector() {
        let key = [0u8; 32];
        assert_eq!(
            hex::encode(signature(&key, b"hello")),
            "4352b26e33fe0d769a8922a6ba29004109f01688e26acc9e6cb347e5a5afc4da"
        );
    }
}
#[cfg(test)]
mod verify_download_tests {
    use super::*;
    #[test]
    fn rejects_wrong_keys_archives_expiration_and_tampering() {
        let key = [9u8; 32];
        let mut grant = DownloadGrant {
            archive_id: Uuid::new_v4().to_string(),
            owner_id: Uuid::new_v4().to_string(),
            expires_at: Utc::now() + chrono::Duration::minutes(10),
        };
        let token = sign_download(&key, &grant).unwrap();
        assert_eq!(
            verify_download(&key, &token, &grant.archive_id)
                .unwrap()
                .owner_id,
            grant.owner_id
        );
        assert!(verify_download(&[8u8; 32], &token, &grant.archive_id).is_err());
        assert!(verify_download(&key, &token, "other").is_err());
        assert!(verify_download(&key, &format!("x{token}"), &grant.archive_id).is_err());
        grant.expires_at = Utc::now() - chrono::Duration::seconds(1);
        assert!(verify_download(
            &key,
            &sign_download(&key, &grant).unwrap(),
            &grant.archive_id
        )
        .is_err());
    }
}
