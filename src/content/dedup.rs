//! Content-based deduplication within a token directory.
//!
//! Sources sometimes move content to a new URL (a CDN path becoming an IPFS
//! CID, say). The new URL derives a new filename, so the existence check misses
//! the copy already on disk and the bytes are downloaded again. Once they are,
//! we can at least recognise them and avoid storing them twice.

use std::path::{Path, PathBuf};

use tokio::fs;
use tokio::io::AsyncReadExt;

const COMPARE_CHUNK_SIZE: usize = 64 * 1024;

/// Find a regular file in the same directory as `path` with identical content.
/// `path` itself and directories are ignored; candidates are pre-filtered by size.
pub(crate) async fn find_identical_sibling(path: &Path) -> anyhow::Result<Option<PathBuf>> {
    let Some(parent) = path.parent() else {
        return Ok(None);
    };
    let len = fs::metadata(path).await?.len();

    let mut entries = fs::read_dir(parent).await?;
    while let Some(entry) = entries.next_entry().await? {
        if Some(entry.file_name().as_os_str()) == path.file_name() {
            continue;
        }
        let metadata = entry.metadata().await?;
        if !metadata.is_file() || metadata.len() != len {
            continue;
        }
        let candidate = entry.path();
        if files_identical(path, &candidate).await? {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

async fn files_identical(a: &Path, b: &Path) -> anyhow::Result<bool> {
    let mut a = fs::File::open(a).await?;
    let mut b = fs::File::open(b).await?;
    let mut buf_a = vec![0u8; COMPARE_CHUNK_SIZE];
    let mut buf_b = vec![0u8; COMPARE_CHUNK_SIZE];
    loop {
        let read_a = a.read(&mut buf_a).await?;
        let read_b = b.read(&mut buf_b).await?;
        if read_a != read_b || buf_a[..read_a] != buf_b[..read_b] {
            return Ok(false);
        }
        if read_a == 0 {
            return Ok(true);
        }
    }
}

/// Replace `duplicate` with a hard link to `original`, so the content is
/// stored once but stays addressable under both names. The link is created
/// under a temporary name and renamed into place, so `duplicate` is never
/// missing if the link cannot be created.
pub(crate) async fn replace_with_hard_link(
    duplicate: &Path,
    original: &Path,
) -> anyhow::Result<()> {
    let tmp = duplicate.with_extension("nftbk-link.tmp");
    fs::hard_link(original, &tmp).await?;
    fs::rename(&tmp, duplicate).await?;
    Ok(())
}

#[cfg(test)]
mod find_identical_sibling_tests {
    use super::*;
    use tempfile::TempDir;

    async fn write(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, content).await.unwrap();
        path
    }

    #[tokio::test]
    async fn finds_file_with_identical_content_under_another_name() {
        let dir = TempDir::new().unwrap();
        let original = write(dir.path(), "1667336455.jpg", b"same bytes").await;
        let downloaded = write(dir.path(), "image.jpg", b"same bytes").await;

        let found = find_identical_sibling(&downloaded).await.unwrap();
        assert_eq!(found, Some(original));
    }

    #[tokio::test]
    async fn ignores_same_size_but_different_content() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "other.jpg", b"same size!").await;
        let downloaded = write(dir.path(), "image.jpg", b"same bytes").await;

        assert_eq!(find_identical_sibling(&downloaded).await.unwrap(), None);
    }

    #[tokio::test]
    async fn ignores_different_size_itself_and_directories() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "metadata.json", b"{}").await;
        fs::create_dir(dir.path().join("TemplateData"))
            .await
            .unwrap();
        let downloaded = write(dir.path(), "image.jpg", b"same bytes").await;

        assert_eq!(find_identical_sibling(&downloaded).await.unwrap(), None);
    }

    #[tokio::test]
    async fn compares_content_beyond_the_first_chunk() {
        let dir = TempDir::new().unwrap();
        let mut a = vec![0u8; 200_000];
        let mut b = a.clone();
        a[199_999] = 1;
        b[199_999] = 2;
        write(dir.path(), "a.bin", &a).await;
        let downloaded = write(dir.path(), "b.bin", &b).await;

        assert_eq!(find_identical_sibling(&downloaded).await.unwrap(), None);
    }
}

#[cfg(test)]
mod replace_with_hard_link_tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use tempfile::TempDir;

    #[tokio::test]
    async fn duplicate_becomes_hard_link_to_original() {
        let dir = TempDir::new().unwrap();
        let original = dir.path().join("original.jpg");
        let duplicate = dir.path().join("image.jpg");
        fs::write(&original, b"bytes").await.unwrap();
        fs::write(&duplicate, b"bytes").await.unwrap();

        replace_with_hard_link(&duplicate, &original).await.unwrap();

        let original_meta = fs::metadata(&original).await.unwrap();
        let duplicate_meta = fs::metadata(&duplicate).await.unwrap();
        assert_eq!(original_meta.ino(), duplicate_meta.ino());
        assert_eq!(original_meta.nlink(), 2);
        assert_eq!(fs::read(&duplicate).await.unwrap(), b"bytes");
    }
}
