use std::fs;
use std::io::{self, Seek, Write};
use std::path::Path as StdPath;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use zip::write::FileOptions;

use crate::server::hashing::compute_file_sha256;

/// Error message used when archiving is interrupted by shutdown signal
pub const ARCHIVE_INTERRUPTED_BY_SHUTDOWN: &str =
    "Archive operation interrupted by shutdown signal";

/// A writer that writes to two destinations: the archive file and a hasher
struct TeeWriter<W: Write, H: Write> {
    writer: W,
    hasher: H,
}

impl<W: Write, H: Write> TeeWriter<W, H> {
    fn new(writer: W, hasher: H) -> Self {
        Self { writer, hasher }
    }
}

impl<W: Write, H: Write> Write for TeeWriter<W, H> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.writer.write(buf)?;
        self.hasher.write_all(&buf[..n])?;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()?;
        self.hasher.flush()
    }
}

pub fn sync_files(files_written: &[std::path::PathBuf]) {
    let mut synced_dirs = std::collections::HashSet::new();
    for file in files_written {
        if file.is_file() {
            if let Ok(f) = std::fs::File::open(file) {
                let _ = f.sync_all();
            }
        }
        if let Some(parent) = file.parent() {
            if synced_dirs.insert(parent.to_path_buf()) {
                if let Ok(dir) = std::fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }
    }
}

pub fn zip_backup(
    out_path: &StdPath,
    zip_path: &StdPath,
    archive_format: String,
    shutdown_flag: Option<Arc<AtomicBool>>,
) -> Result<String, String> {
    match archive_format.as_str() {
        "zip" => zip_backup_zip(out_path, zip_path, shutdown_flag),
        _ => zip_backup_tar_gz(out_path, zip_path, shutdown_flag),
    }
}

fn zip_backup_zip(
    out_path: &StdPath,
    zip_path: &StdPath,
    shutdown_flag: Option<Arc<AtomicBool>>,
) -> Result<String, String> {
    let zip_path_str = zip_path.to_str().unwrap();
    let zip_file =
        fs::File::create(zip_path_str).map_err(|e| format!("Failed to create zip: {e}"))?;
    let mut zip = zip::ZipWriter::new(zip_file);
    let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    if let Err(e) = add_dir_to_zip(&mut zip, out_path, out_path, options, shutdown_flag) {
        return Err(format!("Failed to zip dir: {e}"));
    }
    zip.finish()
        .map_err(|e| format!("Failed to finish zip: {e}"))?;
    // Compute SHA256 after writing
    let mut file =
        fs::File::open(zip_path_str).map_err(|e| format!("Failed to open zip for hashing: {e}"))?;
    use std::io::Read;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("Failed to read zip for hashing: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let checksum = format!("{:x}", hasher.finalize());
    Ok(checksum)
}

fn add_dir_to_zip<W: Write + Seek>(
    zip: &mut zip::ZipWriter<W>,
    src_dir: &StdPath,
    base: &StdPath,
    options: FileOptions,
    shutdown_flag: Option<Arc<AtomicBool>>,
) -> io::Result<()> {
    for entry in fs::read_dir(src_dir)? {
        check_shutdown_signal(shutdown_flag.as_ref())?;

        let entry = entry?;
        let path = entry.path();
        let rel_path = path.strip_prefix(base).unwrap();
        let rel_path_str = rel_path
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        if path.is_dir() {
            zip.add_directory(format!("{rel_path_str}/"), options)?;
            add_dir_to_zip(zip, &path, base, options, shutdown_flag.clone())?;
        } else if path.is_file() {
            zip.start_file(rel_path_str, options)?;
            let mut f = fs::File::open(&path)?;
            io::copy(&mut f, zip)?;
        }
    }
    Ok(())
}

fn zip_backup_tar_gz(
    out_path: &StdPath,
    zip_path: &StdPath,
    shutdown_flag: Option<Arc<AtomicBool>>,
) -> Result<String, String> {
    let zip_path_str = zip_path.to_str().unwrap();
    let tar_gz =
        fs::File::create(zip_path_str).map_err(|e| format!("Failed to create zip: {e}"))?;
    let mut hasher = Sha256::new();
    let tee_writer = TeeWriter::new(tar_gz, &mut hasher);
    let enc = GzEncoder::new(tee_writer, Compression::default());
    let mut tar = tar::Builder::new(enc);
    if let Err(e) = add_dir_to_tar_gz(&mut tar, out_path, out_path, shutdown_flag) {
        return Err(format!("Failed to tar dir: {e}"));
    }
    let enc = tar
        .into_inner()
        .map_err(|e| format!("Failed to finish tar: {e}"))?;
    enc.finish()
        .map_err(|e| format!("Failed to encode tar: {e}"))?;
    let checksum = format!("{:x}", hasher.finalize());
    Ok(checksum)
}

fn add_dir_to_tar_gz<T: Write>(
    tar: &mut tar::Builder<T>,
    src_dir: &StdPath,
    base: &StdPath,
    shutdown_flag: Option<Arc<AtomicBool>>,
) -> std::io::Result<()> {
    for entry in fs::read_dir(src_dir)? {
        check_shutdown_signal(shutdown_flag.as_ref())?;

        let entry = entry?;
        let path = entry.path();
        let rel_path = path.strip_prefix(base).unwrap();
        if path.is_dir() {
            tar.append_dir(rel_path, &path)?;
            add_dir_to_tar_gz(tar, &path, base, shutdown_flag.clone())?;
        } else if path.is_file() {
            tar.append_path_with_name(&path, rel_path)?;
        }
    }
    Ok(())
}

fn check_shutdown_signal(shutdown_flag: Option<&Arc<AtomicBool>>) -> io::Result<()> {
    if let Some(flag) = shutdown_flag {
        if flag.load(Ordering::Relaxed) {
            warn!("Received shutdown signal, stopping archive operation");
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                ARCHIVE_INTERRUPTED_BY_SHUTDOWN,
            ));
        }
    }
    Ok(())
}

pub fn get_zipped_backup_paths(
    base_dir: &str,
    task_id: &str,
    archive_format: &str,
) -> (PathBuf, PathBuf) {
    let zip_path = PathBuf::from(format!("{base_dir}/nftbk-{task_id}.{archive_format}"));
    let checksum_path = PathBuf::from(format!("{}.sha256", zip_path.display()));
    (zip_path, checksum_path)
}

pub async fn check_backup_on_disk(
    base_dir: &str,
    task_id: &str,
    unsafe_skip_checksum_check: bool,
    archive_format: &str,
) -> Option<PathBuf> {
    let (path, checksum_path) = get_zipped_backup_paths(base_dir, task_id, archive_format);

    // First check if both files exist
    match (
        tokio::fs::try_exists(&path).await,
        tokio::fs::try_exists(&checksum_path).await,
    ) {
        (Ok(true), Ok(true)) => {
            if unsafe_skip_checksum_check {
                // Only check for existence, skip reading and comparing checksums
                return Some(path);
            }
            // Read stored checksum
            info!("Checking backup on disk for task {}", task_id);
            let stored_checksum = match tokio::fs::read_to_string(&checksum_path).await {
                Ok(checksum) => checksum,
                Err(e) => {
                    warn!("Failed to read checksum file for {}: {}", path.display(), e);
                    return None;
                }
            };

            // Compute current checksum
            debug!("Computing backup checksum for task {}", task_id);
            let current_checksum = match compute_file_sha256(&path).await {
                Ok(checksum) => checksum,
                Err(e) => {
                    warn!("Failed to compute checksum for {}: {}", path.display(), e);
                    return None;
                }
            };

            if stored_checksum.trim() != current_checksum {
                warn!(
                    "Backup archive {} is corrupted: checksum mismatch",
                    path.display()
                );
                return None;
            }

            Some(path)
        }
        _ => None,
    }
}

pub fn archive_format_from_user_agent(user_agent: &str) -> String {
    if user_agent.contains("Windows")
        || user_agent.contains("Macintosh")
        || user_agent.contains("Mac OS")
    {
        "zip".to_string()
    } else if user_agent.contains("Linux") || user_agent.contains("X11") {
        "tar.gz".to_string()
    } else {
        "zip".to_string() // Default to zip for max compatibility
    }
}

/// Parse Accept header to decide archive format. Returns None if undecidable.
pub fn archive_format_from_accept(accept: &str) -> Option<String> {
    if accept.contains("application/zip") {
        return Some("zip".to_string());
    }
    if accept.contains("application/gzip")
        || accept.contains("application/x-gtar")
        || accept.contains("application/x-tar")
    {
        return Some("tar.gz".to_string());
    }
    None
}

/// Decide archive format based on HTTP headers, preferring Accept when present,
/// and falling back to user-agent heuristics. Defaults to "zip" if undecidable.
pub fn negotiate_archive_format(accept: Option<&str>, user_agent: Option<&str>) -> String {
    if let Some(accept_val) = accept {
        // Skip generic Accept headers like "*/*" and fall back to user-agent
        if accept_val == "*/*" {
            // Fall through to user-agent logic
        } else if let Some(fmt) = archive_format_from_accept(accept_val) {
            return fmt;
        } else {
            // Accept provided but undecidable -> default to zip
            return "zip".to_string();
        }
    }
    user_agent
        .map(archive_format_from_user_agent)
        .unwrap_or_else(|| "zip".to_string())
}

#[cfg(test)]
mod archive_helpers_tests {
    use super::{archive_format_from_accept, negotiate_archive_format};
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    #[test]
    fn accept_zip_parses_to_zip() {
        let fmt = archive_format_from_accept("application/zip");
        assert_eq!(fmt.as_deref(), Some("zip"));
    }

    #[test]
    fn accept_gzip_parses_to_tar_gz() {
        let fmt = archive_format_from_accept("application/gzip");
        assert_eq!(fmt.as_deref(), Some("tar.gz"));
    }

    #[test]
    fn accept_undecidable_returns_none() {
        let fmt = archive_format_from_accept("application/json");
        assert!(fmt.is_none());
    }

    #[test]
    fn negotiate_prefers_accept_when_present_zip() {
        let fmt = negotiate_archive_format(Some("application/zip"), Some("Linux"));
        assert_eq!(fmt, "zip");
    }

    #[test]
    fn negotiate_prefers_accept_when_present_gzip() {
        let fmt = negotiate_archive_format(Some("application/gzip"), Some("Windows"));
        assert_eq!(fmt, "tar.gz");
    }

    #[test]
    fn negotiate_undecidable_accept_defaults_to_zip() {
        let fmt = negotiate_archive_format(Some("application/octet-stream"), Some("Linux"));
        assert_eq!(fmt, "zip");
    }

    #[test]
    fn negotiate_no_accept_uses_user_agent() {
        // Linux -> tar.gz by UA heuristic
        let fmt_linux = negotiate_archive_format(None, Some("Linux"));
        assert_eq!(fmt_linux, "tar.gz");
        // Windows -> zip by UA heuristic
        let fmt_win = negotiate_archive_format(None, Some("Windows"));
        assert_eq!(fmt_win, "zip");
    }

    #[test]
    fn negotiate_generic_accept_falls_back_to_user_agent() {
        // Generic Accept header "*/*" should fall back to user-agent
        let fmt_linux = negotiate_archive_format(Some("*/*"), Some("Linux"));
        assert_eq!(fmt_linux, "tar.gz");
        let fmt_windows = negotiate_archive_format(Some("*/*"), Some("Windows"));
        assert_eq!(fmt_windows, "zip");
        let fmt_mac = negotiate_archive_format(Some("*/*"), Some("Macintosh"));
        assert_eq!(fmt_mac, "zip");
    }

    #[test]
    fn test_shutdown_interruption_returns_correct_error() {
        use super::{check_shutdown_signal, ARCHIVE_INTERRUPTED_BY_SHUTDOWN};
        use std::io;

        // Test that shutdown signal returns the correct error message
        let shutdown_flag = Arc::new(AtomicBool::new(true));
        let result = check_shutdown_signal(Some(&shutdown_flag));

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(error.to_string(), ARCHIVE_INTERRUPTED_BY_SHUTDOWN);
    }

    #[test]
    fn test_no_shutdown_signal_returns_ok() {
        use super::check_shutdown_signal;

        // Test that no shutdown signal returns Ok
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let result = check_shutdown_signal(Some(&shutdown_flag));
        assert!(result.is_ok());

        // Test that no flag at all returns Ok
        let result = check_shutdown_signal(None);
        assert!(result.is_ok());
    }
}
