use anyhow::Result;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncReadExt;

/// List of known media file extensions that we handle
const KNOWN_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "mp3", "mp4", "mov", "mpg", "html", "json", "glb", "svg",
];

/// Checks if a path has a known media file extension
pub fn has_known_extension(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(OsStr::to_str) {
        KNOWN_EXTENSIONS.contains(&ext.to_lowercase().as_str())
    } else {
        false
    }
}

/// Gets a path with a known extension in the same directory, if one exists
pub async fn find_path_with_known_extension(path: &Path) -> Result<Option<PathBuf>> {
    if let Some(parent) = path.parent() {
        // Get the appropriate stem based on whether the path has a known extension
        let search_stem = if has_known_extension(path) {
            path.file_stem().map(|s| s.to_string_lossy().to_string())
        } else {
            // If path doesn't have a known extension, use the whole filename as stem
            path.file_name().map(|s| s.to_string_lossy().to_string())
        };

        if let Some(stem) = search_stem {
            if fs::try_exists(parent).await? {
                let mut dir = fs::read_dir(parent).await?;
                while let Some(entry) = dir.next_entry().await? {
                    let entry_path = entry.path();
                    if entry_path
                        .file_stem()
                        .is_some_and(|s| s.to_string_lossy() == stem)
                        && has_known_extension(&entry_path)
                    {
                        return Ok(Some(entry_path));
                    }
                }
            }
        }
    }
    Ok(None)
}

pub fn detect_media_extension(content: &[u8]) -> Option<&'static str> {
    // Check for common image/video formats
    match content {
        // PNG
        [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, ..] => Some("png"),
        // JPEG
        [0xFF, 0xD8, 0xFF, ..] => Some("jpg"),
        // GIF
        [b'G', b'I', b'F', b'8', b'9', b'a', ..] => Some("gif"),
        [b'G', b'I', b'F', b'8', b'7', b'a', ..] => Some("gif"),
        // WEBP
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => Some("webp"),
        // MP3
        [0x49, 0x44, 0x33, ..] => Some("mp3"),
        // MP4
        [0x00, 0x00, 0x00, _, 0x66, 0x74, 0x79, 0x70, 0x6D, 0x70, 0x34, 0x32, ..] => Some("mp4"),
        [0x00, 0x00, 0x00, _, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6F, 0x6D, ..] => Some("mp4"),
        // QuickTime MOV
        [0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70, 0x71, 0x74, 0x20, 0x20, ..] => Some("mov"),
        // MPG
        [0x00, 0x00, 0x01, 0xBA, ..] => Some("mpg"),
        // HTML
        [b'<', b'h', b't', b'm', b'l', ..] => Some("html"),
        // HTML starting with <!DOCTYPE html
        [0x3C, 0x21, 0x44, 0x4F, 0x43, 0x54, 0x59, 0x50, 0x45, 0x20, 0x68, 0x74, 0x6D, 0x6C, ..] => {
            Some("html")
        }
        // JSON
        [b'{', ..] => Some("json"),
        // GLB
        [0x47, 0x4C, 0x42, 0x0D, 0x0A, 0x1A, 0x0A, ..] => Some("glb"),
        [0x67, 0x6C, 0x54, 0x46, 0x02, 0x00, 0x00, 0x00, ..] => Some("glb"),
        // SVG (starts with <svg, <?xml, or <!DOCTYPE svg)
        [b'<', b's', b'v', b'g', ..] => Some("svg"),
        [b'<', b'?', b'x', b'm', b'l', ..] => Some("svg"),
        [b'<', b'!', b'D', b'O', b'C', b'T', b'Y', b'P', b'E', b' ', b's', b'v', b'g', ..] => {
            Some("svg")
        }
        _ => {
            // Also check for <svg after whitespace or xml declaration
            let whitespace: &[u8] = b" \t\r\n";
            let trimmed = content
                .iter()
                .skip_while(|b| whitespace.contains(b))
                .cloned()
                .collect::<Vec<u8>>();
            if trimmed.starts_with(b"<svg") {
                Some("svg")
            } else {
                None
            }
        }
    }
}

/// Reads the first 32 bytes from a stream and detects the media extension, returning both the extension and the buffer read.
pub async fn detect_extension_from_stream<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> (Option<&'static str>, Vec<u8>) {
    let mut buf = [0u8; 32];
    let n = match reader.read(&mut buf).await {
        Ok(n) => n,
        Err(_) => return (None, Vec::new()),
    };
    let ext = detect_media_extension(&buf[..n]);
    (ext, buf[..n].to_vec())
}
