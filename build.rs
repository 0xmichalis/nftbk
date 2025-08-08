fn main() {
    // Re-run the build script if Git HEAD or refs change
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");

    // First try to use GIT_COMMIT from environment (for Docker builds)
    let commit = std::env::var("GIT_COMMIT").ok().unwrap_or_else(|| {
        // Try to get the short commit hash, with fallback for shallow clones
        std::process::Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| {
                // Fallback: try to get the full commit hash if short fails
                std::process::Command::new("git")
                    .args(["rev-parse", "HEAD"])
                    .output()
                    .ok()
                    .and_then(|o| {
                        if o.status.success() {
                            let full_hash = String::from_utf8_lossy(&o.stdout).trim().to_string();
                            // Take first 7 characters as short hash
                            Some(full_hash.chars().take(7).collect())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| "unknown".to_string())
            })
    });

    println!("cargo:rustc-env=GIT_COMMIT={commit}");
}
