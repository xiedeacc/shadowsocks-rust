use std::{path::Path, process::Command};

/// Embed the short git commit of the working tree so the web admin can show
/// which commit the running binary was built from. Falls back to "unknown"
/// when git is unavailable (e.g. building from a release tarball).
fn main() {
    let commit = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .filter(|commit| !commit.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=SSRUST_GIT_COMMIT={commit}");

    // Re-run when HEAD or the checked-out ref moves so the embedded commit
    // stays in sync with the working tree across rebuilds.
    for path in ["../../.git/HEAD", "../../.git/refs", "../../.git/packed-refs"] {
        if Path::new(path).exists() {
            println!("cargo:rerun-if-changed={path}");
        }
    }
}
