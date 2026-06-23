use std::{path::Path, process::Command};

/// Embed the short git commit of the working tree so the web admin can show
/// which commit the running binary was built from. Falls back to "unknown"
/// when git is unavailable (e.g. building from a release tarball).
fn main() {
    let commit = git_output(&["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=SSRUST_GIT_COMMIT={commit}");
    let commit_time_bj = Command::new("git")
        .env("TZ", "Asia/Shanghai")
        .args(["show", "-s", "--format=%cd", "--date=format-local:%Y-%m-%d %H:%M:%S %z", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .filter(|time| !time.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=SSRUST_GIT_COMMIT_TIME_BJ={commit_time_bj}");

    // Re-run when HEAD or the checked-out ref moves so the embedded commit
    // stays in sync with the working tree across rebuilds.
    for path in ["../../.git/HEAD", "../../.git/refs", "../../.git/packed-refs"] {
        if Path::new(path).exists() {
            println!("cargo:rerun-if-changed={path}");
        }
    }
}

fn git_output(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .filter(|output| !output.is_empty())
}
