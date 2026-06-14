//! Emits `CRYPTIRC_BUILD` = "<short-sha>[-dirty]" at compile time so the served
//! frontend can show a build stamp (the git commit) in the version pill that
//! changes on every commit. `-dirty` is appended when the binary is built with
//! uncommitted changes to tracked files.
use std::process::Command;

fn main() {
    let sha = Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "nogit".into());

    let dirty = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    let stamp = if dirty { format!("{sha}-dirty") } else { sha };
    println!("cargo:rustc-env=CRYPTIRC_BUILD={stamp}");

    // Refresh the stamp when HEAD moves (commit/checkout), the index changes
    // (stage/commit), or the main sources are edited (affects the -dirty flag).
    for p in [
        ".git/HEAD",
        ".git/index",
        "src/main.rs",
        "static/app.js",
        "static/index.html",
    ] {
        println!("cargo:rerun-if-changed={p}");
    }
}
