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

    // r10: one hash over exactly the static files the server EMBEDS (and so serves): the
    // `include_str!` / `include_bytes!` paths into static/ found in the src/ sources — the
    // embedding code itself is the list, so the two cannot drift, and files that are not
    // served (.DS_Store, editor backups) do not count. main.rs frontend_id() turns it into
    // the page's CRYPTIRC_ASSETS / AuthOk `assets`: a redeploy that changes any served
    // frontend file asks the open pages to reload. Change detection only (FNV-1a 64 over
    // path, length and bytes of each file, in path order).
    println!("cargo:rustc-env=CRYPTIRC_STATIC_HASH={}", static_hash(&embedded_static_files(std::path::Path::new("src"))));

    // Refresh the stamp when HEAD moves (commit/checkout), the index changes
    // (stage/commit), or the main sources are edited (affects the -dirty flag).
    for p in [".git/HEAD", ".git/index", "src", "static"] {
        println!("cargo:rerun-if-changed={p}");
    }
}

/// The files under static/ that a source file under `src` embeds with include_str!/include_bytes!.
fn embedded_static_files(src: &std::path::Path) -> Vec<std::path::PathBuf> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() { walk(&p, out) } else if p.extension().map_or(false, |x| x == "rs") { out.push(p) }
            }
        }
    }
    let mut sources = Vec::new();
    walk(src, &mut sources);
    let static_dir = std::fs::canonicalize("static").ok();
    let mut files = std::collections::BTreeSet::new();
    for rs in &sources {
        let text = std::fs::read_to_string(rs).unwrap_or_default();
        let dir = rs.parent().unwrap_or(std::path::Path::new("."));
        for mac in ["include_str!(\"", "include_bytes!(\""] {
            let mut rest = text.as_str();
            while let Some(i) = rest.find(mac) {
                rest = &rest[i + mac.len()..];
                let Some(end) = rest.find('"') else { break };
                let rel = &rest[..end];
                if let (Ok(full), Some(sd)) = (std::fs::canonicalize(dir.join(rel)), static_dir.as_ref()) {
                    if full.starts_with(sd) { files.insert(full); }
                }
            }
        }
    }
    files.into_iter().collect()
}

fn static_hash(files: &[std::path::PathBuf]) -> String {
    let root = std::fs::canonicalize("static").unwrap_or_default();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |bytes: &[u8]| for &b in bytes { h = (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3); };
    for f in files {
        let rel = f.strip_prefix(&root).unwrap_or(f).to_string_lossy().replace('\\', "/");
        let data = std::fs::read(f).unwrap_or_default();
        eat(rel.as_bytes()); eat(&(data.len() as u64).to_le_bytes()); eat(&data);
    }
    format!("{:016x}-{}", h, files.len())
}
