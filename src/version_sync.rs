//! version_sync.rs — enforces that Cargo.toml's `[package].version` is the
//! ONE human-edited canonical version. `electron/package.json` and the
//! README's version badge must always match it; this module's test fails
//! `cargo test` if they don't, so drift is caught locally (and in CI, if any
//! runs `cargo test`) rather than only at deploy time.
//!
//! Fix drift with `scripts/sync-version.sh fix`. See that script's header
//! comment for the full list of what derives automatically vs. what it syncs.
//! No runtime code here — test-only, so it's excluded from release builds.

#[cfg(test)]
mod tests {
    use std::fs;

    fn repo_path(rel: &str) -> String {
        format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel)
    }

    fn extract<'a>(haystack: &'a str, marker: &str, quote_prefix: &str) -> Option<&'a str> {
        let start = haystack.find(marker)? + marker.len();
        let rest = &haystack[start..];
        let q = rest.find(quote_prefix)? + quote_prefix.len();
        let rest = &rest[q..];
        // Plain `X.Y.Z` only (matches every version this project has ever used —
        // no semver pre-release/build-metadata suffix) — deliberately narrower
        // than a full semver charset so a trailing `-color` (README badge) or
        // closing `"` (package.json) always terminates the match correctly.
        let end = rest.find(|c: char| !(c.is_ascii_digit() || c == '.'))?;
        Some(&rest[..end])
    }

    #[test]
    fn electron_package_json_version_matches_cargo_toml() {
        let canon = env!("CARGO_PKG_VERSION");
        let pkg = fs::read_to_string(repo_path("electron/package.json"))
            .expect("read electron/package.json");
        let got = extract(&pkg, "\"version\"", "\"").expect("parse version from package.json");
        assert_eq!(
            got, canon,
            "electron/package.json version ({got}) != Cargo.toml version ({canon}) — run `scripts/sync-version.sh fix`"
        );
    }

    #[test]
    fn electron_package_lock_versions_match_cargo_toml() {
        let canon = env!("CARGO_PKG_VERSION");
        let lock = fs::read_to_string(repo_path("electron/package-lock.json"))
            .expect("read electron/package-lock.json");
        let json: serde_json::Value =
            serde_json::from_str(&lock).expect("parse electron/package-lock.json");
        assert_eq!(json["version"].as_str(), Some(canon));
        assert_eq!(json["packages"][""]["version"].as_str(), Some(canon));
    }

    #[test]
    fn readme_badge_version_matches_cargo_toml() {
        let canon = env!("CARGO_PKG_VERSION");
        let readme = fs::read_to_string(repo_path("README.md")).expect("read README.md");
        let got = extract(&readme, "badge/version-", "").expect("parse version badge from README.md");
        assert_eq!(
            got, canon,
            "README.md version badge ({got}) != Cargo.toml version ({canon}) — run `scripts/sync-version.sh fix`"
        );
    }
}
