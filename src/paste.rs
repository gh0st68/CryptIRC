/// paste.rs — Pastebin-style text snippet sharing
///
/// Pastes are stored as JSON files in data/pastes/<id>.<expiry_epoch>.json
/// (expiry_epoch is 0 when the paste never expires — audit #47, so cleanup can
/// decide deletion from the filename alone without reading/parsing every body).
/// Optional password protection (Argon2id hash) and expiration.
///
/// ## Access-control model (audit #19 / #45)
/// Paste IDs are FULL-entropy UUIDv4 strings (122 bits — see `create`), so the
/// id itself is an unguessable capability: knowledge of the id IS the grant to
/// read the paste ("public-by-link"). Enumeration/collision is infeasible.
///
/// This module intentionally contains NO session/ownership gate. If a stronger
/// policy than public-by-link is desired (e.g. only the author may view), the
/// route layer in main.rs must compare the requester's authenticated session
/// against `Paste::author` (exposed via the `author` field / accessor) and
/// return 404 on mismatch. Absent that gate, public-by-link is the intended,
/// documented model.
///
/// L6: the id is a full 122-bit random UUID, so enumeration is infeasible
/// regardless of response shape. The view/raw routes therefore return DISTINCT
/// statuses — 403 (unlock form) for a present-but-password-protected paste vs 404
/// for an unknown id — which is fine given the entropy. Ideally callers would
/// equalize timing on the password-verify path; the status divergence itself is
/// not an enumeration risk (see `get` docs and `verify_password`).

use anyhow::Result;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use uuid::Uuid;

const MAX_PASTE_SIZE: usize = 500_000; // 500KB max

/// r5 (codex P1 paste.rs:230): per-account paste quota — pastes on disk (expired ones count
/// until they are swept) and their bytes. Defaults 500 pastes / 200 MiB; override with
/// CRYPTIRC_PASTE_QUOTA_COUNT and CRYPTIRC_PASTE_QUOTA_MB (0 = no limit of that kind).
const DEFAULT_PASTE_QUOTA_COUNT: usize = 500;
const DEFAULT_PASTE_QUOTA_MB: u64 = 200;
fn paste_quota() -> (usize, u64) {
    let num = |k: &str| std::env::var(k).ok().and_then(|v| v.trim().parse::<u64>().ok());
    let count = num("CRYPTIRC_PASTE_QUOTA_COUNT").map_or(DEFAULT_PASTE_QUOTA_COUNT, |v| v as usize);
    let mb = num("CRYPTIRC_PASTE_QUOTA_MB").unwrap_or(DEFAULT_PASTE_QUOTA_MB);
    (count, mb.saturating_mul(1024 * 1024))
}

/// Render type of a paste: how the `/paste/<id>` view presents the stored content.
/// `Text` (the historical default) keeps the escaped-`<pre>` view, `Markdown`
/// renders a sanitized document, and `Html` runs the payload as a sandboxed app.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum PasteKind {
    #[default]
    Text,
    Markdown,
    Html,
}

impl PasteKind {
    /// Parse a client-supplied wire value. `None` marks an unrecognized type so the
    /// create path can reject it with a client error — unlike stored-file parsing,
    /// which tolerates unknown values by falling back to `Text`.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "text" => Some(Self::Text),
            "markdown" => Some(Self::Markdown),
            "html" => Some(Self::Html),
            _ => None,
        }
    }

    /// Stable wire name (also used in API responses).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Markdown => "markdown",
            Self::Html => "html",
        }
    }
}

/// Tolerant deserializer for stored pastes: a missing field is handled by
/// `#[serde(default)]`, and an unknown value falls back to `Text` so a file from a
/// future build (or a hand-edited one) still opens as a safe plain-text paste
/// instead of failing the whole view.
fn deserialize_kind<'de, D>(d: D) -> Result<PasteKind, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(d)?;
    Ok(PasteKind::from_wire(&raw).unwrap_or_default())
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Paste {
    pub id: String,
    pub content: String,
    pub language: String,
    /// Render type. Missing (pre-change files) or unknown values parse as `Text`.
    #[serde(default, deserialize_with = "deserialize_kind")]
    pub content_type: PasteKind,
    pub created_at: i64,
    pub expires_at: Option<i64>,     // Unix timestamp, None = no expiry
    pub password_hash: Option<String>, // Argon2id hash if password-protected
    pub author: String,
}

#[derive(Deserialize)]
pub struct CreatePasteRequest {
    pub content: String,
    pub language: Option<String>,
    /// Optional render type (`text` | `markdown` | `html`); omitted = `text`.
    #[serde(default)]
    pub content_type: Option<String>,
    pub expires_in: Option<i64>,  // seconds from now, 0 or None = no expiry
    pub password: Option<String>,
}

pub struct PasteStore {
    dir: PathBuf,
    /// id → on-disk path. Built once at startup (one dir scan) and kept current by
    /// create/get/cleanup, so a view is an O(1) lookup instead of a full `read_dir`
    /// of the pastes dir per request (rust-content LOW; the filename carries the
    /// expiry epoch, so the path can't be rebuilt from the id alone).
    index: DashMap<String, PathBuf>,
    /// Last full rescan triggered by an index miss. A miss (unknown id, or a file
    /// placed in the dir out of band) rescans at most once per MISS_RESCAN_EVERY,
    /// so unknown-id probing can't turn back into a dir walk per request.
    last_rescan: std::sync::Mutex<Option<Instant>>,
    /// r5: id → (author, bytes on disk), for the per-account quota. Filled by one full scan
    /// on first use (the author is inside the file) and kept current by create / delete /
    /// expiry; a file dropped in out of band is simply not counted.
    owners: DashMap<String, (String, u64)>,
    owners_scanned: tokio::sync::OnceCell<()>,
    /// Serializes quota check + write, so two concurrent creates can't both pass the check.
    quota_lock: tokio::sync::Mutex<()>,
    /// (max pastes, max bytes) per account, read from the environment at startup.
    quota: (usize, u64),
}

/// Minimum spacing between miss-triggered rescans of the pastes dir.
const MISS_RESCAN_EVERY: Duration = Duration::from_secs(30);

/// The paste id of a stored file name: `<id>.<expiry>.json` (current) or
/// `<id>.json` (pre-#47 legacy). Ids never contain a dot.
fn id_from_name(name: &str) -> Option<&str> {
    let stem = name.strip_suffix(".json")?;
    let id = stem.split('.').next()?;
    if id.is_empty() || !id.chars().all(|c| c.is_alphanumeric() || c == '-') { return None; }
    Some(id)
}

impl PasteStore {
    pub fn new(data_dir: &str) -> Self {
        let dir = PathBuf::from(data_dir).join("pastes");
        // audit #46: the paste dir holds Argon2 password hashes and plaintext
        // paste bodies. Create it 0700 so other local users on a shared host
        // cannot traverse/read it. Fall back to a plain create on non-unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)
                .ok();
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(&dir).ok();
        }
        let index = DashMap::new();
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                if let Some(name) = e.file_name().to_str() {
                    if let Some(id) = id_from_name(name) { index.insert(id.to_string(), e.path()); }
                }
            }
        }
        Self { dir, index, last_rescan: std::sync::Mutex::new(None), owners: DashMap::new(),
               owners_scanned: tokio::sync::OnceCell::new(), quota_lock: tokio::sync::Mutex::new(()),
               quota: paste_quota() }
    }

    pub async fn create(&self, req: &CreatePasteRequest, author: &str) -> Result<Paste> {
        if req.content.len() > MAX_PASTE_SIZE {
            anyhow::bail!("Paste too large (max 500KB)");
        }
        if req.content.is_empty() {
            anyhow::bail!("Paste cannot be empty");
        }

        // Explicit opt-in render type. An unknown value is a client error; omitting
        // it keeps every legacy client on plain text. Validate before the Argon2
        // derive below so a malformed request never pays the hashing cost.
        let content_type = match req.content_type.as_deref() {
            None => PasteKind::Text,
            Some(s) => PasteKind::from_wire(s).ok_or_else(|| {
                anyhow::anyhow!("Unknown content type (expected text, markdown, or html)")
            })?,
        };

        // audit #45: use the FULL UUIDv4 (122 bits of entropy) as the id rather
        // than truncating to 12 hex chars (~48 bits). This makes the id an
        // unguessable capability — enumeration/collision is infeasible.
        let id = Uuid::new_v4().to_string().replace('-', "");
        let now = chrono::Utc::now().timestamp();

        // audit #F20: clamp expires_in and use saturating arithmetic so an
        // attacker-supplied value near i64::MAX can't overflow `now + secs`.
        // Release builds have no overflow-checks, so a raw `+` would wrap to a
        // large NEGATIVE timestamp — the paste would be written then treated as
        // already-expired on first view (silent data loss). The UI's largest
        // expiry option is 30 days; MAX_EXPIRES_IN (1 year) is well above every
        // legitimate choice so no real selection is cut. None / 0 (never
        // expires) is preserved.
        const MAX_EXPIRES_IN: i64 = 365 * 24 * 60 * 60; // 1 year
        let expires_at = match req.expires_in {
            Some(secs) if secs > 0 => Some(now.saturating_add(secs.min(MAX_EXPIRES_IN))),
            _ => None,
        };

        let password_hash = if let Some(ref pw) = req.password {
            if !pw.is_empty() {
                let salt = SaltString::generate(&mut OsRng);
                let hash = Argon2::default()
                    .hash_password(pw.as_bytes(), &salt)
                    .map_err(|e| anyhow::anyhow!("Hash error: {}", e))?
                    .to_string();
                Some(hash)
            } else { None }
        } else { None };

        let paste = Paste {
            id: id.clone(),
            content: req.content.clone(),
            language: req.language.clone().unwrap_or_else(|| "text".into()),
            content_type,
            created_at: now,
            expires_at,
            password_hash,
            author: author.to_string(),
        };

        // audit #47: encode the expiry epoch into the filename (0 == never
        // expires) so cleanup_expired can act on the filename without reading
        // and JSON-parsing every paste body.
        let path = self.dir.join(Self::file_name(&id, expires_at));
        let json = serde_json::to_string_pretty(&paste)?;
        // r5 (codex P1 paste.rs:230): per-account quota and the server's free-space floor
        // (the uploads' MIN_FREE_DISK_BYTES), checked and committed under one lock.
        let _q = self.quota_lock.lock().await;
        let (count, bytes) = self.author_usage(author).await;
        let (max_count, max_bytes) = self.quota;
        if max_count > 0 && count >= max_count {
            anyhow::bail!("Paste limit reached ({} pastes). Expired pastes are removed automatically; Clear All Data deletes yours.", max_count);
        }
        if max_bytes > 0 && bytes.saturating_add(json.len() as u64) > max_bytes {
            anyhow::bail!("Paste storage limit reached ({} MB). Expired pastes are removed automatically; Clear All Data deletes yours.", max_bytes / (1024 * 1024));
        }
        if let Some(avail) = crate::upload::available_disk_bytes(&self.dir) {
            if avail < crate::upload::MIN_FREE_DISK_BYTES.saturating_add(json.len() as u64) {
                anyhow::bail!("Server storage is nearly full — try again later");
            }
        }
        let size = json.len() as u64;
        tokio::fs::write(&path, json).await?;
        // audit #46: restrict the freshly written file to 0600 — it contains an
        // Argon2 password hash and the plaintext paste body.
        set_secret_mode(&path).await;
        self.index.insert(id.clone(), path);
        self.owners.insert(id.clone(), (author.to_string(), size));

        Ok(paste)
    }

    /// r5: (pastes, bytes) `author` has on disk, per the owners map (scanned once on first use).
    pub async fn author_usage(&self, author: &str) -> (usize, u64) {
        self.owners_scanned.get_or_init(|| self.scan_owners()).await;
        self.owners.iter().filter(|e| e.value().0 == author)
            .fold((0usize, 0u64), |(n, b), e| (n + 1, b + e.value().1))
    }

    /// r5: read every paste file once to learn its author (unreadable files are skipped).
    async fn scan_owners(&self) {
        let Ok(mut rd) = tokio::fs::read_dir(&self.dir).await else { return };
        while let Ok(Some(entry)) = rd.next_entry().await {
            let Some(name) = entry.file_name().to_str().map(|n| n.to_string()) else { continue };
            let Some(id) = id_from_name(&name).map(|i| i.to_string()) else { continue };
            let Ok(json) = tokio::fs::read_to_string(entry.path()).await else { continue };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) else { continue };
            let Some(a) = v.get("author").and_then(|a| a.as_str()) else { continue };
            self.owners.entry(id).or_insert((a.to_string(), json.len() as u64));
        }
    }

    /// r5: drop an id from the index and the quota map (the file is gone or being removed).
    fn forget(&self, id: &str) {
        self.index.remove(id);
        self.owners.remove(id);
    }

    /// Build the on-disk filename for a paste: `<id>.<expiry_epoch>.json`.
    /// `expiry_epoch` is the absolute Unix expiry timestamp, or 0 for no expiry.
    fn file_name(id: &str, expires_at: Option<i64>) -> String {
        format!("{}.{}.json", id, expires_at.unwrap_or(0))
    }

    /// Fetch a paste by id.
    ///
    /// Returns `Ok(None)` for an unknown / expired id. L6: the id is a full-entropy
    /// 122-bit UUID (audit #19/#45), so it cannot be probed by enumeration even
    /// though the routes return 403 (present-but-locked) vs 404 (unknown) — the
    /// status divergence does not leak anything an attacker could feasibly exploit.
    pub async fn get(&self, id: &str) -> Result<Option<Paste>> {
        // Sanitize ID (filenames are `<id>.<expiry>.json`; the id is hex so
        // alphanumerics only — keep `-` for backward-compat with any legacy
        // hyphenated ids).
        let safe_id: String = id.chars().filter(|c| c.is_alphanumeric() || *c == '-').take(64).collect();
        if safe_id.is_empty() { return Ok(None); }

        // The expiry is encoded in the filename, so locate the file by id prefix
        // (`<id>.`) rather than reconstructing the full name (audit #47).
        let path = match self.find_path(&safe_id).await {
            Some(p) => p,
            None => return Ok(None),
        };

        let json = match tokio::fs::read_to_string(&path).await {
            Ok(j) => j,
            Err(_) => {
                // Vanished from disk (deleted out of band) — drop the stale entry.
                self.forget(&safe_id);
                return Ok(None);
            }
        };
        let paste: Paste = serde_json::from_str(&json)?;

        // Check expiration
        if let Some(exp) = paste.expires_at {
            if chrono::Utc::now().timestamp() > exp {
                // Expired — delete it
                let _ = tokio::fs::remove_file(&path).await;
                self.forget(&safe_id);
                return Ok(None);
            }
        }

        Ok(Some(paste))
    }

    /// Find the on-disk path for a paste id (the `<id>.` filename prefix — the
    /// suffix carries the expiry epoch, audit #47). O(1) via the in-memory index;
    /// on a miss, at most one rescan per MISS_RESCAN_EVERY picks up files that
    /// appeared out of band.
    async fn find_path(&self, safe_id: &str) -> Option<PathBuf> {
        if let Some(p) = self.index.get(safe_id) { return Some(p.clone()); }
        let due = {
            let mut last = self.last_rescan.lock().unwrap_or_else(|e| e.into_inner());
            let due = last.map_or(true, |t| t.elapsed() >= MISS_RESCAN_EVERY);
            if due { *last = Some(Instant::now()); }
            due
        };
        if due { self.rescan().await; }
        self.index.get(safe_id).map(|p| p.clone())
    }

    /// Re-read the pastes dir into the index (adds new files; entries whose file
    /// is gone are dropped). Returns nothing; best-effort.
    async fn rescan(&self) {
        let mut seen = std::collections::HashSet::new();
        if let Ok(mut rd) = tokio::fs::read_dir(&self.dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                if let Some(name) = entry.file_name().to_str() {
                    if let Some(id) = id_from_name(name) {
                        seen.insert(id.to_string());
                        self.index.insert(id.to_string(), entry.path());
                    }
                }
            }
        } else {
            return;
        }
        // Only drop entries we didn't see whose file is really gone — a paste
        // created mid-scan is in the index but may not have been listed.
        let unseen: Vec<(String, PathBuf)> = self.index.iter()
            .filter(|e| !seen.contains(e.key()))
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();
        for (id, path) in unseen {
            if tokio::fs::metadata(&path).await.is_err() { self.forget(&id); }
        }
    }

    /// Author of a paste. Exposed so the route layer (main.rs) can enforce an
    /// optional author-scoping policy on top of the public-by-link default
    /// (audit #19): compare against the requester's authenticated session and
    /// return a 404-identical response on mismatch.
    pub fn author(paste: &Paste) -> &str {
        &paste.author
    }

    pub fn verify_password(paste: &Paste, password: &str) -> bool {
        if let Some(ref hash) = paste.password_hash {
            match PasswordHash::new(hash) {
                Ok(h) => Argon2::default().verify_password(password.as_bytes(), &h).is_ok(),
                Err(_) => false,
            }
        } else {
            true
        }
    }

    /// r4 C1-7 (codex P1 main.rs:326): delete every paste whose `author` is exactly
    /// `author` (the canonical, lower-case account name the create route stores), the same
    /// match Clear All Data uses. Account deletion calls this so an erased account's pastes
    /// stop being served and can never be attributed to (or deleted by) a later account that
    /// registers the same name. Reads each file (the author is not in the file name); files
    /// that can't be read or parsed are left alone. Returns how many were removed.
    pub async fn delete_by_author(&self, author: &str) -> usize {
        if author.is_empty() { return 0; }
        let mut removed = 0;
        let Ok(mut rd) = tokio::fs::read_dir(&self.dir).await else { return 0 };
        while let Ok(Some(entry)) = rd.next_entry().await {
            let path = entry.path();
            let Some(name) = entry.file_name().to_str().map(|n| n.to_string()) else { continue };
            let Some(id) = id_from_name(&name).map(|i| i.to_string()) else { continue };
            let Ok(json) = tokio::fs::read_to_string(&path).await else { continue };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) else { continue };
            if v.get("author").and_then(|a| a.as_str()) != Some(author) { continue; }
            if tokio::fs::remove_file(&path).await.is_ok() {
                self.forget(&id);
                removed += 1;
            }
        }
        removed
    }

    /// Remove one paste by id (r4 C1-7: a paste whose author account was deleted while it
    /// was being created). Returns true if a file was removed.
    pub async fn delete(&self, id: &str) -> bool {
        let Some(path) = self.find_path(id).await else { return false };
        let ok = tokio::fs::remove_file(&path).await.is_ok();
        self.forget(id);
        ok
    }

    /// Clean up expired pastes (call periodically).
    ///
    /// audit #47: the expiry epoch is encoded in the filename
    /// (`<id>.<expiry_epoch>.json`, 0 == never), so this no longer reads or
    /// JSON-parses any paste body — deletion is decided from the filename alone
    /// (O(N) over dir entries, but with zero file I/O per non-expired paste).
    pub async fn cleanup_expired(&self) {
        let now = chrono::Utc::now().timestamp();
        if let Ok(mut rd) = tokio::fs::read_dir(&self.dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let name = match entry.file_name().into_string() {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                if let Some(exp) = Self::expiry_from_name(&name) {
                    // exp == 0 means "never expires" — skip.
                    if exp != 0 && now > exp {
                        if tokio::fs::remove_file(entry.path()).await.is_ok() {
                            if let Some(id) = id_from_name(&name) { self.forget(id); }
                        }
                    }
                }
            }
        }
        // Same hourly cadence: reconcile the index with the directory.
        self.rescan().await;
    }

    /// Parse the expiry epoch out of a `<id>.<expiry_epoch>.json` filename.
    /// Returns `None` for names that don't match the expected shape (legacy or
    /// unrelated files are left untouched).
    fn expiry_from_name(name: &str) -> Option<i64> {
        let stem = name.strip_suffix(".json")?;
        // The expiry is the final dot-separated component; the id may itself be
        // plain hex (no dots) but split off only the last segment to be safe.
        let (_, exp) = stem.rsplit_once('.')?;
        exp.parse::<i64>().ok()
    }
}

/// Best-effort chmod 0600 on a freshly written paste file (audit #46): pastes
/// hold Argon2 password hashes and plaintext bodies, and the data dir may be
/// readable by other local users. No-op on non-unix targets. Mirrors the
/// `set_secret_mode` helper in certs.rs.
async fn set_secret_mode(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await;
    }
    #[cfg(not(unix))]
    { let _ = path; }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> (PasteStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!("cryptirc-paste-test-{}", Uuid::new_v4()));
        (PasteStore::new(dir.to_str().unwrap()), dir)
    }

    fn req(content: String, kind: Option<&str>) -> CreatePasteRequest {
        CreatePasteRequest {
            content,
            language: None,
            content_type: kind.map(|s| s.to_string()),
            expires_in: None,
            password: None,
        }
    }

    fn full_paste(kind: PasteKind) -> Paste {
        Paste {
            id: "abc".into(),
            content: "hello".into(),
            language: "text".into(),
            content_type: kind,
            created_at: 1,
            expires_at: None,
            password_hash: None,
            author: "tester".into(),
        }
    }

    #[test]
    fn legacy_paste_without_type_parses_as_text() {
        let json = r#"{"id":"abc","content":"hello","language":"text","created_at":1,"expires_at":null,"password_hash":null,"author":"tester"}"#;
        let p: Paste = serde_json::from_str(json).unwrap();
        assert_eq!(p.content_type, PasteKind::Text);
    }

    #[test]
    fn unknown_stored_type_falls_back_to_text() {
        let json = r#"{"id":"abc","content":"hello","language":"text","content_type":"exe","created_at":1,"expires_at":null,"password_hash":null,"author":"tester"}"#;
        let p: Paste = serde_json::from_str(json).unwrap();
        assert_eq!(p.content_type, PasteKind::Text);
    }

    #[test]
    fn each_allowed_type_round_trips() {
        for (wire, kind) in [
            ("text", PasteKind::Text),
            ("markdown", PasteKind::Markdown),
            ("html", PasteKind::Html),
        ] {
            let json = serde_json::to_string(&full_paste(kind)).unwrap();
            assert!(json.contains(&format!("\"content_type\":\"{}\"", wire)), "{}", json);
            let back: Paste = serde_json::from_str(&json).unwrap();
            assert_eq!(back.content_type, kind);
        }
    }

    #[test]
    fn request_wire_values_validate() {
        assert_eq!(PasteKind::from_wire("text"), Some(PasteKind::Text));
        assert_eq!(PasteKind::from_wire("markdown"), Some(PasteKind::Markdown));
        assert_eq!(PasteKind::from_wire("html"), Some(PasteKind::Html));
        assert_eq!(PasteKind::from_wire("HTML"), None);
        assert_eq!(PasteKind::from_wire("exe"), None);
    }

    #[tokio::test]
    async fn omitted_type_creates_text_paste() {
        let (store, dir) = test_store();
        let p = store.create(&req("hello".into(), None), "tester").await.unwrap();
        assert_eq!(p.content_type, PasteKind::Text);
        // The stored file round-trips through get() with the same type.
        let loaded = store.get(&p.id).await.unwrap().unwrap();
        assert_eq!(loaded.content_type, PasteKind::Text);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn requested_types_are_stored() {
        let (store, dir) = test_store();
        for wire in ["markdown", "html"] {
            let p = store.create(&req("<h1>hi</h1>".into(), Some(wire)), "tester").await.unwrap();
            assert_eq!(p.content_type.as_str(), wire);
            let loaded = store.get(&p.id).await.unwrap().unwrap();
            assert_eq!(loaded.content_type.as_str(), wire);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unknown_type_is_rejected() {
        let (store, dir) = test_store();
        assert!(store.create(&req("hello".into(), Some("exe")), "tester").await.is_err());
        assert!(store.create(&req("hello".into(), Some("HTML")), "tester").await.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn index_finds_existing_new_and_legacy_files_without_scanning() {
        let dir = std::env::temp_dir().join(format!("cryptirc-paste-idx-{}", Uuid::new_v4()));
        let pastes = dir.join("pastes");
        std::fs::create_dir_all(&pastes).unwrap();
        // A legacy `<id>.json` and a current `<id>.<exp>.json` present at startup.
        let legacy = Paste { id: "legacyid".into(), ..full_paste(PasteKind::Text) };
        std::fs::write(pastes.join("legacyid.json"), serde_json::to_string(&legacy).unwrap()).unwrap();
        let cur = Paste { id: "curid".into(), ..full_paste(PasteKind::Markdown) };
        std::fs::write(pastes.join("curid.0.json"), serde_json::to_string(&cur).unwrap()).unwrap();
        let store = PasteStore::new(dir.to_str().unwrap());
        assert!(store.get("legacyid").await.unwrap().is_some());
        assert_eq!(store.get("curid").await.unwrap().unwrap().content_type, PasteKind::Markdown);
        // Created after startup → in the index immediately.
        let p = store.create(&req("x".into(), None), "t").await.unwrap();
        assert!(store.get(&p.id).await.unwrap().is_some());
        // Unknown id → None (one rate-limited rescan at most).
        assert!(store.get("nope").await.unwrap().is_none());
        // A file dropped out of band is NOT seen until the rescan window passes,
        // proving a miss doesn't scan the directory every time …
        let oob = Paste { id: "oobid".into(), ..full_paste(PasteKind::Text) };
        std::fs::write(pastes.join("oobid.0.json"), serde_json::to_string(&oob).unwrap()).unwrap();
        assert!(store.get("oobid").await.unwrap().is_none());
        // … but the hourly cleanup reconciles it, and drops deleted files.
        std::fs::remove_file(pastes.join("curid.0.json")).unwrap();
        store.cleanup_expired().await;
        assert!(store.get("oobid").await.unwrap().is_some());
        assert!(store.index.get("curid").is_none());
        // Expired paste: deleted on view and removed from the index.
        let exp = Paste { id: "expid".into(), expires_at: Some(1), ..full_paste(PasteKind::Text) };
        std::fs::write(pastes.join("expid.1.json"), serde_json::to_string(&exp).unwrap()).unwrap();
        store.index.insert("expid".into(), pastes.join("expid.1.json"));
        assert!(store.get("expid").await.unwrap().is_none());
        assert!(!pastes.join("expid.1.json").exists());
        assert!(store.index.get("expid").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// r4 C1-7: account deletion removes exactly that account's pastes (files + index), so
    /// their links stop working; other authors' pastes (incl. a name that merely starts the
    /// same) and unparseable files are untouched.
    #[tokio::test]
    async fn r4_delete_by_author_removes_only_that_accounts_pastes() {
        let (store, dir) = test_store();
        let a1 = store.create(&req("alice one".into(), None), "alice").await.unwrap();
        let a2 = store.create(&CreatePasteRequest { expires_in: Some(3600), ..req("alice two".into(), Some("markdown")) }, "alice").await.unwrap();
        let b = store.create(&req("bob".into(), None), "bob").await.unwrap();
        let al = store.create(&req("alice2".into(), None), "alice2").await.unwrap();
        std::fs::write(dir.join("pastes").join("junk.0.json"), b"{not json").unwrap();
        assert_eq!(store.delete_by_author("alice").await, 2);
        assert!(store.get(&a1.id).await.unwrap().is_none());
        assert!(store.get(&a2.id).await.unwrap().is_none());
        assert!(store.index.get(&a1.id).is_none() && store.index.get(&a2.id).is_none());
        assert!(store.get(&b.id).await.unwrap().is_some());
        assert!(store.get(&al.id).await.unwrap().is_some());
        assert!(dir.join("pastes").join("junk.0.json").exists());
        assert_eq!(store.delete_by_author("alice").await, 0, "idempotent");
        assert_eq!(store.delete_by_author("").await, 0);
        // Single delete by id.
        assert!(store.delete(&b.id).await);
        assert!(store.get(&b.id).await.unwrap().is_none());
        assert!(!store.delete(&b.id).await);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// r5 (codex P1 paste.rs:230): the per-account quota counts pastes already on disk
    /// (learned by the one-time scan), refuses beyond it, is per author, and frees up when
    /// pastes are deleted.
    #[tokio::test]
    async fn r5_per_account_paste_quota() {
        let (mut store, dir) = test_store();
        // Two pastes by "heavy" already on disk before this process (out of band).
        for id in ["oldaa", "oldbb"] {
            let p = Paste { id: id.into(), author: "heavy".into(), ..full_paste(PasteKind::Text) };
            std::fs::write(dir.join("pastes").join(format!("{}.0.json", id)), serde_json::to_string(&p).unwrap()).unwrap();
        }
        store.quota = (3, 1_000_000);
        let a = store.create(&req("one".into(), None), "heavy").await;
        assert!(a.is_ok(), "{:?}", a.as_ref().err());
        let b = store.create(&req("two".into(), None), "heavy").await;
        let e = b.err().map(|e| e.to_string()).unwrap_or_default();
        println!("R5 paste quota: 4th paste of an account limited to 3 -> {e}");
        assert!(e.contains("Paste limit reached"), "{e}");
        assert!(store.create(&req("other".into(), None), "light").await.is_ok(), "per author");
        assert_eq!(store.author_usage("heavy").await.0, 3);
        // Bytes: a big paste over the byte quota is refused.
        store.quota = (100, 50_000);
        let big = store.create(&req("a".repeat(60_000), None), "light").await;
        assert!(big.err().map(|e| e.to_string()).unwrap_or_default().contains("storage limit"));
        // Deleting frees the slot.
        store.quota = (3, 1_000_000);
        assert_eq!(store.delete_by_author("heavy").await, 3);
        assert_eq!(store.author_usage("heavy").await, (0, 0));
        assert!(store.create(&req("again".into(), None), "heavy").await.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn size_limit_applies_to_every_type() {
        let (store, dir) = test_store();
        for kind in ["text", "markdown", "html"] {
            let over = "a".repeat(MAX_PASTE_SIZE + 1);
            assert!(store.create(&req(over, Some(kind)), "tester").await.is_err(), "{} should reject oversize", kind);
        }
        // Exactly at the cap is still accepted (unchanged boundary).
        let exact = "a".repeat(MAX_PASTE_SIZE);
        assert!(store.create(&req(exact, Some("html")), "tester").await.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
