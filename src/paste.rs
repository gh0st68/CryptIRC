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
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

const MAX_PASTE_SIZE: usize = 500_000; // 500KB max

#[derive(Serialize, Deserialize, Clone)]
pub struct Paste {
    pub id: String,
    pub content: String,
    pub language: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,     // Unix timestamp, None = no expiry
    pub password_hash: Option<String>, // Argon2id hash if password-protected
    pub author: String,
}

#[derive(Deserialize)]
pub struct CreatePasteRequest {
    pub content: String,
    pub language: Option<String>,
    pub expires_in: Option<i64>,  // seconds from now, 0 or None = no expiry
    pub password: Option<String>,
}

pub struct PasteStore {
    dir: PathBuf,
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
        Self { dir }
    }

    pub async fn create(&self, req: &CreatePasteRequest, author: &str) -> Result<Paste> {
        if req.content.len() > MAX_PASTE_SIZE {
            anyhow::bail!("Paste too large (max 500KB)");
        }
        if req.content.is_empty() {
            anyhow::bail!("Paste cannot be empty");
        }

        // audit #45: use the FULL UUIDv4 (122 bits of entropy) as the id rather
        // than truncating to 12 hex chars (~48 bits). This makes the id an
        // unguessable capability — enumeration/collision is infeasible.
        let id = Uuid::new_v4().to_string().replace('-', "");
        let now = chrono::Utc::now().timestamp();

        let expires_at = match req.expires_in {
            Some(secs) if secs > 0 => Some(now + secs),
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
        tokio::fs::write(&path, json).await?;
        // audit #46: restrict the freshly written file to 0600 — it contains an
        // Argon2 password hash and the plaintext paste body.
        set_secret_mode(&path).await;

        Ok(paste)
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
            Err(_) => return Ok(None),
        };
        let paste: Paste = serde_json::from_str(&json)?;

        // Check expiration
        if let Some(exp) = paste.expires_at {
            if chrono::Utc::now().timestamp() > exp {
                // Expired — delete it
                let _ = tokio::fs::remove_file(&path).await;
                return Ok(None);
            }
        }

        Ok(Some(paste))
    }

    /// Find the on-disk path for a paste id by matching the `<id>.` filename
    /// prefix (the suffix carries the expiry epoch — audit #47).
    async fn find_path(&self, safe_id: &str) -> Option<PathBuf> {
        let prefix = format!("{}.", safe_id);
        if let Ok(mut rd) = tokio::fs::read_dir(&self.dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                if let Some(name) = entry.file_name().to_str() {
                    if name.starts_with(&prefix) && name.ends_with(".json") {
                        return Some(entry.path());
                    }
                }
            }
        }
        None
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
                        let _ = tokio::fs::remove_file(entry.path()).await;
                    }
                }
            }
        }
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
