/// paste.rs — Pastebin-style text snippet sharing
///
/// Pastes are stored as JSON files in data/pastes/{id}.json
/// Optional password protection (Argon2id hash) and expiration.

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
        std::fs::create_dir_all(&dir).ok();
        Self { dir }
    }

    pub async fn create(&self, req: &CreatePasteRequest, author: &str) -> Result<Paste> {
        if req.content.len() > MAX_PASTE_SIZE {
            anyhow::bail!("Paste too large (max 500KB)");
        }
        if req.content.is_empty() {
            anyhow::bail!("Paste cannot be empty");
        }

        let id = Uuid::new_v4().to_string().replace('-', "")[..12].to_string(); // 12-char hex ID (~2^48 entropy)
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

        let path = self.dir.join(format!("{}.json", id));
        let json = serde_json::to_string_pretty(&paste)?;
        tokio::fs::write(&path, json).await?;

        Ok(paste)
    }

    pub async fn get(&self, id: &str) -> Result<Option<Paste>> {
        // Sanitize ID
        let safe_id: String = id.chars().filter(|c| c.is_alphanumeric() || *c == '-').take(64).collect();
        let path = self.dir.join(format!("{}.json", safe_id));
        if !path.exists() { return Ok(None); }

        let json = tokio::fs::read_to_string(&path).await?;
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

    /// Clean up expired pastes (call periodically)
    pub async fn cleanup_expired(&self) {
        let now = chrono::Utc::now().timestamp();
        if let Ok(mut rd) = tokio::fs::read_dir(&self.dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let path = entry.path();
                if path.extension().map(|x| x == "json").unwrap_or(false) {
                    if let Ok(json) = tokio::fs::read_to_string(&path).await {
                        if let Ok(paste) = serde_json::from_str::<Paste>(&json) {
                            if let Some(exp) = paste.expires_at {
                                if now > exp {
                                    let _ = tokio::fs::remove_file(&path).await;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
