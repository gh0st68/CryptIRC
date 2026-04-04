//! auth.rs — User registration, login, session, email verification
//!
//! Fixes this pass:
//!   S1 — write-through create_new handle (no empty-file window)
//!   S5 — rate_limits DashMap capped + TTL sweep to prevent memory exhaustion

use anyhow::{bail, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

const SESSION_MAX_AGE_SECS:    i64   = 60 * 60 * 24 * 30; // 30 days
const MAX_SESSIONS_PER_USER:   usize = 10;
const RATE_LIMIT_WINDOW_SECS:  u64   = 60;
const RATE_LIMIT_MAX_ATTEMPTS: u32   = 10;
/// S5: hard cap on total rate-limit buckets to prevent unbounded DashMap growth
const RATE_LIMIT_MAX_BUCKETS:  usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username:      String,
    pub email:         String,
    pub password_hash: String,
    pub verified:      bool,
    pub created_at:    i64,
    #[serde(default)]
    pub admin:         bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingVerification {
    pub username:   String,
    pub email:      String,
    pub token:      String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingReset {
    pub username:   String,
    pub token:      String,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub username:   String,
    pub created_at: i64,
    pub last_used:  i64,
}

struct RateBucket {
    attempts:     u32,
    window_start: Instant,
}

pub struct AuthManager {
    pub data_dir: String,
    sessions:     Arc<DashMap<String, Session>>,
    rate_limits:  Arc<DashMap<String, RateBucket>>,
}

impl AuthManager {
    pub fn new(data_dir: &str) -> Result<Self> {
        std::fs::create_dir_all(format!("{}/users",   data_dir))?;
        std::fs::create_dir_all(format!("{}/pending", data_dir))?;
        Ok(Self {
            data_dir:    data_dir.to_string(),
            sessions:    Arc::new(DashMap::new()),
            rate_limits: Arc::new(DashMap::new()),
        })
    }

    // ── Rate limiting ─────────────────────────────────────────────────────────

    fn check_rate_limit(&self, key: &str) -> Result<()> {
        // S5: if at cap, sweep expired buckets first; if still at cap, hard-fail
        if self.rate_limits.len() >= RATE_LIMIT_MAX_BUCKETS {
            self.sweep_rate_buckets();
            if self.rate_limits.len() >= RATE_LIMIT_MAX_BUCKETS {
                bail!("Too many attempts — try again later");
            }
        }

        let now = Instant::now();
        let mut entry = self.rate_limits.entry(key.to_string()).or_insert_with(|| {
            RateBucket { attempts: 0, window_start: now }
        });
        if now.duration_since(entry.window_start) > Duration::from_secs(RATE_LIMIT_WINDOW_SECS) {
            entry.attempts    = 0;
            entry.window_start = now;
        }
        entry.attempts += 1;
        if entry.attempts > RATE_LIMIT_MAX_ATTEMPTS {
            bail!("Too many attempts — try again later");
        }
        Ok(())
    }

    /// Remove rate-limit buckets whose window has fully expired.
    pub fn sweep_rate_buckets(&self) {
        let threshold = Duration::from_secs(RATE_LIMIT_WINDOW_SECS * 2);
        let stale: Vec<String> = self.rate_limits.iter()
            .filter(|b| b.window_start.elapsed() > threshold)
            .map(|b| b.key().clone())
            .collect();
        for k in stale { self.rate_limits.remove(&k); }
    }

    // ── Registration ──────────────────────────────────────────────────────────

    pub async fn register(&self, username: &str, email: &str, password: &str) -> Result<String> {
        let uname = username.trim().to_lowercase();
        if uname.len() < 3 || uname.len() > 32 {
            bail!("Username must be 3–32 characters");
        }
        if !uname.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
            bail!("Username may only contain letters, numbers, _ and -");
        }
        if password.len() < 10 {
            bail!("Password must be at least 10 characters");
        }
        let has_upper = password.chars().any(|c| c.is_uppercase());
        let has_lower = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());
        if !has_upper || !has_lower || !has_digit || !has_special {
            bail!("Password must contain uppercase, lowercase, number, and special character");
        }
        if !email.contains('@') || email.len() > 254 {
            bail!("Invalid email address");
        }

        self.check_rate_limit(&format!("reg:{}", uname))?;

        let user_path = PathBuf::from(&self.data_dir)
            .join("users")
            .join(format!("{}.json", uname));

        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| anyhow::anyhow!("Password hashing failed"))?
            .to_string();

        let user = User {
            username:      uname.clone(),
            email:         email.to_lowercase(),
            password_hash: hash,
            verified:      false,
            created_at:    Utc::now().timestamp(),
            admin:         false,
        };
        let json = serde_json::to_string_pretty(&user)?;

        // S1: atomic create + write-through in one operation.
        // create_new fails if the file already exists (no TOCTOU).
        // We write through the same handle so no empty-file window exists.
        {
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&user_path)
                .await
                .map_err(|_| anyhow::anyhow!("Username already taken"))?;
            file.write_all(json.as_bytes()).await?;
            file.flush().await?;
        }

        let token    = Uuid::new_v4().to_string();
        let pending  = PendingVerification {
            username: uname, email: email.to_lowercase(),
            token: token.clone(), expires_at: Utc::now().timestamp() + 86400,
        };
        let pending_path = PathBuf::from(&self.data_dir)
            .join("pending")
            .join(format!("{}.json", token));
        tokio::fs::write(pending_path, serde_json::to_string_pretty(&pending)?).await?;
        Ok(token)
    }

    // ── Password reset ────────────────────────────────────────────────────────

    pub async fn request_password_reset(&self, email_addr: &str) -> Result<Option<(String, String)>> {
        let email_lower = email_addr.trim().to_lowercase();
        self.check_rate_limit(&format!("reset:{}", email_lower))?;

        // Find user by email
        let users_dir = PathBuf::from(&self.data_dir).join("users");
        let mut entries = tokio::fs::read_dir(&users_dir).await?;
        let mut found_user: Option<User> = None;
        while let Some(entry) = entries.next_entry().await? {
            if let Ok(json) = tokio::fs::read_to_string(entry.path()).await {
                if let Ok(user) = serde_json::from_str::<User>(&json) {
                    if user.email == email_lower && user.verified {
                        found_user = Some(user);
                        break;
                    }
                }
            }
        }

        let user = match found_user {
            Some(u) => u,
            None => return Ok(None), // Don't reveal whether the email exists
        };

        let token = Uuid::new_v4().to_string();
        let reset_dir = PathBuf::from(&self.data_dir).join("resets");
        tokio::fs::create_dir_all(&reset_dir).await?;

        let reset = PendingReset {
            username: user.username.clone(),
            token: token.clone(),
            expires_at: Utc::now().timestamp() + 3600, // 1 hour
        };
        let reset_path = reset_dir.join(format!("{}.json", token));
        tokio::fs::write(reset_path, serde_json::to_string_pretty(&reset)?).await?;

        Ok(Some((token, user.username)))
    }

    pub async fn reset_password(&self, raw_token: &str, new_password: &str) -> Result<String> {
        let token = validate_uuid(raw_token)
            .ok_or_else(|| anyhow::anyhow!("Invalid reset link"))?;

        if new_password.len() < 10 {
            bail!("Password must be at least 10 characters");
        }
        let has_upper = new_password.chars().any(|c| c.is_uppercase());
        let has_lower = new_password.chars().any(|c| c.is_lowercase());
        let has_digit = new_password.chars().any(|c| c.is_ascii_digit());
        let has_special = new_password.chars().any(|c| !c.is_alphanumeric());
        if !has_upper || !has_lower || !has_digit || !has_special {
            bail!("Password must contain uppercase, lowercase, number, and special character");
        }

        let reset_path = PathBuf::from(&self.data_dir)
            .join("resets")
            .join(format!("{}.json", token));
        let json = tokio::fs::read_to_string(&reset_path)
            .await
            .map_err(|_| anyhow::anyhow!("Invalid or expired reset link"))?;
        let reset: PendingReset = serde_json::from_str(&json)?;

        if reset.expires_at < Utc::now().timestamp() {
            let _ = tokio::fs::remove_file(&reset_path).await;
            bail!("Reset link has expired");
        }

        let user_path = PathBuf::from(&self.data_dir)
            .join("users")
            .join(format!("{}.json", reset.username));
        let user_json = tokio::fs::read_to_string(&user_path).await
            .map_err(|_| anyhow::anyhow!("Account not found"))?;
        let mut user: User = serde_json::from_str(&user_json)?;

        let salt = SaltString::generate(&mut OsRng);
        user.password_hash = Argon2::default()
            .hash_password(new_password.as_bytes(), &salt)
            .map_err(|_| anyhow::anyhow!("Password hashing failed"))?
            .to_string();

        tokio::fs::write(&user_path, serde_json::to_string_pretty(&user)?).await?;
        let _ = tokio::fs::remove_file(&reset_path).await;
        // Purge all existing sessions for this user
        let to_remove: Vec<String> = self.sessions.iter()
            .filter(|s| s.username == reset.username)
            .map(|s| s.key().clone())
            .collect();
        for k in to_remove { self.sessions.remove(&k); }
        Ok(reset.username)
    }

    // ── Email verification ────────────────────────────────────────────────────

    pub async fn verify_email(&self, raw_token: &str) -> Result<String> {
        let token = validate_uuid(raw_token)
            .ok_or_else(|| anyhow::anyhow!("Invalid verification link"))?;

        let pending_path = PathBuf::from(&self.data_dir)
            .join("pending")
            .join(format!("{}.json", token));
        let json = tokio::fs::read_to_string(&pending_path)
            .await
            .map_err(|_| anyhow::anyhow!("Invalid or expired verification link"))?;
        let pending: PendingVerification = serde_json::from_str(&json)?;

        if pending.expires_at < Utc::now().timestamp() {
            let _ = tokio::fs::remove_file(&pending_path).await;
            bail!("Verification link has expired");
        }

        let user_path = PathBuf::from(&self.data_dir)
            .join("users")
            .join(format!("{}.json", pending.username));
        let user_json = tokio::fs::read_to_string(&user_path).await
            .map_err(|_| anyhow::anyhow!("Account not found"))?;
        let mut user: User = serde_json::from_str(&user_json)?;
        user.verified = true;
        tokio::fs::write(&user_path, serde_json::to_string_pretty(&user)?).await?;
        let _ = tokio::fs::remove_file(&pending_path).await;
        Ok(pending.username)
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    pub async fn login(&self, username: &str, password: &str) -> Result<String> {
        let uname = username.trim().to_lowercase();
        self.check_rate_limit(&format!("login:{}", uname))?;

        let user_path = PathBuf::from(&self.data_dir)
            .join("users")
            .join(format!("{}.json", uname));
        let json = tokio::fs::read_to_string(&user_path)
            .await
            .map_err(|_| anyhow::anyhow!("Invalid username or password"))?;
        let user: User = serde_json::from_str(&json)
            .map_err(|_| anyhow::anyhow!("Invalid username or password"))?;

        if !user.verified {
            bail!("Email address not verified — check your inbox");
        }

        let parsed = PasswordHash::new(&user.password_hash)
            .map_err(|_| anyhow::anyhow!("Invalid username or password"))?;
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .map_err(|_| anyhow::anyhow!("Invalid username or password"))?;

        // Evict oldest session if at per-user cap
        let user_sessions: Vec<String> = self.sessions.iter()
            .filter(|s| s.username == uname)
            .map(|s| s.key().clone())
            .collect();
        if user_sessions.len() >= MAX_SESSIONS_PER_USER {
            let oldest = user_sessions.iter()
                .min_by_key(|k| self.sessions.get(*k).map(|s| s.created_at).unwrap_or(i64::MAX))
                .cloned();
            if let Some(k) = oldest { self.sessions.remove(&k); }
        }

        let token = Uuid::new_v4().to_string();
        self.sessions.insert(token.clone(), Session {
            username: uname, created_at: Utc::now().timestamp(),
            last_used: Utc::now().timestamp(),
        });
        Ok(token)
    }

    // ── Session management ────────────────────────────────────────────────────

    pub fn validate_session(&self, raw_token: &str) -> Option<String> {
        let token = validate_uuid(raw_token)?;
        let now   = Utc::now().timestamp();
        let mut entry = self.sessions.get_mut(&token)?;
        if now - entry.created_at > SESSION_MAX_AGE_SECS {
            drop(entry);
            self.sessions.remove(&token);
            return None;
        }
        entry.last_used = now;
        Some(entry.username.clone())
    }

    pub fn logout(&self, raw_token: &str) {
        if let Some(token) = validate_uuid(raw_token) {
            self.sessions.remove(&token);
        }
    }

    /// List all sessions for a user (returns token_prefix, created_at, last_used)
    pub fn list_sessions(&self, username: &str) -> Vec<(String, i64, i64)> {
        let uname = username.trim().to_lowercase();
        self.sessions.iter()
            .filter(|s| s.username == uname)
            .map(|s| {
                let prefix = format!("{}…{}", &s.key()[..4], &s.key()[s.key().len()-4..]);
                (prefix, s.created_at, s.last_used)
            })
            .collect()
    }

    /// Revoke a session by token prefix (first4…last4)
    pub fn revoke_session_by_prefix(&self, username: &str, prefix: &str) {
        let uname = username.trim().to_lowercase();
        let to_remove: Vec<String> = self.sessions.iter()
            .filter(|s| {
                s.username == uname && {
                    let k = s.key();
                    let p = format!("{}…{}", &k[..4], &k[k.len()-4..]);
                    p == prefix
                }
            })
            .map(|s| s.key().clone())
            .collect();
        for k in to_remove { self.sessions.remove(&k); }
    }

    /// Delete a user account: remove user file, sessions, and user data directory.
    pub async fn delete_account(&self, username: &str) {
        let uname = username.trim().to_lowercase();
        // Remove user JSON
        let user_file = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", uname));
        let _ = tokio::fs::remove_file(&user_file).await;
        // Remove user data directory (appearance, etc.)
        let user_dir = PathBuf::from(&self.data_dir).join("users").join(&uname);
        let _ = tokio::fs::remove_dir_all(&user_dir).await;
        // Remove networks directory
        let net_dir = PathBuf::from(&self.data_dir).join("networks").join(&uname);
        let _ = tokio::fs::remove_dir_all(&net_dir).await;
        // Remove logs directory
        let log_dir = PathBuf::from(&self.data_dir).join("logs").join(&uname);
        let _ = tokio::fs::remove_dir_all(&log_dir).await;
        // Remove E2E data
        let e2e_dir = PathBuf::from(&self.data_dir).join("e2e").join(&uname);
        let _ = tokio::fs::remove_dir_all(&e2e_dir).await;
        // Purge all sessions for this user
        let to_remove: Vec<String> = self.sessions.iter()
            .filter(|s| s.username == uname)
            .map(|s| s.key().clone())
            .collect();
        for k in to_remove { self.sessions.remove(&k); }
    }

    pub fn purge_expired_sessions(&self) {
        let now = Utc::now().timestamp();
        let expired: Vec<String> = self.sessions.iter()
            .filter(|s| now - s.created_at > SESSION_MAX_AGE_SECS)
            .map(|s| s.key().clone())
            .collect();
        for k in expired { self.sessions.remove(&k); }
        self.sweep_rate_buckets();
    }

    // ── Admin helpers ─────────────────────────────────────────────────────────

    pub async fn is_admin(&self, username: &str) -> bool {
        let path = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", username.to_lowercase()));
        if let Ok(json) = tokio::fs::read_to_string(&path).await {
            if let Ok(user) = serde_json::from_str::<User>(&json) {
                return user.admin;
            }
        }
        false
    }

    pub async fn list_users(&self) -> Vec<serde_json::Value> {
        let dir = PathBuf::from(&self.data_dir).join("users");
        let mut users = vec![];
        if let Ok(mut rd) = tokio::fs::read_dir(&dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    if let Ok(json) = tokio::fs::read_to_string(&path).await {
                        if let Ok(user) = serde_json::from_str::<User>(&json) {
                            // Count active sessions
                            let session_count = self.sessions.iter()
                                .filter(|s| s.username == user.username)
                                .count();
                            users.push(serde_json::json!({
                                "username": user.username,
                                "email": user.email,
                                "verified": user.verified,
                                "admin": user.admin,
                                "created_at": user.created_at,
                                "sessions": session_count,
                            }));
                        }
                    }
                }
            }
        }
        users
    }

    pub async fn set_admin(&self, username: &str, is_admin: bool) -> Result<()> {
        let path = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", username.to_lowercase()));
        let json = tokio::fs::read_to_string(&path).await?;
        let mut user: User = serde_json::from_str(&json)?;
        user.admin = is_admin;
        tokio::fs::write(&path, serde_json::to_string_pretty(&user)?).await?;
        Ok(())
    }

    pub async fn disable_user(&self, username: &str) -> Result<()> {
        let path = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", username.to_lowercase()));
        let json = tokio::fs::read_to_string(&path).await?;
        let mut user: User = serde_json::from_str(&json)?;
        user.verified = false; // Disabling = unverify, can't log in
        tokio::fs::write(&path, serde_json::to_string_pretty(&user)?).await?;
        // Purge their sessions
        let to_remove: Vec<String> = self.sessions.iter()
            .filter(|s| s.username == username.to_lowercase())
            .map(|s| s.key().clone()).collect();
        for k in to_remove { self.sessions.remove(&k); }
        Ok(())
    }
}

/// Validate that a string is a canonical UUID.
/// Returns Some(lowercase_uuid) if valid, None otherwise.
pub fn validate_uuid(s: &str) -> Option<String> {
    if s.len() != 36 { return None; }
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 { return None; }
    let expected_lens = [8usize, 4, 4, 4, 12];
    for (part, &len) in parts.iter().zip(expected_lens.iter()) {
        if part.len() != len { return None; }
        if !part.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
    }
    Some(s.to_lowercase())
}
