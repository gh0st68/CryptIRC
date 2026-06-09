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
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

const SESSION_MAX_AGE_SECS:    i64   = 60 * 60 * 24 * 30; // 30 days
/// #61: idle/inactivity timeout. A session unused for this long is rejected and
/// removed, in addition to the absolute age cap, so a leaked-then-idle token
/// cannot be used for the full 30-day window.
const SESSION_IDLE_MAX_SECS:   i64   = 60 * 60 * 24 * 14; // 14 days
const MAX_SESSIONS_PER_USER:   usize = 10;
const RATE_LIMIT_WINDOW_SECS:  u64   = 60;
const RATE_LIMIT_MAX_ATTEMPTS: u32   = 10;
/// S5: hard cap on total rate-limit buckets to prevent unbounded DashMap growth
const RATE_LIMIT_MAX_BUCKETS:  usize = 4096;

/// #56: A valid Argon2 hash (over a random throwaway password) used to equalize
/// login timing for nonexistent / unverified accounts. Computed once with the
/// crate's own default params so verify_password does equivalent work whether
/// or not the account exists. Lazily initialized to guarantee a parseable PHC
/// string with matching parameters.
fn dummy_argon2_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(b"cryptirc-login-timing-equalizer", &salt)
            .map(|h| h.to_string())
            // Fallback should never happen; if it does, an unparseable string makes
            // verify fail closed (login is rejected) which is the safe direction.
            .unwrap_or_else(|_| String::new())
    }).as_str()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username:      String,
    pub email:         String,
    pub password_hash: String,
    pub verified:      bool,
    pub created_at:    i64,
    #[serde(default)]
    pub admin:         bool,
    /// Whether the user is allowed to upload files. Off by default — admin must grant it.
    #[serde(default)]
    pub can_upload:    bool,
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
    /// #22/#63: per-username async mutex serializing read-modify-write of the
    /// user's JSON record and the login session-cap eviction, so concurrent
    /// mutators (admin toggles, password change, verify, reset, login) cannot
    /// clobber each other (lost update) or race past MAX_SESSIONS_PER_USER.
    user_locks:   Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl AuthManager {
    pub fn new(data_dir: &str) -> Result<Self> {
        std::fs::create_dir_all(format!("{}/users",   data_dir))?;
        std::fs::create_dir_all(format!("{}/pending", data_dir))?;
        Ok(Self {
            data_dir:    data_dir.to_string(),
            sessions:    Arc::new(DashMap::new()),
            rate_limits: Arc::new(DashMap::new()),
            user_locks:  Arc::new(DashMap::new()),
        })
    }

    /// #22: get (creating if needed) the per-username serialization lock.
    fn user_lock(&self, uname: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.user_locks
            .entry(uname.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// #22: atomically write a user record via temp-file + rename so a crash mid-write
    /// cannot truncate the JSON. Callers must hold the per-user lock around
    /// the read→mutate→write to avoid lost updates.
    async fn write_user_atomic(&self, uname: &str, user: &User) -> Result<()> {
        let dir = PathBuf::from(&self.data_dir).join("users");
        let final_path = dir.join(format!("{}.json", uname));
        let tmp_path   = dir.join(format!("{}.json.tmp.{}", uname, Uuid::new_v4()));
        let json = serde_json::to_string_pretty(user)?;
        tokio::fs::write(&tmp_path, json.as_bytes()).await?;
        // rename is atomic on the same filesystem
        if let Err(e) = tokio::fs::rename(&tmp_path, &final_path).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e.into());
        }
        Ok(())
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

    /// #15: IP-dimension rate limit. The route handlers extract the real client IP
    /// from the X-Real-IP / X-Forwarded-For header nginx forwards and pass it here.
    /// This adds a per-IP bucket on top of the per-identifier bucket so that
    /// credential-stuffing / password-spraying that varies the username (and thus
    /// dodges the per-username bucket) is still throttled by source IP.
    ///
    /// `ip` is `None` when the caller could not determine a client IP (e.g. a
    /// direct-to-:9001 request that bypassed nginx); in that case we fall back to
    /// a single shared "noip" bucket so the limiter still applies globally.
    fn check_ip_rate_limit(&self, action: &str, ip: Option<&str>) -> Result<()> {
        let ip = ip.unwrap_or("noip");
        // Bound the key length (char-safe — never byte-slices across a multibyte
        // boundary) to avoid an attacker stuffing the bucket table with huge header
        // values; an IP is short, so 64 chars is generous.
        let ip: String = ip.chars().take(64).collect();
        self.check_rate_limit(&format!("ip:{}:{}", action, ip))
    }

    /// #13: WS-path rate limit for vault unlock / passphrase change. These trigger a
    /// 64-MiB Argon2id KDF, so an authenticated user spamming them over a WebSocket
    /// can exhaust CPU/RAM. Throttle per-username on the WS path the same way the
    /// HTTP auth routes are throttled. Public because it is called from main.rs.
    pub fn check_ws_kdf_rate_limit(&self, username: &str, action: &str) -> Result<()> {
        let uname = username.trim().to_lowercase();
        self.check_rate_limit(&format!("ws_kdf:{}:{}", action, uname))
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

    pub async fn register(&self, username: &str, email: &str, password: &str, ip: Option<&str>) -> Result<String> {
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

        let email_lower = email.to_lowercase();
        self.check_rate_limit(&format!("reg:{}", uname))?;
        // #14: rate-limit per email too, so varying the username with one victim
        // email cannot mint a fresh bucket on every request (mail-bomb defense).
        self.check_rate_limit(&format!("regemail:{}", email_lower))?;
        // #15: add an IP dimension so distributed username-varying registration
        // (which dodges the per-username bucket) is still throttled by source IP.
        self.check_ip_rate_limit("reg", ip)?;

        // #14: reject registration when an account with this email already exists
        // (verified or pending). Prevents binding many usernames to a victim's
        // email to mail-bomb them and litter the data dir.
        if self.email_in_use(&email_lower).await {
            // Generic message — do not confirm the email is registered (anti-enumeration).
            bail!("Username already taken");
        }

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
            email:         email_lower.clone(),
            password_hash: hash,
            verified:      false,
            created_at:    Utc::now().timestamp(),
            admin:         false,
            can_upload:    false,
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
            username: uname, email: email_lower,
            token: token.clone(), expires_at: Utc::now().timestamp() + 86400,
        };
        let pending_path = PathBuf::from(&self.data_dir)
            .join("pending")
            .join(format!("{}.json", token));
        tokio::fs::write(pending_path, serde_json::to_string_pretty(&pending)?).await?;
        Ok(token)
    }

    /// #14: Returns true if any user account OR pending verification already uses
    /// this (lowercased) email. Used to block multiple accounts per email.
    async fn email_in_use(&self, email_lower: &str) -> bool {
        // Scan verified/created user records.
        let users_dir = PathBuf::from(&self.data_dir).join("users");
        if let Ok(mut entries) = tokio::fs::read_dir(&users_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    if let Ok(json) = tokio::fs::read_to_string(&path).await {
                        if let Ok(user) = serde_json::from_str::<User>(&json) {
                            if user.email == email_lower { return true; }
                        }
                    }
                }
            }
        }
        // Scan in-flight (unverified) pending registrations so the bomb can't be
        // staged before any account is verified.
        let pending_dir = PathBuf::from(&self.data_dir).join("pending");
        if let Ok(mut entries) = tokio::fs::read_dir(&pending_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(json) = tokio::fs::read_to_string(entry.path()).await {
                    if let Ok(p) = serde_json::from_str::<PendingVerification>(&json) {
                        if p.email == email_lower && p.expires_at >= Utc::now().timestamp() {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    // ── Password reset ────────────────────────────────────────────────────────

    pub async fn request_password_reset(&self, email_addr: &str, ip: Option<&str>) -> Result<Option<(String, String)>> {
        let email_lower = email_addr.trim().to_lowercase();
        self.check_rate_limit(&format!("reset:{}", email_lower))?;
        // #15/#80: IP dimension so varying the email (which dodges the per-email
        // bucket) cannot force an unbounded full users/ directory scan per request.
        self.check_ip_rate_limit("reset", ip)?;

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

    pub async fn reset_password(&self, raw_token: &str, new_password: &str, ip: Option<&str>) -> Result<String> {
        // #15/#64: per-IP throttle on token consumption (defense-in-depth — tokens
        // are 122-bit UUIDs, but this caps cheap unlimited invalid attempts).
        self.check_ip_rate_limit("reset_consume", ip)?;
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

        // #22: serialize the read→mutate→write under the per-user lock.
        let lock = self.user_lock(&reset.username);
        let _guard = lock.lock().await;
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

        self.write_user_atomic(&reset.username, &user).await?;
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

    pub async fn verify_email(&self, raw_token: &str, ip: Option<&str>) -> Result<String> {
        // #15/#64: per-IP throttle on verify-token consumption (defense-in-depth).
        self.check_ip_rate_limit("verify_consume", ip)?;
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

        // #22: serialize the read→mutate→write under the per-user lock so a
        // concurrent reset_password cannot clobber the verified flag (or vice-versa).
        let lock = self.user_lock(&pending.username);
        let _guard = lock.lock().await;
        let user_path = PathBuf::from(&self.data_dir)
            .join("users")
            .join(format!("{}.json", pending.username));
        let user_json = tokio::fs::read_to_string(&user_path).await
            .map_err(|_| anyhow::anyhow!("Account not found"))?;
        let mut user: User = serde_json::from_str(&user_json)?;
        user.verified = true;
        self.write_user_atomic(&pending.username, &user).await?;
        let _ = tokio::fs::remove_file(&pending_path).await;
        Ok(pending.username)
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    pub async fn login(&self, username: &str, password: &str, ip: Option<&str>) -> Result<String> {
        let uname = username.trim().to_lowercase();
        self.check_rate_limit(&format!("login:{}", uname))?;
        // #15: IP dimension so credential-stuffing across many usernames from one
        // IP (which gets a fresh per-username bucket each time) is still throttled.
        self.check_ip_rate_limit("login", ip)?;

        let user_path = PathBuf::from(&self.data_dir)
            .join("users")
            .join(format!("{}.json", uname));
        // #56: read the user, but DON'T early-return on missing/unverified before
        // running Argon2 — that created a message+timing enumeration oracle. We
        // always do equivalent CPU work and return ONE generic message.
        let user_opt: Option<User> = tokio::fs::read_to_string(&user_path).await
            .ok()
            .and_then(|json| serde_json::from_str::<User>(&json).ok());

        // Verify against the real hash if present and verified, otherwise verify
        // against a fixed dummy Argon2 hash so the Argon2 cost is always paid.
        let hash_str = match &user_opt {
            Some(u) if u.verified => u.password_hash.clone(),
            _ => dummy_argon2_hash().to_string(),
        };
        let verify_ok = PasswordHash::new(&hash_str)
            .ok()
            .map(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
            .unwrap_or(false);

        // #56: single generic error for nonexistent / unverified / wrong-password.
        if user_opt.as_ref().map(|u| u.verified).unwrap_or(false) && verify_ok {
            // fall through to issue a session
        } else {
            bail!("Invalid username or password");
        }

        // #63: serialize the session-cap eviction + insert under the per-user lock
        // so concurrent logins for the same user cannot both snapshot the same
        // count, evict the same "oldest", and both insert past the cap.
        let lock = self.user_lock(&uname);
        let _guard = lock.lock().await;
        // Evict oldest sessions while at/over the per-user cap (loop, not single-shot)
        loop {
            let user_sessions: Vec<String> = self.sessions.iter()
                .filter(|s| s.username == uname)
                .map(|s| s.key().clone())
                .collect();
            if user_sessions.len() < MAX_SESSIONS_PER_USER { break; }
            let oldest = user_sessions.iter()
                .min_by_key(|k| self.sessions.get(*k).map(|s| s.created_at).unwrap_or(i64::MAX))
                .cloned();
            match oldest {
                Some(k) => { self.sessions.remove(&k); }
                None    => break,
            }
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
        // #61: reject on absolute age OR inactivity.
        if now - entry.created_at > SESSION_MAX_AGE_SECS
            || now - entry.last_used > SESSION_IDLE_MAX_SECS {
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
        // #58: reject anything that isn't a legitimate username before joining it
        // into remove_dir_all paths. Registration restricts usernames to
        // [A-Za-z0-9_-]{3,32}; a value like ".." (reachable via %2E%2E in the admin
        // route) would otherwise make remove_dir_all wipe the entire data dir.
        if !is_safe_username(&uname) {
            return;
        }
        // #6: enumerate the user's network config ids (filenames under
        // networks/<username>/) and delete the REAL per-conn_id logs dirs at
        // logs/<conn_id>/. The old code deleted logs/<username>, which never
        // existed, so encrypted message history survived account deletion.
        let net_dir = PathBuf::from(&self.data_dir).join("networks").join(&uname);
        if let Ok(mut rd) = tokio::fs::read_dir(&net_dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    if let Some(conn_id) = path.file_stem().and_then(|s| s.to_str()) {
                        // conn_id is a network UUID; validate before pathing.
                        if let Some(safe_id) = validate_uuid(conn_id) {
                            let log_dir = PathBuf::from(&self.data_dir).join("logs").join(&safe_id);
                            let _ = tokio::fs::remove_dir_all(&log_dir).await;
                        }
                    }
                }
            }
        }
        // #6: remove the per-user log sequence counter (logs/.seq_<username>).
        let seq_file = PathBuf::from(&self.data_dir).join("logs").join(format!(".seq_{}", uname));
        let _ = tokio::fs::remove_file(&seq_file).await;

        // Remove user JSON
        let user_file = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", uname));
        let _ = tokio::fs::remove_file(&user_file).await;
        // Remove user data directory (appearance, etc.)
        let user_dir = PathBuf::from(&self.data_dir).join("users").join(&uname);
        let _ = tokio::fs::remove_dir_all(&user_dir).await;
        // Remove networks directory
        let _ = tokio::fs::remove_dir_all(&net_dir).await;
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
        // #61: purge on absolute age OR inactivity.
        let expired: Vec<String> = self.sessions.iter()
            .filter(|s| now - s.created_at > SESSION_MAX_AGE_SECS
                     || now - s.last_used > SESSION_IDLE_MAX_SECS)
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

    /// Returns true if the user is allowed to upload files. Admins can always upload.
    pub async fn can_upload(&self, username: &str) -> bool {
        let path = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", username.to_lowercase()));
        if let Ok(json) = tokio::fs::read_to_string(&path).await {
            if let Ok(user) = serde_json::from_str::<User>(&json) {
                return user.admin || user.can_upload;
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
                                "can_upload": user.can_upload,
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
        let uname = username.to_lowercase();
        // #22: serialize read→mutate→write under the per-user lock + atomic write.
        let lock = self.user_lock(&uname);
        let _guard = lock.lock().await;
        let path = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", uname));
        let json = tokio::fs::read_to_string(&path).await?;
        let mut user: User = serde_json::from_str(&json)?;
        user.admin = is_admin;
        self.write_user_atomic(&uname, &user).await?;
        Ok(())
    }

    pub async fn set_can_upload(&self, username: &str, can_upload: bool) -> Result<()> {
        let uname = username.to_lowercase();
        // #22: serialize read→mutate→write under the per-user lock + atomic write.
        let lock = self.user_lock(&uname);
        let _guard = lock.lock().await;
        let path = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", uname));
        let json = tokio::fs::read_to_string(&path).await?;
        let mut user: User = serde_json::from_str(&json)?;
        user.can_upload = can_upload;
        self.write_user_atomic(&uname, &user).await?;
        Ok(())
    }

    pub async fn change_password(&self, username: &str, old_password: &str, new_password: &str, ip: Option<&str>) -> Result<()> {
        let uname = username.trim().to_lowercase();
        self.check_rate_limit(&format!("chpass:{}", uname))?;
        // #15: IP dimension.
        self.check_ip_rate_limit("chpass", ip)?;

        // #22: serialize the entire verify→mutate→write under the per-user lock.
        let lock = self.user_lock(&uname);
        let _guard = lock.lock().await;

        // Verify old password
        let user_path = PathBuf::from(&self.data_dir)
            .join("users")
            .join(format!("{}.json", uname));
        let json = tokio::fs::read_to_string(&user_path)
            .await
            .map_err(|_| anyhow::anyhow!("Account not found"))?;
        let mut user: User = serde_json::from_str(&json)?;

        let parsed = PasswordHash::new(&user.password_hash)
            .map_err(|_| anyhow::anyhow!("Invalid password hash"))?;
        Argon2::default()
            .verify_password(old_password.as_bytes(), &parsed)
            .map_err(|_| anyhow::anyhow!("Current password is incorrect"))?;

        // Validate new password
        if new_password.len() < 10 {
            bail!("New password must be at least 10 characters");
        }
        let has_upper = new_password.chars().any(|c| c.is_uppercase());
        let has_lower = new_password.chars().any(|c| c.is_lowercase());
        let has_digit = new_password.chars().any(|c| c.is_ascii_digit());
        let has_special = new_password.chars().any(|c| !c.is_alphanumeric());
        if !has_upper || !has_lower || !has_digit || !has_special {
            bail!("New password must contain uppercase, lowercase, number, and special character");
        }

        // Hash new password
        let salt = SaltString::generate(&mut OsRng);
        user.password_hash = Argon2::default()
            .hash_password(new_password.as_bytes(), &salt)
            .map_err(|_| anyhow::anyhow!("Password hashing failed"))?
            .to_string();

        self.write_user_atomic(&uname, &user).await?;
        // #62: invalidate ALL of this user's sessions after a password change so an
        // attacker who already holds a session token is logged out (mirrors
        // reset_password). The route layer can re-issue a session for the caller.
        let to_remove: Vec<String> = self.sessions.iter()
            .filter(|s| s.username == uname)
            .map(|s| s.key().clone())
            .collect();
        for k in to_remove { self.sessions.remove(&k); }
        Ok(())
    }

    pub async fn disable_user(&self, username: &str) -> Result<()> {
        let uname = username.to_lowercase();
        // #58: reject path-unsafe usernames before touching the filesystem.
        if !is_safe_username(&uname) {
            bail!("Invalid username");
        }
        // #22: serialize read→mutate→write under the per-user lock + atomic write.
        let lock = self.user_lock(&uname);
        let _guard = lock.lock().await;
        let path = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", uname));
        let json = tokio::fs::read_to_string(&path).await?;
        let mut user: User = serde_json::from_str(&json)?;
        user.verified = false; // Disabling = unverify, can't log in
        self.write_user_atomic(&uname, &user).await?;
        // Purge their sessions
        let to_remove: Vec<String> = self.sessions.iter()
            .filter(|s| s.username == uname)
            .map(|s| s.key().clone()).collect();
        for k in to_remove { self.sessions.remove(&k); }
        Ok(())
    }
}

/// #58: Validate a username for safe filesystem-path use. Matches the same charset
/// and length registration enforces ([A-Za-z0-9_-], 3–32) and explicitly rejects
/// '.', '..', and empty. Used before any path join in delete_account / disable_user.
pub fn is_safe_username(s: &str) -> bool {
    if s.len() < 3 || s.len() > 32 { return false; }
    if s == "." || s == ".." { return false; }
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
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
