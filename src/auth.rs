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
/// After this many failed logins from one IP within LOGIN_FAIL_WINDOW_SECS, the login
/// route requires a captcha until a successful login resets the counter.
const LOGIN_FAIL_CAPTCHA_THRESHOLD: u32 = 3;
const LOGIN_FAIL_WINDOW_SECS:       u64 = 900; // 15-minute sliding window

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
    /// Unix time of the most recent successful login (0 = never). Updated by login().
    #[serde(default)]
    pub last_login:    i64,
    /// Last.fm username for the /np now-playing command (empty = not linked).
    #[serde(default)]
    pub lastfm_user:   String,
    /// Optional per-user Last.fm API key; overrides the server's shared key.
    #[serde(default)]
    pub lastfm_key:    String,
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

/// Result of register(): tells the caller whether to send a verification email.
pub struct RegisterOutcome {
    /// Some(token) → caller should email a verification link to the address.
    /// None → the account is already active (auto-verified; no email step needed).
    pub verify_token: Option<String>,
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
    /// Per-email async mutex serializing register()'s email-uniqueness check→create, so
    /// concurrent same-email/different-username registrations can't all pass email_in_use()
    /// before any writes its pending record (#14 one-account-per-email TOCTOU).
    email_locks:  Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Failed-login counter per client IP (in-memory; value = (count, window_start)). After
    /// LOGIN_FAIL_CAPTCHA_THRESHOLD failures within the window, login requires a captcha
    /// until a success resets it. Self-bounded by the window + a size cap (no persistence).
    login_fails:  Arc<DashMap<String, (u32, Instant)>>,
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
            email_locks: Arc::new(DashMap::new()),
            login_fails: Arc::new(DashMap::new()),
        })
    }

    /// #22: get (creating if needed) the per-username serialization lock.
    fn user_lock(&self, uname: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.user_locks
            .entry(uname.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Per-email serialization lock for register()'s check→create window.
    fn email_lock(&self, email_lower: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.email_locks
            .entry(email_lower.to_string())
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
    pub fn check_ip_rate_limit(&self, action: &str, ip: Option<&str>) -> Result<()> {
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

    /// Per-user sliding-window limit for authenticated resource-creation routes
    /// (paste / short-link). Each created object writes a file to disk, so an
    /// unthrottled authenticated client can exhaust disk. Reuses the same bucket
    /// machinery as the auth limiter, keyed on username + action. The shared
    /// RATE_LIMIT_MAX_ATTEMPTS budget (10/60s) is generous for normal use while
    /// stopping a creation flood. Public because it is called from main.rs.
    pub fn check_user_create_rate_limit(&self, username: &str, action: &str) -> Result<()> {
        let uname = username.trim().to_lowercase();
        self.check_rate_limit(&format!("create:{}:{}", action, uname))
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

    /// True if (this IP, this login identifier) has failed enough times recently that the
    /// next attempt must include a valid captcha. Keyed per (IP, account) so a success on a
    /// DIFFERENT account from the same IP can't lift the gate raised against this one.
    pub fn login_captcha_required(&self, ip: Option<&str>, identifier: &str) -> bool {
        if let Some(e) = self.login_fails.get(&Self::login_fail_key(ip, identifier)) {
            let (count, start) = *e;
            return count >= LOGIN_FAIL_CAPTCHA_THRESHOLD
                && start.elapsed() <= Duration::from_secs(LOGIN_FAIL_WINDOW_SECS);
        }
        false
    }

    /// Record a failed login for (this IP, identifier). Sliding window — the start slides to
    /// the most recent failure, so a sustained attack keeps the gate up; self-bounded under
    /// a flood.
    pub fn record_login_fail(&self, ip: Option<&str>, identifier: &str) {
        let now = Instant::now();
        // Safety cap: under a distributed flood, drop expired entries before growing.
        if self.login_fails.len() > 8192 {
            self.login_fails.retain(|_, v| v.1.elapsed() <= Duration::from_secs(LOGIN_FAIL_WINDOW_SECS));
        }
        let mut e = self.login_fails.entry(Self::login_fail_key(ip, identifier)).or_insert((0, now));
        if e.1.elapsed() > Duration::from_secs(LOGIN_FAIL_WINDOW_SECS) { e.0 = 0; }
        e.1 = now;                       // slide the window to the most recent failure
        e.0 = e.0.saturating_add(1);
    }

    /// Clear the failed-login counter for (this IP, identifier) on a successful login.
    pub fn reset_login_fails(&self, ip: Option<&str>, identifier: &str) {
        self.login_fails.remove(&Self::login_fail_key(ip, identifier));
    }

    /// Composite (capped) key for the per-(IP, account) login-fail counter.
    fn login_fail_key(ip: Option<&str>, identifier: &str) -> String {
        let ip: String = ip.unwrap_or("noip").chars().take(64).collect();
        let id: String = identifier.trim().to_lowercase().chars().take(64).collect();
        format!("{}|{}", ip, id)
    }

    // ── Registration ──────────────────────────────────────────────────────────

    pub async fn register(&self, username: &str, email: &str, password: &str, ip: Option<&str>, email_required: bool) -> Result<RegisterOutcome> {
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
        // Email is OPTIONAL unless the admin requires it. A blank email means "no email on
        // file": the account is auto-verified and simply can't do password resets until the
        // user (or an admin) adds one later.
        let email_lower = email.trim().to_lowercase();
        let has_email = !email_lower.is_empty();
        if !has_email && email_required {
            bail!("Email is required to sign up");
        }
        if has_email && (!email_lower.contains('@') || email_lower.len() > 254) {
            bail!("Invalid email address");
        }
        // #15: IP dimension FIRST (before the per-key inserts below) so an over-budget IP
        // bails before minting a fresh reg:<rand>/regemail:<rand> bucket — otherwise one IP
        // can fill the global bucket table and lock out all auth. See login() for detail.
        self.check_ip_rate_limit("reg", ip)?;
        self.check_rate_limit(&format!("reg:{}", uname))?;
        // #14: rate-limit per email too, so varying the username with one victim
        // email cannot mint a fresh bucket on every request (mail-bomb defense).
        if has_email {
            self.check_rate_limit(&format!("regemail:{}", email_lower))?;
        }

        // Compute the Argon2 hash BEFORE the email-existence check so the dominant
        // timing component (the ~tens-of-ms KDF) is paid on BOTH the email-in-use and
        // the success branch. Otherwise the email_in_use bail returns measurably faster
        // than a real registration, turning the deliberately-generic "Username already
        // taken" message into an email-enumeration timing oracle. Mirrors the #56
        // dummy-hash mitigation on the login path.
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| anyhow::anyhow!("Password hashing failed"))?
            .to_string();

        // The account is auto-verified unless the admin requires email verification.
        let verified = !email_required;
        let user_path = PathBuf::from(&self.data_dir)
            .join("users")
            .join(format!("{}.json", uname));
        let user = User {
            username:      uname.clone(),
            email:         email_lower.clone(),
            password_hash: hash,
            verified,
            created_at:    Utc::now().timestamp(),
            admin:         false,
            can_upload:    false,
            last_login:    0,
            lastfm_user:   String::new(),
            lastfm_key:    String::new(),
        };
        let json = serde_json::to_string_pretty(&user)?;

        if has_email {
            // Serialize the email check→create window per email (held through the create_new +
            // pending write below). Without it, concurrent same-email/different-username
            // registrations could all pass email_in_use() before any wrote its record (#14
            // TOCTOU). Acquired AFTER the KDF so hashing is never serialized; register holds
            // no user_lock, so no deadlock.
            let _elock = self.email_lock(&email_lower);
            let _eguard = _elock.lock().await;
            // #14: reject when an account with this email already exists (verified or pending).
            if self.email_in_use(&email_lower).await {
                // Generic message — do not confirm the email is registered (anti-enumeration).
                bail!("Username already taken");
            }
            // S1: atomic create + write-through (create_new fails if the file exists; no TOCTOU).
            {
                let mut file = tokio::fs::OpenOptions::new()
                    .write(true).create_new(true).open(&user_path).await
                    .map_err(|_| anyhow::anyhow!("Username already taken"))?;
                file.write_all(json.as_bytes()).await?;
                file.flush().await?;
            }
            if verified {
                // Email provided but verification not required → active immediately; the
                // address is just stored for password resets. No verification email.
                Ok(RegisterOutcome { verify_token: None })
            } else {
                // Email verification required → stage the pending record + token to email.
                let token = Uuid::new_v4().to_string();
                let pending = PendingVerification {
                    username: uname, email: email_lower,
                    token: token.clone(), expires_at: Utc::now().timestamp() + 86400,
                };
                let pending_path = PathBuf::from(&self.data_dir)
                    .join("pending").join(format!("{}.json", token));
                tokio::fs::write(pending_path, serde_json::to_string_pretty(&pending)?).await?;
                Ok(RegisterOutcome { verify_token: Some(token) })
            }
        } else {
            // No email on file: username uniqueness is enforced solely by create_new (atomic),
            // and the account is auto-verified (email_required is false here). No email_lock.
            {
                let mut file = tokio::fs::OpenOptions::new()
                    .write(true).create_new(true).open(&user_path).await
                    .map_err(|_| anyhow::anyhow!("Username already taken"))?;
                file.write_all(json.as_bytes()).await?;
                file.flush().await?;
            }
            Ok(RegisterOutcome { verify_token: None })
        }
    }

    /// #14: Returns true if any user account OR pending verification already uses
    /// this (lowercased) email. Used to block multiple accounts per email.
    /// Resolve a (lowercased) email to its owning User so login() can accept the email
    /// in place of the username. Mirrors email_in_use's scan; at most one match exists
    /// (register enforces one account per email). Returns the first verified-or-not match;
    /// login() then applies the same verified+password checks it does for username login.
    async fn find_user_by_email(&self, email_lower: &str) -> Option<User> {
        // Never resolve a blank email (no-email accounts aren't reachable by email login).
        if email_lower.is_empty() { return None; }
        let users_dir = PathBuf::from(&self.data_dir).join("users");
        if let Ok(mut entries) = tokio::fs::read_dir(&users_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    if let Ok(json) = tokio::fs::read_to_string(&path).await {
                        if let Ok(user) = serde_json::from_str::<User>(&json) {
                            if user.email == email_lower { return Some(user); }
                        }
                    }
                }
            }
        }
        None
    }

    async fn email_in_use(&self, email_lower: &str) -> bool {
        // A blank email is never "in use" — no-email accounts must not collide (an empty
        // match would otherwise block every other no-email signup).
        if email_lower.is_empty() { return false; }
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
        // Scan in-flight (unverified) pending registrations so an email-bomb can't be
        // staged before any account is verified. Skip ORPHANED records: a pending whose
        // username no longer has a user file is a leftover from a deletion (register() always
        // writes the user file alongside the pending record, so a live signup has BOTH).
        // Counting an orphan would wrongly block re-registering a deleted user's email until
        // the 24h expiry; a real email-bomb's pending records all still have their user files,
        // so ignoring file-less orphans does not weaken the bomb guard.
        let pending_dir = PathBuf::from(&self.data_dir).join("pending");
        if let Ok(mut entries) = tokio::fs::read_dir(&pending_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(json) = tokio::fs::read_to_string(entry.path()).await {
                    if let Ok(p) = serde_json::from_str::<PendingVerification>(&json) {
                        if p.email == email_lower && p.expires_at >= Utc::now().timestamp() {
                            // Only block if the named account still LIVES with this email. A
                            // pending whose user file is gone (deleted) — or now holds a
                            // different email (deleted + re-registered with another address) —
                            // is stale and must not block this email. Fail closed: a read or
                            // parse error counts as in-use so an IO glitch can't open the guard.
                            let user_file = PathBuf::from(&self.data_dir)
                                .join("users").join(format!("{}.json", p.username));
                            match tokio::fs::read_to_string(&user_file).await {
                                Ok(j) => match serde_json::from_str::<User>(&j) {
                                    Ok(u) => { if u.email == email_lower { return true; } }
                                    Err(_) => return true, // unparseable user file → fail closed
                                },
                                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // orphan → skip
                                Err(_) => return true, // unexpected IO error → fail closed
                            }
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
        // #15/#80: IP dimension FIRST (before the per-email bucket insert) so varying the
        // email cannot force an unbounded users/ scan AND cannot fill the global bucket
        // table from one IP. See login() for the ordering rationale.
        self.check_ip_rate_limit("reset", ip)?;
        self.check_rate_limit(&format!("reset:{}", email_lower))?;

        // No-email accounts are unreachable; never mint a reset for a blank address (mirrors
        // find_user_by_email / email_in_use, which also treat blank email as "not present").
        if email_lower.is_empty() { return Ok(None); }

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

    /// Authenticate by EITHER username OR account email. Returns (session token,
    /// resolved account username) so callers always get the real username even when
    /// the user signed in with their email.
    pub async fn login(&self, identifier: &str, password: &str, ip: Option<&str>) -> Result<(String, String)> {
        let ident = identifier.trim().to_lowercase();
        // #15: IP dimension FIRST so credential-stuffing across many usernames from one
        // IP is throttled. Order matters: check_rate_limit INSERTS a per-key bucket before
        // it can reject, so the per-IP check must run BEFORE the per-username one —
        // otherwise an over-budget IP still mints a fresh login:<rand> bucket per request
        // and can fill the global RATE_LIMIT_MAX_BUCKETS table, locking out all auth.
        self.check_ip_rate_limit("login", ip)?;

        // Resolve the identifier to a User. Usernames can never contain '@' (register
        // restricts to [A-Za-z0-9_-]); an email always does — so '@' cleanly selects the
        // lookup, and email_in_use() guarantees at most one account per email.
        // #56: read the user, but DON'T early-return on missing/unverified before
        // running Argon2 — that created a message+timing enumeration oracle. We
        // always do equivalent CPU work and return ONE generic message.
        let user_opt: Option<User> = if ident.contains('@') {
            self.find_user_by_email(&ident).await
        } else {
            let user_path = PathBuf::from(&self.data_dir)
                .join("users")
                .join(format!("{}.json", ident));
            tokio::fs::read_to_string(&user_path).await
                .ok()
                .and_then(|json| serde_json::from_str::<User>(&json).ok())
        };

        // Per-account brute-force throttle, keyed on the RESOLVED username so an
        // account's username and email aliases share ONE bucket — logging in by email
        // must not grant a second 10/min budget. Runs AFTER the IP gate (so an over-
        // budget IP still can't mint fresh per-key buckets to exhaust the bucket table)
        // and BEFORE the Argon2 verify so it short-circuits the KDF. Unknown identifiers
        // fall back to the raw ident (login:<username> is identical whether or not the
        // username exists, so this is not an enumeration oracle).
        let rl_key = match &user_opt { Some(u) => u.username.clone(), None => ident.clone() };
        // Key this per (IP, account), NOT globally per account: a single attacker IP must not
        // be able to fill a victim account's bucket and lock the real owner out (a global
        // per-account hard-cap is a targeted login-DoS). Per-account brute-force across many
        // IPs is bounded instead by the per-(IP,account) captcha gate (after 3 fails) + the
        // per-IP "login" gate above + Argon2 + the strong-password policy.
        let ip_seg: String = ip.unwrap_or("noip").chars().take(64).collect();
        self.check_rate_limit(&format!("login:{}:{}", ip_seg, rl_key))?;

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
        // On success bind to the RESOLVED account username (NOT the identifier, which may
        // be an email) so the lock, session filtering, and returned identity are correct.
        let uname = match &user_opt {
            Some(u) if u.verified && verify_ok => u.username.clone(),
            _ => bail!("Invalid username or password"),
        };

        // #63: serialize the session-cap eviction + insert under the per-user lock
        // so concurrent logins for the same user cannot both snapshot the same
        // count, evict the same "oldest", and both insert past the cap.
        let lock = self.user_lock(&uname);
        let _guard = lock.lock().await;
        // Record the last-login timestamp (best-effort; we already hold the per-user lock).
        {
            let upath = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", uname));
            if let Ok(j) = tokio::fs::read_to_string(&upath).await {
                if let Ok(mut u) = serde_json::from_str::<User>(&j) {
                    u.last_login = Utc::now().timestamp();
                    let _ = self.write_user_atomic(&uname, &u).await;
                }
            }
        }
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
            username: uname.clone(), created_at: Utc::now().timestamp(),
            last_used: Utc::now().timestamp(),
        });
        Ok((token, uname))
    }

    /// Mint a fresh session token for an already-authenticated user. Used after
    /// change_password() purges all sessions, so the caller who changed their OWN password
    /// isn't logged out (other devices stay purged — that's the security intent).
    pub fn issue_session(&self, username: &str) -> String {
        let token = Uuid::new_v4().to_string();
        self.sessions.insert(token.clone(), Session {
            username: username.to_lowercase(),
            created_at: Utc::now().timestamp(),
            last_used: Utc::now().timestamp(),
        });
        token
    }

    /// Delete expired password-reset tokens (resets/) and email-verification records
    /// (pending/) from disk so they don't accumulate forever (and don't slow the
    /// email_in_use / reset directory scans). Called from the hourly maintenance task.
    pub async fn sweep_expired_tokens(&self) {
        let now = Utc::now().timestamp();
        for dir in ["resets", "pending"] {
            let path = PathBuf::from(&self.data_dir).join(dir);
            if let Ok(mut rd) = tokio::fs::read_dir(&path).await {
                while let Ok(Some(entry)) = rd.next_entry().await {
                    let p = entry.path();
                    if p.extension().map(|e| e == "json").unwrap_or(false) {
                        if let Ok(json) = tokio::fs::read_to_string(&p).await {
                            let exp = serde_json::from_str::<serde_json::Value>(&json).ok()
                                .and_then(|v| v.get("expires_at").and_then(|x| x.as_i64()))
                                .unwrap_or(i64::MAX); // unparseable → keep (don't delete what we can't read)
                            if exp < now { let _ = tokio::fs::remove_file(&p).await; }
                        }
                    }
                }
            }
        }
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

    /// Read-only liveness check for an already-validated session, used to re-validate
    /// a long-lived open WebSocket's OUTBOUND stream without the side effects of
    /// validate_session. Unlike validate_session it takes only a SHARED ref (get, not
    /// get_mut), does NOT bump last_used, and does NOT evict on expiry (lazy eviction
    /// stays with validate_session / the idle-prune sweep). This keeps it observably
    /// side-effect-free for a valid session, so periodic polling from send_task cannot
    /// itself extend a session's idle lifetime. Returns true only if the token still
    /// maps to `expected_user` and is within both the age and idle limits.
    pub fn session_valid_for(&self, raw_token: &str, expected_user: &str) -> bool {
        let token = match validate_uuid(raw_token) { Some(t) => t, None => return false };
        let now = Utc::now().timestamp();
        match self.sessions.get(&token) {
            Some(entry) => {
                entry.username == expected_user
                    && now - entry.created_at <= SESSION_MAX_AGE_SECS
                    && now - entry.last_used  <= SESSION_IDLE_MAX_SECS
            }
            None => false,
        }
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
        // Hold the same per-user lock every other mutator takes (reset_password,
        // verify_email, set_admin, set_can_upload, change_password, disable_user, login's
        // session-cap section). delete_account was the lone mutator that skipped it, so a
        // concurrent change_password (slow Argon2 verify+hash under the lock) could finish
        // its write_user_atomic rename AFTER this remove_file, RESURRECTING users/<u>.json
        // (verified=true + valid hash) atop the already-deleted vault/e2e/networks — an
        // undead, loginable account that defeats deletion. Serializing here closes that
        // race. Deadlock-free: no caller holds user_lock when invoking delete_account
        // (purge_account does not; the WS path's preceding login() drops its guard first).
        let lock = self.user_lock(&uname);
        let _guard = lock.lock().await;
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
                            // Also drop the per-connection TLS client-cert dir
                            // (certs/<conn_id>: cert.pem + key.enc). Nothing else in the
                            // deletion path removed these, so a deleted account's client
                            // certs lingered on disk. safe_id is already UUID-validated.
                            let cert_dir = PathBuf::from(&self.data_dir).join("certs").join(&safe_id);
                            let _ = tokio::fs::remove_dir_all(&cert_dir).await;
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
        // Remove any pending email-verification record(s) for this user — otherwise a
        // surviving non-expired record makes email_in_use() reject re-registration with the
        // same email for up to 24h ("Username already taken"), so a deleted user (or one who
        // deleted their own account) could not sign up again. (See remove_pending_records_for.)
        self.remove_pending_records_for(&uname).await;
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

    /// Load a user's record by username. None if the name is unsafe or the account is missing.
    pub async fn get_user(&self, username: &str) -> Option<User> {
        let uname = username.to_lowercase();
        if !is_safe_username(&uname) { return None; }
        let path = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", uname));
        let json = tokio::fs::read_to_string(&path).await.ok()?;
        serde_json::from_str::<User>(&json).ok()
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
                                "last_login": user.last_login,
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
        // Path-safety guard (mirrors disable_user/delete_account) so a crafted target
        // username can't traverse out of users/. Behavior-preserving for valid names.
        if !is_safe_username(&uname) { anyhow::bail!("Invalid username"); }
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

    pub async fn set_verified(&self, username: &str, verified: bool) -> Result<()> {
        let uname = username.to_lowercase();
        if !is_safe_username(&uname) { anyhow::bail!("Invalid username"); }
        // #22: serialize read→mutate→write under the per-user lock + atomic write, like
        // every other mutator. The admin add-user route previously did a raw, unlocked,
        // non-atomic read-modify-write to flip verified=true, which could race a concurrent
        // mutator (resurrection / lost-update) and left a crash-truncation window.
        let lock = self.user_lock(&uname);
        let _guard = lock.lock().await;
        let path = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", uname));
        let json = tokio::fs::read_to_string(&path).await?;
        let mut user: User = serde_json::from_str(&json)?;
        user.verified = verified;
        self.write_user_atomic(&uname, &user).await?;
        Ok(())
    }

    /// Admin "approve": verify a registered-but-unverified account WITHOUT requiring the
    /// user to click the email verification link. Mirrors verify_email's net effect — flip
    /// verified=true and drop the now-moot pending verification record — but is admin-
    /// initiated (no token). set_verified() validates the username, takes the per-user lock
    /// + atomic write, and errors if the account doesn't exist. Idempotent: re-approving an
    /// already-verified user is a harmless no-op. (If the user instead clicks the email
    /// link, verify_email does the same thing, so no approval is then needed.)
    pub async fn approve_user(&self, username: &str) -> Result<()> {
        self.set_verified(username, true).await?;
        // Drop the pending record(s) so the dead link can't be replayed and a later
        // delete/re-register isn't blocked by a stale email match (same cleanup that
        // verify_email and delete_account do).
        self.remove_pending_records_for(&username.to_lowercase()).await;
        Ok(())
    }

    /// Remove any pending email-verification record(s) for `uname` (already lowercased).
    /// register() writes one for EVERY signup (keyed by token, holding the email + a 24h
    /// expiry); it is otherwise consumed only by verify_email. A surviving non-expired
    /// record makes email_in_use() reject re-registration with the same email for up to
    /// 24h. Shared by delete_account + approve_user. Best-effort (deletion failures are
    /// non-fatal; an orphan would self-heal at expiry and is ignored by email_in_use).
    async fn remove_pending_records_for(&self, uname: &str) {
        let pending_dir = PathBuf::from(&self.data_dir).join("pending");
        if let Ok(mut rd) = tokio::fs::read_dir(&pending_dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    if let Ok(json) = tokio::fs::read_to_string(&path).await {
                        if let Ok(p) = serde_json::from_str::<PendingVerification>(&json) {
                            if p.username == uname {
                                let _ = tokio::fs::remove_file(&path).await;
                            }
                        }
                    }
                }
            }
        }
    }

    pub async fn set_can_upload(&self, username: &str, can_upload: bool) -> Result<()> {
        let uname = username.to_lowercase();
        // Path-safety guard (mirrors disable_user/delete_account) so a crafted target
        // username can't traverse out of users/. Behavior-preserving for valid names.
        if !is_safe_username(&uname) { anyhow::bail!("Invalid username"); }
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

    /// Set (or clear) a user's email address. Used by the user themselves (Profile) AND by
    /// an admin (set an email for an account that has none). Validates format + one-account-
    /// per-email uniqueness; a blank value clears the email. Locked + atomic like every mutator.
    pub async fn set_email(&self, username: &str, new_email: &str) -> Result<()> {
        let uname = username.to_lowercase();
        if !is_safe_username(&uname) { anyhow::bail!("Invalid username"); }
        let email_lower = new_email.trim().to_lowercase();
        if !email_lower.is_empty() && (!email_lower.contains('@') || email_lower.len() > 254) {
            bail!("Invalid email address");
        }
        // Serialize on the target email (mirrors register) so a concurrent signup/set with the
        // same address can't bind it to two accounts; then the per-user lock for the atomic write.
        let _eguard = if !email_lower.is_empty() {
            Some(self.email_lock(&email_lower).lock_owned().await)
        } else { None };
        let lock = self.user_lock(&uname);
        let _guard = lock.lock().await;
        let path = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", uname));
        let json = tokio::fs::read_to_string(&path).await
            .map_err(|_| anyhow::anyhow!("Account not found"))?;
        let mut user: User = serde_json::from_str(&json)?;
        // Allow a no-op set to the user's own current address; reject another account's.
        if !email_lower.is_empty() && user.email != email_lower && self.email_in_use(&email_lower).await {
            bail!("That email is already in use");
        }
        user.email = email_lower;
        self.write_user_atomic(&uname, &user).await?;
        Ok(())
    }

    /// Link / unlink the user's Last.fm username (+ optional own API key).
    /// Empty user = disconnect (clears both). key = None/blank keeps the saved key.
    pub async fn set_lastfm(&self, username: &str, lfm_user: &str, lfm_key: Option<&str>) -> Result<()> {
        let uname = username.to_lowercase();
        if !is_safe_username(&uname) { anyhow::bail!("Invalid username"); }
        let lfm_user = lfm_user.trim();
        if !lfm_user.is_empty() && (lfm_user.len() > 32
            || !lfm_user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')) {
            bail!("Invalid Last.fm username (letters, numbers, _ and - only)");
        }
        // A provided key is validated; None or blank means "keep the current key".
        let new_key = match lfm_key.map(|k| k.trim()) {
            Some(k) if !k.is_empty() => {
                if k.len() > 64 || !k.chars().all(|c| c.is_ascii_alphanumeric()) {
                    bail!("Invalid Last.fm API key");
                }
                Some(k.to_string())
            }
            _ => None,
        };
        let lock = self.user_lock(&uname);
        let _guard = lock.lock().await;
        let path = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", uname));
        let json = tokio::fs::read_to_string(&path).await
            .map_err(|_| anyhow::anyhow!("Account not found"))?;
        let mut user: User = serde_json::from_str(&json)?;
        if lfm_user.is_empty() {
            user.lastfm_user = String::new();
            user.lastfm_key = String::new();   // disconnect clears the saved key too
        } else {
            user.lastfm_user = lfm_user.to_string();
            if let Some(k) = new_key { user.lastfm_key = k; }  // else keep existing key
        }
        self.write_user_atomic(&uname, &user).await?;
        Ok(())
    }

    pub async fn change_password(&self, username: &str, old_password: &str, new_password: &str, ip: Option<&str>) -> Result<()> {
        let uname = username.trim().to_lowercase();
        // #15: IP dimension FIRST (before the per-user bucket insert) so one IP can't fill
        // the global bucket table via varying usernames. See login() for the rationale.
        self.check_ip_rate_limit("chpass", ip)?;
        self.check_rate_limit(&format!("chpass:{}", uname))?;

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

/// #58: Validate a username for safe filesystem-path use. MUST match the exact charset
/// and length registration enforces — register() allows `c.is_alphanumeric()` (Unicode)
/// plus '_'/'-', 3–32 bytes — otherwise a legitimately-registered (Unicode) username
/// would be rejected here and become unmanageable/undeletable. This charset is still
/// path-safe: Unicode alphanumerics contain no path separators ('/','\\') or '.', and
/// '.'/'..'/empty are rejected explicitly. Used before any path join in
/// delete_account / disable_user / set_admin / set_can_upload.
pub fn is_safe_username(s: &str) -> bool {
    if s.len() < 3 || s.len() > 32 { return false; }
    if s == "." || s == ".." { return false; }
    s.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-')
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
