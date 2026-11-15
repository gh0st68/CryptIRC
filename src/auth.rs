//! auth.rs — User registration, login, session, email verification
//!
//! Fixes this pass:
//!   S1 — write-through create_new handle (no empty-file window)
//!   S5 — rate_limits DashMap capped + TTL sweep to prevent memory exhaustion

use anyhow::{bail, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
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
/// Lifetime of an email-verification link (pending/<token>.json). email.rs documents it.
const VERIFY_TOKEN_TTL_SECS:   i64   = 86400; // 24 h
/// Lifetime of a password-reset link (resets/<token>.json). email.rs documents it.
const RESET_TOKEN_TTL_SECS:    i64   = 3600;  // 1 h
/// Email-required mode only: an unverified account older than this is garbage-collected
/// by the hourly reaper even if it still holds a (re-sent) live link, so a squat can't be
/// kept alive forever by re-sending. Before this age an admin can still Approve it; from
/// VERIFY_TOKEN_TTL_SECS on it already stops blocking its username/email (see
/// unverified_is_stale) and is reaped on demand when someone else registers either.
const UNVERIFIED_GC_AGE_SECS:  i64   = 7 * 86400; // 7 days

/// #6: one shared, tuned Argon2id used for EVERY password hash (register / reset /
/// change) AND the login-timing dummy, so the credential hashes that gate account
/// access are as expensive to crack offline as the vault KDF (m=64 MiB, t=3, p=1),
/// and the dummy stays parameter-matched to the real hashes for timing equalization.
fn tuned_argon2() -> Argon2<'static> {
    // None output-len → PHC default (32-byte tag); constants are valid, so the
    // params build can never fail in practice.
    let params = Params::new(65536, 3, 1, None).expect("valid Argon2id params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// #56: A valid Argon2 hash (over a random throwaway password) used to equalize
/// login timing for nonexistent / unverified accounts. Computed once with the
/// SAME tuned params as real hashes (#6) so verify_password does equivalent work
/// whether or not the account exists. Lazily initialized to guarantee a parseable
/// PHC string with matching parameters.
fn dummy_argon2_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        let salt = SaltString::generate(&mut OsRng);
        tuned_argon2()
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
    /// A3: admin "Disable login" (a ban). Its own flag so tools and the admin panel can tell
    /// a banned account from one that merely never verified its email — before this, a ban
    /// was stored only as verified=false, and `resetpass.sh --verify` (or any reset)
    /// silently lifted it. disable_user() ALSO keeps verified=false (so an older binary or
    /// script that predates this flag still refuses the login); enable_user() clears both.
    /// serde default → records written before this field existed load as not-disabled, and
    /// migrate_legacy_disabled_flag() classifies the old verified=false ones at startup.
    #[serde(default)]
    pub disabled:      bool,
    /// r5 (codex P4 resetpass.sh:794): session revocation stamp, unix seconds. Every session
    /// created before it (`Session.created_at < sessions_valid_after`) is invalid on every
    /// validate path — HTTP, the WebSocket auth frame, the WebSocket's 30 s re-validation and
    /// the push re-checks. Sessions live in this process's memory; this field is how a change
    /// made on disk while the server runs (resetpass.sh) revokes them: the server re-reads the
    /// record when its mtime changes (session_revoked). The server itself sets it on a
    /// password change / email-link reset. 0 / absent = no stamp, and then it is not written
    /// (a record that never had a stamp stays byte-identical across the server's rewrites).
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub sessions_valid_after: i64,
}

fn is_zero_i64(v: &i64) -> bool { *v == 0 }

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
    /// created_at of the exact account the token was minted for. reset_password() refuses
    /// the token for any other account — e.g. a later re-registration of the same username
    /// after the original was deleted. Absent in tokens minted by older builds (they fall
    /// back to the mint-time check in reset_password); old builds ignore the extra field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_created: Option<i64>,
    /// Credential fingerprint (see `reset_cred_fingerprint`) of the account at mint time:
    /// a hash over the password hash + recovery email. reset_password() refuses the token
    /// once either has changed, so ANY password change (change-password, another reset,
    /// resetpass.sh editing the record) or email change kills outstanding links without
    /// having to find and delete them. Absent in older tokens (they keep the old checks);
    /// older builds ignore the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_fp: Option<String>,
}

/// Fingerprint of the credentials a reset link was issued against. Bound into every new
/// reset token (PendingReset::cred_fp). Not secret-equivalent: resets/ is as protected as
/// users/ (0700/0600) and the inputs already sit in users/<name>.json.
fn reset_cred_fingerprint(u: &User) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"cryptirc-reset-cred-v1\0");
    h.update(u.password_hash.as_bytes());
    h.update(b"\0");
    h.update(u.email.as_bytes());
    h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

/// Result of register(): tells the caller whether to send a verification email.
pub struct RegisterOutcome {
    /// Some(token) → caller should email a verification link to the address.
    /// None → the account is already active (auto-verified; no email step needed).
    pub verify_token: Option<String>,
    /// #F12: true when register() found the email ALREADY IN USE and therefore did NOT
    /// create an account (no token minted; verify_token is None). This is NOT an error:
    /// the route MUST respond IDENTICALLY to a real signup in the current verification
    /// mode — if email_required, emit the same "check your email" response; otherwise the
    /// same "account created" response — and MUST NOT send any email. Returning a 400/
    /// distinct message here (vs. 200 on success with a unique username) is a clean
    /// email-enumeration oracle, which this flag lets the route close.
    pub email_in_use: bool,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub username:   String,
    pub created_at: i64,
    pub last_used:  i64,
    /// r4 V3S-1 / C1-1: the account generation (AuthManager::account_epoch) the session was
    /// minted for. Sessions are keyed by username alone, so a token minted for an account
    /// that was then deleted (e.g. change-password's re-issued session landing at the very
    /// end of a purge) would otherwise validate for a later account registered under the
    /// same name. A session whose generation is no longer current never validates.
    pub epoch:      u64,
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
    /// A3: usernames known (in THIS process) to be disabled. Lets the synchronous session
    /// checks (validate_session / session_valid_for) refuse a disabled account's session
    /// without a disk read. Sessions are in-memory only, so an empty set at startup is
    /// correct: every session is minted by login(), which re-reads the record under the
    /// per-user lock and refreshes this entry (so a hand edit / CLI --enable converges on
    /// the next login). Updated by disable/enable/approve/delete.
    disabled_users: Arc<DashMap<String, ()>>,
    /// codex P1 main.rs:372: usernames whose account teardown (AppState::purge_account) is
    /// still running, with a count of concurrent purges. While listed: no login, no session
    /// validates, and register() treats the name as taken — so a same-name re-registration
    /// can never land in the middle of a deletion and inherit the old vault key, sessions,
    /// sockets, E2E or other data (the record file is also removed only at the very end).
    deleting_users: Arc<DashMap<String, usize>>,
    /// r4 C1-1: per-username account generation, bumped when a deletion of that name begins
    /// AND when it ends. Work accepted for an account (a detached AI / bot request, a paste
    /// being hashed) records the value first and delivers its result only while it is
    /// unchanged and no deletion is running (account_ticket_live) — so a slow request of a
    /// deleted account can never reach a later same-name account. In-memory: a restart
    /// kills every such task too. One entry per name ever deleted in this process.
    account_epochs: Arc<DashMap<String, u64>>,
    /// r5 (codex P4 resetpass.sh:794): per-user cache of the record's sessions_valid_after
    /// (and whether the record exists), refreshed when the record's mtime changes; see
    /// session_revoked.
    revocations: Arc<DashMap<String, Revocation>>,
    revocation_recheck: Duration,
}

/// r5: what session_revoked last learned from users/<name>.json. r6 (agy P1 auth.rs:1659): an
/// entry belongs to one account generation (`epoch`) and is never used for a session minted at
/// or after the moment it was taken (`checked_unix`); a missing record is not cached at all.
struct Revocation { checked: Instant, checked_unix: i64, epoch: u64, mtime: Option<RecordStamp>, stamp: i64 }
/// Identity of one version of a record file: inode (every atomic rename makes a new one), size
/// and mtime/ctime to the nanosecond. mtime alone is not enough — the kernel's file clock is
/// coarse, so a script's edit landing in the same tick as the server's last write kept it.
type RecordStamp = (u64, u64, i64, i64, i64, i64);
fn record_stamp(m: &std::fs::Metadata) -> RecordStamp {
    use std::os::unix::fs::MetadataExt;
    (m.ino(), m.size(), m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec())
}
/// At most one stat of a user's record per this interval per user (AuthManager::revocation_recheck;
/// tests may lengthen it to exercise the cache).
const REVOCATION_RECHECK: Duration = if cfg!(test) { Duration::ZERO } else { Duration::from_secs(1) };

/// #31/#32: best-effort chmod 0600 on a secret file (user records hold the
/// password hash + plaintext Last.fm key; pending/reset files hold bearer tokens).
async fn set_secret_mode(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await {
            tracing::warn!("could not chmod 0600 {}: {}", path.display(), e);
        }
    }
    #[cfg(not(unix))]
    { let _ = path; }
}

/// #32: create a secret-bearing directory with mode 0700 (owner-only), so the
/// data dir being world-traversable cannot expose user records / tokens.
fn create_dir_secure(path: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    { std::fs::create_dir_all(path) }
}

// ── Cross-process account lock (codex P4 resetpass.sh:487 / adduser.sh:181) ──────────────
// adduser.sh / resetpass.sh / makeadmin.sh hold flock(LOCK_EX) on <data>/.cryptirc-admin.lock
// while they read-modify-write users/*.json or scan emails + create an account. The server's
// own user/email mutexes are in-process only, so a login's last_login write (or any other
// record rewrite) that read the record BEFORE a script's change could rename its stale copy
// over it afterwards — restoring an old password hash or a revoked admin flag — and a browser
// signup could take an email a script had just checked. The server therefore holds the same
// file SHARED around every user-record read→modify→write and around registration's email
// scan + create. Shared holders never exclude each other, so server requests still run in
// parallel; only a script's exclusive hold separates them.
//   - A fresh descriptor per operation (closing it releases the lock).
//   - Never blocks a tokio worker: non-blocking flock attempts with an async sleep between
//     them, bounded by ADMIN_LOCK_WAIT (scripts hold it for about a second: one Argon2).
//   - Never waited for while an in-process user/email mutex is held (r4 F1-4, lock_with_admin):
//     while a script holds the file, the mutexes are released for the wait and re-taken.
//   - Known degraded mode: a lock file the server cannot open (e.g. a stray root-owned 0600 lock
//     left by an older script run as root), or one that is not a regular file, is left alone;
//     the server logs a rate-limited warning and carries on with its in-process locks only —
//     exactly the behaviour before this lock existed. It never refuses logins or registration
//     because of the lock file.

/// Name of the shared account lock file inside the data dir (same name the scripts use).
pub const ADMIN_LOCK_FILE: &str = ".cryptirc-admin.lock";
/// Longest an operation waits for a script to release the lock before it gives up.
const ADMIN_LOCK_WAIT: Duration = if cfg!(test) { Duration::from_millis(1500) } else { Duration::from_secs(10) };
const ADMIN_LOCK_POLL: Duration = Duration::from_millis(20);

/// A held SHARED lock on ADMIN_LOCK_FILE (released when dropped). `None` = the file could not
/// be used at all, so the operation proceeds without cross-process exclusion (warned).
pub(crate) struct AdminFileLock { _file: Option<std::fs::File> }

/// Open the lock file O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC, mode 0600 (the integrator's server-side
/// contract; O_NONBLOCK only keeps a planted FIFO from blocking the open, as the scripts do), then
/// fstat the descriptor and refuse anything that is not a regular file. No O_EXCL: the server is
/// unprivileged and never chowns it.
fn open_admin_lock_file(data_dir: &str) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = PathBuf::from(data_dir).join(ADMIN_LOCK_FILE);
    let flags = libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    let f = std::fs::OpenOptions::new().read(true).write(true).create(true).mode(0o600)
        .custom_flags(flags).open(&path)?;
    if !f.metadata()?.file_type().is_file() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file"));
    }
    Ok(f)
}

/// One non-blocking shared-lock attempt. Ok(true) = held, Ok(false) = an exclusive holder.
fn try_flock_shared(f: &std::fs::File) -> std::io::Result<bool> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: flock on a valid, owned descriptor; no memory is passed.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 { return Ok(true); }
    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::EWOULDBLOCK) | Some(libc::EINTR) => Ok(false),
        _ => Err(e),
    }
}

/// Log (at most hourly) that the lock file can't be used, so an operator can fix it.
fn warn_admin_lock_unusable(data_dir: &str, e: &std::io::Error) {
    static LAST: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|p| p.into_inner());
    if last.map_or(true, |t| t.elapsed() > Duration::from_secs(3600)) {
        *last = Some(Instant::now());
        tracing::warn!("auth: cannot use {}/{} ({}) — account changes are not coordinated with \
            adduser.sh/resetpass.sh/makeadmin.sh until it is a regular file the service can open \
            (e.g. `chown cryptirc: {}/{}`, or remove it while no admin script runs)", data_dir, ADMIN_LOCK_FILE, e, data_dir, ADMIN_LOCK_FILE);
    }
}

/// Startup: create the lock file (owned by this service, 0600) if it is missing, so it exists
/// before any script or request needs it. An existing file the service can't open (e.g. a
/// stray root-owned 0600 lock left by an older script run as root), a symlink or a non-file is
/// NOT touched: the server logs the (rate-limited) warning and runs in the known degraded mode
/// — in-process locks only, exactly the behaviour before this lock existed — until an operator
/// fixes or removes the file. Logins and registration are never refused because of it.
fn ensure_admin_lock_file(data_dir: &str) {
    if let Err(e) = open_admin_lock_file(data_dir) { warn_admin_lock_unusable(data_dir, &e); }
}

/// Synchronous variant for startup work (the legacy-record migration runs before the
/// server accepts requests). Err only when a script holds the lock past ADMIN_LOCK_WAIT.
fn admin_lock_shared_sync(data_dir: &str) -> std::io::Result<AdminFileLock> {
    let f = match open_admin_lock_file(data_dir) {
        Ok(f) => f,
        Err(e) => { warn_admin_lock_unusable(data_dir, &e); return Ok(AdminFileLock { _file: None }); }
    };
    let deadline = Instant::now() + ADMIN_LOCK_WAIT;
    loop {
        match try_flock_shared(&f) {
            Ok(true) => return Ok(AdminFileLock { _file: Some(f) }),
            Ok(false) => {}
            Err(e) => { warn_admin_lock_unusable(data_dir, &e); return Ok(AdminFileLock { _file: None }); }
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "account lock held by an admin script"));
        }
        std::thread::sleep(ADMIN_LOCK_POLL);
    }
}

/// set_email_reauthed refusals (route_set_email maps them to 403).
pub const EMAIL_CHANGE_NEEDS_PASSWORD: &str = "Enter your current login password to change your email.";
pub const EMAIL_CHANGE_STALE: &str = "Your login changed while saving (password reset or sign-out) — sign in again and retry.";

/// Message returned when a script keeps the account lock past ADMIN_LOCK_WAIT.
/// The shared account lock for the data dir `data_dir` (AuthManager::admin_lock_shared; r9: also
/// taken by the notification store, which has no AuthManager).
pub(crate) async fn admin_lock_shared_in(data_dir: &str) -> Result<AdminFileLock> {
    let f = match open_admin_lock_file(data_dir) {
        Ok(f) => f,
        Err(e) => { warn_admin_lock_unusable(data_dir, &e); return Ok(AdminFileLock { _file: None }); }
    };
    let deadline = Instant::now() + ADMIN_LOCK_WAIT;
    loop {
        match try_flock_shared(&f) {
            Ok(true) => return Ok(AdminFileLock { _file: Some(f) }),
            Ok(false) => {}
            Err(e) => { warn_admin_lock_unusable(data_dir, &e); return Ok(AdminFileLock { _file: None }); }
        }
        if Instant::now() >= deadline { bail!(ADMIN_LOCK_BUSY); }
        tokio::time::sleep(ADMIN_LOCK_POLL).await;
    }
}

/// One non-blocking attempt at the shared account lock (AuthManager::admin_lock_try_shared).
pub(crate) fn admin_lock_try_shared_in(data_dir: &str) -> Option<AdminFileLock> {
    let f = match open_admin_lock_file(data_dir) {
        Ok(f) => f,
        Err(e) => { warn_admin_lock_unusable(data_dir, &e); return Some(AdminFileLock { _file: None }); }
    };
    match try_flock_shared(&f) {
        Ok(true) => Some(AdminFileLock { _file: Some(f) }),
        Ok(false) => None,
        Err(e) => { warn_admin_lock_unusable(data_dir, &e); Some(AdminFileLock { _file: None }) }
    }
}

pub const ADMIN_LOCK_BUSY: &str = "Account data is busy (an admin script is running) — try again in a moment";

/// What a self-service email change was authorized with (route_set_email): the credential
/// the caller's password was verified against, and the session that asked.
pub struct EmailChangeAuth<'a> {
    /// (password_hash, created_at) returned by verify_current_password, or None when no
    /// password was given (then only a no-op save of the address already on file passes).
    pub verified: Option<&'a (String, i64)>,
    /// The caller's session token; the change is refused once it no longer validates
    /// (a password reset / change / disable / deletion revoked it meanwhile).
    pub session_token: &'a str,
}

impl AuthManager {
    pub fn new(data_dir: &str) -> Result<Self> {
        // #32: secret-bearing dirs are created 0700 (not the umask default 0755).
        create_dir_secure(&format!("{}/users",   data_dir))?;
        create_dir_secure(&format!("{}/pending", data_dir))?;
        create_dir_secure(&format!("{}/resets",  data_dir))?;
        // Cross-process account lock shared with the admin scripts: create it (owned by
        // this service) before anything can need it. An existing file it can't use is left
        // alone (warned degraded mode, see ensure_admin_lock_file) — never repaired here.
        ensure_admin_lock_file(data_dir);
        // A3: one-time, idempotent classification of pre-`disabled`-flag records (runs
        // before the server accepts any request). Best-effort: it never fails startup.
        // It rewrites user records, so it holds the account lock like every other writer;
        // if a script keeps the lock past the bounded wait, this start skips the migration
        // (it is idempotent and runs again on the next start).
        match admin_lock_shared_sync(data_dir) {
            Ok(_held) => migrate_legacy_disabled_flag(data_dir),
            Err(e) => tracing::warn!("auth migration: skipped this start ({})", e),
        }
        Ok(Self {
            data_dir:    data_dir.to_string(),
            sessions:    Arc::new(DashMap::new()),
            rate_limits: Arc::new(DashMap::new()),
            user_locks:  Arc::new(DashMap::new()),
            email_locks: Arc::new(DashMap::new()),
            login_fails: Arc::new(DashMap::new()),
            disabled_users: Arc::new(DashMap::new()),
            deleting_users: Arc::new(DashMap::new()),
            account_epochs: Arc::new(DashMap::new()),
            revocations: Arc::new(DashMap::new()),
            revocation_recheck: REVOCATION_RECHECK,
        })
    }

    /// Take the cross-process account lock SHARED (see ADMIN_LOCK_FILE). Never blocks a
    /// worker thread: non-blocking attempts with an async sleep in between, for at most
    /// ADMIN_LOCK_WAIT. Err(ADMIN_LOCK_BUSY) only when a script holds it that long; an
    /// unusable lock file degrades to no cross-process exclusion (warned), never an error.
    /// Callers that also need their in-process user/email lock use lock_with_admin (r4 F1-4),
    /// which never holds such a mutex during this wait.
    pub(crate) async fn admin_lock_shared(&self) -> Result<AdminFileLock> {
        admin_lock_shared_in(&self.data_dir).await
    }

    /// One non-blocking attempt at the shared account lock. Some(lock) when it is held — or
    /// when the lock file is unusable (the warned degraded mode: no cross-process exclusion,
    /// exactly as admin_lock_shared) — None while an admin script holds it exclusively.
    fn admin_lock_try_shared(&self) -> Option<AdminFileLock> {
        admin_lock_try_shared_in(&self.data_dir)
    }

    /// r4 F1-4 (agy P1 auth.rs:1359): take the in-process mutexes `ms` (in this order: email
    /// lock before user lock, as everywhere) AND the shared account lock, without ever holding
    /// one of those mutexes while waiting for an admin script. Uncontended: mutexes, then one
    /// non-blocking flock attempt (the usual order). If a script holds the account lock, the
    /// mutexes are released, the bounded wait (admin_lock_shared) runs with none of them
    /// held, and they are taken again afterwards — so the account's other requests (logins,
    /// profile changes) are not queued behind the script for up to ADMIN_LOCK_WAIT. Callers
    /// read the record only after this returns, so nothing decided before the wait is reused.
    /// Deadlock-free: shared holds never conflict with each other, and a task waiting for the
    /// flock holds no mutex. The second value is admin_lock_shared's result (Err only after
    /// the bounded wait); the mutexes are held either way.
    pub(crate) async fn lock_with_admin(&self, ms: &[&Arc<tokio::sync::Mutex<()>>])
        -> (Vec<tokio::sync::OwnedMutexGuard<()>>, Result<AdminFileLock>)
    {
        async fn take_all(ms: &[&Arc<tokio::sync::Mutex<()>>]) -> Vec<tokio::sync::OwnedMutexGuard<()>> {
            let mut guards = Vec::with_capacity(ms.len());
            for m in ms { guards.push(Arc::clone(m).lock_owned().await); }
            guards
        }
        let guards = take_all(ms).await;
        if let Some(held) = self.admin_lock_try_shared() { return (guards, Ok(held)); }
        drop(guards);
        let held = self.admin_lock_shared().await;
        (take_all(ms).await, held)
    }

    // ── Account deletion window (codex P1 main.rs:372) ───────────────────────────────

    /// Start tearing down `uname` (AppState::purge_account): from now until
    /// end_account_deletion the name can't log in, its sessions stop validating, every
    /// existing session is revoked, and register() refuses the name. Counted, so two
    /// overlapping purges of one account (admin + self-service) both hold it.
    pub async fn begin_account_deletion(&self, uname: &str) {
        let lock = self.user_lock(uname);
        let _guard = lock.lock().await;
        *self.deleting_users.entry(uname.to_string()).or_insert(0) += 1;
        // r4 C1-1: everything accepted for the account before this point is now stale.
        self.bump_account_epoch(uname);
        let to_remove: Vec<String> = self.sessions.iter()
            .filter(|s| s.username == uname)
            .map(|s| s.key().clone())
            .collect();
        for k in to_remove { self.sessions.remove(&k); }
    }

    /// Release the hold taken by begin_account_deletion (the last release frees the name).
    pub fn end_account_deletion(&self, uname: &str) {
        // r4 C1-1: bump BEFORE the name is freed, so work accepted while the deletion ran is
        // stale by the time a new same-name account can exist (account_ticket_live). r4
        // V3S-1: that also kills every session minted for the old account (sessions carry
        // their generation) — including one change-password re-issued after the purge's last
        // sweep — and they are swept here too, before the name can be registered again.
        self.bump_account_epoch(uname);
        let stale: Vec<String> = self.sessions.iter()
            .filter(|s| s.username == uname)
            .map(|s| s.key().clone())
            .collect();
        for k in stale { self.sessions.remove(&k); }
        if let Some(mut n) = self.deleting_users.get_mut(uname) { *n = n.saturating_sub(1); }
        self.deleting_users.remove_if(uname, |_, n| *n == 0);
    }

    fn bump_account_epoch(&self, uname: &str) {
        let mut e = self.account_epochs.entry(uname.to_string()).or_insert(0);
        *e = e.wrapping_add(1);
    }

    /// r4 C1-1: the current generation of `uname` (see `account_epochs`). Record it when a
    /// request for the account is ACCEPTED, then check account_ticket_live before delivering.
    pub fn account_epoch(&self, uname: &str) -> u64 {
        self.account_epochs.get(uname).map_or(0, |e| *e)
    }

    /// r4 C1-1: may a result of work accepted at generation `epoch` still be delivered to
    /// `uname`? False once a deletion of the name has begun (whether or not it finished, and
    /// whether or not the name was registered again since).
    pub fn account_ticket_live(&self, uname: &str, epoch: u64) -> bool {
        !self.deleting_users.contains_key(uname) && self.account_epoch(uname) == epoch
    }

    /// True while a purge of `uname` is in progress (or in its post-purge hold).
    pub fn is_being_deleted(&self, uname: &str) -> bool {
        self.deleting_users.contains_key(uname)
    }

    /// Whether `uname` is disabled by an admin, from the in-memory set (no disk read).
    pub fn is_disabled_cached(&self, uname: &str) -> bool {
        self.disabled_users.contains_key(uname)
    }

    /// Startup: put every account whose record says `disabled` into the in-memory set (it was
    /// filled only by logins and admin actions, so a web restart forgot existing bans for
    /// is_disabled_cached — codex astra L remote.rs:1056). Returns how many.
    pub async fn load_disabled_users(&self) -> usize {
        let dir = PathBuf::from(&self.data_dir).join("users");
        let Ok(mut rd) = tokio::fs::read_dir(&dir).await else { return 0 };
        let mut n = 0;
        while let Ok(Some(entry)) = rd.next_entry().await {
            let Some(name) = entry.file_name().to_str().and_then(|f| f.strip_suffix(".json")).map(str::to_string) else { continue };
            if !is_safe_username(&name) || name != name.to_lowercase() {
                continue;
            }
            if self.get_user(&name).await.map_or(false, |u| u.disabled) {
                self.disabled_users.insert(name, ());
                n += 1;
            }
        }
        n
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
    /// the read→mutate→write to avoid lost updates, AND the cross-process account lock
    /// (the `_held` guard: codex P4 resetpass.sh:487) taken BEFORE the read.
    async fn write_user_atomic(&self, _held: &AdminFileLock, uname: &str, user: &User) -> Result<()> {
        let dir = PathBuf::from(&self.data_dir).join("users");
        let final_path = dir.join(format!("{}.json", uname));
        let tmp_path   = dir.join(format!("{}.json.tmp.{}", uname, Uuid::new_v4()));
        let json = serde_json::to_string_pretty(user)?;
        tokio::fs::write(&tmp_path, json.as_bytes()).await?;
        set_secret_mode(&tmp_path).await; // #31: 0600 before it becomes the live record
        // rename is atomic on the same filesystem
        if let Err(e) = tokio::fs::rename(&tmp_path, &final_path).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e.into());
        }
        // r6: the record changed under our own hand — the next validation re-reads it.
        self.revocations.remove(uname);
        set_secret_mode(&final_path).await; // #31: also chmod the live path (idempotent)
        Ok(())
    }

    // ── Rate limiting ─────────────────────────────────────────────────────────

    fn check_rate_limit(&self, key: &str) -> Result<()> {
        // S5: if at cap, sweep expired buckets first.
        if self.rate_limits.len() >= RATE_LIMIT_MAX_BUCKETS {
            self.sweep_rate_buckets();
            // #F16: if the sweep freed nothing (table full of still-active buckets), EVICT
            // the oldest bucket(s) to admit this key rather than failing EVERY caller with
            // "Too many attempts" — the old hard-fail turned a full table into a global auth
            // outage (any per-IP/account/email/create key could fill it and lock out all
            // auth). Evicting the oldest (smallest window_start) only resets that key's
            // window; every per-key limit below is unchanged. Bounded: each pass removes one
            // entry, so the loop makes progress and stops once below the cap.
            while self.rate_limits.len() >= RATE_LIMIT_MAX_BUCKETS {
                let oldest = self.rate_limits.iter()
                    .min_by_key(|b| b.window_start)
                    .map(|b| b.key().clone());
                match oldest {
                    Some(k) => { self.rate_limits.remove(&k); }
                    None    => break, // table emptied concurrently — nothing to evict
                }
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
        entry.attempts = entry.attempts.saturating_add(1); // #142: no wrap
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

    /// Remove rate-limit buckets whose window has fully expired, and prune the
    /// otherwise-unbounded per-key lock maps (#38) + stale login-fail counters.
    pub fn sweep_rate_buckets(&self) {
        let threshold = Duration::from_secs(RATE_LIMIT_WINDOW_SECS * 2);
        let stale: Vec<String> = self.rate_limits.iter()
            .filter(|b| b.window_start.elapsed() > threshold)
            .map(|b| b.key().clone())
            .collect();
        for k in stale { self.rate_limits.remove(&k); }

        // #38: user_locks / email_locks grow one entry per distinct username/email and
        // were never evicted (an attacker varying the email could grow them slowly).
        // Drop any entry not currently held (strong_count == 1 → only the map holds it).
        // retain() races are benign: a lock acquired between the count and the remove is
        // simply re-created on next use.
        self.user_locks.retain(|_, v| Arc::strong_count(v) > 1);
        self.email_locks.retain(|_, v| Arc::strong_count(v) > 1);
        self.login_fails.retain(|_, v| v.1.elapsed() <= Duration::from_secs(LOGIN_FAIL_WINDOW_SECS));
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

    /// #7: Resolve a login identifier (username OR email) to its canonical account
    /// username, so the captcha gate and fail-counter are keyed on the ACCOUNT, not the
    /// raw identifier. Without this an account reachable by both username and email gets
    /// two independent captcha/fail buckets (double the brute-force budget). Returns the
    /// lowercased raw identifier when no account matches (consistent, non-enumerating:
    /// the bucket key is identical whether or not the username exists).
    pub async fn canonical_login_id(&self, identifier: &str) -> String {
        let ident = identifier.trim().to_lowercase();
        if ident.contains('@') {
            if let Some(u) = self.find_user_by_email(&ident).await {
                return u.username;
            }
        }
        ident
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
        // #22/#34: ASCII-only charset. Unicode alphanumerics would let two distinct
        // registered names normalize/compose to the same on-disk path (or be confusable
        // homographs), serving E2E/vault material for the wrong account. The whole app
        // uses one ASCII sanitizer, so registration must be the ASCII gate.
        if !uname.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            bail!("Username may only contain letters, numbers, _ and -");
        }
        if password.len() < 10 {
            bail!("Password must be at least 10 characters");
        }
        if password.len() > 1024 {
            bail!("Password is too long (max 1024 characters)"); // #110
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
        // #67: validate up front (reject control chars / CRLF / multiple addresses)
        // rather than deferring entirely to lettre at send time.
        if has_email && (!email_lower.contains('@') || email_lower.len() > 254 || !crate::email::validate_email(&email_lower)) {
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
        let hash = tuned_argon2()
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
            disabled:      false,
            sessions_valid_after: 0,
        };
        let json = serde_json::to_string_pretty(&user)?;

        if has_email {
            // Serialize the email check→create window per email (held through the create_new +
            // pending write below). Without it, concurrent same-email/different-username
            // registrations could all pass email_in_use() before any wrote its record (#14
            // TOCTOU). Acquired AFTER the KDF so hashing is never serialized; register holds
            // no user_lock, so no deadlock.
            let _elock = self.email_lock(&email_lower);
            // codex P4 adduser.sh:181: the scripts' email scan + create runs under their
            // exclusive hold of the account lock; holding it shared across ours keeps a
            // provisioning run and a browser signup from both taking one address.
            // r4 F1-4: the email lock is never held while waiting for a script.
            let (_eguard, held) = self.lock_with_admin(&[&_elock]).await;
            let held = held?;
            // codex P1 main.rs:372: a name still being torn down is taken.
            if self.is_being_deleted(&uname) { bail!("Username already taken"); }
            // Email-verification mode only (never in open / code modes): an unverified signup
            // that can no longer be verified stops squatting its username + email, and a
            // still-pending one can get its link re-sent. Before this, such an account held
            // both forever (no reaper, no resend) — see unverified_is_stale.
            if email_required {
                if let Some(token) = self.resend_or_reap_for_register(&held, &uname, &email_lower, password).await? {
                    // Re-send: same response as a fresh signup (the route mails the new link).
                    return Ok(RegisterOutcome { verify_token: Some(token), email_in_use: false });
                }
                self.reap_stale_holders_of_email(&held, &email_lower).await;
            }
            // #14/#F12: an account with this email already exists (verified or pending).
            // Do NOT create a duplicate-email account, but do NOT bail either — bailing
            // produced a 400 + distinct message vs. the 200 success of a unique username,
            // a clean email-enumeration oracle. Return a success-shaped outcome (no token,
            // no account, no mail) and let the route mirror the real-signup response.
            if self.email_in_use(&email_lower).await {
                return Ok(RegisterOutcome { verify_token: None, email_in_use: true });
            }
            // S1: atomic create + write-through (create_new fails if the file exists; no TOCTOU).
            {
                let mut file = tokio::fs::OpenOptions::new()
                    .write(true).create_new(true).open(&user_path).await
                    .map_err(|_| anyhow::anyhow!("Username already taken"))?;
                file.write_all(json.as_bytes()).await?;
                file.flush().await?;
            }
            // r6 (agy P1 auth.rs:1659): a new account instance starts with no cached stamp.
            self.revocations.remove(&uname);
            set_secret_mode(&user_path).await; // #31: 0600 on the user record
            if verified {
                // Email provided but verification not required → active immediately; the
                // address is just stored for password resets. No verification email.
                Ok(RegisterOutcome { verify_token: None, email_in_use: false })
            } else {
                // Email verification required → stage the pending record + token to email.
                let token = Uuid::new_v4().to_string();
                let pending = PendingVerification {
                    username: uname, email: email_lower,
                    token: token.clone(), expires_at: Utc::now().timestamp() + VERIFY_TOKEN_TTL_SECS,
                };
                let pending_path = PathBuf::from(&self.data_dir)
                    .join("pending").join(format!("{}.json", token));
                // #107: if the pending record can't be written, roll back the user file
                // so the username isn't wedged (created-but-unverifiable, un-reregisterable).
                if let Err(e) = tokio::fs::write(&pending_path, serde_json::to_string_pretty(&pending)?).await {
                    let _ = tokio::fs::remove_file(&user_path).await;
                    return Err(e.into());
                }
                set_secret_mode(&pending_path).await; // #31: 0600 on the bearer token
                Ok(RegisterOutcome { verify_token: Some(token), email_in_use: false })
            }
        } else {
            // No email on file: username uniqueness is enforced solely by create_new (atomic),
            // and the account is auto-verified (email_required is false here). No email_lock.
            // The account lock is still held across the create (scripts create accounts
            // under it), and a name still being torn down is taken (codex P1 main.rs:372).
            let _held = self.admin_lock_shared().await?;
            if self.is_being_deleted(&uname) { bail!("Username already taken"); }
            {
                let mut file = tokio::fs::OpenOptions::new()
                    .write(true).create_new(true).open(&user_path).await
                    .map_err(|_| anyhow::anyhow!("Username already taken"))?;
                file.write_all(json.as_bytes()).await?;
                file.flush().await?;
            }
            // r6 (agy P1 auth.rs:1659): a new account instance starts with no cached stamp.
            self.revocations.remove(&uname);
            set_secret_mode(&user_path).await; // #31: 0600 on the user record
            Ok(RegisterOutcome { verify_token: None, email_in_use: false })
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
        // #F13: scan the FULL directory unconditionally — do NOT return on the first
        // match. The old early return made a REGISTERED email resolve after reading only
        // up to its file, while an UNKNOWN email always read every file, an email-existence
        // timing oracle observable on both the login and reset paths that call this. Register
        // enforces one account per email, so the single match is unambiguous; keeping it
        // (last write wins on the impossible duplicate) is correct.
        let mut found: Option<User> = None;
        if let Ok(mut entries) = tokio::fs::read_dir(&users_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    if let Ok(json) = tokio::fs::read_to_string(&path).await {
                        if let Ok(user) = serde_json::from_str::<User>(&json) {
                            if user.email == email_lower { found = Some(user); }
                        }
                    }
                }
            }
        }
        found
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

    // ── Unverified-account lifecycle (email-required mode) ───────────────────

    fn user_path(&self, uname: &str) -> PathBuf {
        PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", uname))
    }

    /// True if an UNEXPIRED email-verification link exists for `uname`. Fails closed (true)
    /// if the pending/ dir exists but can't be listed, so an IO glitch never makes a live
    /// signup look abandoned.
    async fn has_live_pending(&self, uname: &str) -> bool {
        let now = Utc::now().timestamp();
        let dir = PathBuf::from(&self.data_dir).join("pending");
        let mut rd = match tokio::fs::read_dir(&dir).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
            Err(_) => return true,
        };
        while let Ok(Some(entry)) = rd.next_entry().await {
            if let Ok(json) = tokio::fs::read_to_string(entry.path()).await {
                if let Ok(p) = serde_json::from_str::<PendingVerification>(&json) {
                    if p.username == uname && p.expires_at >= now { return true; }
                }
            }
        }
        false
    }

    /// Email-required register() helper, run under the email lock BEFORE the uniqueness
    /// checks. If users/<uname>.json already exists:
    ///  - a stale unverified account (unverified_is_stale) is reaped so the name is free → None;
    ///  - a still-pending unverified signup with the SAME email AND the same password gets a
    ///    fresh verification link (older links for it die) → Some(token). The password must
    ///    match: otherwise anyone who knew a pending signup's username + email could re-register
    ///    it with THEIR password and have the real owner's click activate it for them;
    ///  - anything else → None (the normal checks answer "taken" / email-in-use as before).
    async fn resend_or_reap_for_register(&self, held: &AdminFileLock, uname: &str, email_lower: &str, password: &str) -> Result<Option<String>> {
        if !is_safe_username(uname) { return Ok(None); }
        let path = self.user_path(uname);
        let Some((user, classified)) = read_user_record(&path).await else { return Ok(None) };
        let now = Utc::now().timestamp();
        if classified && unverified_is_stale(&user, now, self.has_live_pending(uname).await) {
            self.reap_if_stale_held(held, uname, false).await;
            return Ok(None);
        }
        let eligible = classified && resendable(&user, email_lower);
        // Always pay one Argon2 verify on this username-exists path (real hash when eligible,
        // dummy otherwise) so timing doesn't tell which accounts are re-sendable.
        let hash = if eligible { user.password_hash.clone() } else { dummy_argon2_hash().to_string() };
        let pw_ok = PasswordHash::new(&hash).ok()
            .map(|p| Argon2::default().verify_password(password.as_bytes(), &p).is_ok())
            .unwrap_or(false);
        if !(eligible && pw_ok) { return Ok(None); }
        // Re-check + mint under the per-user lock so a concurrent verify / approve / disable /
        // delete wins cleanly.
        let lock = self.user_lock(uname);
        let _guard = lock.lock().await;
        match read_user_record(&path).await {
            Some((u, true)) if resendable(&u, email_lower) => {}
            _ => return Ok(None),
        }
        self.remove_pending_records_for(uname).await;
        let token = Uuid::new_v4().to_string();
        let pending = PendingVerification {
            username: uname.to_string(), email: email_lower.to_string(),
            token: token.clone(), expires_at: Utc::now().timestamp() + VERIFY_TOKEN_TTL_SECS,
        };
        let pending_path = PathBuf::from(&self.data_dir).join("pending").join(format!("{}.json", token));
        tokio::fs::write(&pending_path, serde_json::to_string_pretty(&pending)?).await?;
        set_secret_mode(&pending_path).await; // #31: 0600 on the bearer token
        Ok(Some(token))
    }

    /// Email-required register() helper (under the email lock): reap every stale unverified
    /// account still holding `email_lower`, so it no longer blocks a real owner's signup.
    async fn reap_stale_holders_of_email(&self, held: &AdminFileLock, email_lower: &str) {
        if email_lower.is_empty() { return; }
        let users_dir = PathBuf::from(&self.data_dir).join("users");
        let mut holders = Vec::new();
        if let Ok(mut rd) = tokio::fs::read_dir(&users_dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        if let Some((u, true)) = read_user_record(&path).await {
                            if u.email == email_lower && unverified_reapable_shape(&u) {
                                holders.push(stem.to_string());
                            }
                        }
                    }
                }
            }
        }
        for h in holders { self.reap_if_stale_held(held, &h, false).await; }
    }

    /// Delete `uname` iff it is (re-checked under its lock) a stale unverified account —
    /// `gc=false`: unverified_is_stale (stops-blocking threshold); `gc=true`: the hourly
    /// reaper's UNVERIFIED_GC_AGE_SECS threshold. Never touches verified, disabled, admin,
    /// ever-logged-in, no-email or not-yet-classified records, nor any account that owns
    /// per-user data dirs. Returns true if reaped.
    async fn reap_if_stale(&self, uname: &str, gc: bool) -> bool {
        // The record is deleted, so this holds the cross-process account lock too.
        let Ok(held) = self.admin_lock_shared().await else { return false };
        self.reap_if_stale_held(&held, uname, gc).await
    }

    /// reap_if_stale with the account lock already held (register's email-locked section).
    async fn reap_if_stale_held(&self, held: &AdminFileLock, uname: &str, gc: bool) -> bool {
        if !is_safe_username(uname) { return false; }
        let lock = self.user_lock(uname);
        let _guard = lock.lock().await;
        let Some((user, true)) = read_user_record(&self.user_path(uname)).await else { return false };
        if user.username != uname { return false; }
        let now = Utc::now().timestamp();
        let stale = if gc {
            unverified_reapable_shape(&user) && now - user.created_at > UNVERIFIED_GC_AGE_SECS
        } else {
            unverified_is_stale(&user, now, self.has_live_pending(uname).await)
        };
        if !stale { return false; }
        // Belt and braces: an account that never logged in cannot own per-user data; if any
        // exists anyway, keep the account (fail closed on any error other than NotFound).
        // vaults/<u> matters most: delete_account doesn't remove it (purge_account does), and
        // crypto::migrate_legacy_vault can create one for every account, verified or not.
        for sub in ["users", "networks", "e2e", "vaults"] {
            match tokio::fs::metadata(PathBuf::from(&self.data_dir).join(sub).join(uname)).await {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                _ => return false,
            }
        }
        self.delete_account_locked(held, uname).await;
        tracing::info!("auth: reaped unverified account '{}' (created {}, never verified)", uname, user.created_at);
        true
    }

    /// Hourly maintenance (main.rs): garbage-collect unverified accounts older than
    /// UNVERIFIED_GC_AGE_SECS. Does nothing unless email verification is currently required
    /// (open / code modes never reap). Returns the number of accounts removed.
    pub async fn reap_stale_unverified(&self, email_required: bool) -> usize {
        if !email_required { return 0; }
        let users_dir = PathBuf::from(&self.data_dir).join("users");
        let now = Utc::now().timestamp();
        let mut cands = Vec::new();
        if let Ok(mut rd) = tokio::fs::read_dir(&users_dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        if let Some((u, true)) = read_user_record(&path).await {
                            if unverified_reapable_shape(&u) && now - u.created_at > UNVERIFIED_GC_AGE_SECS {
                                cands.push(stem.to_string());
                            }
                        }
                    }
                }
            }
        }
        let mut n = 0;
        for c in cands { if self.reap_if_stale(&c, true).await { n += 1; } }
        n
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

        // Find user by email. #37: swallow read_dir/next_entry I/O errors (return the
        // same generic Ok(None) as "unknown email") so a transient FS error can't make
        // the unknown-email path observably differ (Err) from the success path.
        let users_dir = PathBuf::from(&self.data_dir).join("users");
        let mut found_user: Option<User> = None;
        if let Ok(mut entries) = tokio::fs::read_dir(&users_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(json) = tokio::fs::read_to_string(entry.path()).await {
                    if let Ok(user) = serde_json::from_str::<User>(&json) {
                        // #F14: scan the FULL directory — do NOT break on the match. Breaking
                        // early made a registered email finish the scan sooner than an unknown
                        // one (which read every file), a timing oracle on top of the write below.
                        if user.email == email_lower && user.verified && !user.disabled {
                            found_user = Some(user);
                        }
                    }
                }
            }
        }

        let user = match found_user {
            Some(u) => u,
            None => return Ok(None), // Don't reveal whether the email exists
        };

        let token = Uuid::new_v4().to_string();
        let reset = PendingReset {
            username: user.username.clone(),
            token: token.clone(),
            expires_at: Utc::now().timestamp() + RESET_TOKEN_TTL_SECS, // 1 hour
            account_created: Some(user.created_at),
            cred_fp: Some(reset_cred_fingerprint(&user)),
        };
        // #F14: do the dir-create + old-token invalidation + new-token write in a spawned
        // task so a REGISTERED email's response isn't measurably slower than an unknown
        // email's (which returns right after the scan) — the write/chmod/create_dir were an
        // existence timing oracle. The verification mail is already sent by the caller off a
        // spawn, so the token is delivered well after the (millisecond) background write lands.
        let data_dir = self.data_dir.clone();
        let uname = user.username.clone();
        tokio::spawn(async move {
            Self::persist_reset(&data_dir, &reset).await;
        });

        Ok(Some((token, uname)))
    }

    /// #F14/#F15: (re)create a password-reset record off the request's response path.
    /// #F15: first delete this account's prior outstanding resets/*.json so a newer reset
    /// request invalidates older tokens (reset_password still removes the consumed one, and
    /// sweep_expired_tokens still enforces the TTL — single-use + expiry are preserved). Then
    /// write the fresh token 0600. Best-effort: any IO error just means no (or a stale-cleared)
    /// reset file, which reset_password treats as an invalid link.
    async fn persist_reset(data_dir: &str, reset: &PendingReset) {
        let reset_dir = PathBuf::from(data_dir).join("resets");
        let _ = create_dir_secure(reset_dir.to_str().unwrap_or_default()); // #32: 0700
        // #F15: invalidate the account's existing outstanding reset tokens (match by username).
        if let Ok(mut rd) = tokio::fs::read_dir(&reset_dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    if let Ok(json) = tokio::fs::read_to_string(&path).await {
                        if let Ok(old) = serde_json::from_str::<PendingReset>(&json) {
                            if old.username == reset.username {
                                let _ = tokio::fs::remove_file(&path).await;
                            }
                        }
                    }
                }
            }
        }
        // Write the fresh token AFTER the purge (its UUID name can't collide with the deletions).
        let reset_path = reset_dir.join(format!("{}.json", reset.token));
        if let Ok(json) = serde_json::to_string_pretty(reset) {
            if tokio::fs::write(&reset_path, json).await.is_ok() {
                set_secret_mode(&reset_path).await; // #31: 0600 on the bearer token
            }
        }
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
        if new_password.len() > 1024 {
            bail!("Password is too long (max 1024 characters)"); // #110
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
        // r4 F1-4: the account lock is never waited for while holding the user lock.
        let (_guards, held) = self.lock_with_admin(&[&lock]).await;
        let held = held?;
        // Single use, atomically: the token was read before the lock, so two concurrent
        // submissions of one link could both get here. The winner removes the file while
        // still holding this lock, so re-reading it under the lock lets exactly one through.
        let still_live = tokio::fs::read_to_string(&reset_path).await.ok()
            .and_then(|j| serde_json::from_str::<PendingReset>(&j).ok())
            .map_or(false, |r| r.username == reset.username && r.expires_at == reset.expires_at);
        if !still_live {
            bail!("Invalid or expired reset link");
        }
        let user_path = PathBuf::from(&self.data_dir)
            .join("users")
            .join(format!("{}.json", reset.username));
        let user_json = tokio::fs::read_to_string(&user_path).await
            .map_err(|_| anyhow::anyhow!("Account not found"))?;
        let mut user: User = serde_json::from_str(&user_json)?;

        // The token must belong to THIS account, not merely to this username: a token minted
        // before the account was deleted must never reset a later same-name re-registration.
        // New tokens carry the account's created_at; older tokens (no field) are refused if the
        // account was created after the token was minted (mint = expires_at - TTL). A disabled
        // account can't be reset through a link either (disable_user also deletes its tokens).
        // Tokens that carry a credential fingerprint also die once the password hash or the
        // recovery email changed after they were issued.
        let minted_at = reset.expires_at - RESET_TOKEN_TTL_SECS;
        let fp_changed = reset.cred_fp.as_deref().map_or(false, |fp| {
            use subtle::ConstantTimeEq;
            !bool::from(fp.as_bytes().ct_eq(reset_cred_fingerprint(&user).as_bytes()))
        });
        if reset.account_created.map_or(false, |c| c != user.created_at)
            || user.created_at > minted_at
            || user.disabled
            || fp_changed
        {
            let _ = tokio::fs::remove_file(&reset_path).await;
            bail!("Invalid or expired reset link");
        }

        let salt = SaltString::generate(&mut OsRng);
        user.password_hash = tuned_argon2()
            .hash_password(new_password.as_bytes(), &salt)
            .map_err(|_| anyhow::anyhow!("Password hashing failed"))?
            .to_string();
        // r5: every session minted before this reset is revoked durably (persisted stamp; the
        // in-memory purge below covers this process, the stamp every validate path).
        user.sessions_valid_after = user.sessions_valid_after.max(Utc::now().timestamp());

        self.write_user_atomic(&held, &reset.username, &user).await?;
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
        // r4 F1-4: the account lock is never waited for while holding the user lock.
        let (_guards, held) = self.lock_with_admin(&[&lock]).await;
        let held = held?;
        let user_path = PathBuf::from(&self.data_dir)
            .join("users")
            .join(format!("{}.json", pending.username));
        let user_json = tokio::fs::read_to_string(&user_path).await
            .map_err(|_| anyhow::anyhow!("Account not found"))?;
        let mut user: User = serde_json::from_str(&user_json)?;
        // A link minted before this account existed (a deleted/reaped same-name predecessor's)
        // never verifies the new account; nor does any link lift an admin's Disable (A3 — before
        // the flag, a banned user's still-live link set verified=true and un-banned them).
        if user.created_at > pending.expires_at - VERIFY_TOKEN_TTL_SECS || user.disabled {
            let _ = tokio::fs::remove_file(&pending_path).await;
            bail!("Invalid or expired verification link");
        }
        user.verified = true;
        self.write_user_atomic(&held, &pending.username, &user).await?;
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
        } else if is_safe_username(&ident) {
            // Only a name register() could have created is ever joined into a path: the raw
            // identifier used to be joined as-is, so "../x" read users/../x.json (pre-auth
            // path-traversal file read / User-shaped-file login). Anything else falls through
            // to the dummy-hash path below — same work, same generic error.
            let user_path = PathBuf::from(&self.data_dir)
                .join("users")
                .join(format!("{}.json", ident));
            tokio::fs::read_to_string(&user_path).await
                .ok()
                .and_then(|json| serde_json::from_str::<User>(&json).ok())
        } else {
            None
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
        // (The hash + created_at that were verified are re-checked under the lock below.)
        let verified_against = user_opt.as_ref().map(|u| (u.password_hash.clone(), u.created_at));
        let hash_str = match &user_opt {
            Some(u) if u.verified && !u.disabled => u.password_hash.clone(),
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
            Some(u) if u.verified && !u.disabled && verify_ok && is_safe_username(&u.username) => u.username.clone(),
            _ => bail!("Invalid username or password"),
        };

        // #63: serialize the session-cap eviction + insert under the per-user lock
        // so concurrent logins for the same user cannot both snapshot the same
        // count, evict the same "oldest", and both insert past the cap.
        let lock = self.user_lock(&uname);
        // The last_login write below is a record read→modify→write, so the cross-process
        // account lock is taken too (codex P4 resetpass.sh:487: a stale copy renamed in after
        // a script's reset would restore the old password). If a script holds it past the
        // bounded wait, the login still succeeds but skips the best-effort last_login update
        // rather than writing a possibly stale record. r4 F1-4 (agy P1 auth.rs:1359): taken
        // with lock_with_admin, so the user lock is not held during that wait (other requests
        // of this account used to queue behind a running admin script for up to 10 s).
        let (_guards, held) = self.lock_with_admin(&[&lock]).await;
        let held = held.ok();
        // Re-read the record UNDER the lock before minting a session: the read above was
        // unlocked and the Argon2 verify is slow, so an admin Disable or a deletion can land
        // in between (disable_user purges sessions under this same lock — a session minted
        // after it would outlive the ban; one minted after delete_account would be a ghost
        // session for a deleted account). Then record the last-login timestamp (best-effort).
        // A purge in progress refuses the login outright (codex P1 main.rs:372).
        if self.is_being_deleted(&uname) { bail!("Invalid username or password"); }
        {
            let upath = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", uname));
            let cur = tokio::fs::read_to_string(&upath).await.ok()
                .and_then(|j| serde_json::from_str::<User>(&j).ok());
            // The password may also have changed meanwhile (a reset or change-password holding
            // this lock installs a new hash and revokes every session): a login verified
            // against the OLD hash must not mint a fresh session afterwards. Same for an
            // account deleted and re-registered under the same name (different created_at).
            let same_cred = |u: &User| verified_against.as_ref()
                .map_or(false, |(h, c)| *h == u.password_hash && *c == u.created_at);
            match cur {
                Some(u) if !same_cred(&u) => bail!("Invalid username or password"),
                Some(mut u) if u.verified && !u.disabled => {
                    self.disabled_users.remove(&uname);
                    u.last_login = Utc::now().timestamp();
                    if let Some(held) = held.as_ref() {
                        let _ = self.write_user_atomic(held, &uname, &u).await;
                    }
                }
                Some(u) => {
                    if u.disabled { self.disabled_users.insert(uname.clone(), ()); }
                    bail!("Invalid username or password");
                }
                None => bail!("Invalid username or password"),
            }
        }
        drop(held); // the account lock covered only the record rewrite (as before)
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
        // Generation read under the user lock: a deletion can't begin before the insert
        // (begin_account_deletion takes the same lock), and one that begins after it revokes
        // this session and bumps the generation anyway.
        self.sessions.insert(token.clone(), Session {
            username: uname.clone(), created_at: Utc::now().timestamp(),
            last_used: Utc::now().timestamp(), epoch: self.account_epoch(&uname),
        });
        Ok((token, uname))
    }

    /// Mint a fresh session token for an already-authenticated user. Used after
    /// change_password() purges all sessions, so the caller who changed their OWN password
    /// isn't logged out (other devices stay purged — that's the security intent).
    /// (r4 V3S-1: the route uses issue_session_if_live; this unconditional form is kept for
    /// the tests.)
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn issue_session(&self, username: &str) -> String {
        let epoch = self.account_epoch(&username.to_lowercase());
        self.mint_session(username, epoch)
    }

    /// r4 V3S-1: issue_session for a request that was authorized at account generation
    /// `epoch` (taken when its session was validated). None — and no session — once a
    /// deletion of the account has begun since; and since the session is bound to `epoch`, one
    /// minted just before such a deletion still never validates after it.
    pub fn issue_session_if_live(&self, username: &str, epoch: u64) -> Option<String> {
        let uname = username.to_lowercase();
        if !self.account_ticket_live(&uname, epoch) { return None; }
        Some(self.mint_session(&uname, epoch))
    }

    fn mint_session(&self, username: &str, epoch: u64) -> String {
        let uname = username.to_lowercase();
        // #102: enforce the per-user session cap here too (it was previously bypassed),
        // so this post-change_password mint can't push a user above MAX_SESSIONS_PER_USER.
        loop {
            let user_sessions: Vec<String> = self.sessions.iter()
                .filter(|s| s.username == uname)
                .map(|s| s.key().clone())
                .collect();
            if user_sessions.len() < MAX_SESSIONS_PER_USER { break; }
            let oldest = user_sessions.iter()
                .min_by_key(|k| self.sessions.get(*k).map(|s| s.created_at).unwrap_or(i64::MAX))
                .cloned();
            match oldest { Some(k) => { self.sessions.remove(&k); } None => break }
        }
        let token = Uuid::new_v4().to_string();
        self.sessions.insert(token.clone(), Session {
            username: uname,
            created_at: Utc::now().timestamp(),
            last_used: Utc::now().timestamp(),
            epoch,
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
        let (user, created_at) = {
            let entry = self.sessions.get(&token)?;
            // #61: reject on absolute age OR inactivity. A3: also drop a disabled account's session
            // (disable_user already purges them; this closes the issue_session-after-disable race).
            if now - entry.created_at > SESSION_MAX_AGE_SECS
                || now - entry.last_used > SESSION_IDLE_MAX_SECS
                || self.disabled_users.contains_key(&entry.username)
                || self.deleting_users.contains_key(&entry.username)
                || entry.epoch != self.account_epoch(&entry.username) {   // r4 V3S-1
                drop(entry);
                self.sessions.remove(&token);
                return None;
            }
            (entry.username.clone(), entry.created_at)
        };
        // r5: revoked on disk (resetpass.sh / a password change), or the record is gone —
        // checked with no session-map lock held (it may read the record).
        if self.session_revoked(&user, created_at) {
            self.sessions.remove(&token);
            return None;
        }
        let mut entry = self.sessions.get_mut(&token)?;
        entry.last_used = now;
        Some(entry.username.clone())
    }

    /// r5 (codex P4 resetpass.sh:794): is a session of `user` created at `created_at` revoked by
    /// the record's `sessions_valid_after` stamp, or is the record gone? Learns of an admin
    /// script's edit made while the server runs by re-reading users/<name>.json when the file
    /// changed (inode/size/mtime/ctime, see RecordStamp) — at most one stat per user per
    /// REVOCATION_RECHECK, the hot path otherwise one
    /// map lookup. A transient read problem (or a half-written file) keeps the last known
    /// stamp and retries on the next check.
    fn session_revoked(&self, user: &str, created_at: i64) -> bool {
        self.session_revoked_at(user, created_at, false)
    }

    /// `fresh` (r9): skip the REVOCATION_RECHECK shortcut and look at the record itself.
    fn session_revoked_at(&self, user: &str, created_at: i64, fresh: bool) -> bool {
        let now = Instant::now();
        let now_unix = Utc::now().timestamp();
        let epoch = self.account_epoch(user);
        // r6 (agy P1 auth.rs:1659): a cached entry is used only for the same account generation
        // and only for a session minted before the entry was taken — a session of a NEW account
        // instance (same name re-registered, or the record re-created out of band within the
        // window) always looks at the record itself.
        let prev = self.revocations.get(user).filter(|e| e.epoch == epoch).map(|e| (e.checked, e.checked_unix, e.mtime, e.stamp));
        if let Some((checked, checked_unix, _, stamp)) = prev.filter(|_| !fresh) {
            if now.duration_since(checked) < self.revocation_recheck && created_at < checked_unix {
                return created_at < stamp;
            }
        }
        let path = self.user_path(user);
        let meta = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // No record: no session of this name is valid. Not cached (r6): the record
                // may be created again at any moment, and its sessions must not hit a stale
                // "missing" answer. Sessions of a missing record are dropped on this check.
                self.revocations.remove(user);
                return true;
            }
            Err(_) => return prev.map_or(false, |(_, _, _, st)| created_at < st),
        };
        let mtime = Some(record_stamp(&meta));
        let stamp = match prev {
            Some((_, _, mt, st)) if mt.is_some() && mt == mtime => st,
            _ => {
                let parsed = std::fs::read_to_string(&path).ok()
                    .and_then(|j| serde_json::from_str::<serde_json::Value>(&j).ok());
                match parsed {
                    Some(v) => v.get("sessions_valid_after").and_then(|x| x.as_i64()).unwrap_or(0),
                    None => {
                        // Unreadable right now: keep the last stamp, look again next time.
                        let st = prev.map_or(0, |(_, _, _, st)| st);
                        self.revocations.insert(user.to_string(), Revocation { checked: now, checked_unix: now_unix, epoch, mtime: None, stamp: st });
                        return created_at < st;
                    }
                }
            }
        };
        self.revocations.insert(user.to_string(), Revocation { checked: now, checked_unix: now_unix, epoch, mtime, stamp });
        created_at < stamp
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
        self.session_valid_for_at(raw_token, expected_user, false)
    }

    /// r9 (astra P4 resetpass.sh:717): session_valid_for without the up-to-1 s revocation cache —
    /// the record is looked at now. For a check made under the shared account lock right before a
    /// write that an admin script's purge must not be overtaken by.
    pub fn session_valid_now(&self, raw_token: &str, expected_user: &str) -> bool {
        self.session_valid_for_at(raw_token, expected_user, true)
    }

    fn session_valid_for_at(&self, raw_token: &str, expected_user: &str, fresh: bool) -> bool {
        let token = match validate_uuid(raw_token) { Some(t) => t, None => return false };
        let now = Utc::now().timestamp();
        let created_at = match self.sessions.get(&token) {
            Some(entry) => {
                let ok = entry.username == expected_user
                    && now - entry.created_at <= SESSION_MAX_AGE_SECS
                    && now - entry.last_used  <= SESSION_IDLE_MAX_SECS
                    && !self.disabled_users.contains_key(expected_user)
                    && !self.deleting_users.contains_key(expected_user)
                    && entry.epoch == self.account_epoch(expected_user);   // r4 V3S-1
                if !ok { return false; }
                entry.created_at
            }
            None => return false,
        };
        // r5: the on-disk revocation stamp / record existence (no map lock held).
        !self.session_revoked_at(expected_user, created_at, fresh)
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
        let (_guards, held) = self.lock_with_admin(&[&lock]).await; // r4 F1-4
        let held = Self::admin_lock_or_proceed(held);
        self.delete_account_locked(&held, &uname).await;
    }

    /// codex P1 main.rs:372: purge_account's first pass — everything delete_account removes
    /// EXCEPT users/<name>.json itself, so the username stays taken (create_new and the
    /// scripts' link() both fail on it) until the whole teardown, vault purge included, is
    /// done; purge_account then calls delete_account, which removes the record last.
    pub async fn delete_account_data(&self, username: &str) {
        let uname = username.trim().to_lowercase();
        if !is_safe_username(&uname) { return; }
        let lock = self.user_lock(&uname);
        let (_guards, held) = self.lock_with_admin(&[&lock]).await; // r4 F1-4
        let held = Self::admin_lock_or_proceed(held);
        self.delete_account_inner(&held, &uname, true).await;
    }

    /// The account lock for a deletion: a deletion must never be skipped, so if a script
    /// holds the lock past the bounded wait this proceeds without it (logged).
    fn admin_lock_or_proceed(held: Result<AdminFileLock>) -> AdminFileLock {
        match held {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!("auth: deleting an account without the account lock ({})", e);
                AdminFileLock { _file: None }
            }
        }
    }

    /// delete_account's body. Caller MUST hold user_lock(uname) and the account lock, and
    /// have validated it with is_safe_username (delete_account and reap_if_stale both do).
    async fn delete_account_locked(&self, held: &AdminFileLock, uname: &str) {
        self.delete_account_inner(held, uname, false).await;
    }

    /// `keep_record`: leave users/<name>.json in place (delete_account_data).
    async fn delete_account_inner(&self, _held: &AdminFileLock, uname: &str, keep_record: bool) {
        let uname = uname.to_string();
        // #6: enumerate the user's network config ids (filenames under
        // networks/<username>/) and delete the REAL per-conn_id logs dirs at
        // logs/<conn_id>/. The old code deleted logs/<username>, which never
        // existed, so encrypted message history survived account deletion.
        let net_root = PathBuf::from(&self.data_dir).join("networks");
        let net_dir = net_root.join(&uname);
        // logs/<conn_id> and certs/<conn_id> are keyed by conn_id ALONE, so a file name in this
        // user's networks/ dir that also names someone else's connection (a legacy pre-#23 file
        // carrying another user's UUID, or a re-cased copy) must never make us delete THEIR
        // history/certs. Collect every conn_id other users' networks/ dirs name (lowercased, so
        // re-cased variants match too); if that scan can't be completed, delete no per-conn data.
        let others = other_users_conn_ids(&net_root, &uname).await;
        if let Ok(mut rd) = tokio::fs::read_dir(&net_dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    if let Some(conn_id) = path.file_stem().and_then(|s| s.to_str()) {
                        // conn_id is a network UUID; validate before pathing. Only a CANONICAL id
                        // (exactly what Uuid::to_string mints: lowercase, hyphenated) that IS the
                        // file name counts — validate_uuid alone would case-fold "ABC…" onto
                        // another account's "abc…" dirs.
                        let canonical = validate_uuid(conn_id).filter(|id| id.as_str() == conn_id);
                        let claimed = match &others {
                            Some(set) => canonical.as_ref().map_or(false, |id| set.contains(id)),
                            None => true, // couldn't scan the other users → fail closed
                        };
                        if claimed {
                            tracing::warn!("delete_account({}): not deleting logs/certs for conn_id {} — another account's networks/ also names it (or networks/ is unreadable)", uname, conn_id);
                        }
                        if let Some(safe_id) = canonical.filter(|_| !claimed) {
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

        // Remove user JSON (last step of a purge: see delete_account_data)
        if !keep_record {
            let user_file = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", uname));
            let _ = tokio::fs::remove_file(&user_file).await;
        }
        // Remove any pending email-verification record(s) for this user — otherwise a
        // surviving non-expired record makes email_in_use() reject re-registration with the
        // same email for up to 24h ("Username already taken"), so a deleted user (or one who
        // deleted their own account) could not sign up again. (See remove_pending_records_for.)
        self.remove_pending_records_for(&uname).await;
        // ...and every outstanding password-reset token. They are keyed by username, so a
        // surviving one used to reset the password of whoever re-registered this name next
        // (account takeover); reset_password now also binds tokens to the account's created_at.
        self.remove_reset_records_for(&uname).await;
        // A later same-name account must not inherit this one's Disable.
        self.disabled_users.remove(&uname);
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
                     || now - s.last_used > SESSION_IDLE_MAX_SECS
                     || s.epoch != self.account_epoch(&s.username))   // r4 V3S-1: dead anyway
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

    /// True if users/<name>.json exists (any parseable or not — an unreadable record is still
    /// an account an admin must be able to delete). False for unsafe names.
    pub async fn account_exists(&self, username: &str) -> bool {
        let uname = username.trim().to_lowercase();
        if !is_safe_username(&uname) { return false; }
        tokio::fs::symlink_metadata(self.user_path(&uname)).await.is_ok()
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
                                "disabled": user.disabled,
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
        // cross-process account lock (see ADMIN_LOCK_FILE); r4 F1-4: never waited for under the user lock
        let (_guards, held) = self.lock_with_admin(&[&lock]).await;
        let held = held?;
        let path = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", uname));
        let json = tokio::fs::read_to_string(&path).await?;
        let mut user: User = serde_json::from_str(&json)?;
        user.admin = is_admin;
        self.write_user_atomic(&held, &uname, &user).await?;
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
        // cross-process account lock (see ADMIN_LOCK_FILE); r4 F1-4: never waited for under the user lock
        let (_guards, held) = self.lock_with_admin(&[&lock]).await;
        let held = held?;
        let path = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", uname));
        let json = tokio::fs::read_to_string(&path).await?;
        let mut user: User = serde_json::from_str(&json)?;
        user.verified = verified;
        self.write_user_atomic(&held, &uname, &user).await?;
        Ok(())
    }

    /// Admin "approve": verify a registered-but-unverified account WITHOUT requiring the
    /// user to click the email verification link. Mirrors verify_email's net effect — flip
    /// verified=true and drop the now-moot pending verification record — but is admin-
    /// initiated (no token). set_verified() validates the username, takes the per-user lock
    /// + atomic write, and errors if the account doesn't exist. Idempotent: re-approving an
    /// already-verified user is a harmless no-op. (If the user instead clicks the email
    /// link, verify_email does the same thing, so no approval is then needed.)
    ///
    /// A3: on a DISABLED account this also lifts the Disable (it is then exactly enable_user).
    /// That keeps the pre-flag admin panel working — a stale, service-worker-cached app.js
    /// shows a disabled user as "unverified" and offers Approve as the way back in — and the
    /// current panel shows "Enable login" (which calls this route) instead of Approve for a
    /// disabled account. Either way it is an explicit admin action on that one account, not
    /// the silent un-ban the CLI tools used to perform.
    pub async fn approve_user(&self, username: &str) -> Result<()> {
        self.enable_user(username).await.map(|_| ())
    }

    /// A3: lift an admin Disable (and/or approve): disabled=false, verified=true — the inverse
    /// of disable_user, which sets both disabled=true and verified=false. An account disabled
    /// before it ever verified its email therefore comes back verified: re-enabling it is the
    /// admin vouching for it, exactly like Approve. Drops any pending verification record
    /// (moot now) like verify_email / delete_account do. Errors if the account doesn't exist.
    pub async fn enable_user(&self, username: &str) -> Result<String> {
        let uname = username.to_lowercase();
        if !is_safe_username(&uname) { bail!("Invalid username"); }
        {
            let lock = self.user_lock(&uname);
            // cross-process account lock (see ADMIN_LOCK_FILE); r4 F1-4: never waited for under the user lock
            let (_guards, held) = self.lock_with_admin(&[&lock]).await;
            let held = held?;
            let path = self.user_path(&uname);
            let json = tokio::fs::read_to_string(&path).await?;
            let mut user: User = serde_json::from_str(&json)?;
            user.verified = true;
            user.disabled = false;
            self.write_user_atomic(&held, &uname, &user).await?;
            self.disabled_users.remove(&uname);
        }
        // Drop the pending record(s) so the dead link can't be replayed and a later
        // delete/re-register isn't blocked by a stale email match (same cleanup that
        // verify_email and delete_account do).
        self.remove_pending_records_for(&uname).await;
        Ok(uname)
    }

    /// Remove every outstanding password-reset token (resets/*.json) for `uname` (already
    /// lowercased). Used by delete_account and disable_user. Best-effort, like
    /// remove_pending_records_for.
    async fn remove_reset_records_for(&self, uname: &str) {
        let reset_dir = PathBuf::from(&self.data_dir).join("resets");
        if let Ok(mut rd) = tokio::fs::read_dir(&reset_dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    if let Ok(json) = tokio::fs::read_to_string(&path).await {
                        if let Ok(r) = serde_json::from_str::<PendingReset>(&json) {
                            if r.username == uname {
                                let _ = tokio::fs::remove_file(&path).await;
                            }
                        }
                    }
                }
            }
        }
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
        // cross-process account lock (see ADMIN_LOCK_FILE); r4 F1-4: never waited for under the user lock
        let (_guards, held) = self.lock_with_admin(&[&lock]).await;
        let held = held?;
        let path = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", uname));
        let json = tokio::fs::read_to_string(&path).await?;
        let mut user: User = serde_json::from_str(&json)?;
        user.can_upload = can_upload;
        self.write_user_atomic(&held, &uname, &user).await?;
        Ok(())
    }

    /// Set (or clear) a user's email address. Used by the user themselves (Profile) AND by
    /// an admin (set an email for an account that has none). Validates format + one-account-
    /// per-email uniqueness; a blank value clears the email. Locked + atomic like every mutator.
    /// This is the ADMIN path (the caller is an authenticated admin); the self-service route
    /// uses set_email_reauthed.
    pub async fn set_email(&self, username: &str, new_email: &str) -> Result<()> {
        self.set_email_inner(username, new_email, None).await
    }

    /// codex P1 main.rs:2860: the self-service email change. The password check
    /// (verify_current_password) runs unlocked and slowly before this, so a password reset
    /// (or change, disable, deletion) can commit in between and revoke the very authority
    /// the change was granted on. This re-checks, UNDER the same per-user lock those
    /// mutators hold, that (a) the caller's session still validates and (b) the record still
    /// carries the exact credential the password was verified against; otherwise nothing is
    /// written. Without a verified credential only a no-op (the address already on file)
    /// passes — decided on the locked record, not on an earlier unlocked read.
    pub async fn set_email_reauthed(&self, username: &str, new_email: &str, auth: EmailChangeAuth<'_>) -> Result<()> {
        self.set_email_inner(username, new_email, Some(auth)).await
    }

    async fn set_email_inner(&self, username: &str, new_email: &str, auth: Option<EmailChangeAuth<'_>>) -> Result<()> {
        let uname = username.to_lowercase();
        if !is_safe_username(&uname) { anyhow::bail!("Invalid username"); }
        let email_lower = new_email.trim().to_lowercase();
        // Same validator register() uses (#67): rejects control chars / CRLF, whitespace,
        // ','/';' multi-address lists, and anything lettre can't parse as one mailbox.
        if !email_lower.is_empty() && (!email_lower.contains('@') || email_lower.len() > 254
            || !crate::email::validate_email(&email_lower)) {
            bail!("Invalid email address");
        }
        // Serialize on the target email (mirrors register) so a concurrent signup/set with the
        // same address can't bind it to two accounts; then the per-user lock for the atomic write.
        // r4 F1-4: both mutexes and the cross-process account lock (see ADMIN_LOCK_FILE) via
        // lock_with_admin, so neither mutex is held while waiting for an admin script.
        let elock = if !email_lower.is_empty() { Some(self.email_lock(&email_lower)) } else { None };
        let lock = self.user_lock(&uname);
        let mut ms: Vec<&Arc<tokio::sync::Mutex<()>>> = Vec::with_capacity(2);
        if let Some(e) = elock.as_ref() { ms.push(e); }
        ms.push(&lock);
        let (_guards, held) = self.lock_with_admin(&ms).await;
        let held = held?;
        let path = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", uname));
        let json = tokio::fs::read_to_string(&path).await
            .map_err(|_| anyhow::anyhow!("Account not found"))?;
        let mut user: User = serde_json::from_str(&json)?;
        let changed = user.email != email_lower;
        if let Some(a) = auth.as_ref() {
            // Self-service: the session that asked must still be live (a reset, password
            // change, disable or deletion revokes it under this lock)...
            if !self.session_valid_for(a.session_token, &uname) {
                bail!(EMAIL_CHANGE_STALE);
            }
            // ...and an actual change needs the credential the password was verified
            // against to still be the account's (same hash, same account instance).
            if changed {
                match a.verified {
                    None => bail!(EMAIL_CHANGE_NEEDS_PASSWORD),
                    Some((h, c)) if *h == user.password_hash && *c == user.created_at => {}
                    Some(_) => bail!(EMAIL_CHANGE_STALE),
                }
            }
            if !changed { return Ok(()); } // nothing to write
        }
        // Allow a no-op set to the user's own current address; reject another account's.
        if !email_lower.is_empty() && changed && self.email_in_use(&email_lower).await {
            bail!("That email is already in use");
        }
        user.email = email_lower;
        self.write_user_atomic(&held, &uname, &user).await?;
        // A reset link mailed to the previous address must not outlive the change (new
        // tokens are also fingerprint-bound to the email; this covers older tokens too).
        if changed { self.remove_reset_records_for(&uname).await; }
        Ok(())
    }

    /// Current email of `username` (lowercased; "" when none or unknown). Lets the route
    /// tell a no-op save from a real change before asking for the password.
    pub async fn current_email(&self, username: &str) -> Option<String> {
        self.get_user(username).await.map(|u| u.email)
    }

    /// Check `password` against the account's current login password (Argon2 verify —
    /// callers run it through run_auth_kdf). Used to re-authenticate sensitive changes
    /// made with only a session token (e.g. the recovery email). Rate-limited per user
    /// like change_password so it can't become an online password oracle. On success returns
    /// the (password_hash, created_at) it verified against, which set_email_reauthed re-checks
    /// under the account lock before writing.
    pub async fn verify_current_password(&self, username: &str, password: &str, ip: Option<&str>) -> Result<(String, i64)> {
        let uname = username.trim().to_lowercase();
        if !is_safe_username(&uname) { bail!("Invalid username"); }
        self.check_ip_rate_limit("reauth", ip)?;
        self.check_rate_limit(&format!("reauth:{}", uname))?;
        let user = self.get_user(&uname).await.ok_or_else(|| anyhow::anyhow!("Account not found"))?;
        let ok = PasswordHash::new(&user.password_hash).ok()
            .map(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
            .unwrap_or(false);
        if !ok { bail!("Current password is incorrect"); }
        Ok((user.password_hash, user.created_at))
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
        // cross-process account lock (see ADMIN_LOCK_FILE); r4 F1-4: never waited for under the user lock
        let (_guards, held) = self.lock_with_admin(&[&lock]).await;
        let held = held?;
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
        self.write_user_atomic(&held, &uname, &user).await?;
        Ok(())
    }

    /// #F9: returns the resolved (lowercased) username on success so the route can purge
    /// the user's push subscription + notif-prefs stores (mirroring delete_account), which
    /// AuthManager itself has no NotificationManager handle to touch.
    pub async fn change_password(&self, username: &str, old_password: &str, new_password: &str, ip: Option<&str>) -> Result<String> {
        let uname = username.trim().to_lowercase();
        // #15: IP dimension FIRST (before the per-user bucket insert) so one IP can't fill
        // the global bucket table via varying usernames. See login() for the rationale.
        self.check_ip_rate_limit("chpass", ip)?;
        self.check_rate_limit(&format!("chpass:{}", uname))?;

        // #22: serialize the entire verify→mutate→write under the per-user lock.
        let lock = self.user_lock(&uname);
        // cross-process account lock (see ADMIN_LOCK_FILE); r4 F1-4: never waited for under the user lock
        let (_guards, held) = self.lock_with_admin(&[&lock]).await;
        let held = held?;

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
        if new_password.len() > 1024 {
            bail!("New password is too long (max 1024 characters)"); // #110
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
        user.password_hash = tuned_argon2()
            .hash_password(new_password.as_bytes(), &salt)
            .map_err(|_| anyhow::anyhow!("Password hashing failed"))?
            .to_string();
        // r5: other sessions minted before this change are revoked durably too (the route
        // re-issues the caller's session afterwards; its created_at is not before the stamp).
        user.sessions_valid_after = user.sessions_valid_after.max(Utc::now().timestamp());

        self.write_user_atomic(&held, &uname, &user).await?;
        // #62: invalidate ALL of this user's sessions after a password change so an
        // attacker who already holds a session token is logged out (mirrors
        // reset_password). The route layer can re-issue a session for the caller.
        let to_remove: Vec<String> = self.sessions.iter()
            .filter(|s| s.username == uname)
            .map(|s| s.key().clone())
            .collect();
        for k in to_remove { self.sessions.remove(&k); }
        // Outstanding reset links die with the old password (new tokens are fingerprint-
        // bound anyway; this also covers tokens minted before that field existed).
        self.remove_reset_records_for(&uname).await;
        Ok(uname)
    }

    /// #F9: returns the resolved (lowercased) username on success so the route can purge
    /// the user's push subscription + notif-prefs stores (mirroring delete_account).
    pub async fn disable_user(&self, username: &str) -> Result<String> {
        let uname = username.to_lowercase();
        // #58: reject path-unsafe usernames before touching the filesystem.
        if !is_safe_username(&uname) {
            bail!("Invalid username");
        }
        // #22: serialize read→mutate→write under the per-user lock + atomic write.
        let lock = self.user_lock(&uname);
        // cross-process account lock (see ADMIN_LOCK_FILE); r4 F1-4: never waited for under the user lock
        let (_guards, held) = self.lock_with_admin(&[&lock]).await;
        let held = held?;
        let path = PathBuf::from(&self.data_dir).join("users").join(format!("{}.json", uname));
        let json = tokio::fs::read_to_string(&path).await?;
        let mut user: User = serde_json::from_str(&json)?;
        // A3: the ban is its own flag now. verified=false is ALSO kept, as before, so an older
        // binary or script that predates `disabled` (a rollback) still refuses this login.
        user.disabled = true;
        user.verified = false;
        self.write_user_atomic(&held, &uname, &user).await?;
        self.disabled_users.insert(uname.clone(), ());
        // Purge their sessions
        let to_remove: Vec<String> = self.sessions.iter()
            .filter(|s| s.username == uname)
            .map(|s| s.key().clone()).collect();
        for k in to_remove { self.sessions.remove(&k); }
        // Kill outstanding links too: a pre-ban reset link would let the banned user keep
        // changing the password, and a still-live verification link used to un-ban them.
        self.remove_reset_records_for(&uname).await;
        self.remove_pending_records_for(&uname).await;
        Ok(uname)
    }
}

/// #22/#34/#58: Validate a username for safe filesystem-path use. Matches the exact
/// ASCII charset and length registration now enforces — `[A-Za-z0-9_-]`, 3–32 bytes.
/// ASCII-only means no two distinct names can collide to one on-disk path via NFC
/// normalization or case-folding on a case-insensitive FS. '.'/'..'/empty rejected.
/// Used before any path join in delete_account / disable_user / set_admin / etc.
pub fn is_safe_username(s: &str) -> bool {
    if s.len() < 3 || s.len() > 32 { return false; }
    if s == "." || s == ".." { return false; }
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Read + parse a user record. Returns (user, classified), where `classified` means the file
/// carries the `disabled` key — i.e. it was written by a build that knows the flag (or by
/// migrate_legacy_disabled_flag). Unclassified legacy records are never reaped or re-sent.
async fn read_user_record(path: &std::path::Path) -> Option<(User, bool)> {
    let json = tokio::fs::read_to_string(path).await.ok()?;
    let val: serde_json::Value = serde_json::from_str(&json).ok()?;
    let classified = val.as_object()?.contains_key("disabled");
    let user: User = serde_json::from_value(val).ok()?;
    Some((user, classified))
}

/// Every conn_id (file stem, lowercased) named by a `*.json` file in ANY networks/<other>/ dir
/// except `uname`'s. None if networks/ (or one of its per-user dirs) exists but can't be
/// listed, so the caller can fail closed. A missing networks/ dir is an empty set.
async fn other_users_conn_ids(net_root: &std::path::Path, uname: &str) -> Option<std::collections::HashSet<String>> {
    let mut set = std::collections::HashSet::new();
    let mut rd = match tokio::fs::read_dir(net_root).await {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(set),
        Err(_) => return None,
    };
    loop {
        let entry = match rd.next_entry().await { Ok(Some(e)) => e, Ok(None) => break, Err(_) => return None };
        if entry.file_name().to_str() == Some(uname) { continue; }
        let is_dir = match entry.file_type().await { Ok(t) => t.is_dir(), Err(_) => return None };
        if !is_dir { continue; }
        let mut sub = match tokio::fs::read_dir(entry.path()).await { Ok(s) => s, Err(_) => return None };
        loop {
            let f = match sub.next_entry().await { Ok(Some(f)) => f, Ok(None) => break, Err(_) => return None };
            let p = f.path();
            if p.extension().map(|e| e == "json").unwrap_or(false) {
                if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                    set.insert(stem.to_ascii_lowercase());
                }
            }
        }
    }
    Some(set)
}

/// The only shape of account the unverified-account lifecycle may ever delete or re-send:
/// unverified, not disabled, not admin, never logged in, with an email on file.
fn unverified_reapable_shape(u: &User) -> bool {
    !u.verified && !u.disabled && !u.admin && u.last_login == 0 && !u.email.is_empty()
}

/// Email-required mode: an unverified signup that can no longer be verified — its link
/// expired (older than the verify TTL with no live link left), or it is older than
/// UNVERIFIED_GC_AGE_SECS whatever links it re-sent. Such an account stops blocking its
/// username and email (register reaps it on demand); the hourly reaper deletes it at GC age.
fn unverified_is_stale(u: &User, now: i64, has_live_pending: bool) -> bool {
    if !unverified_reapable_shape(u) { return false; }
    let age = now - u.created_at;
    (age > VERIFY_TOKEN_TTL_SECS && !has_live_pending) || age > UNVERIFIED_GC_AGE_SECS
}

/// An unverified signup whose verification link may be re-sent to `email_lower`.
fn resendable(u: &User, email_lower: &str) -> bool {
    unverified_reapable_shape(u) && u.email == email_lower
}

/// A3 migration — runs from AuthManager::new on every start, before any request is served.
///
/// Before the `disabled` field existed, admin "Disable login" stored a ban as verified=false,
/// which on disk looks exactly like a signup that never verified its email. This classifies
/// every users/*.json record that has verified=false and NO `disabled` key, writing the key
/// (true or false) so the record is never re-examined (idempotent). It only uses evidence the
/// old code left behind:
///   1. last_login > 0 → DISABLED. login() only ever records a login for a verified account,
///      and disable_user() was the only code path that ever set verified=false afterwards.
///   2. admin → left as unverified (disabled=false): makeadmin.sh grants admin to unverified
///      accounts (and warns about it), while the panel never offered Disable on an admin.
///      Admins are never reaped either way.
///   3. email == "" → DISABLED. No signup path makes an unverified account without an email
///      (email-required mode demands one; every other mode auto-verifies).
///   4. otherwise (never logged in, has an email): it is a plain unverified signup
///      (disabled=false) ONLY when the signup's own pending/<token>.json still exists and the
///      record is not newer than it — register() writes that file right AFTER the user
///      record, so an untouched record is never newer than it, while any later rewrite
///      (disable_user, or an admin toggling upload / admin / email on it) is. Everything
///      else becomes DISABLED, the fail-safe side (never reaped, never silently un-banned,
///      shown as "disabled" in the panel, one click on Enable login / Delete to resolve).
///      There is deliberately NO mtime fallback for a record without a pending file (w-srv
///      NEW-5 follow-up): an open/code-mode signup never writes one, so an account banned
///      seconds after an auto-verified signup looks exactly like an untouched record, and
///      classifying it "awaiting verification" let the banned user re-verify (resend) and
///      lift the ban. The cost is that an email-mode signup whose link expired and was swept
///      before the upgrade is also shown as disabled — which, like before the reaper
///      existed, just keeps its name until an admin deletes or enables it.
/// Before rewriting, the original bytes are saved (once, never overwritten) to
/// <data>/migration-backup/disabled-flag-v1/<user>.json (dir 0700, file 0600); the record is
/// then replaced via temp file + rename with every other key preserved. Best-effort: any
/// failure skips that record (it stays exactly as it was) and never blocks startup.
fn migrate_legacy_disabled_flag(data_dir: &str) {
    let users_dir = PathBuf::from(data_dir).join("users");
    let Ok(rd) = std::fs::read_dir(&users_dir) else { return };
    let backup_dir = PathBuf::from(data_dir).join("migration-backup").join("disabled-flag-v1");
    let (mut n_disabled, mut n_unverified) = (0usize, 0usize);
    // Newest pending-verification record mtime per username (rule 4a). Read lazily: only
    // needed when a candidate record reaches rule 4.
    let mut pending_mtimes: Option<std::collections::HashMap<String, std::time::SystemTime>> = None;
    let load_pending = || {
        let mut m: std::collections::HashMap<String, std::time::SystemTime> = std::collections::HashMap::new();
        if let Ok(prd) = std::fs::read_dir(PathBuf::from(data_dir).join("pending")) {
            for e in prd.flatten() {
                let p = e.path();
                if p.extension().map(|x| x != "json").unwrap_or(true) { continue; }
                let Ok(pm) = std::fs::symlink_metadata(&p) else { continue };
                if !pm.file_type().is_file() { continue; }
                let Ok(t) = pm.modified() else { continue };
                let Some(pv) = std::fs::read_to_string(&p).ok()
                    .and_then(|s| serde_json::from_str::<PendingVerification>(&s).ok()) else { continue };
                let slot = m.entry(pv.username.to_ascii_lowercase()).or_insert(t);
                if t > *slot { *slot = t; }
            }
        }
        m
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.extension().map(|e| e != "json").unwrap_or(true) { continue; }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()).map(str::to_string) else { continue };
        if !is_safe_username(&stem) { continue; }
        let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
        if !meta.file_type().is_file() { continue; }
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
        let needs = match val.as_object() {
            Some(o) => !o.contains_key("disabled") && o.get("verified").and_then(|v| v.as_bool()) == Some(false),
            None => false,
        };
        if !needs { continue; }
        let Ok(u) = serde_json::from_value::<User>(val.clone()) else { continue };
        let disabled = if u.last_login > 0 {
            true
        } else if u.admin {
            false
        } else if u.email.is_empty() {
            true
        } else {
            let pend = pending_mtimes.get_or_insert_with(|| load_pending()).get(&stem.to_ascii_lowercase()).copied();
            match (pend, meta.modified().ok()) {
                // Rule 4: newer than the signup's own pending record → rewritten after signup.
                (Some(p), Some(m)) => m > p,
                // No pending witness (auto-verified signup later banned, or a link long
                // expired): cannot prove untouched → fail-safe DISABLED.
                _ => true,
            }
        };
        // Back up the untouched original first; without a backup, don't migrate this record.
        if let Err(e) = create_dir_secure(&backup_dir.to_string_lossy()) {
            tracing::warn!("auth migration: cannot create {}: {} — skipping", backup_dir.display(), e);
            return;
        }
        match write_new_secret_sync(&backup_dir.join(format!("{}.json", stem)), text.as_bytes()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {} // keep the first original
            Err(e) => { tracing::warn!("auth migration: backup of {} failed: {} — skipping", stem, e); continue; }
        }
        if let Some(o) = val.as_object_mut() { o.insert("disabled".into(), serde_json::Value::Bool(disabled)); }
        let Ok(out) = serde_json::to_string_pretty(&val) else { continue };
        let tmp = users_dir.join(format!("{}.json.tmp.{}", stem, Uuid::new_v4()));
        if let Err(e) = write_new_secret_sync(&tmp, out.as_bytes()).and_then(|_| std::fs::rename(&tmp, &path)) {
            let _ = std::fs::remove_file(&tmp);
            tracing::warn!("auth migration: rewriting {} failed: {}", path.display(), e);
            continue;
        }
        if disabled { n_disabled += 1; } else { n_unverified += 1; }
    }
    if n_disabled + n_unverified > 0 {
        tracing::info!("auth migration: classified {} legacy unverified account(s): {} disabled, {} awaiting email verification (originals in {})",
            n_disabled + n_unverified, n_disabled, n_unverified, backup_dir.display());
    }
}

/// Create a NEW file (O_EXCL, never follows/overwrites) with mode 0600 and fsync it.
fn write_new_secret_sync(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
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

#[cfg(test)]
mod coreauth_fix_tests {
    //! 2026-11-01 coreauth fixes: reset-token survival, login traversal, unverified squatting,
    //! set_email validation, and the A3 disabled-vs-unverified split (incl. legacy migration).
    use super::*;

    const PW: &str = "Correct1!horse";
    const PW2: &str = "Another2@pass";

    fn tmp(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("coreauth-test-{}-{}", tag, Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }
    fn read_json(p: &str) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }
    fn write_json(p: &str, v: &serde_json::Value) {
        std::fs::write(p, serde_json::to_string_pretty(v).unwrap()).unwrap();
    }
    fn count_dir(p: &str) -> usize {
        std::fs::read_dir(p).map(|r| r.filter_map(|e| e.ok()).count()).unwrap_or(0)
    }
    /// Age a user record's created_at by `secs` (and its pending records' expiry with it).
    fn age_account(d: &str, uname: &str, secs: i64) {
        let up = format!("{}/users/{}.json", d, uname);
        let mut v = read_json(&up);
        v["created_at"] = serde_json::json!(v["created_at"].as_i64().unwrap() - secs);
        write_json(&up, &v);
        for e in std::fs::read_dir(format!("{}/pending", d)).unwrap().flatten() {
            let p = e.path().to_string_lossy().into_owned();
            let mut pv = read_json(&p);
            if pv["username"] == uname {
                pv["expires_at"] = serde_json::json!(pv["expires_at"].as_i64().unwrap() - secs);
                write_json(&p, &pv);
            }
        }
    }
    async fn wait_for_files(dir: &str, n: usize) {
        for _ in 0..100 {
            if count_dir(dir) >= n { return; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    // ── HIGH: reset token survived account deletion (auditor repro, now asserting the fix) ──
    #[tokio::test]
    async fn reset_token_dies_with_account() {
        let d = tmp("reset"); let a = AuthManager::new(&d).unwrap();
        a.register("victimname", "old@example.com", PW, Some("1.1.1.1"), false).await.unwrap();
        let (tok, _) = a.request_password_reset("old@example.com", Some("1.1.1.1")).await.unwrap().unwrap();
        wait_for_files(&format!("{}/resets", d), 1).await;
        a.delete_account("victimname").await;
        let left = count_dir(&format!("{}/resets", d));
        a.register("victimname", "", PW2, Some("2.2.2.2"), false).await.unwrap();
        let r = a.reset_password(&tok, "Hijacked3#pass", Some("1.1.1.1")).await;
        let hijack = a.login("victimname", "Hijacked3#pass", Some("3.3.3.3")).await.is_ok();
        let owner = a.login("victimname", PW2, Some("4.4.4.4")).await.is_ok();
        println!("FIX reset-after-delete: reset files left after delete={} reset_result={:?} hijack_login={} new_owner_login={}", left, r.as_ref().map(|s| s.clone()), hijack, owner);
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(left, 0);
        assert!(r.is_err() && !hijack && owner);
    }

    // Defence in depth: a token that somehow survives (e.g. minted by an older build, no
    // account_created field) still can't reset an account created after it was minted.
    #[tokio::test]
    async fn legacy_reset_token_bound_by_mint_time() {
        let d = tmp("legacyreset"); let a = AuthManager::new(&d).unwrap();
        a.register("newowner", "", PW, Some("1.1.1.1"), false).await.unwrap();
        let now = Utc::now().timestamp();
        let write_tok = |minted: i64| {
            let t = Uuid::new_v4().to_string();
            let v = serde_json::json!({"username":"newowner","token":t,"expires_at":minted + RESET_TOKEN_TTL_SECS});
            write_json(&format!("{}/resets/{}.json", d, t), &v);
            t
        };
        let stale = write_tok(now - 120);           // minted before the account existed
        let r1 = a.reset_password(&stale, "Hijacked3#pass", Some("1.1.1.1")).await;
        // ...but a legacy token minted for THIS account (after its creation) still works.
        let mut v = read_json(&format!("{}/users/newowner.json", d));
        v["created_at"] = serde_json::json!(now - 600);
        write_json(&format!("{}/users/newowner.json", d), &v);
        let good = write_tok(now - 60);
        let r2 = a.reset_password(&good, "Legit4$pass!", Some("1.1.1.1")).await;
        let login = a.login("newowner", "Legit4$pass!", Some("2.2.2.2")).await.is_ok();
        println!("FIX legacy reset token: predates-account={:?} legit-legacy={:?} login={}", r1.is_ok(), r2.is_ok(), login);
        let _ = std::fs::remove_dir_all(&d);
        assert!(r1.is_err() && r2.is_ok() && login);
    }

    #[tokio::test]
    async fn reset_flow_still_works_and_token_is_bound() {
        let d = tmp("resetok"); let a = AuthManager::new(&d).unwrap();
        a.register("resetme", "me@example.com", PW, Some("1.1.1.1"), false).await.unwrap();
        let (tok, who) = a.request_password_reset("ME@example.com", Some("1.1.1.1")).await.unwrap().unwrap();
        wait_for_files(&format!("{}/resets", d), 1).await;
        let rec = read_json(&format!("{}/resets/{}.json", d, tok));
        let created = read_json(&format!("{}/users/resetme.json", d))["created_at"].clone();
        assert_eq!(rec["account_created"], created);
        let r = a.reset_password(&tok, "Brand5%newpw", Some("1.1.1.1")).await.unwrap();
        assert_eq!((who.as_str(), r.as_str()), ("resetme", "resetme"));
        assert!(a.login("resetme", "Brand5%newpw", Some("2.2.2.2")).await.is_ok());
        assert!(a.login("me@example.com", "Brand5%newpw", Some("3.3.3.3")).await.is_ok());
        assert!(a.reset_password(&tok, "Again6^newpw", Some("1.1.1.1")).await.is_err()); // single use
        let _ = std::fs::remove_dir_all(&d);
    }

    // ── MEDIUM: login identifier joined into a path unchecked (auditor repro, now asserting) ──
    #[tokio::test]
    async fn login_rejects_traversal_identifier() {
        let d = tmp("trav");
        std::fs::create_dir_all(format!("{}/users", d)).unwrap();
        let planted = User {
            username: "planted".into(), email: "".into(),
            password_hash: tuned_argon2().hash_password(b"Secret9!pw", &SaltString::generate(&mut OsRng)).unwrap().to_string(),
            verified: true, created_at: 0, admin: true, can_upload: true, last_login: 0,
            lastfm_user: String::new(), lastfm_key: String::new(), disabled: false, sessions_valid_after: 0,
        };
        std::fs::write(format!("{}/planted.json", d), serde_json::to_string(&planted).unwrap()).unwrap();
        let a = AuthManager::new(&d).unwrap();
        let r = a.login("../planted", "Secret9!pw", Some("9.9.9.9")).await;
        let r2 = a.login("..%2Fplanted", "Secret9!pw", Some("9.9.9.8")).await;
        println!("FIX login-traversal: login(../planted) ok={}", r.is_ok());
        // Normal username + email login keep working.
        a.register("normal_user", "Normal@Example.com", PW, Some("1.1.1.1"), false).await.unwrap();
        let by_name  = a.login("Normal_User", PW, Some("2.2.2.2")).await;
        let by_email = a.login("normal@example.com", PW, Some("3.3.3.3")).await;
        let _ = std::fs::remove_dir_all(&d);
        assert!(r.is_err() && r2.is_err(), "traversal identifier must not authenticate");
        assert_eq!(by_name.unwrap().1, "normal_user");
        assert_eq!(by_email.unwrap().1, "normal_user");
    }

    // ── MEDIUM: unverified accounts squatted username + email forever ──────────────────
    #[tokio::test]
    async fn stale_unverified_squat_releases_email_and_username() {
        let d = tmp("unv"); let a = AuthManager::new(&d).unwrap();
        let out = a.register("squatter", "victim@example.com", PW, Some("1.1.1.1"), true).await.unwrap();
        let tok = out.verify_token.unwrap();
        // Within the TTL the email stays reserved (email-bomb guard unchanged).
        let early = a.register("realowner", "victim@example.com", PW2, Some("2.2.2.2"), true).await.unwrap();
        assert!(early.email_in_use && early.verify_token.is_none());
        // Past the TTL with the link expired + swept: the squat no longer blocks.
        age_account(&d, "squatter", VERIFY_TOKEN_TTL_SECS + 60);
        a.sweep_expired_tokens().await;
        let ver = a.verify_email(&tok, Some("1.1.1.1")).await;
        let again = a.register("realowner", "victim@example.com", PW2, Some("3.3.3.3"), true).await.unwrap();
        let squat_gone = !std::path::Path::new(&format!("{}/users/squatter.json", d)).exists();
        println!("FIX unverified: verify_after_sweep_ok={} second_signup email_in_use={} token_minted={} squat_reaped={}", ver.is_ok(), again.email_in_use, again.verify_token.is_some(), squat_gone);
        assert!(ver.is_err() && !again.email_in_use && again.verify_token.is_some() && squat_gone);
        // The real owner can verify and log in.
        a.verify_email(&again.verify_token.unwrap(), Some("3.3.3.3")).await.unwrap();
        assert!(a.login("victim@example.com", PW2, Some("4.4.4.4")).await.is_ok());
        // And the squatted USERNAME is free again too (stale → reaped on demand).
        let o3 = a.register("taken2", "t2@example.com", PW, Some("5.5.5.5"), true).await.unwrap();
        assert!(o3.verify_token.is_some());
        age_account(&d, "taken2", VERIFY_TOKEN_TTL_SECS + 60);
        a.sweep_expired_tokens().await;
        let o4 = a.register("taken2", "other@example.com", PW2, Some("6.6.6.6"), true).await;
        assert!(o4.as_ref().map(|o| o.verify_token.is_some()).unwrap_or(false), "stale username reusable: {:?}", o4.err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn resend_requires_same_email_and_password() {
        let d = tmp("resend"); let a = AuthManager::new(&d).unwrap();
        let t1 = a.register("pend", "pend@example.com", PW, Some("1.1.1.1"), true).await.unwrap().verify_token.unwrap();
        // Same username + email + password → a fresh link; the old one dies.
        let o2 = a.register("pend", "pend@example.com", PW, Some("1.1.1.2"), true).await.unwrap();
        let t2 = o2.verify_token.clone().unwrap();
        assert!(!o2.email_in_use && t2 != t1);
        assert_eq!(count_dir(&format!("{}/pending", d)), 1);
        // Someone else re-registering it with THEIR password gets the masked answer, no link,
        // and the stored password is untouched.
        let o3 = a.register("pend", "pend@example.com", PW2, Some("1.1.1.3"), true).await.unwrap();
        assert!(o3.email_in_use && o3.verify_token.is_none());
        // Different email → still "taken".
        let o4 = a.register("pend", "x@example.com", PW, Some("1.1.1.4"), true).await;
        assert!(o4.err().map(|e| e.to_string().contains("taken")).unwrap_or(false));
        assert!(a.verify_email(&t1, Some("1.1.1.5")).await.is_err());
        a.verify_email(&t2, Some("1.1.1.6")).await.unwrap();
        assert!(a.login("pend", PW, Some("1.1.1.7")).await.is_ok());
        assert!(a.login("pend", PW2, Some("1.1.1.8")).await.is_err());
        // A verified account is never "re-sent".
        let o5 = a.register("pend", "pend@example.com", PW, Some("1.1.1.9"), true).await.unwrap();
        assert!(o5.email_in_use && o5.verify_token.is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn reaper_only_in_email_mode_and_only_never_verified() {
        let d = tmp("reap"); let a = AuthManager::new(&d).unwrap();
        a.register("oldunv", "oldunv@example.com", PW, Some("1.1.1.1"), true).await.unwrap();
        a.register("freshunv", "freshunv@example.com", PW, Some("1.1.1.2"), true).await.unwrap();
        a.register("oldver", "oldver@example.com", PW, Some("1.1.1.3"), false).await.unwrap();
        a.register("olddis", "olddis@example.com", PW, Some("1.1.1.4"), false).await.unwrap();
        a.disable_user("olddis").await.unwrap();
        a.register("oldadm", "oldadm@example.com", PW, Some("1.1.1.5"), true).await.unwrap();
        a.set_admin("oldadm", true).await.unwrap();
        for u in ["oldunv", "oldver", "olddis", "oldadm"] { age_account(&d, u, UNVERIFIED_GC_AGE_SECS + 60); }
        // Within GC age (but past TTL) an admin can still approve; the reaper leaves it.
        age_account(&d, "freshunv", VERIFY_TOKEN_TTL_SECS + 60);
        assert_eq!(a.reap_stale_unverified(false).await, 0, "never reap in non-email modes");
        assert_eq!(a.reap_stale_unverified(true).await, 1);
        let exists = |u: &str| std::path::Path::new(&format!("{}/users/{}.json", d, u)).exists();
        println!("FIX reaper: oldunv={} freshunv={} oldver={} olddis={} oldadm={}", exists("oldunv"), exists("freshunv"), exists("oldver"), exists("olddis"), exists("oldadm"));
        assert!(!exists("oldunv") && exists("freshunv") && exists("oldver") && exists("olddis") && exists("oldadm"));
        a.approve_user("freshunv").await.unwrap();
        assert!(a.login("freshunv", PW, Some("2.2.2.2")).await.is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    // ── LOW: set_email skipped validate_email (auditor repro, now asserting) ──────────────
    #[tokio::test]
    async fn set_email_uses_register_validator() {
        let d = tmp("email"); let a = AuthManager::new(&d).unwrap();
        a.register("someuser", "", PW, Some("1.1.1.1"), false).await.unwrap();
        let bad = ["a@b.com, c@d.com", "a@b.com;c@d.com", "a@b.com\r\nBcc: x@y.com", "a b@c.com", "@nope"];
        for b in bad {
            let r = a.set_email("someuser", b).await;
            println!("FIX set_email({:?}) -> ok={}", b, r.is_ok());
            assert!(r.is_err(), "{:?} must be rejected", b);
        }
        assert!(a.set_email("someuser", "Good@Example.com").await.is_ok());
        assert_eq!(a.get_user("someuser").await.unwrap().email, "good@example.com");
        assert!(a.set_email("someuser", "").await.is_ok());
        assert_eq!(a.get_user("someuser").await.unwrap().email, "");
        let _ = std::fs::remove_dir_all(&d);
    }

    // ── A3: disable is its own flag; verify/reset/links can't silently lift it ────────────
    #[tokio::test]
    async fn disable_is_distinct_and_sticky() {
        let d = tmp("dis"); let a = AuthManager::new(&d).unwrap();
        a.register("bob", "bob@example.com", PW, Some("1.1.1.1"), false).await.unwrap();
        let (tok, _) = a.login("bob", PW, Some("1.1.1.2")).await.unwrap();
        assert_eq!(a.validate_session(&tok).as_deref(), Some("bob"));
        a.disable_user("bob").await.unwrap();
        let rec = read_json(&format!("{}/users/bob.json", d));
        assert_eq!((rec["disabled"].as_bool(), rec["verified"].as_bool()), (Some(true), Some(false)));
        assert!(a.validate_session(&tok).is_none());
        assert!(a.login("bob", PW, Some("1.1.1.3")).await.is_err());
        // A session minted after the ban (issue_session race) is refused too.
        let late = a.issue_session("bob");
        assert!(a.validate_session(&late).is_none() && !a.session_valid_for(&late, "bob"));
        // What `resetpass.sh --verify` / an old tool does (verified=true only) no longer un-bans.
        a.set_verified("bob", true).await.unwrap();
        assert!(a.login("bob", PW, Some("1.1.1.4")).await.is_err(), "--verify must not lift a ban");
        // Neither does a reset request (no token for a disabled account).
        assert!(a.request_password_reset("bob@example.com", Some("1.1.1.5")).await.unwrap().is_none());
        let listed = a.list_users().await;
        assert_eq!(listed[0]["disabled"], serde_json::json!(true));
        // Enable lifts it.
        a.enable_user("bob").await.unwrap();
        assert!(a.login("bob", PW, Some("1.1.1.6")).await.is_ok());
        // Approve on a disabled account also lifts it (pre-flag admin panel compatibility).
        a.disable_user("bob").await.unwrap();
        a.approve_user("bob").await.unwrap();
        assert!(a.login("bob", PW, Some("1.1.1.7")).await.is_ok());
        // Delete + re-register the same name: the new account is not disabled.
        a.disable_user("bob").await.unwrap();
        a.delete_account("bob").await;
        a.register("bob", "", PW2, Some("1.1.1.8"), false).await.unwrap();
        let (t2, _) = a.login("bob", PW2, Some("1.1.1.9")).await.unwrap();
        assert!(a.validate_session(&t2).is_some());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn verify_link_cannot_unban_and_old_links_cannot_verify_new_account() {
        let d = tmp("vlink"); let a = AuthManager::new(&d).unwrap();
        let t = a.register("eve", "eve@example.com", PW, Some("1.1.1.1"), true).await.unwrap().verify_token.unwrap();
        // Keep a copy of the pending record, disable (which deletes it), then restore it.
        let pp = format!("{}/pending/{}.json", d, t);
        let saved = std::fs::read_to_string(&pp).unwrap();
        a.disable_user("eve").await.unwrap();
        assert!(!std::path::Path::new(&pp).exists());
        std::fs::write(&pp, &saved).unwrap();
        assert!(a.verify_email(&t, Some("1.1.1.2")).await.is_err());
        assert!(a.login("eve", PW, Some("1.1.1.3")).await.is_err());
        // A predecessor's link (minted before this account was created) can't verify it.
        a.delete_account("eve").await;
        let t2 = a.register("eve", "eve@example.com", PW2, Some("1.1.1.4"), true).await.unwrap().verify_token.unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&saved).unwrap();
        v["expires_at"] = serde_json::json!(Utc::now().timestamp() + VERIFY_TOKEN_TTL_SECS - 120);
        write_json(&pp, &v);
        assert!(a.verify_email(&t, Some("1.1.1.5")).await.is_err());
        a.verify_email(&t2, Some("1.1.1.6")).await.unwrap();
        assert!(a.login("eve", PW2, Some("1.1.1.7")).await.is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    // delete_account must never delete ANOTHER account's logs/<id> or certs/<id> because the
    // deleted user's networks/ dir names the same conn_id (planted / legacy / re-cased file).
    #[tokio::test]
    async fn delete_account_spares_other_users_conn_dirs() {
        let d = tmp("conn"); let a = AuthManager::new(&d).unwrap();
        a.register("usera", "", PW, Some("1.1.1.1"), false).await.unwrap();
        a.register("userb", "", PW, Some("1.1.1.2"), false).await.unwrap();
        let x = Uuid::new_v4().to_string();            // B's real connection
        let y = Uuid::new_v4().to_string();            // A's own real connection
        let mk = |p: String| { std::fs::create_dir_all(&p).unwrap(); std::fs::write(format!("{}/data", p), b"x").unwrap(); };
        let touch = |p: String| { std::fs::create_dir_all(std::path::Path::new(&p).parent().unwrap()).unwrap(); std::fs::write(p, b"{}").unwrap(); };
        touch(format!("{}/networks/userb/{}.json", d, x));
        mk(format!("{}/logs/{}", d, x)); mk(format!("{}/certs/{}", d, x));
        // A: a planted copy of B's id, an upper-cased variant, and A's own network.
        touch(format!("{}/networks/usera/{}.json", d, x));
        touch(format!("{}/networks/usera/{}.json", d, x.to_uppercase()));
        touch(format!("{}/networks/usera/{}.json", d, y));
        mk(format!("{}/logs/{}", d, y)); mk(format!("{}/certs/{}", d, y));
        a.delete_account("usera").await;
        let ex = |p: String| std::path::Path::new(&p).exists();
        let b_logs = ex(format!("{}/logs/{}/data", d, x));
        let b_certs = ex(format!("{}/certs/{}/data", d, x));
        let a_logs = ex(format!("{}/logs/{}", d, y));
        let a_certs = ex(format!("{}/certs/{}", d, y));
        println!("FIX delete conn-collision: B logs kept={} B certs kept={} A logs removed={} A certs removed={} A networks removed={}",
            b_logs, b_certs, !a_logs, !a_certs, !ex(format!("{}/networks/usera", d)));
        assert!(b_logs && b_certs, "another account's logs/certs must survive");
        assert!(!a_logs && !a_certs, "the deleted account's own logs/certs are still removed");
        assert!(ex(format!("{}/networks/userb/{}.json", d, x)) && !ex(format!("{}/networks/usera", d)));
        // Deleting B afterwards (no more collision) removes B's dirs normally.
        a.delete_account("userb").await;
        assert!(!ex(format!("{}/logs/{}", d, x)) && !ex(format!("{}/certs/{}", d, x)));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn legacy_records_without_disabled_field_load_and_migrate() {
        let d = tmp("mig");
        std::fs::create_dir_all(format!("{}/users", d)).unwrap();
        let hash = tuned_argon2().hash_password(PW.as_bytes(), &SaltString::generate(&mut OsRng)).unwrap().to_string();
        let now = Utc::now().timestamp();
        let created = now - 5 * 86400;
        let mk = |name: &str, email: &str, verified: bool, admin: bool, last_login: i64, touched: bool| {
            let p = format!("{}/users/{}.json", d, name);
            // Exactly the pre-flag on-disk shape (no "disabled" key), plus an unknown key that
            // must survive the rewrite.
            let v = serde_json::json!({"username":name,"email":email,"password_hash":hash,"verified":verified,
                "created_at":created,"admin":admin,"can_upload":false,"last_login":last_login,
                "lastfm_user":"","lastfm_key":"","future_field":"keep-me"});
            write_json(&p, &v);
            let mt = std::time::UNIX_EPOCH + Duration::from_secs((created + if touched { 3600 } else { 2 }) as u64);
            std::fs::File::options().write(true).open(&p).unwrap().set_modified(mt).unwrap();
        };
        mk("wasbanned", "wb@example.com", false, false, now - 86400, true); // rule 1
        mk("unvadmin",  "ua@example.com", false, true,  0, true);           // rule 2
        mk("noemail",   "",               false, false, 0, true);           // rule 3
        mk("pendsign",  "ps@example.com", false, false, 0, false);          // rule 4, untouched + pending record
        mk("nopend",    "np@example.com", false, false, 0, false);          // rule 4, untouched, no pending (r3: fail-safe)
        mk("touched",   "tt@example.com", false, false, 0, true);           // rule 4, touched
        // The signup's pending record, written just after the user record (mtime created+3).
        std::fs::create_dir_all(format!("{}/pending", d)).unwrap();
        let ptok = Uuid::new_v4().to_string();
        let pp = format!("{}/pending/{}.json", d, ptok);
        write_json(&pp, &serde_json::json!({"username":"pendsign","email":"ps@example.com","token":ptok,"expires_at":now + 3600}));
        std::fs::File::options().write(true).open(&pp).unwrap().set_modified(std::time::UNIX_EPOCH + Duration::from_secs((created + 3) as u64)).unwrap();
        mk("normal",    "nn@example.com", true,  false, now - 10, true);    // not a candidate
        // Old record shape still deserializes (serde default).
        let u: User = serde_json::from_str(&std::fs::read_to_string(format!("{}/users/normal.json", d)).unwrap()).unwrap();
        assert!(!u.disabled);
        let normal_before = std::fs::read_to_string(format!("{}/users/normal.json", d)).unwrap();
        let a = AuthManager::new(&d).unwrap();
        let get = |n: &str| read_json(&format!("{}/users/{}.json", d, n));
        let dis = |n: &str| get(n)["disabled"].as_bool();
        println!("FIX migration: wasbanned={:?} unvadmin={:?} noemail={:?} pendsign={:?} nopend={:?} touched={:?} normal={:?}",
            dis("wasbanned"), dis("unvadmin"), dis("noemail"), dis("pendsign"), dis("nopend"), dis("touched"), dis("normal"));
        assert_eq!(dis("wasbanned"), Some(true));
        assert_eq!(dis("unvadmin"), Some(false));
        assert_eq!(dis("noemail"), Some(true));
        assert_eq!(dis("pendsign"), Some(false));
        assert_eq!(dis("nopend"), Some(true), "no pending witness → fail-safe disabled (w-srv NEW-5)");
        assert_eq!(dis("touched"), Some(true));
        assert_eq!(dis("normal"), None, "verified records are left byte-identical");
        assert_eq!(std::fs::read_to_string(format!("{}/users/normal.json", d)).unwrap(), normal_before);
        assert_eq!(get("wasbanned")["future_field"], "keep-me");
        assert_eq!(get("wasbanned")["verified"], false);
        let bdir = format!("{}/migration-backup/disabled-flag-v1", d);
        assert_eq!(count_dir(&bdir), 6);
        assert!(read_json(&format!("{}/wasbanned.json", bdir)).get("disabled").is_none());
        // Idempotent: a second start changes nothing and keeps the original backups.
        let snap = std::fs::read_to_string(format!("{}/users/touched.json", d)).unwrap();
        drop(a);
        let a = AuthManager::new(&d).unwrap();
        assert_eq!(std::fs::read_to_string(format!("{}/users/touched.json", d)).unwrap(), snap);
        assert_eq!(count_dir(&bdir), 6);
        // Migrated ban: login refused, Enable restores the account with its old password.
        assert!(a.login("wasbanned", PW, Some("1.1.1.1")).await.is_err());
        a.enable_user("wasbanned").await.unwrap();
        assert!(a.login("wasbanned", PW, Some("1.1.1.2")).await.is_ok());
        // Migrated plain signup: never reaped while the reaper is off; is reaped at GC age.
        assert_eq!(a.reap_stale_unverified(false).await, 0);
        assert_eq!(a.reap_stale_unverified(true).await, 0, "5 days old < GC age");
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod r2_srv_a_auth_tests {
    //! Round-2 (srv-a) fixes: reset links bound to the credentials they were issued for,
    //! single-use reset consumption under concurrency, login re-checked under the user lock,
    //! and the legacy disabled-flag migration's pending-record evidence.
    use super::*;

    const PW: &str = "Correct1!horse";
    const PW2: &str = "Another2@pass";

    fn tmp(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("r2srva-test-{}-{}", tag, Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }
    fn read_json(p: &str) -> serde_json::Value { serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap() }
    fn write_json(p: &str, v: &serde_json::Value) { std::fs::write(p, serde_json::to_string_pretty(v).unwrap()).unwrap(); }
    async fn wait_for(path: &str) {
        for _ in 0..200 {
            if std::path::Path::new(path).exists() { return; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("{} never appeared", path);
    }
    async fn mint(a: &AuthManager, d: &str, email: &str, ip: &str) -> String {
        let (tok, _) = a.request_password_reset(email, Some(ip)).await.unwrap().unwrap();
        wait_for(&format!("{}/resets/{}.json", d, tok)).await;
        tok
    }

    #[tokio::test]
    async fn reset_link_dies_when_password_or_email_changes() {
        let d = tmp("fp"); let a = AuthManager::new(&d).unwrap();
        a.register("fpuser", "fp@example.com", PW, Some("1.1.1.1"), false).await.unwrap();
        // The token carries the fingerprint of the credentials it was issued for.
        let t0 = mint(&a, &d, "fp@example.com", "1.1.1.1").await;
        let rec = read_json(&format!("{}/resets/{}.json", d, t0));
        assert_eq!(rec["cred_fp"].as_str().map(|s| s.len()), Some(64));
        // 1. change-password: the old link is dead.
        a.change_password("fpuser", PW, PW2, Some("1.1.1.1")).await.unwrap();
        let r1 = a.reset_password(&t0, "Hijack1!pass", Some("1.1.1.1")).await;
        // 2. resetpass.sh-style hand edit of password_hash (no AuthManager involved): dead.
        let t1 = mint(&a, &d, "fp@example.com", "1.1.1.2").await;
        let up = format!("{}/users/fpuser.json", d);
        let mut v = read_json(&up);
        v["password_hash"] = serde_json::json!(tuned_argon2().hash_password(b"Script3#pass", &SaltString::generate(&mut OsRng)).unwrap().to_string());
        write_json(&up, &v);
        let r2 = a.reset_password(&t1, "Hijack2!pass", Some("1.1.1.2")).await;
        assert!(std::path::Path::new(&format!("{}/resets/{}.json", d, t1)).exists() == false, "dead token is removed");
        // 3. email change: a link mailed to the old address is dead.
        let t2 = mint(&a, &d, "fp@example.com", "1.1.1.3").await;
        a.set_email("fpuser", "new@example.com").await.unwrap();
        let r3 = a.reset_password(&t2, "Hijack3!pass", Some("1.1.1.3")).await;
        // 4. a fresh link for the current credentials still works.
        let t3 = mint(&a, &d, "new@example.com", "1.1.1.4").await;
        let r4 = a.reset_password(&t3, "Fresh4$pass!", Some("1.1.1.4")).await;
        println!("R2 reset fingerprint: after chpass={:?} after hand-edit={:?} after email-change={:?} fresh={:?}",
            r1.is_ok(), r2.is_ok(), r3.is_ok(), r4.is_ok());
        assert!(r1.is_err() && r2.is_err() && r3.is_err());
        assert!(r4.is_ok());
        assert!(a.login("fpuser", "Fresh4$pass!", Some("2.2.2.2")).await.is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn legacy_reset_token_without_fingerprint_still_works() {
        // Minted by 7ee4ccb (no cred_fp): keeps working for its own account.
        let d = tmp("fplegacy"); let a = AuthManager::new(&d).unwrap();
        a.register("legacyfp", "", PW, Some("1.1.1.1"), false).await.unwrap();
        let up = format!("{}/users/legacyfp.json", d);
        let mut v = read_json(&up);
        let created = Utc::now().timestamp() - 600;
        v["created_at"] = serde_json::json!(created);
        write_json(&up, &v);
        let t = Uuid::new_v4().to_string();
        write_json(&format!("{}/resets/{}.json", d, t), &serde_json::json!({"username":"legacyfp","token":t,
            "expires_at": Utc::now().timestamp() - 60 + RESET_TOKEN_TTL_SECS, "account_created": created}));
        assert!(a.reset_password(&t, "Legacy5%pass", Some("1.1.1.1")).await.is_ok());
        assert!(a.login("legacyfp", "Legacy5%pass", Some("2.2.2.2")).await.is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_reset_submissions_are_single_use() {
        let d = tmp("race"); let a = Arc::new(AuthManager::new(&d).unwrap());
        a.register("racer", "race@example.com", PW, Some("1.1.1.1"), false).await.unwrap();
        let tok = mint(&a, &d, "race@example.com", "1.1.1.1").await;
        // Park both submissions behind the user lock after they have read the token file.
        let lock = a.user_lock("racer");
        let guard = lock.lock().await;
        let (a1, a2, t1, t2) = (a.clone(), a.clone(), tok.clone(), tok.clone());
        let h1 = tokio::spawn(async move { a1.reset_password(&t1, "Winner1!pass", Some("3.3.3.1")).await });
        let h2 = tokio::spawn(async move { a2.reset_password(&t2, "Winner2!pass", Some("3.3.3.2")).await });
        tokio::time::sleep(Duration::from_millis(500)).await;
        drop(guard);
        let (r1, r2) = (h1.await.unwrap(), h2.await.unwrap());
        let ok = [r1.is_ok(), r2.is_ok()];
        let l1 = a.login("racer", "Winner1!pass", Some("4.4.4.1")).await.is_ok();
        let l2 = a.login("racer", "Winner2!pass", Some("4.4.4.2")).await.is_ok();
        println!("R2 reset race: results={:?} login(pw1)={} login(pw2)={}", ok, l1, l2);
        assert_eq!(ok.iter().filter(|x| **x).count(), 1, "exactly one submission may consume the link");
        assert!(l1 ^ l2);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn login_verified_against_superseded_password_mints_no_session() {
        let d = tmp("loginrace"); let a = Arc::new(AuthManager::new(&d).unwrap());
        a.register("lrace", "", PW, Some("1.1.1.1"), false).await.unwrap();
        // Hold the user lock (as a concurrent reset would) while the login verifies PW.
        let lock = a.user_lock("lrace");
        let guard = lock.lock().await;
        let a1 = a.clone();
        let h = tokio::spawn(async move { a1.login("lrace", PW, Some("5.5.5.5")).await });
        tokio::time::sleep(Duration::from_millis(1500)).await; // Argon2 verify done, now waiting
        // The "reset" installs a new password while the login is parked.
        let up = format!("{}/users/lrace.json", d);
        let mut v = read_json(&up);
        v["password_hash"] = serde_json::json!(tuned_argon2().hash_password(PW2.as_bytes(), &SaltString::generate(&mut OsRng)).unwrap().to_string());
        write_json(&up, &v);
        drop(guard);
        let r = h.await.unwrap();
        let sessions = a.list_sessions("lrace").len();
        println!("R2 login race: stale-password login={:?} sessions={}", r.as_ref().map(|_| "SESSION"), sessions);
        assert!(r.is_err());
        assert_eq!(sessions, 0);
        // The new password logs in normally.
        assert!(a.login("lrace", PW2, Some("5.5.5.6")).await.is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn migration_uses_pending_record_evidence() {
        let d = tmp("migpend");
        std::fs::create_dir_all(format!("{}/users", d)).unwrap();
        std::fs::create_dir_all(format!("{}/pending", d)).unwrap();
        let hash = tuned_argon2().hash_password(PW.as_bytes(), &SaltString::generate(&mut OsRng)).unwrap().to_string();
        let created = Utc::now().timestamp() - 3600;
        let at = |secs: f64| std::time::UNIX_EPOCH + Duration::from_secs_f64(created as f64 + secs);
        let mk_user = |name: &str, mtime: f64| {
            let p = format!("{}/users/{}.json", d, name);
            write_json(&p, &serde_json::json!({"username":name,"email":format!("{}@example.com", name),"password_hash":hash,
                "verified":false,"created_at":created,"admin":false,"can_upload":false,"last_login":0,"lastfm_user":"","lastfm_key":""}));
            std::fs::File::options().write(true).open(&p).unwrap().set_modified(at(mtime)).unwrap();
        };
        let mk_pending = |name: &str, mtime: f64| {
            let t = Uuid::new_v4().to_string();
            let p = format!("{}/pending/{}.json", d, t);
            write_json(&p, &serde_json::json!({"username":name,"email":format!("{}@example.com", name),"token":t,"expires_at":created + 86400}));
            std::fs::File::options().write(true).open(&p).unwrap().set_modified(at(mtime)).unwrap();
        };
        // Banned ~1 s after signup, pending record still there: user record newer → disabled.
        mk_user("quickban", 1.0); mk_pending("quickban", 0.01);
        // Plain signup: pending written just after the user record → awaiting verification.
        mk_user("plainpend", 0.004); mk_pending("plainpend", 0.006);
        // Same-tick timestamps (coarse FS clock) still count as untouched.
        mk_user("sametick", 0.5); mk_pending("sametick", 0.5);
        // No pending record left: no witness that the record is untouched → disabled, however
        // close its mtime is to created_at (r3: w-srv NEW-5 — an auto-verified signup banned
        // ~1 s later has no pending record either; it must never read as "awaiting").
        mk_user("oldban", 20.0);
        mk_user("oldplain", 0.8);
        let _a = AuthManager::new(&d).unwrap();
        let dis = |n: &str| read_json(&format!("{}/users/{}.json", d, n))["disabled"].as_bool();
        println!("R2 migration: quickban={:?} plainpend={:?} sametick={:?} oldban={:?} oldplain={:?}",
            dis("quickban"), dis("plainpend"), dis("sametick"), dis("oldban"), dis("oldplain"));
        assert_eq!(dis("quickban"), Some(true));
        assert_eq!(dis("plainpend"), Some(false));
        assert_eq!(dis("sametick"), Some(false));
        assert_eq!(dis("oldban"), Some(true));
        assert_eq!(dis("oldplain"), Some(true));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn verify_current_password_checks_and_throttles() {
        let d = tmp("reauth"); let a = AuthManager::new(&d).unwrap();
        a.register("reauth", "", PW, Some("1.1.1.1"), false).await.unwrap();
        assert!(a.verify_current_password("reauth", PW, Some("6.6.6.1")).await.is_ok());
        assert!(a.verify_current_password("reauth", "wrong", Some("6.6.6.2")).await.is_err());
        assert!(a.verify_current_password("../x", PW, Some("6.6.6.3")).await.is_err());
        // Per-user budget (10/min) bounds online guessing even across IPs.
        let mut limited = false;
        for i in 0..12 { if a.verify_current_password("reauth", "wrong", Some(&format!("7.7.7.{}", i))).await.map_err(|e| e.to_string()).err().map_or(false, |e| e.contains("Too many")) { limited = true; } }
        assert!(limited);
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod r3_srv_a_auth_tests {
    //! Round-3 (srv-a): email change bound to the verified credential + session (codex P1
    //! main.rs:2860), the account-deletion window (codex P1 main.rs:372), and the server half
    //! of the cross-process account lock (codex P4 resetpass.sh:487 / adduser.sh:181).
    use super::*;

    const PW: &str = "Correct1!horse";
    const PW2: &str = "Another2@pass";

    fn tmp(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("r3srva-test-{}-{}", tag, Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }
    fn email_of(d: &str, u: &str) -> String {
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(format!("{}/users/{}.json", d, u)).unwrap()).unwrap();
        v["email"].as_str().unwrap_or("").to_string()
    }
    async fn mint(a: &AuthManager, d: &str, email: &str, ip: &str) -> String {
        let (tok, _) = a.request_password_reset(email, Some(ip)).await.unwrap().unwrap();
        let p = format!("{}/resets/{}.json", d, tok);
        for _ in 0..200 { if std::path::Path::new(&p).exists() { break; } tokio::time::sleep(Duration::from_millis(10)).await; }
        tok
    }
    /// Hold flock(LOCK_EX) on the account lock file from another thread, like a script.
    fn hold_ex(d: &str, ms: u64) -> std::thread::JoinHandle<()> {
        use std::os::unix::io::AsRawFd;
        let f = std::fs::OpenOptions::new().read(true).write(true).create(true).open(format!("{}/{}", d, ADMIN_LOCK_FILE)).unwrap();
        assert_eq!(unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) }, 0);
        std::thread::spawn(move || { std::thread::sleep(Duration::from_millis(ms)); drop(f); })
    }

    /// codex P1 main.rs:2860: the password was verified, then a reset committed (new hash,
    /// sessions revoked) before the email write — the write must not happen.
    #[tokio::test]
    async fn email_change_dies_when_a_reset_lands_after_the_password_check() {
        let d = tmp("emailrace"); let a = AuthManager::new(&d).unwrap();
        a.register("victim", "victim@example.com", PW, Some("1.1.1.1"), false).await.unwrap();
        let (sess, _) = a.login("victim", PW, Some("1.1.1.1")).await.unwrap();
        // The attacker's request: password verified (slow, unlocked) ...
        let cred = a.verify_current_password("victim", PW, Some("1.1.1.2")).await.unwrap();
        // ... meanwhile the victim resets the password ...
        let t = mint(&a, &d, "victim@example.com", "1.1.1.3").await;
        a.reset_password(&t, PW2, Some("1.1.1.3")).await.unwrap();
        // ... then the attacker's email write runs: refused, address unchanged.
        let r = a.set_email_reauthed("victim", "attacker@example.com",
            EmailChangeAuth { verified: Some(&cred), session_token: &sess }).await;
        println!("R3 email race: after-reset write = {:?}, stored = {}", r.as_ref().map_err(|e| e.to_string()), email_of(&d, "victim"));
        assert_eq!(r.unwrap_err().to_string(), EMAIL_CHANGE_STALE);
        assert_eq!(email_of(&d, "victim"), "victim@example.com");
        // A live session but a credential from before the reset: still refused.
        let (sess2, _) = a.login("victim", PW2, Some("1.1.1.4")).await.unwrap();
        let r = a.set_email_reauthed("victim", "attacker@example.com",
            EmailChangeAuth { verified: Some(&cred), session_token: &sess2 }).await;
        assert_eq!(r.unwrap_err().to_string(), EMAIL_CHANGE_STALE);
        // No password: only a no-op save passes; a real change needs one.
        assert!(a.set_email_reauthed("victim", "victim@example.com", EmailChangeAuth { verified: None, session_token: &sess2 }).await.is_ok());
        assert_eq!(a.set_email_reauthed("victim", "x@example.com", EmailChangeAuth { verified: None, session_token: &sess2 }).await.unwrap_err().to_string(),
            EMAIL_CHANGE_NEEDS_PASSWORD);
        // The current credential + live session: the change goes through.
        let cred2 = a.verify_current_password("victim", PW2, Some("1.1.1.5")).await.unwrap();
        a.set_email_reauthed("victim", "new@example.com", EmailChangeAuth { verified: Some(&cred2), session_token: &sess2 }).await.unwrap();
        assert_eq!(email_of(&d, "victim"), "new@example.com");
        // The admin path is unchanged.
        a.set_email("victim", "admin-set@example.com").await.unwrap();
        assert_eq!(email_of(&d, "victim"), "admin-set@example.com");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// codex P1 main.rs:372 (auth half): while a purge runs the name is unusable and cannot
    /// be re-registered, even after the record is gone, until the purge releases it.
    #[tokio::test]
    async fn username_stays_reserved_through_the_whole_deletion() {
        let d = tmp("delwin"); let a = AuthManager::new(&d).unwrap();
        a.register("gone", "gone@example.com", PW, Some("1.1.1.1"), false).await.unwrap();
        let (sess, _) = a.login("gone", PW, Some("1.1.1.1")).await.unwrap();
        a.begin_account_deletion("gone").await;
        assert!(a.validate_session(&sess).is_none(), "sessions revoked");
        assert!(a.login("gone", PW, Some("1.1.1.2")).await.is_err(), "no login mid-purge");
        a.delete_account_data("gone").await;
        assert!(std::path::Path::new(&format!("{}/users/gone.json", d)).exists(), "record kept until the end");
        assert!(a.register("gone", "", PW, Some("1.1.1.3"), false).await.is_err());
        a.delete_account("gone").await;
        assert!(!std::path::Path::new(&format!("{}/users/gone.json", d)).exists());
        // Record gone, purge not released yet: still taken (both register branches).
        let e1 = a.register("gone", "", PW, Some("1.1.1.4"), false).await.err().map(|e| e.to_string()).unwrap_or_default();
        let e2 = a.register("gone", "fresh@example.com", PW, Some("1.1.1.5"), false).await.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(e1.contains("taken") && e2.contains("taken"), "{e1} / {e2}");
        a.end_account_deletion("gone");
        assert!(!a.is_being_deleted("gone"));
        a.register("gone", "fresh@example.com", PW, Some("1.1.1.6"), false).await.unwrap();
        assert!(a.login("gone", PW, Some("1.1.1.7")).await.is_ok());
        // account_exists: the record decides (nonexistent / unsafe names are false).
        assert!(a.account_exists("gone").await && a.account_exists(" GONE ").await);
        assert!(!a.account_exists("nobody").await && !a.account_exists("../x").await);
        // Counted: two overlapping purges both hold the name.
        a.begin_account_deletion("gone").await;
        a.begin_account_deletion("gone").await;
        a.end_account_deletion("gone");
        assert!(a.is_being_deleted("gone"));
        a.end_account_deletion("gone");
        assert!(!a.is_being_deleted("gone"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// C4-3/C4-8 server half: a record write waits for a script's exclusive hold and never
    /// blocks the runtime meanwhile (current-thread runtime: a blocking wait would starve
    /// the ticker); the lock file is created 0600; shared holders don't exclude each other.
    #[tokio::test(flavor = "current_thread")]
    async fn record_writes_wait_for_a_script_without_blocking_the_runtime() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("flock"); let a = AuthManager::new(&d).unwrap();
        let lp = format!("{}/{}", d, ADMIN_LOCK_FILE);
        assert_eq!(std::fs::metadata(&lp).unwrap().permissions().mode() & 0o777, 0o600, "created 0600 at startup");
        a.register("locky", "", PW, Some("1.1.1.1"), false).await.unwrap();
        let held = hold_ex(&d, 600);
        let ticks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let t2 = ticks.clone();
        let ticker = tokio::spawn(async move { loop { tokio::time::sleep(Duration::from_millis(20)).await; t2.fetch_add(1, std::sync::atomic::Ordering::SeqCst); } });
        let t0 = Instant::now();
        a.set_admin("locky", true).await.unwrap();
        let waited = t0.elapsed();
        let n = ticks.load(std::sync::atomic::Ordering::SeqCst);
        println!("R3 flock: set_admin waited {:?} for the script; runtime ticks meanwhile = {}", waited, n);
        assert!(waited >= Duration::from_millis(450), "the write waited for the exclusive holder");
        assert!(n >= 10, "the runtime kept running while waiting ({n} ticks)");
        assert!(a.is_admin("locky").await);
        held.join().unwrap();
        // Two shared holders at once are fine.
        let g1 = a.admin_lock_shared().await.unwrap();
        let g2 = a.admin_lock_shared().await.unwrap();
        a.set_can_upload("locky", true).await.unwrap();
        drop((g1, g2));
        ticker.abort();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A script that keeps the lock past the bounded wait: mutations fail with a clear
    /// "busy" error (no deadlock), login still works but skips the last_login rewrite,
    /// registration reports busy; everything works again once it is released.
    #[tokio::test]
    async fn a_stuck_script_makes_writes_busy_not_hung() {
        let d = tmp("flockbusy"); let a = AuthManager::new(&d).unwrap();
        a.register("stuck", "stuck@example.com", PW, Some("1.1.1.1"), false).await.unwrap();
        let before = std::fs::read_to_string(format!("{}/users/stuck.json", d)).unwrap();
        let held = hold_ex(&d, 8000);
        let t0 = Instant::now();
        let e = a.set_admin("stuck", true).await.unwrap_err().to_string();
        assert_eq!(e, ADMIN_LOCK_BUSY);
        assert!(t0.elapsed() < Duration::from_secs(3), "bounded wait");
        let er = a.register("other", "o@example.com", PW, Some("1.1.1.3"), false).await.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(er.contains("busy"), "{er}");
        assert!(a.login("stuck", PW, Some("1.1.1.2")).await.is_ok(), "login is not blocked by a script");
        assert_eq!(std::fs::read_to_string(format!("{}/users/stuck.json", d)).unwrap(), before, "no record rewrite while held");
        assert!(t0.elapsed() < Duration::from_secs(8), "all of the above ran while the script held the lock");
        held.join().unwrap();
        a.set_admin("stuck", true).await.unwrap();
        a.register("other", "o@example.com", PW, Some("1.1.1.4"), false).await.unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Known degraded mode: a lock file the server can't use — a symlink (never followed, its
    /// target untouched), or one it can't open (as non-root, mode 000 stands in for a stray
    /// root-owned 0600 lock from an older script) — is left alone, and logins, registration and
    /// record writes keep working on the in-process locks alone (no error, no wait).
    #[tokio::test]
    async fn unusable_lock_file_degrades_to_in_process_locks() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("flockfix");
        let lp = format!("{}/{}", d, ADMIN_LOCK_FILE);
        let target = format!("{}/elsewhere", d);
        std::fs::write(&target, b"do not touch").unwrap();
        std::os::unix::fs::symlink(&target, &lp).unwrap();
        let a = AuthManager::new(&d).unwrap();
        assert!(std::fs::symlink_metadata(&lp).unwrap().file_type().is_symlink(), "left alone");
        a.register("deg1", "deg1@example.com", PW, Some("1.1.1.1"), false).await.unwrap();
        assert!(a.login("deg1", PW, Some("1.1.1.2")).await.is_ok());
        a.set_admin("deg1", true).await.unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"do not touch", "symlink target never written");
        // A regular file this process can't open.
        std::fs::remove_file(&lp).unwrap();
        std::fs::write(&lp, b"").unwrap();
        std::fs::set_permissions(&lp, std::fs::Permissions::from_mode(0o000)).unwrap();
        let a = AuthManager::new(&d).unwrap();
        a.register("deg2", "", PW, Some("1.1.1.3"), false).await.unwrap();
        assert!(a.login("deg2", PW, Some("1.1.1.4")).await.is_ok());
        // Time only record writes that take the account lock and hash nothing (register and
        // login pay Argon2, whose duration under CPU load says nothing about lock waits — r4:
        // this span used to include them and failed under a load average of ~40).
        let t0 = Instant::now();
        a.set_can_upload("deg2", true).await.unwrap();
        a.set_admin("deg2", false).await.unwrap();
        a.set_verified("deg2", true).await.unwrap();
        assert!(t0.elapsed() < ADMIN_LOCK_WAIT, "no bounded wait in degraded mode ({:?})", t0.elapsed());
        assert_eq!(std::fs::metadata(&lp).unwrap().permissions().mode() & 0o777, 0, "left alone");
        let _ = std::fs::set_permissions(&lp, std::fs::Permissions::from_mode(0o600));
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod r4_srv_a_auth_tests {
    //! Round-4 (srv-a): account generations (codex P1 bots.rs:2870 / w3-srv V3S-1) and the
    //! account lock no longer waited for under an in-process mutex (agy P1 auth.rs:1359).
    use super::*;

    const PW: &str = "Correct1!horse";

    fn tmp(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("r4srva-test-{}-{}", tag, Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }
    fn hold_ex(d: &str, ms: u64) -> std::thread::JoinHandle<()> {
        use std::os::unix::io::AsRawFd;
        let f = std::fs::OpenOptions::new().read(true).write(true).create(true).open(format!("{}/{}", d, ADMIN_LOCK_FILE)).unwrap();
        assert_eq!(unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) }, 0);
        std::thread::spawn(move || { std::thread::sleep(Duration::from_millis(ms)); drop(f); })
    }

    /// C1-1: work accepted for an account (its generation recorded) can't be delivered once a
    /// deletion of the name began — during it, after it, and after a same-name re-registration;
    /// the new account's own work is live.
    #[tokio::test]
    async fn work_of_a_deleted_account_never_reaches_the_next_same_name_account() {
        let d = tmp("epoch"); let a = AuthManager::new(&d).unwrap();
        a.register("alice", "", PW, Some("1.1.1.1"), false).await.unwrap();
        let before = a.account_epoch("alice");
        assert!(a.account_ticket_live("alice", before));
        a.begin_account_deletion("alice").await;
        let during = a.account_epoch("alice");
        assert!(!a.account_ticket_live("alice", before) && !a.account_ticket_live("alice", during));
        a.delete_account("alice").await;
        a.end_account_deletion("alice");
        a.register("alice", "", PW, Some("1.1.1.2"), false).await.unwrap();
        let after = a.account_epoch("alice");
        println!("R4 C1-1 generations: before={} during={} after={} live(before)={} live(during)={} live(after)={}",
            before, during, after, a.account_ticket_live("alice", before), a.account_ticket_live("alice", during), a.account_ticket_live("alice", after));
        assert!(!a.account_ticket_live("alice", before));
        assert!(!a.account_ticket_live("alice", during));
        assert!(a.account_ticket_live("alice", after));
        // Other names are unaffected.
        assert!(a.account_ticket_live("bob", a.account_epoch("bob")));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// V3S-1 (w3-srv): a session minted for the old account — by change-password's re-issue
    /// landing after the purge's last session sweep, or just before the deletion began — never
    /// validates for the account registered under the same name afterwards; the generation-
    /// checked re-issue refuses outright once the deletion began.
    #[tokio::test]
    async fn a_session_minted_for_a_deleted_account_dies_with_it() {
        let d = tmp("v3s1"); let a = AuthManager::new(&d).unwrap();
        a.register("carol", "", PW, Some("1.1.1.1"), false).await.unwrap();
        let (_s, _) = a.login("carol", PW, Some("1.1.1.1")).await.unwrap();
        let epoch = a.account_epoch("carol");             // route_change_password validated here
        let early = a.issue_session("carol");             // minted just before the deletion
        a.begin_account_deletion("carol").await;
        a.delete_account("carol").await;                  // the purge's last session sweep
        let late = a.issue_session("carol");              // the old unconditional re-issue (0d3570d/3b92eaf)
        assert!(a.issue_session_if_live("carol", epoch).is_none(), "re-issue refused once the deletion began");
        a.end_account_deletion("carol");
        a.register("carol", "", PW, Some("1.1.1.2"), false).await.unwrap();
        let early_ok = a.validate_session(&early).is_some();
        let late_ok = a.validate_session(&late).is_some();
        println!("R4 V3S-1: pre-deletion token valid for the new carol = {}, post-sweep token valid = {}", early_ok, late_ok);
        assert!(!early_ok && !late_ok);
        assert!(!a.session_valid_for(&late, "carol"));
        // Bound to its generation even if a sweep missed it: a token carrying the old
        // generation, inserted after the release, does not validate for the new carol.
        let ghost = a.mint_session("carol", epoch);
        assert!(a.validate_session(&ghost).is_none() && !a.session_valid_for(&ghost, "carol"));
        // The new account's own sessions work, including the generation-checked re-issue.
        let (s2, _) = a.login("carol", PW, Some("1.1.1.3")).await.unwrap();
        assert!(a.validate_session(&s2).is_some());
        let t = a.issue_session_if_live("carol", a.account_epoch("carol")).expect("live account");
        assert!(a.session_valid_for(&t, "carol"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// V3S-1 (w3-srv, CONFIRMED live): the verifier's exact sequence — a session minted after the
    /// purge's final delete_account (change-password's re-issue landing late) — must neither
    /// work while no account holds the name (planting window) nor for the next same-name
    /// account; nor may the generation-checked re-issue of the route mint one at all.
    #[tokio::test]
    async fn v3s1_session_minted_after_final_delete_dies_at_release() {
        let d = tmp("v3s1seq"); let a = AuthManager::new(&d).unwrap();
        a.register("gone", "", PW, Some("1.1.1.1"), false).await.unwrap();
        let route_epoch = a.account_epoch("gone");        // route_change_password validated its session
        a.begin_account_deletion("gone").await;
        a.delete_account_data("gone").await;
        a.delete_account("gone").await;
        let late = a.issue_session("gone");               // an unconditional late re-issue
        assert!(a.issue_session_if_live("gone", route_epoch).is_none(), "the route's re-issue is refused");
        a.end_account_deletion("gone");
        // Record gone, name free, nobody registered yet: the late token must not work.
        let planting = a.validate_session(&late);
        let late2 = a.mint_session("gone", route_epoch);  // and no pre-deletion generation works either
        assert!(planting.is_none() && a.validate_session(&late2).is_none(), "{planting:?}");
        a.register("gone", "", PW, Some("1.1.1.2"), false).await.unwrap();
        let v = a.validate_session(&late);
        println!("R4 V3S-1 sequence: late token while the name is free = {:?}, after re-registration = {:?}", planting, v);
        assert!(v.is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// F1-4 (agy P1 auth.rs:1359): while a script holds the account lock, an account's
    /// requests wait for it side by side instead of one after another behind the user lock.
    /// Before: each held the user lock through its own full bounded wait, so N requests took
    /// N × ADMIN_LOCK_WAIT. Also: the user lock is free during the wait.
    #[tokio::test(flavor = "current_thread")]
    async fn a_waiting_script_does_not_queue_the_accounts_requests() {
        let d = tmp("f14"); let a = AuthManager::new(&d).unwrap();
        a.register("queued", "", PW, Some("1.1.1.1"), false).await.unwrap();
        let held = hold_ex(&d, 3 * ADMIN_LOCK_WAIT.as_millis() as u64 + 1500);
        let t0 = Instant::now();
        let (r1, r2, r3) = tokio::join!(
            a.set_admin("queued", true),
            a.set_can_upload("queued", true),
            a.set_verified("queued", true),
        );
        let took = t0.elapsed();
        println!("R4 F1-4: three requests of one account during a script hold finished after {:?} (bounded wait {:?} each)", took, ADMIN_LOCK_WAIT);
        for r in [r1, r2, r3] { assert_eq!(r.unwrap_err().to_string(), ADMIN_LOCK_BUSY); }
        assert!(took < ADMIN_LOCK_WAIT * 2, "waits overlap (took {:?})", took);
        // The user lock is not held while lock_with_admin waits for the script.
        let lock = a.user_lock("queued");
        let a2 = &a;
        let waiter = async { a2.lock_with_admin(&[&lock]).await };
        let probe = async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            lock.try_lock().is_ok()
        };
        let ((g0, held2), free_meanwhile) = tokio::join!(waiter, probe);
        assert!(free_meanwhile, "user lock free during the wait");
        assert!(held2.is_err(), "still held by the script → busy after the bounded wait");
        assert!(lock.try_lock().is_err(), "but the user lock is held on return");
        drop(g0);
        held.join().unwrap();
        // Uncontended: immediate, both held.
        let t1 = Instant::now();
        let (g, h) = a.lock_with_admin(&[&lock]).await;
        assert!(h.is_ok() && g.len() == 1 && lock.try_lock().is_err() && t1.elapsed() < Duration::from_millis(500));
        drop(g);
        a.set_admin("queued", true).await.unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod r5_srv_a_auth_tests {
    //! r5 (codex P4 resetpass.sh:794): the persisted session revocation stamp.
    use super::*;
    const PW: &str = "Correct1!horse";
    fn tmp(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("r5srva-test-{}-{}", tag, Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }
    /// What resetpass.sh does under LOCK_EX while the server runs: edit the record on disk.
    fn script_sets_stamp(d: &str, user: &str, stamp: i64) {
        let p = format!("{}/users/{}.json", d, user);
        let mut v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        v["sessions_valid_after"] = serde_json::json!(stamp);
        let tmpf = format!("{}.tmp", p);
        std::fs::write(&tmpf, serde_json::to_string(&v).unwrap()).unwrap();
        std::fs::rename(&tmpf, &p).unwrap();
    }

    /// A stamp written to the record by a script revokes every older live session on every
    /// validate path (validate_session for HTTP / WS auth, session_valid_for for the WS
    /// re-validation and the push re-checks); sessions minted afterwards work; the server
    /// keeps the field on its own record rewrites.
    #[tokio::test]
    async fn a_stamp_written_on_disk_revokes_older_sessions() {
        let d = tmp("stamp"); let a = AuthManager::new(&d).unwrap();
        a.register("victim", "", PW, Some("1.1.1.1"), false).await.unwrap();
        let (s1, _) = a.login("victim", PW, Some("1.1.1.2")).await.unwrap();
        let (s2, _) = a.login("victim", PW, Some("1.1.1.3")).await.unwrap();
        assert!(a.validate_session(&s1).is_some() && a.session_valid_for(&s2, "victim"));
        let now = Utc::now().timestamp();
        script_sets_stamp(&d, "victim", now + 1);   // the contract: resetpass.sh writes now+1
        let r1 = a.validate_session(&s1); let r2 = a.session_valid_for(&s2, "victim");
        println!("R5 revocation stamp: old sessions after the on-disk stamp: validate={:?} valid_for={}", r1, r2);
        assert!(r1.is_none() && !r2);
        // After the stamp's second, a new login works.
        while Utc::now().timestamp() <= now + 1 { tokio::time::sleep(Duration::from_millis(50)).await; }
        let (s3, _) = a.login("victim", PW, Some("1.1.1.4")).await.unwrap();
        assert!(a.validate_session(&s3).is_some());
        // The server's own rewrite (login's last_login) keeps the stamp.
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(format!("{}/users/victim.json", d)).unwrap()).unwrap();
        assert_eq!(v["sessions_valid_after"].as_i64(), Some(now + 1));
        // A record that is gone: no session of that name validates.
        std::fs::remove_file(format!("{}/users/victim.json", d)).unwrap();
        assert!(a.validate_session(&s3).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The in-app password change revokes the OTHER sessions (in memory and by stamp) while the
    /// session re-issued to the caller (same second as the stamp) works.
    #[tokio::test]
    async fn change_password_revokes_other_sessions_but_not_the_reissued_one() {
        let d = tmp("chpw"); let a = AuthManager::new(&d).unwrap();
        a.register("chg", "", PW, Some("1.1.1.1"), false).await.unwrap();
        let (other, _) = a.login("chg", PW, Some("1.1.1.2")).await.unwrap();
        let epoch = a.account_epoch("chg");
        a.change_password("chg", PW, "N3w!Passw0rd#22", Some("1.1.1.3")).await.unwrap();
        let reissued = a.issue_session_if_live("chg", epoch).unwrap();
        assert!(a.validate_session(&other).is_none(), "other device logged out");
        assert!(a.validate_session(&reissued).is_some(), "the caller's re-issued session works");
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(format!("{}/users/chg.json", d)).unwrap()).unwrap();
        assert!(v["sessions_valid_after"].as_i64().unwrap_or(0) > 0, "stamp persisted");
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod r6_srv_a_auth_tests {
    //! r6 (agy P1 auth.rs:1659): the revocation cache must never judge a NEW account instance's
    //! sessions by what it learned about an earlier one (a missing record, or an old stamp).
    use super::*;
    const PW: &str = "Correct1!horse";
    fn tmp(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("r6srva-test-{}-{}", tag, Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }
    fn set_stamp(d: &str, user: &str, stamp: i64) {
        let p = format!("{}/users/{}.json", d, user);
        let mut v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        v["sessions_valid_after"] = serde_json::json!(stamp);
        std::fs::write(format!("{}.tmp", p), serde_json::to_string(&v).unwrap()).unwrap();
        std::fs::rename(format!("{}.tmp", p), &p).unwrap();
    }

    /// The record disappears (a session of it is refused), then the account is created again at
    /// once (out of band here; a same-name re-registration alike): the new account's session is
    /// valid immediately — no cached "missing" answer. Cache window set long, as in production.
    #[tokio::test]
    async fn a_recreated_account_is_not_judged_by_a_cached_missing_record() {
        let d = tmp("missing"); let mut a = AuthManager::new(&d).unwrap();
        a.revocation_recheck = Duration::from_secs(60);
        a.register("alice", "", PW, Some("1.1.1.1"), false).await.unwrap();
        let (s1, _) = a.login("alice", PW, Some("1.1.1.2")).await.unwrap();
        let p = format!("{}/users/alice.json", d);
        let rec = std::fs::read(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        assert!(a.validate_session(&s1).is_none(), "no record → refused");
        std::fs::write(&p, &rec).unwrap();
        // Minted without a server-side record write (which would also clear the cache), so only
        // the cache rule decides: f5796e1 answered from a cached "missing" for the whole window.
        let s2 = a.mint_session("alice", a.account_epoch("alice"));
        let v = a.validate_session(&s2);
        println!("R6 revocation cache: new session right after the record came back = {:?}", v);
        assert!(v.is_some());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A stamp of the deleted account (here a far-future one, as a script could leave it) does
    /// not reach the same-name account registered right after; a new account starts unstamped.
    #[tokio::test]
    async fn a_new_account_instance_starts_with_no_stamp() {
        let d = tmp("newgen"); let mut a = AuthManager::new(&d).unwrap();
        a.revocation_recheck = Duration::from_secs(60);
        a.register("bob", "", PW, Some("1.1.1.1"), false).await.unwrap();
        let (b1, _) = a.login("bob", PW, Some("1.1.1.2")).await.unwrap();
        set_stamp(&d, "bob", Utc::now().timestamp() + 30);
        assert!(a.validate_session(&b1).is_none(), "stamped → refused (and cached)");
        a.begin_account_deletion("bob").await;
        a.delete_account("bob").await;
        a.end_account_deletion("bob");
        a.register("bob", "", PW, Some("1.1.1.3"), false).await.unwrap();
        let (b2, _) = a.login("bob", PW, Some("1.1.1.4")).await.unwrap();
        assert!(a.validate_session(&b2).is_some(), "the new bob is not judged by the old stamp");
        let b3 = a.mint_session("bob", a.account_epoch("bob"));
        assert!(a.session_valid_for(&b3, "bob"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// As designed for the CURRENT account, with the cache on: after an in-app password change
    /// the re-issued session (same second as the stamp) works and older ones don't; a stamp set
    /// ahead of time (resetpass.sh's now+1) ends sessions minted before it, by design.
    #[tokio::test]
    async fn same_second_rules_for_the_current_account() {
        let d = tmp("cur"); let mut a = AuthManager::new(&d).unwrap();
        a.revocation_recheck = Duration::from_secs(60);
        a.register("carl", "", PW, Some("1.1.1.1"), false).await.unwrap();
        let (old, _) = a.login("carl", PW, Some("1.1.1.2")).await.unwrap();
        assert!(a.validate_session(&old).is_some());   // caches the unstamped record
        let epoch = a.account_epoch("carl");
        a.change_password("carl", PW, "N3w!Passw0rd#22", Some("1.1.1.3")).await.unwrap();
        let re = a.issue_session_if_live("carl", epoch).unwrap();
        assert!(a.validate_session(&re).is_some(), "re-issued session valid in the stamp's second");
        assert!(a.validate_session(&old).is_none());
        a.revocation_recheck = Duration::ZERO;   // the ≤ 1 s window has passed
        set_stamp(&d, "carl", Utc::now().timestamp() + 30);
        assert!(a.validate_session(&re).is_none(), "an admin stamp ahead of time ends it (resetpass rule)");
        let _ = std::fs::remove_dir_all(&d);
    }
}
