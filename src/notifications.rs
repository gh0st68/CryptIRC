/// notifications.rs — Web Push / VAPID notification engine
///
/// VAPID keys are generated once and stored in data/vapid.json.
/// Each user's push subscriptions are stored in data/push/{username}.json.
/// Notification preferences are stored in data/notif_prefs/{username}.json.
///
/// Push is sent when:
///   - A PRIVMSG arrives that mentions the user's current nick
///   - A DM (private query) arrives
///   - The user's pref allows it (all_messages / mentions_only / dms_only)
///   - The network/channel is not muted by the user

use anyhow::{bail, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use web_push::*;

/// Cap stored push subscriptions per user (#83). Each subscription is an
/// outbound POST target on every notification, so the list must be bounded.
const MAX_SUBSCRIPTIONS_PER_USER: usize = 20;

/// Aggregate deadline for the whole push fan-out in `maybe_notify` (#11). The
/// up-to-20 endpoints are sent CONCURRENTLY and the entire batch is bounded by
/// this timeout so a hung/black-holing endpoint cannot park the spawned task
/// (and thus delay dead-endpoint pruning) indefinitely. Each individual send
/// already has its own per-request timeout in `send_push`.
const FANOUT_DEADLINE: Duration = Duration::from_secs(12);

/// Per-user push rate limit (#11): at most this many pushes per user within
/// `RATE_WINDOW`. Bounds the outbound-POST amplification a chatty channel (or a
/// malicious peer flooding mentions) can drive through the server.
const RATE_MAX_PER_WINDOW: usize = 30;
const RATE_WINDOW: Duration = Duration::from_secs(60);

/// Cap on the number of per-username buckets held in `rate_state()` (#24). The
/// map keeps one entry per username that ever triggered a notify and never
/// reclaims it (even after account deletion). When it crosses this cap we sweep
/// buckets whose timestamps have all aged out of the window (see
/// `rate_limit_allow`). Mirrors the opportunistic cap-sweep on auth's
/// `login_fails` map and `otpk_low_should_notify`.
const MAX_RATE_KEYS: usize = 8192;

/// In-module per-user rate-limit state. Keyed by username; value is the list of
/// recent send timestamps within the sliding window. DashMap is concurrency-safe
/// and `'static`, so this needs no plumbing through other files.
fn rate_state() -> &'static DashMap<String, Vec<Instant>> {
    static STATE: OnceLock<DashMap<String, Vec<Instant>>> = OnceLock::new();
    STATE.get_or_init(DashMap::new)
}

/// Returns true if a push is allowed for `username` right now, recording the
/// send. Sliding-window: prunes timestamps older than `RATE_WINDOW`, then admits
/// only if under `RATE_MAX_PER_WINDOW`.
fn rate_limit_allow(username: &str) -> bool {
    let now = Instant::now();
    let state = rate_state();
    // #24: `state` keeps one bucket per username that ever triggered a notify and
    // never reclaims it (even after account deletion). When it crosses
    // MAX_RATE_KEYS, opportunistically drop any bucket whose timestamps have ALL
    // aged out of the window — such a bucket contributes nothing to a future
    // decision (its stale timestamps would be pruned on the next access anyway,
    // see the retain below), so removing it is behavior-preserving. Mirrors the
    // cap-sweep on auth's login_fails / the otpk_low map.
    if state.len() > MAX_RATE_KEYS {
        state.retain(|_, v| v.iter().any(|t| now.duration_since(*t) < RATE_WINDOW));
    }
    let mut entry = state.entry(username.to_string()).or_default();
    entry.retain(|t| now.duration_since(*t) < RATE_WINDOW);
    if entry.len() >= RATE_MAX_PER_WINDOW {
        return false;
    }
    entry.push(now);
    true
}

/// Outcome of an individual push send. Pruning decisions (#116) are made on the
/// HTTP status code, NOT on a substring of the error string (the endpoint URL is
/// attacker-controlled and could itself contain "410"/"404"/"Gone").
enum PushSendError {
    /// The push service reported the subscription is gone (410) or not found
    /// (404). The endpoint should be pruned from the user's subscription list.
    Gone,
    /// Any other failure (network error, build error, other HTTP status). The
    /// endpoint is kept; only logged.
    Other(anyhow::Error),
}

impl std::fmt::Display for PushSendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PushSendError::Gone     => write!(f, "subscription gone (410/404)"),
            PushSendError::Other(e) => write!(f, "{}", e),
        }
    }
}

// ─── VAPID key storage ────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct VapidKeys {
    /// Base64url-encoded uncompressed P-256 public key (65 bytes)
    pub public_key:  String,
    /// Base64url-encoded P-256 private key (32 bytes)
    pub private_key: String,
}

/// Generate or load VAPID keys from data_dir/vapid.json
pub fn load_or_generate_vapid(data_dir: &str) -> Result<VapidKeys> {
    let path = PathBuf::from(data_dir).join("vapid.json");
    if path.exists() {
        let json = std::fs::read_to_string(&path)?;
        let keys: VapidKeys = serde_json::from_str(&json)?;
        // Re-tighten perms on an already-leaked on-disk key file (#7/#71).
        set_secret_mode_sync(&path);
        info!("Loaded VAPID keys from disk");
        return Ok(keys);
    }

    // Generate a new P-256 key pair for VAPID
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;
    let sk = SigningKey::random(&mut OsRng);
    let priv_bytes = sk.to_bytes();
    let pub_bytes  = sk.verifying_key().to_encoded_point(false);
    let priv_b64   = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        priv_bytes.as_slice(),
    );
    let pub_b64    = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        pub_bytes.as_bytes(),
    );
    let keys = VapidKeys { public_key: pub_b64, private_key: priv_b64 };
    // vapid.json holds the VAPID EC PRIVATE key in cleartext; create it 0600
    // ATOMICALLY so the world-traversable data dir cannot leak it to other local
    // users in the create→chmod window (which would let them forge web-push to
    // all users) — #7/#71/#101. L8: write_secret_file_sync uses
    // .create(true).truncate(true) (NOT create_new), so it does NOT guard against
    // clobbering a pre-existing file; that race is irrelevant here because this is
    // a single-process, startup-once generator. The security-relevant property —
    // the 0600 mode delivered atomically — is what matters.
    write_secret_file_sync(&path, serde_json::to_string_pretty(&keys)?.as_bytes())?;
    info!("Generated new VAPID keys");
    Ok(keys)
}

// ─── Push subscription ────────────────────────────────────────────────────────

/// Browser-supplied push subscription (from PushManager.subscribe())
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushSubscription {
    pub endpoint: String,
    pub keys:     PushKeys,
    /// Optional browser/device label set by the client
    pub label:    Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushKeys {
    pub p256dh: String,
    pub auth:   String,
}

// ─── Notification preferences ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotifPrefs {
    pub enabled: bool,
    /// "mentions_only" | "dms_only" | "all_messages" | "mentions_and_dms"
    pub trigger: String,
    /// conn_ids that are muted
    pub muted_networks: Vec<String>,
    /// "conn_id/target" keys that are muted
    pub muted_channels: Vec<String>,
    /// Do Not Disturb (fix: mobile push must honor DND / quiet hours, previously
    /// client-only). `dnd` = manual DND on (suppress unconditionally). `dnd_start`
    /// / `dnd_end` = "HH:MM" scheduled quiet-hours window in the user's local time;
    /// `dnd_tz_offset` = the client's `Date.getTimezoneOffset()` (minutes to ADD to
    /// local to reach UTC) so the server can evaluate the window in the user's TZ.
    /// All `#[serde(default)]` so older clients / prefs files deserialize cleanly.
    #[serde(default)]
    pub dnd: bool,
    #[serde(default)]
    pub dnd_start: String,
    #[serde(default)]
    pub dnd_end: String,
    #[serde(default)]
    pub dnd_tz_offset: i64,
    /// The client's /ignore list (lower-cased `nick` or `nick!user@host` glob masks,
    /// same semantics as app.js isIgnored). Pushes from a matching sender are
    /// suppressed, so an ignored user can no longer reach the lock screen while the
    /// app is closed. Missing in older prefs files / PUT bodies → empty → no filter
    /// (today's behaviour).
    #[serde(default)]
    pub ignore: Vec<String>,
    /// Global PM Protection settings mirrored from the client (block_pms, cooldown,
    /// deliver-first, allow list). Default = disabled → no filter.
    #[serde(default)]
    pub pm_protect: PmProtect,
    /// Per-network PM Protection overrides (conn_id → settings). Only networks whose
    /// client-side override is ON are present; others fall back to `pm_protect`.
    #[serde(default)]
    pub pm_protect_net: std::collections::HashMap<String, PmProtect>,
}

/// PM Protection settings as the push engine needs them. Mirrors app.js
/// getPmSettings / isPmAllowedFor: when enabled, a DM from a sender that is not on
/// the allow list is dropped — except (deliver_first) the first one per
/// `cooldown_hours` window, which the client also lets through.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PmProtect {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_pm_cooldown_hours")]
    pub cooldown_hours: u32,
    #[serde(default = "default_true")]
    pub deliver_first: bool,
    /// Lower-cased nicks allowed to PM regardless of protection.
    #[serde(default)]
    pub allow: Vec<String>,
}
fn default_pm_cooldown_hours() -> u32 { 24 }
fn default_true() -> bool { true }
impl Default for PmProtect {
    fn default() -> Self {
        PmProtect { enabled: false, cooldown_hours: 24, deliver_first: true, allow: vec![] }
    }
}

/// Body of `PUT /push/settings`. Every field is optional: a field that is absent
/// keeps its stored value, so a device that only changes its mutes no longer
/// overwrites the trigger/enabled/ignore settings another device saved (the old
/// handler replaced the whole file with the sender's possibly stale cached copy).
/// An old client that sends the full object still gets exactly today's behaviour.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct NotifPrefsPatch {
    pub enabled:        Option<bool>,
    pub trigger:        Option<String>,
    pub muted_networks: Option<Vec<String>>,
    pub muted_channels: Option<Vec<String>>,
    pub dnd:            Option<bool>,
    pub dnd_start:      Option<String>,
    pub dnd_end:        Option<String>,
    pub dnd_tz_offset:  Option<i64>,
    pub ignore:         Option<Vec<String>>,
    pub pm_protect:     Option<PmProtect>,
    pub pm_protect_net: Option<std::collections::HashMap<String, PmProtect>>,
}

/// Caps on what a push-settings PUT may store. The prefs file is re-read on every
/// candidate notification, so it must stay bounded; anything over a cap is
/// REJECTED with a clear message (the client shows it) instead of being silently
/// truncated or silently 413'd as before.
const MAX_MUTED_NETWORKS: usize = 256;
const MAX_MUTED_CHANNELS: usize = 2000;
const MAX_IGNORE_MASKS:   usize = 500;
const MAX_ALLOW_NICKS:    usize = 500;
const MAX_PM_NET:         usize = 64;
const MAX_KEY_LEN:        usize = 300;
const MAX_MASK_LEN:       usize = 256;
const MAX_NICK_LEN:       usize = 64;

/// Why a push-settings update was refused.
#[derive(Debug)]
pub enum PrefsUpdateError {
    /// The request exceeded a cap (maps to 413 with this message).
    TooLarge(String),
    /// Persisting failed (maps to 500).
    Io(anyhow::Error),
    /// r4 C1-5: the caller's session was revoked while the request waited (maps to 401).
    SessionGone,
}
impl std::fmt::Display for PrefsUpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrefsUpdateError::TooLarge(m) => write!(f, "{}", m),
            PrefsUpdateError::Io(e)       => write!(f, "{}", e),
            PrefsUpdateError::SessionGone => write!(f, "{}", SUBSCRIBE_SESSION_GONE),
        }
    }
}

/// r4 C1-5: the session that asked was revoked (password reset / change, disable, account
/// deletion) before its push write could commit.
pub const SUBSCRIBE_SESSION_GONE: &str = "Not authenticated";

fn check_list(name: &str, v: &[String], max_items: usize, max_len: usize) -> std::result::Result<(), PrefsUpdateError> {
    if v.len() > max_items {
        return Err(PrefsUpdateError::TooLarge(format!("Too many {} ({} — max {})", name, v.len(), max_items)));
    }
    if v.iter().any(|s| s.len() > max_len) {
        return Err(PrefsUpdateError::TooLarge(format!("An entry in {} is too long (max {} bytes)", name, max_len)));
    }
    Ok(())
}

/// Normalise a mask/nick list the way the client compares it: trimmed, lower-cased,
/// non-empty, de-duplicated (order kept).
fn norm_list(v: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    v.into_iter()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty() && seen.insert(s.clone()))
        .collect()
}

fn norm_pm_protect(mut p: PmProtect) -> std::result::Result<PmProtect, PrefsUpdateError> {
    check_list("PM allow-list nicks", &p.allow, MAX_ALLOW_NICKS, MAX_NICK_LEN)?;
    p.allow = norm_list(p.allow);
    // 0 would mean "never first again" — clamp to the client's own range (1h..1y).
    p.cooldown_hours = p.cooldown_hours.clamp(1, 24 * 365);
    Ok(p)
}

impl NotifPrefs {
    /// What `GET /push/settings` returns: everything except the client-owned push
    /// filters (ignore / PM Protection). The browser keeps those in its own synced
    /// prefs and only ever WRITES them here; leaving them out of the GET means a
    /// stale cached 0.5.7 app.js — which PUTs back the whole object it last GOT —
    /// can never echo an old copy over a newer one.
    pub fn client_view(&self) -> serde_json::Value {
        let mut v = serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({}));
        if let Some(o) = v.as_object_mut() {
            o.remove("ignore");
            o.remove("pm_protect");
            o.remove("pm_protect_net");
        }
        v
    }

    /// Apply a validated patch: present fields replace the stored value, absent
    /// fields are kept. Validation happens before any field is touched, so a
    /// rejected patch leaves `self` unchanged.
    pub fn apply_patch(&mut self, p: NotifPrefsPatch) -> std::result::Result<(), PrefsUpdateError> {
        if let Some(v) = &p.muted_networks { check_list("muted networks", v, MAX_MUTED_NETWORKS, MAX_KEY_LEN)?; }
        if let Some(v) = &p.muted_channels { check_list("muted channels/PMs", v, MAX_MUTED_CHANNELS, MAX_KEY_LEN)?; }
        if let Some(v) = &p.ignore         { check_list("ignore masks", v, MAX_IGNORE_MASKS, MAX_MASK_LEN)?; }
        if let Some(t) = &p.trigger { if t.len() > 32 { return Err(PrefsUpdateError::TooLarge("Invalid trigger".into())); } }
        for s in [&p.dnd_start, &p.dnd_end].into_iter().flatten() {
            if s.len() > 16 { return Err(PrefsUpdateError::TooLarge("Invalid Do Not Disturb time".into())); }
        }
        let pm_protect = match p.pm_protect { Some(x) => Some(norm_pm_protect(x)?), None => None };
        let pm_protect_net = match p.pm_protect_net {
            Some(m) => {
                if m.len() > MAX_PM_NET {
                    return Err(PrefsUpdateError::TooLarge(format!("Too many per-network PM Protection overrides (max {})", MAX_PM_NET)));
                }
                let mut out = std::collections::HashMap::new();
                for (k, v) in m {
                    if k.len() > MAX_KEY_LEN { return Err(PrefsUpdateError::TooLarge("Invalid network id".into())); }
                    out.insert(k, norm_pm_protect(v)?);
                }
                Some(out)
            }
            None => None,
        };
        if let Some(v) = p.enabled        { self.enabled = v; }
        if let Some(v) = p.trigger        { self.trigger = v; }
        if let Some(v) = p.muted_networks { self.muted_networks = v; }
        if let Some(v) = p.muted_channels { self.muted_channels = v; }
        if let Some(v) = p.dnd            { self.dnd = v; }
        if let Some(v) = p.dnd_start      { self.dnd_start = v; }
        if let Some(v) = p.dnd_end        { self.dnd_end = v; }
        if let Some(v) = p.dnd_tz_offset  { self.dnd_tz_offset = v; }
        if let Some(v) = p.ignore         { self.ignore = norm_list(v); }
        if let Some(v) = pm_protect       { self.pm_protect = v; }
        if let Some(v) = pm_protect_net   { self.pm_protect_net = v; }
        Ok(())
    }
}

// ─── Push filters: /ignore + PM Protection (server-side mirror of app.js) ─────

/// IRC glob match (`*` = any run, `?` = any one char), case already folded by the
/// caller. Iterative with single-star backtracking: O(len(p)·len(t)) worst case,
/// and both inputs are length-capped (masks ≤ MAX_MASK_LEN, prefixes ≤ 512).
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1; ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi); mark = ti; pi += 1;
        } else if let Some(s) = star {
            pi = s + 1; mark += 1; ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' { pi += 1; }
    pi == p.len()
}

/// Mirrors app.js isIgnored(nick, prefix): an exact (case-insensitive) nick match,
/// or a glob mask (one containing `!`, `@`, `*` or `?`) matched against the full
/// `nick!user@host` prefix when known, else against the bare nick. When only the
/// nick is known, a `nick!*@*`-style mask (all-wildcard user@host) matches on its
/// nick part.
pub fn is_ignored(masks: &[String], nick: &str, prefix: Option<&str>) -> bool {
    if masks.is_empty() || nick.is_empty() { return false; }
    let lnick = nick.to_lowercase();
    let lpfx: Option<String> = prefix.map(|p| p.to_lowercase()).filter(|p| !p.is_empty() && p.len() <= 512);
    for mask in masks {
        let m = mask.to_lowercase();
        if m == lnick { return true; }
        // Argon P1 notifications.rs:409: `?` is a wildcard too (`/ignore guest?`); no IRC
        // nick can contain `?`, so such a mask was never an exact-nick entry.
        if m.contains('!') || m.contains('@') || m.contains('*') || m.contains('?') {
            let target = lpfx.as_deref().unwrap_or(&lnick);
            if glob_match(&m, target) { return true; }
            // A mask with no `!`/`@` is a nick mask: also try it on the nick itself, or
            // `guest?` could never match `guest1!u@h` (`guest*` only did by accident).
            if lpfx.is_some() && !m.contains('!') && !m.contains('@') && glob_match(&m, &lnick) { return true; }
            if lpfx.is_none() {
                if let Some((np, rest)) = m.split_once('!') {
                    if !rest.is_empty() && rest.chars().all(|c| c == '*' || c == '@') && glob_match(np, &lnick) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Last time a protected DM from (user, conn, sender) was let through as the
/// cooldown window's "first message". In-memory only: after a restart at most one
/// extra push per sender gets through, which matches the client's own behaviour
/// on a fresh device.
fn pm_first_state() -> &'static DashMap<String, Instant> {
    static STATE: OnceLock<DashMap<String, Instant>> = OnceLock::new();
    STATE.get_or_init(DashMap::new)
}
const MAX_PM_FIRST_KEYS: usize = 16384;

/// True when PM Protection says this DM must NOT be pushed. Same decision as the
/// irc_message handler in app.js: settings = per-network override, else global;
/// disabled or allow-listed → push; otherwise only the first DM per cooldown
/// window passes (deliver_first), or none at all.
fn pm_protect_blocks(prefs: &NotifPrefs, username: &str, conn_id: &str, from: &str, now: Instant) -> bool {
    let s = prefs.pm_protect_net.get(conn_id).unwrap_or(&prefs.pm_protect);
    if !s.enabled { return false; }
    let lf = from.to_lowercase();
    if s.allow.iter().any(|a| a.to_lowercase() == lf) { return false; }
    if !s.deliver_first { return true; }
    let cooldown = Duration::from_secs(u64::from(s.cooldown_hours.max(1)) * 3600);
    let state = pm_first_state();
    if state.len() > MAX_PM_FIRST_KEYS {
        // Bound the map: drop entries older than the longest window the client UI
        // offers (7 days); if a flood still overfills it, start over (worst case:
        // one extra push per sender).
        state.retain(|_, t| now.duration_since(*t) < Duration::from_secs(7 * 24 * 3600));
        if state.len() > MAX_PM_FIRST_KEYS { state.clear(); }
    }
    let key = format!("{}\u{0}{}\u{0}{}", username, conn_id, lf);
    match state.entry(key) {
        dashmap::mapref::entry::Entry::Occupied(mut e) => {
            // app.js: first = now - last > cooldown; otherwise silently dropped.
            if now.duration_since(*e.get()) <= cooldown { true } else { e.insert(now); false }
        }
        dashmap::mapref::entry::Entry::Vacant(e) => { e.insert(now); false }
    }
}

/// The new push filters, as one decision: `Some(reason)` = do not push.
fn push_filter_reason(
    prefs: &NotifPrefs, username: &str, conn_id: &str, from: &str,
    prefix: Option<&str>, is_dm: bool, now: Instant,
) -> Option<&'static str> {
    if is_ignored(&prefs.ignore, from, prefix) { return Some("sender is on the ignore list"); }
    if is_dm && pm_protect_blocks(prefs, username, conn_id, from, now) { return Some("PM Protection"); }
    None
}

// ─── Notification manager ─────────────────────────────────────────────────────

pub struct NotificationManager {
    data_dir:     String,
    vapid_keys:   VapidKeys,
    /// One async mutex per username, guarding the read-modify-write of that
    /// user's push/{username}.json and notif_prefs/{username}.json. Mirrors
    /// upload::user_record_lock so concurrent subscribe / dead-endpoint prune /
    /// pref writes cannot lose each other's updates (#21-style RMW race).
    user_locks:   DashMap<String, Arc<Mutex<()>>>,
}

impl NotificationManager {
    pub fn new(data_dir: &str, vapid_keys: VapidKeys) -> Self {
        std::fs::create_dir_all(format!("{}/push", data_dir)).ok();
        std::fs::create_dir_all(format!("{}/notif_prefs", data_dir)).ok();
        Self {
            data_dir: data_dir.to_string(),
            vapid_keys,
            user_locks: DashMap::new(),
        }
    }

    /// Acquire (creating if needed) the per-user RMW lock.
    fn user_lock(&self, username: &str) -> Arc<Mutex<()>> {
        self.user_locks
            .entry(username.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// r9 (astra P4 resetpass.sh:717): the per-user lock AND the shared account lock
    /// (auth.rs ADMIN_LOCK_FILE). resetpass.sh deletes push/<user>.json and notif_prefs/<user>.json
    /// while it holds that lock exclusively — after it has stamped sessions_valid_after — so a
    /// writer holding it shared either finishes before the script starts (and the script deletes
    /// what it wrote) or starts after the script is done (and its session check, made under this
    /// lock, sees the revocation). The in-process mutex alone could not see the script. Same
    /// order as auth.rs lock_with_admin: the mutex is never held while waiting for the script.
    async fn lock_user_and_account(&self, username: &str)
        -> Result<(tokio::sync::OwnedMutexGuard<()>, crate::auth::AdminFileLock)>
    {
        let m = self.user_lock(username);
        let g = Arc::clone(&m).lock_owned().await;
        if let Some(held) = crate::auth::admin_lock_try_shared_in(&self.data_dir) { return Ok((g, held)); }
        drop(g);
        let held = crate::auth::admin_lock_shared_in(&self.data_dir).await?;
        Ok((m.lock_owned().await, held))
    }

    /// Persist a JSON value to `path` via temp-file + atomic rename so a crash
    /// mid-write cannot truncate the file and a concurrent reader never observes
    /// a partial file. Tightens perms after rename (push endpoints / muted lists
    /// are privacy-sensitive, #7). Returns the write result.
    async fn write_json_atomic<T: Serialize>(path: &std::path::Path, value: &T) -> Result<()> {
        let json = serde_json::to_string_pretty(value)?;
        let tmp = path.with_extension("json.tmp");
        // Create the temp file 0600 atomically (#101): the staged file holds the
        // same privacy-sensitive data (push endpoints / muted lists, #7), so it
        // must never be world-readable even for the instant before the rename.
        if write_secret_file_async(&tmp, json.as_bytes()).await.is_ok() {
            if tokio::fs::rename(&tmp, path).await.is_err() {
                // Rename can fail across some filesystems; fall back to direct write.
                write_secret_file_async(path, json.as_bytes()).await?;
                let _ = tokio::fs::remove_file(&tmp).await;
            }
        } else {
            // Could not stage the temp file; write directly so we still persist.
            write_secret_file_async(path, json.as_bytes()).await?;
        }
        Ok(())
    }

    pub fn vapid_public_key(&self) -> &str {
        &self.vapid_keys.public_key
    }

    // ── Subscriptions ─────────────────────────────────────────────────────────

    /// `still_authorized` (r4 C1-5, codex P1 notifications.rs:543): re-checked UNDER the
    /// per-user lock, after the endpoint's DNS resolution (which an attacker's name server can
    /// stall). The route passes "the caller's session still validates". A password reset /
    /// change / disable / deletion revokes the sessions and then purges the stored
    /// subscriptions under this same lock (purge_user), so a subscribe that was admitted
    /// before the revocation can no longer write its endpoint back afterwards. Refused with
    /// SUBSCRIBE_SESSION_GONE (the route answers 401).
    pub async fn save_subscription(&self, username: &str, sub: PushSubscription, still_authorized: impl FnOnce() -> bool) -> Result<()> {
        // r5 (codex P1 notifications.rs:1246): admission BEFORE the endpoint's DNS lookup — at
        // most SUBSCRIBE_INFLIGHT_PER_USER validations of one account at a time (and every
        // lookup is bounded process-wide and by a deadline, see resolve_push_host).
        let _inflight = SubscribeInFlight::acquire(username).ok_or_else(|| anyhow::anyhow!(SUBSCRIBE_BUSY))?;
        // #83: the endpoint is a client-supplied outbound URL that send_push will
        // POST to. Without validation an authenticated user could register an
        // internal target and turn the server into a blind-SSRF probe. Require
        // https and reject loopback/private/link-local/internal hosts.
        validate_push_endpoint(&sub.endpoint).await?;

        // Serialize the load→mutate→write window per user so a concurrent
        // subscribe and a notify-time dead-endpoint prune cannot clobber each
        // other (last-writer-wins data loss).
        let _locks = self.lock_user_and_account(username).await?;   // r9
        if !still_authorized() { bail!(SUBSCRIBE_SESSION_GONE); }

        let mut subs = self.load_subscriptions(username).await;
        // Replace existing subscription with same endpoint
        subs.retain(|s| s.endpoint != sub.endpoint);
        // #83: cap subscriptions per user so the endpoint store cannot grow
        // unbounded (each becomes an outbound POST target on every push).
        if subs.len() >= MAX_SUBSCRIPTIONS_PER_USER {
            // Drop the oldest to make room for the newest device.
            subs.remove(0);
        }
        subs.push(sub);
        let path = self.subs_path(username);
        Self::write_json_atomic(&path, &subs).await // push endpoints are privacy-sensitive (#7)
    }

    pub async fn remove_subscription(&self, username: &str, endpoint: &str) -> Result<()> {
        // r9: a prune that read the file before resetpass.sh deleted it would write the rest back.
        let _locks = self.lock_user_and_account(username).await?;

        let mut subs = self.load_subscriptions(username).await;
        let before = subs.len();
        subs.retain(|s| s.endpoint != endpoint);
        // r4 C1-5: nothing to remove → write nothing. A dead-endpoint prune that ran across a
        // purge_user used to re-create an (empty) push file for a purged / deleted account.
        if subs.len() == before { return Ok(()); }
        let path = self.subs_path(username);
        Self::write_json_atomic(&path, &subs).await // push endpoints are privacy-sensitive (#7)
    }

    /// r4 C1-5: remove the user's push subscriptions AND notification prefs, under the same
    /// per-user lock every subscription / prefs write takes. Used on password reset, password
    /// change, admin disable and account deletion (after their sessions were revoked).
    pub async fn purge_user(&self, username: &str) {
        let lock = self.user_lock(username);
        let _guard = lock.lock().await;
        let _ = tokio::fs::remove_file(self.subs_path(username)).await;
        let _ = tokio::fs::remove_file(self.prefs_path(username)).await;
    }

    pub async fn load_subscriptions(&self, username: &str) -> Vec<PushSubscription> {
        let path = self.subs_path(username);
        let Ok(json) = tokio::fs::read_to_string(&path).await else { return vec![]; };
        match serde_json::from_str(&json) {
            Ok(subs) => subs,
            Err(e) => {
                // Do NOT silently default to empty (#116): a corrupt/forward-incompatible
                // file would otherwise look like "no subscriptions" and the cause would be
                // invisible. Surface it so it can be diagnosed, then degrade to empty.
                warn!("Failed to parse push subscriptions for {}: {}", username, e);
                vec![]
            }
        }
    }

    // ── Preferences ───────────────────────────────────────────────────────────

    pub async fn load_prefs(&self, username: &str) -> NotifPrefs {
        let path = self.prefs_path(username);
        let Ok(json) = tokio::fs::read_to_string(&path).await else {
            return NotifPrefs {
                enabled: false,
                trigger: "mentions_and_dms".to_string(),
                ..Default::default()
            };
        };
        match serde_json::from_str(&json) {
            Ok(prefs) => prefs,
            Err(e) => {
                // Surface parse failures rather than silently defaulting (#116). A
                // default NotifPrefs has enabled=false, so a corrupt file safely
                // disables notifications — but the operator gets told why.
                warn!("Failed to parse notification prefs for {}: {}", username, e);
                NotifPrefs::default()
            }
        }
    }

    #[allow(dead_code)] // kept for API stability; the PUT route now uses update_prefs
    pub async fn save_prefs(&self, username: &str, prefs: &NotifPrefs) -> Result<()> {
        let lock = self.user_lock(username);
        let _guard = lock.lock().await;

        let path = self.prefs_path(username);
        Self::write_json_atomic(&path, prefs).await // muted-channel list leaks metadata (#7)
    }

    /// Merge a partial update into the stored prefs under the per-user lock
    /// (load → apply_patch → atomic write), so concurrent PUTs from two devices
    /// each change only the fields they sent.
    /// `still_authorized`: re-checked under the lock, like save_subscription (r4 C1-5), so a
    /// PUT admitted before a reset / deletion can't re-create the purged prefs file.
    pub async fn update_prefs(&self, username: &str, patch: NotifPrefsPatch, still_authorized: impl FnOnce() -> bool) -> std::result::Result<(), PrefsUpdateError> {
        let _locks = self.lock_user_and_account(username).await.map_err(PrefsUpdateError::Io)?;   // r9
        if !still_authorized() { return Err(PrefsUpdateError::SessionGone); }
        let mut prefs = self.load_prefs(username).await;
        prefs.apply_patch(patch)?;
        let path = self.prefs_path(username);
        Self::write_json_atomic(&path, &prefs).await.map_err(PrefsUpdateError::Io)
    }

    // ── Send notification ─────────────────────────────────────────────────────

    /// Called on every incoming PRIVMSG. Decides whether to push based on prefs.
    /// Kept for callers that don't have the sender's prefix; host-based ignore
    /// masks then match on the nick only (see `is_ignored`).
    #[allow(dead_code)]
    pub async fn maybe_notify(
        &self,
        username:  &str,
        user_nick: &str,
        conn_id:   &str,
        net_label: &str,
        target:    &str,
        from:      &str,
        text:      &str,
        ts:        i64,
    ) {
        self.maybe_notify_with_prefix(username, user_nick, conn_id, net_label, target, from, None, text, ts).await
    }

    /// Same as `maybe_notify`, plus the sender's full `nick!user@host` prefix so
    /// `nick!*@host`-style ignore masks apply to push exactly as they do in the app.
    pub async fn maybe_notify_with_prefix(
        &self,
        username:  &str,
        user_nick: &str,
        conn_id:   &str,
        net_label: &str,
        target:    &str,
        from:      &str,
        prefix:    Option<&str>,
        text:      &str,
        ts:        i64,
    ) {
        // #117/#11: `prefs.enabled` is the cheapest gate, but it lives on disk.
        // We still must read prefs to know it; what we MUST avoid is the SECOND
        // disk read (subscriptions) plus the whole payload build + fan-out when
        // nothing is enabled. The early returns below short-circuit before the
        // subscription read for every disabled/muted/non-matching message (the
        // overwhelmingly common case on a busy channel).
        let prefs = self.load_prefs(username).await;
        if !prefs.enabled { return; }

        // Check muted network
        if prefs.muted_networks.contains(&conn_id.to_string()) { return; }
        // Check muted channel. Case-INSENSITIVE: IRC channel names (and nicks for
        // DM keys) are case-insensitive, and the client may store a mute key in a
        // different case than the wire target (a ZNC bouncer can echo a channel in
        // a different case than the JOIN, and DM mute keys are lowercased client-side).
        let chan_key = format!("{}/{}", conn_id, target);
        if prefs.muted_channels.iter().any(|c| c.eq_ignore_ascii_case(&chan_key)) { return; }

        let is_dm      = !target.starts_with(['#', '&', '+', '!']);
        let is_mention = text_mentions_nick(text, user_nick);

        let should_notify = match prefs.trigger.as_str() {
            "all_messages"      => true,
            "mentions_only"     => is_mention,
            "dms_only"          => is_dm,
            "mentions_and_dms"  => is_mention || is_dm,
            _                   => is_mention || is_dm,
        };

        if !should_notify { return; }

        // Honor Do Not Disturb / scheduled quiet hours (fix: DND was client-only, so
        // mobile push ignored it and fired during quiet hours — exactly when the app
        // is idle/closed and push actually sends). Server-authoritative now: the
        // client syncs its DND state + TZ offset into notif_prefs. Scoped to
        // DM/mention pushes; test/monitor sends are intentionally exempt.
        if dnd_active_now(&prefs) {
            return;
        }

        // /ignore + PM Protection (previously client-only, so an ignored user or a
        // PM-Protection-dropped stranger still reached the lock screen while the app
        // was closed). Evaluated last before the rate limit because the PM
        // Protection "first message" window is stateful and must only be consumed
        // by a DM that would otherwise really be pushed.
        if let Some(reason) = push_filter_reason(&prefs, username, conn_id, from, prefix, is_dm, Instant::now()) {
            debug!("Push suppressed for {}: {}", username, reason);
            return;
        }

        // #11: per-user rate limit BEFORE any subscription read / fan-out, so a
        // flood of matching messages cannot drive unbounded outbound POSTs.
        if !rate_limit_allow(username) {
            warn!("Push rate limit hit for {} — dropping notification", username);
            return;
        }

        // Build notification payload
        let title = if is_dm {
            format!("CryptIRC — DM from {}", from)
        } else {
            format!("CryptIRC — {} ({})", target, net_label)
        };
        let body    = format!("<{}> {}", from, truncate(text, 120));
        let payload = serde_json::json!({
            "title":    title,
            "body":     body,
            "conn_id":  conn_id,
            "target":   target,
            "from":     from,
            "ts":       ts,
            "is_dm":    is_dm,
            "tag":      format!("{}/{}", conn_id, target),
        });

        let subs = self.load_subscriptions(username).await;
        if subs.is_empty() { debug!("Push for {}: no subscriptions", username); return; }
        let payload = payload.to_string();

        // #11: send to all (up to MAX_SUBSCRIPTIONS_PER_USER) endpoints
        // CONCURRENTLY under a single aggregate deadline, instead of sequential
        // awaits. A slow endpoint no longer serializes behind the others, and the
        // whole batch can never outlive FANOUT_DEADLINE.
        let stale = self.fan_out(username, &subs, &payload).await;

        // Prune endpoints the push service reported as gone (410/404). Status-code
        // driven (#116), collected by the concurrent send above.
        for endpoint in &stale {
            let _ = self.remove_subscription(username, endpoint).await;
        }
    }

    /// Send `payload` to every subscription concurrently under an aggregate
    /// deadline (#11). Returns the endpoints the push service reported as gone
    /// (410/404) so the caller can prune them (#116). Shared by maybe_notify /
    /// monitor / test sends so all three fan out identically.
    async fn fan_out(
        &self,
        username: &str,
        subs: &[PushSubscription],
        payload: &str,
    ) -> Vec<String> {
        let sends = subs.iter().map(|sub| async move {
            match self.send_push(sub, payload).await {
                Ok(()) => None,
                Err(PushSendError::Gone) => {
                    warn!("Push endpoint gone for {}, pruning", username);
                    Some(sub.endpoint.clone())
                }
                Err(PushSendError::Other(e)) => {
                    warn!("Push send failed for {}: {}", username, e);
                    None
                }
            }
        });

        match tokio::time::timeout(FANOUT_DEADLINE, futures_util::future::join_all(sends)).await {
            Ok(results) => results.into_iter().flatten().collect(),
            Err(_) => {
                // Aggregate deadline hit: some endpoints were black-holing. Do NOT
                // prune anything (a timeout is not proof the subscription is gone).
                warn!("Push fan-out for {} exceeded {:?}; some sends abandoned", username, FANOUT_DEADLINE);
                vec![]
            }
        }
    }

    pub async fn send_monitor_notification(&self, username: &str, nick: &str, status: &str) {
        // #23: monitor pushes are client-triggered (MonitorPush WS msg) and each
        // fans out one signed web-push per endpoint. Route through the SAME
        // per-user rate limit as maybe_notify so a MonitorPush flood (across
        // sockets) cannot drive unbounded outbound POSTs / self-spam devices.
        if !rate_limit_allow(username) {
            warn!("Push rate limit hit for {} — dropping monitor notification", username);
            return;
        }
        let subs = self.load_subscriptions(username).await;
        if subs.is_empty() { return; }
        let icon = if status == "online" { "🟢" } else { "🔴" };
        let payload = serde_json::json!({
            "title": format!("CryptIRC — Monitor"),
            "body": format!("{} {} is {}", icon, nick, status),
            "tag": format!("monitor-{}", nick.to_lowercase()),
        }).to_string();
        let stale = self.fan_out(username, &subs, &payload).await;
        for endpoint in &stale {
            let _ = self.remove_subscription(username, endpoint).await;
        }
    }

    pub async fn send_test_notification(&self, username: &str) {
        // #23: gate the test send through the shared per-user push rate limit too
        // so every fan_out path is bounded uniformly (the HTTP route has its own
        // coarse push_test bucket; this is the same choke point as maybe_notify).
        if !rate_limit_allow(username) {
            warn!("Push rate limit hit for {} — dropping test notification", username);
            return;
        }
        let subs = self.load_subscriptions(username).await;
        if subs.is_empty() { return; }
        let payload = serde_json::json!({
            "title": "CryptIRC",
            "body": "Test notification — push is working!",
            "tag": "cryptirc-test",
        }).to_string();
        // #100: the test send must also prune 410/404 stale endpoints, mirroring
        // maybe_notify — otherwise a dead device lingers until a real message.
        let stale = self.fan_out(username, &subs, &payload).await;
        for endpoint in &stale {
            let _ = self.remove_subscription(username, endpoint).await;
        }
    }

    /// Send one push. Classifies a 410/404 response as `PushSendError::Gone` so
    /// the caller prunes on the HTTP STATUS CODE (#116), never on an error
    /// substring (the endpoint URL is attacker-controlled).
    async fn send_push(&self, sub: &PushSubscription, payload: &str) -> std::result::Result<(), PushSendError> {
        match self.send_push_raw(sub, payload).await {
            Ok(status) if status.is_success() => Ok(()),
            Ok(status)
                if status == reqwest::StatusCode::GONE
                    || status == reqwest::StatusCode::NOT_FOUND =>
            {
                Err(PushSendError::Gone)
            }
            Ok(status) => {
                Err(PushSendError::Other(anyhow::anyhow!(
                    "Push to {} failed: {}",
                    endpoint_label(&sub.endpoint),
                    status
                )))
            }
            Err(e) => Err(PushSendError::Other(e)),
        }
    }

    /// Perform the actual signed/encrypted POST, returning the HTTP status (or a
    /// transport/build error). Status classification is the caller's job.
    async fn send_push_raw(&self, sub: &PushSubscription, payload: &str) -> Result<reqwest::StatusCode> {
        // #83: re-validate the endpoint at SEND time, not just at registration,
        // AND pin the connection to the exact public IPs we validated. The
        // registration-time check is a TOCTOU window: a DNS name validated as
        // public can be re-pointed (DNS rebinding) at an internal address before
        // this later POST. The previous hyper-based WebPushClient re-resolved the
        // host at connect time with no pinning, so re-validating here was not
        // enough — the connect could still land on 169.254.169.254 / RFC1918.
        // We now resolve+validate once and pin reqwest to those addresses (same
        // approach as preview::build_pinned_client). Legit public push services
        // (FCM/Mozilla/Apple) resolve to public IPs, so this is transparent.
        let pinned = resolve_and_validate_push_endpoint(&sub.endpoint).await?;

        let subscription_info = SubscriptionInfo::new(
            &sub.endpoint,
            &sub.keys.p256dh,
            &sub.keys.auth,
        );

        let priv_key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &self.vapid_keys.private_key,
        )?;

        let mut sig_builder = VapidSignatureBuilder::from_pem(
            std::io::Cursor::new(pem_from_raw_key(&priv_key_bytes)?),
            &subscription_info,
        )?;
        sig_builder.add_claim("sub", "https://github.com/gh0st68/CryptIRC");
        let signature = sig_builder.build()?;

        let mut builder = WebPushMessageBuilder::new(&subscription_info)?;
        builder.set_payload(ContentEncoding::Aes128Gcm, payload.as_bytes());
        builder.set_vapid_signature(signature);
        builder.set_ttl(86400); // 24 hours — push service will retry delivery
        let message = builder.build()?;

        // Convert the fully-signed/encrypted WebPushMessage into an HTTP request
        // (method=POST, endpoint URI, TTL/Urgency/Content-* + VAPID crypto
        // headers, AES128GCM body) using the crate's own request builder, so the
        // bytes on the wire are identical to what the hyper client would have
        // sent — only the transport (a pinned reqwest client) changes.
        let request = web_push::request_builder::build_request::<reqwest::Body>(message);
        let (parts, body) = request.into_parts();

        // Build a reqwest client pinned to the validated public IPs and with
        // redirects disabled, so neither DNS re-resolution nor a 3xx Location can
        // bounce the request to an internal target.
        // Bound both the connect phase and the total request, mirroring the preview
        // client (preview.rs). send_push is awaited INLINE inside the per-connection
        // IRC read loop (a hung/black-holing endpoint with no deadline would otherwise
        // park that loop indefinitely — server PINGs go unanswered until ping-timeout).
        // Real push providers (FCM/Mozilla/Apple) respond in well under a second, so
        // these deadlines never fire for legitimate endpoints; behavior is unchanged.
        let mut client_builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            // Disable system-proxy auto-detection: an ambient HTTP(S)_PROXY/ALL_PROXY env
            // var would tunnel the push through a proxy that re-resolves the host, bypassing
            // the resolve_to_addrs pin + SSRF validation. A pinned client must go direct.
            .no_proxy()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5));
        if !pinned.is_ip_literal {
            client_builder = client_builder.resolve_to_addrs(&pinned.host, &pinned.addrs);
        }
        let client = client_builder
            .build()
            .map_err(|e| anyhow::anyhow!("Push client build failed: {}", e))?;

        // #118: the pin (resolve_to_addrs) is keyed on `pinned.host`. reqwest
        // derives the connect host from the request URL it parses out of
        // `sub.endpoint`. If those two host strings diverge (e.g. different
        // normalization), reqwest would NOT match the pin entry and would fall
        // back to a live DNS lookup — silently disabling the SSRF pin. Re-derive
        // the host the same way reqwest will and require it to equal the pinned
        // host before sending; bail if divergent rather than send unpinned.
        // (resolve_and_validate_push_endpoint already rejected userinfo, so the
        // authority here is host[:port] only.)
        let req_host = reqwest::Url::parse(sub.endpoint.as_str())
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()));
        match req_host {
            Some(h) if h == pinned.host => {}
            _ => {
                bail!("Push endpoint host diverged from pinned host; refusing to send unpinned");
            }
        }

        // web-push 0.9 builds its request with the `http` 0.2 types, while reqwest
        // 0.12 uses `http` 1.x, so copy the (all-ASCII) VAPID/crypto/TTL headers
        // across by name/bytes. Fail loudly rather than send a request missing one.
        let mut push_headers = reqwest::header::HeaderMap::with_capacity(parts.headers.len());
        for (name, value) in parts.headers.iter() {
            let n = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes())
                .map_err(|_| anyhow::anyhow!("Push header name not convertible: {}", name))?;
            let v = reqwest::header::HeaderValue::from_bytes(value.as_bytes())
                .map_err(|_| anyhow::anyhow!("Push header value not convertible for {}", name))?;
            push_headers.append(n, v);
        }

        let resp = client
            .post(sub.endpoint.as_str())
            .headers(push_headers)
            .body(body)
            .send()
            .await
            .map_err(|e| {
                // r9 (astra P1 notifications.rs:1013): reqwest's error carries the full
                // request URL (its Debug output prints it), and the old 60-character prefix
                // already reached into the token — both went to the log via fan_out.
                anyhow::anyhow!("Push to {} failed: {:?}", endpoint_label(&sub.endpoint), e.without_url())
            })?;

        // Return the status; the caller (send_push) classifies success vs. the
        // 410/404 "gone" prune case (#116) from the code, not an error string.
        Ok(resp.status())
    }

    fn subs_path(&self, username: &str) -> PathBuf {
        let safe: String = username.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').collect();
        PathBuf::from(&self.data_dir).join("push").join(format!("{}.json", safe))
    }
    fn prefs_path(&self, username: &str) -> PathBuf {
        let safe: String = username.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').collect();
        PathBuf::from(&self.data_dir).join("notif_prefs").join(format!("{}.json", safe))
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn text_mentions_nick(text: &str, nick: &str) -> bool {
    if nick.is_empty() { return false; }
    let t = text.to_lowercase();
    let n = nick.to_lowercase();
    // Whole-word matching: nick must be bounded by non-alphanumeric chars or string edges
    let is_boundary = |c: char| !c.is_alphanumeric() && c != '_';
    for (i, _) in t.match_indices(&n) {
        let before_ok = i == 0 || t[..i].chars().last().map_or(true, is_boundary);
        let after_pos = i + n.len();
        let after_ok = after_pos >= t.len() || t[after_pos..].chars().next().map_or(true, is_boundary);
        if before_ok && after_ok { return true; }
    }
    false
}

/// Parse an "HH:MM" 24-hour time into minutes-of-day (0..1440). Returns None for
/// empty/malformed input so a missing or bad schedule simply means "no window".
fn parse_hhmm(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() { return None; }
    let (h, m) = s.split_once(':')?;
    let h: i64 = h.trim().parse().ok()?;
    let m: i64 = m.trim().parse().ok()?;
    if !(0..24).contains(&h) || !(0..60).contains(&m) { return None; }
    Some(h * 60 + m)
}

/// True if the user's Do Not Disturb is active right now. Mirrors the client's
/// `isDndActive()`: manual DND (`prefs.dnd`) suppresses unconditionally; otherwise a
/// [start,end) schedule suppresses when the current wall-clock time in the user's
/// timezone falls in the window, with midnight wraparound (start>end) handled the
/// same way. The user's local time is derived from the client-supplied
/// `dnd_tz_offset` (JS `getTimezoneOffset()`, minutes to ADD to local to reach UTC,
/// so local = UTC − offset). A bad/zero offset degrades to UTC evaluation, never a
/// panic; the `% 1440` bounds any absurd client-supplied offset.
fn dnd_active_now(prefs: &NotifPrefs) -> bool {
    if prefs.dnd { return true; }
    let (Some(sv), Some(ev)) = (parse_hhmm(&prefs.dnd_start), parse_hhmm(&prefs.dnd_end)) else {
        return false;
    };
    let secs = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => return false,
    };
    let utc_min = (secs / 60) % 1440;
    // local = UTC − offset; normalize into [0,1440).
    let local_min = (((utc_min - (prefs.dnd_tz_offset % 1440)) % 1440) + 1440) % 1440;
    if sv < ev {
        local_min >= sv && local_min < ev
    } else {
        // Wraparound window (e.g. 22:00–07:00): active if past start OR before end.
        local_min >= sv || local_min < ev
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max { return s; }
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None         => s,
    }
}

/// Best-effort chmod 0600 on a secret file written via the sync std::fs API
/// (audit #7). No-op on non-unix targets. Warns (does not silently ignore, #101)
/// on permission failure: a secret file left world-readable is a real leak.
fn set_secret_mode_sync(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            warn!("Failed to chmod 0600 secret file {}: {}", path.display(), e);
        }
    }
    #[cfg(not(unix))]
    { let _ = path; }
}

/// Write `data` to `path` as an owner-only (0600) secret file, creating it
/// atomically with the restrictive mode (#101). On unix, `OpenOptions::mode`
/// sets the creation mode so the file is NEVER world-readable for any window
/// (no create-then-chmod race); on non-unix it falls back to a plain write.
/// Truncates if the file already exists (we always rewrite the full content).
fn write_secret_file_sync(path: &std::path::Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)?;
        // Re-tighten in case the file pre-existed with looser perms (mode on
        // OpenOptions only applies to newly created files). Warn on failure.
        set_secret_mode_sync(path);
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::File::create(path)?;
        f.write_all(data)?;
        Ok(())
    }
}

/// Async sibling of `write_secret_file_sync` (#101): create `path` 0600
/// atomically via tokio's OpenOptions and write `data`. Used for the push
/// subscription / prefs files (privacy-sensitive, #7).
async fn write_secret_file_async(path: &std::path::Path, data: &[u8]) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    #[cfg(unix)]
    {
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .await?;
        f.write_all(data).await?;
        f.flush().await?;
        // Re-tighten if the file pre-existed with looser perms; warn on failure.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) =
                tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await
            {
                warn!("Failed to chmod 0600 secret file {}: {}", path.display(), e);
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut f = tokio::fs::File::create(path).await?;
        f.write_all(data).await?;
        f.flush().await?;
        Ok(())
    }
}

/// A push endpoint that has passed SSRF validation, along with the exact set of
/// public addresses to pin the outbound connection to (#83). `is_ip_literal` is
/// true when the host was a bare IP (no DNS, so nothing to rebind / pin).
struct PinnedEndpoint {
    /// The host as it appears in the URL (DNS name, or IP literal incl. brackets
    /// for IPv6). Used as the `resolve_to_addrs` key for DNS-name hosts.
    host:          String,
    /// Validated public addresses to pin the connection to (DNS-name hosts).
    addrs:         Vec<std::net::SocketAddr>,
    is_ip_literal: bool,
}

/// Validate a client-supplied web-push endpoint before storing it (#83).
/// Require https and reject hosts that resolve to a private/internal address
/// literal (loopback, RFC1918, link-local incl. cloud metadata, CGNAT, ...)
/// or obvious internal names, so the endpoint cannot be used as an SSRF probe.
async fn validate_push_endpoint(endpoint: &str) -> Result<()> {
    resolve_and_validate_push_endpoint(endpoint).await.map(|_| ())
}

/// r9 (astra P1 notifications.rs:1013): a push endpoint as it may appear in a log or an
/// error: its origin plus a short hash (to tell subscriptions apart). The rest of the URL is
/// the subscription's token — whoever has the full URL can address that device — so it is
/// never logged.
fn endpoint_label(endpoint: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash: String = Sha256::digest(endpoint.as_bytes()).iter().take(4).map(|b| format!("{:02x}", b)).collect();
    let origin = reqwest::Url::parse(endpoint).ok()
        .map(|u| u.origin().ascii_serialization())
        .filter(|o| o != "null")
        .unwrap_or_else(|| "(invalid endpoint)".into());
    format!("{} #{}", origin, hash)
}

/// Resolve + validate a web-push endpoint and return the public addresses to pin
/// the outbound connection to (#83). Same checks as the registration-time guard,
/// but additionally hands back the validated `SocketAddr`s so the SEND path can
/// pin reqwest's connection to exactly these IPs — closing the DNS-rebinding /
/// TOCTOU window where a name validated as public is re-pointed at an internal
/// address before the POST connects. Mirrors preview::resolve_and_validate_host
/// and reuses preview::is_private_ip so both SSRF paths share audited logic.
async fn resolve_and_validate_push_endpoint(endpoint: &str) -> Result<PinnedEndpoint> {
    let parsed = reqwest::Url::parse(endpoint)
        .map_err(|_| anyhow::anyhow!("Invalid push endpoint URL"))?;
    if parsed.scheme() != "https" {
        bail!("Push endpoint must use https");
    }
    // #118: reject userinfo/credentials in the authority. A URL like
    // https://evil.com@fcm.googleapis.com/... has host_str()=fcm.googleapis.com
    // but the leading userinfo is a classic SSRF/parser-confusion vector and
    // serves no purpose for a push endpoint. Refuse outright so the host we
    // validate and pin is unambiguous.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("Push endpoint must not contain credentials");
    }
    let host = parsed.host_str().ok_or_else(|| anyhow::anyhow!("Push endpoint has no host"))?;

    // Reject obvious internal names outright. Argon P1 notifications.rs:1182: compare the
    // name without its trailing root dot(s) — "localhost." / "svc.internal." are the same
    // names in fully-qualified form and used to slip past this check.
    let lower = host.trim_end_matches('.').to_ascii_lowercase();
    if lower.is_empty() || lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".internal") || lower.ends_with(".local") {
        bail!("Push endpoint host is not allowed");
    }

    // If the host is an IP literal, reject private/internal ranges.
    // host_str() serializes IPv6 with surrounding brackets; strip them so the
    // literal parses (e.g. "[::1]" -> "::1").
    let host_ip = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if let Ok(ip) = host_ip.parse::<IpAddr>() {
        if crate::preview::is_private_ip(ip) {
            bail!("Push endpoint host is not allowed");
        }
        // Pure IP literal — no DNS to resolve, decision is final. reqwest connects
        // straight to the literal (no resolver step to rebind), so no pinning set
        // is needed.
        return Ok(PinnedEndpoint { host: host.to_string(), addrs: vec![], is_ip_literal: true });
    }

    // DNS-name host: resolve it and reject if ANY resolved address is private
    // /internal. Without this an authenticated user could register an internal
    // name that the push client later connects to (blind SSRF to metadata/
    // intranet). Legit push services (FCM/Mozilla/Apple) resolve to public IPs,
    // so this is transparent for real endpoints. (#83, mirrors
    // preview::resolve_and_validate_host.)
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addrs = resolve_push_host(host, port, system_resolve).await?;
    if addrs.is_empty() {
        bail!("Push endpoint host is not allowed");
    }
    for addr in &addrs {
        if crate::preview::is_private_ip(addr.ip()) {
            bail!("Push endpoint host is not allowed");
        }
    }
    Ok(PinnedEndpoint { host: host.to_string(), addrs, is_ip_literal: false })
}

// ── r5 (codex P1 notifications.rs:1246): bounded push-endpoint DNS ───────────────────────
// Hostname resolution runs on the shared blocking pool (getaddrinfo), and an attacker's name
// server can stall it for the resolver's full retry cycle. It used to run before any
// admission and without a deadline, so one account could park hundreds of blocking threads.
// Now: at most PUSH_DNS_MAX_CONCURRENT lookups process-wide (a lookup that times out keeps its
// slot until the blocking call really returns, so the bound holds), each awaited for at most
// PUSH_DNS_TIMEOUT, and at most SUBSCRIBE_INFLIGHT_PER_USER subscribe validations per account.
const PUSH_DNS_MAX_CONCURRENT: usize = 8;
const PUSH_DNS_TIMEOUT: Duration = if cfg!(test) { Duration::from_millis(400) } else { Duration::from_secs(5) };
const SUBSCRIBE_INFLIGHT_PER_USER: usize = 2;
/// Refusal while an account already has SUBSCRIBE_INFLIGHT_PER_USER validations running.
pub const SUBSCRIBE_BUSY: &str = "Another push subscription is still being checked — try again in a moment";

fn push_dns_slots() -> &'static Arc<tokio::sync::Semaphore> {
    static S: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    S.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(PUSH_DNS_MAX_CONCURRENT)))
}

struct SubscribeInFlight(String);
impl SubscribeInFlight {
    fn counts() -> &'static DashMap<String, usize> {
        static M: OnceLock<DashMap<String, usize>> = OnceLock::new();
        M.get_or_init(DashMap::new)
    }
    fn acquire(user: &str) -> Option<Self> {
        let mut c = Self::counts().entry(user.to_string()).or_insert(0);
        if *c >= SUBSCRIBE_INFLIGHT_PER_USER { return None; }
        *c += 1;
        Some(SubscribeInFlight(user.to_string()))
    }
}
impl Drop for SubscribeInFlight {
    fn drop(&mut self) {
        if let Some(mut c) = Self::counts().get_mut(&self.0) { *c = c.saturating_sub(1); }
        Self::counts().remove_if(&self.0, |_, v| *v == 0);
    }
}

fn system_resolve(host: &str, port: u16) -> std::io::Result<Vec<std::net::SocketAddr>> {
    use std::net::ToSocketAddrs;
    Ok((host, port).to_socket_addrs()?.collect())
}

/// Resolve `host:port` with `resolver` on the blocking pool, bounded as described above.
async fn resolve_push_host(host: &str, port: u16, resolver: fn(&str, u16) -> std::io::Result<Vec<std::net::SocketAddr>>)
    -> Result<Vec<std::net::SocketAddr>>
{
    let permit = tokio::time::timeout(PUSH_DNS_TIMEOUT, push_dns_slots().clone().acquire_owned()).await
        .map_err(|_| anyhow::anyhow!("Push endpoint host resolution is busy — try again in a moment"))?
        .map_err(|_| anyhow::anyhow!("Push endpoint host resolution failed"))?;
    let h = host.to_string();
    let task = tokio::task::spawn_blocking(move || { let _slot = permit; resolver(&h, port) });
    match tokio::time::timeout(PUSH_DNS_TIMEOUT, task).await {
        Ok(Ok(Ok(addrs))) => Ok(addrs),
        Ok(_) => bail!("Push endpoint host resolution failed"),
        Err(_) => bail!("Push endpoint host resolution timed out"),
    }
}

/// Convert raw 32-byte P-256 private key to PEM format for web-push crate.
fn pem_from_raw_key(raw: &[u8]) -> Result<Vec<u8>> {
    // web-push expects an SEC1 PEM private key
    // We use openssl to build it
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::bn::BigNum;

    if raw.len() != 32 { bail!("Invalid raw private key length"); }

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let bn    = BigNum::from_slice(raw)?;
    // Derive public key point from private key scalar
    let ctx = openssl::bn::BigNumContext::new()?; // #93: ctx is not mutated
    let mut pub_point = openssl::ec::EcPoint::new(&group)?;
    pub_point.mul_generator(&group, &bn, &ctx)?;
    let key   = EcKey::from_private_components(&group, &bn, &pub_point)?;
    Ok(key.private_key_to_pem()?)
}

#[cfg(test)]
mod push_filter_tests {
    use super::*;

    fn prefs() -> NotifPrefs {
        NotifPrefs { enabled: true, trigger: "mentions_and_dms".into(), ..Default::default() }
    }

    #[test]
    fn old_prefs_file_without_new_fields_has_no_filter() {
        // A notif_prefs/<user>.json written by 0.5.7 (no ignore / pm_protect keys).
        let old = r#"{"enabled":true,"trigger":"mentions_and_dms","muted_networks":[],"muted_channels":["c/#x"],"dnd":false,"dnd_start":"","dnd_end":"","dnd_tz_offset":0}"#;
        let p: NotifPrefs = serde_json::from_str(old).unwrap();
        assert!(p.ignore.is_empty());
        assert_eq!(p.pm_protect, PmProtect::default());
        assert!(p.pm_protect_net.is_empty());
        assert_eq!(push_filter_reason(&p, "u-old", "c", "anyone", Some("anyone!x@y"), true, Instant::now()), None);
        // and the oldest form (pre-DND) still parses
        let older = r#"{"enabled":false,"trigger":"dms_only","muted_networks":[],"muted_channels":[]}"#;
        assert!(serde_json::from_str::<NotifPrefs>(older).is_ok());
    }

    #[test]
    fn ignore_matches_like_app_js() {
        let m = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // exact nick, case-insensitive
        assert!(is_ignored(&m(&["evil"]), "EviL", Some("EviL!u@h")));
        assert!(is_ignored(&m(&["evil"]), "evil", None));
        assert!(!is_ignored(&m(&["evil"]), "evil2", Some("evil2!u@h")));
        // host mask against the full prefix
        assert!(is_ignored(&m(&["*!*@bad.host"]), "x", Some("x!ident@BAD.host")));
        assert!(!is_ignored(&m(&["*!*@bad.host"]), "x", Some("x!ident@good.host")));
        assert!(is_ignored(&m(&["*!*@*.isp.com"]), "x", Some("x!i@a.b.isp.com")));
        assert!(is_ignored(&m(&["ev?l!*@*"]), "eval", Some("eval!u@h")));
        // nick!*@* without a prefix matches on the nick part
        assert!(is_ignored(&m(&["evil!*@*"]), "evil", None));
        assert!(!is_ignored(&m(&["evil!*@*"]), "good", None));
        // a host mask cannot be decided from the nick alone
        assert!(!is_ignored(&m(&["*!*@bad.host"]), "x", None));
        // empty list / empty nick
        assert!(!is_ignored(&[], "evil", None));
        assert!(!is_ignored(&m(&["evil"]), "", None));
    }

    /// Argon P1 notifications.rs:409: a bare `?` mask is a wildcard (in-app isIgnored too).
    #[test]
    fn r3_question_mark_masks_are_wildcards() {
        let m = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(is_ignored(&m(&["guest?"]), "guest1", None));
        assert!(is_ignored(&m(&["guest?"]), "Guest7", Some("Guest7!u@h")));
        assert!(!is_ignored(&m(&["guest?"]), "guest12", None));
        assert!(!is_ignored(&m(&["guest?"]), "guest", None));
    }

    /// Argon P1 notifications.rs:1182: internal names in fully-qualified form (trailing dot)
    /// are refused BEFORE any DNS lookup, like their dot-less spelling.
    #[tokio::test]
    async fn r3_push_endpoint_trailing_dot_internal_names_refused() {
        for ep in ["https://localhost./p", "https://localhost../p", "https://svc.internal./p",
                   "https://printer.local./p", "https://a.localhost./p", "https://LOCALHOST./p"] {
            let e = validate_push_endpoint(ep).await.unwrap_err().to_string();
            assert!(e.contains("not allowed") || e.contains("Invalid push endpoint URL"), "{ep}: {e}");
        }
    }

    #[test]
    fn glob_basics() {
        assert!(glob_match("*", ""));
        assert!(glob_match("a*b?d", "axxxbcd"));
        assert!(!glob_match("a*b?d", "axxxbd"));
        assert!(glob_match("**a**", "zzazz"));
        assert!(!glob_match("abc", "abcd"));
        // pathological input stays fast (bounded by the caps)
        let p = "*a".repeat(128);
        let t = "a".repeat(255) + "b";
        assert!(!glob_match(&p, &t));
    }

    #[test]
    fn ignore_filter_blocks_dm_and_channel_push() {
        let mut p = prefs();
        p.ignore = vec!["evil".into(), "*!*@spam.net".into()];
        let now = Instant::now();
        assert_eq!(push_filter_reason(&p, "u-ign", "c1", "evil", Some("evil!a@b"), true, now), Some("sender is on the ignore list"));
        assert_eq!(push_filter_reason(&p, "u-ign", "c1", "evil", Some("evil!a@b"), false, now), Some("sender is on the ignore list"));
        assert_eq!(push_filter_reason(&p, "u-ign", "c1", "bob", Some("bob!a@spam.net"), true, now), Some("sender is on the ignore list"));
        assert_eq!(push_filter_reason(&p, "u-ign", "c1", "bob", Some("bob!a@ok.net"), true, now), None);
    }

    #[test]
    fn pm_protection_deliver_first_then_cooldown() {
        let mut p = prefs();
        p.pm_protect = PmProtect { enabled: true, cooldown_hours: 24, deliver_first: true, allow: vec!["friend".into()] };
        let t0 = Instant::now();
        let u = "u-pm-first";
        // first DM from a stranger passes (client delivers it too) …
        assert_eq!(push_filter_reason(&p, u, "c1", "Stranger", None, true, t0), None);
        // … every further DM inside the cooldown is dropped
        for i in 1..30 {
            assert_eq!(push_filter_reason(&p, u, "c1", "stranger", None, true, t0 + Duration::from_secs(i * 60)), Some("PM Protection"));
        }
        // after the window, the next one is a new "first"
        let later = t0 + Duration::from_secs(24 * 3600 + 5);
        assert_eq!(push_filter_reason(&p, u, "c1", "stranger", None, true, later), None);
        assert_eq!(push_filter_reason(&p, u, "c1", "stranger", None, true, later + Duration::from_secs(1)), Some("PM Protection"));
        // allow-listed sender always passes
        for _ in 0..5 { assert_eq!(push_filter_reason(&p, u, "c1", "FRIEND", None, true, t0), None); }
        // channel messages are not affected by PM Protection
        assert_eq!(push_filter_reason(&p, u, "c1", "stranger", None, false, t0 + Duration::from_secs(5)), None);
        // the window is per network
        assert_eq!(push_filter_reason(&p, u, "c2", "stranger", None, true, t0 + Duration::from_secs(5)), None);
    }

    #[test]
    fn pm_protection_without_deliver_first_and_net_override() {
        let mut p = prefs();
        p.pm_protect = PmProtect { enabled: true, cooldown_hours: 1, deliver_first: false, allow: vec![] };
        let t0 = Instant::now();
        let u = "u-pm-none";
        assert_eq!(push_filter_reason(&p, u, "c1", "x", None, true, t0), Some("PM Protection"));
        // a network override turns protection off for that network only
        p.pm_protect_net.insert("c9".into(), PmProtect { enabled: false, ..PmProtect::default() });
        assert_eq!(push_filter_reason(&p, u, "c9", "x", None, true, t0), None);
        assert_eq!(push_filter_reason(&p, u, "c1", "x", None, true, t0), Some("PM Protection"));
        // override allow list replaces the global one (app.js isPmAllowedFor)
        p.pm_protect.allow = vec!["pal".into()];
        p.pm_protect_net.insert("c8".into(), PmProtect { enabled: true, cooldown_hours: 1, deliver_first: false, allow: vec!["other".into()] });
        assert_eq!(push_filter_reason(&p, u, "c8", "pal", None, true, t0), Some("PM Protection"));
        assert_eq!(push_filter_reason(&p, u, "c8", "other", None, true, t0), None);
        assert_eq!(push_filter_reason(&p, u, "c1", "pal", None, true, t0), None);
        // disabled globally → no filter
        p.pm_protect.enabled = false;
        assert_eq!(push_filter_reason(&p, u, "c1", "x", None, true, t0), None);
    }

    #[test]
    fn patch_keeps_absent_fields_and_old_full_payload_still_works() {
        let mut p = prefs();
        p.muted_channels = vec!["c/#a".into()];
        p.ignore = vec!["evil".into()];
        p.trigger = "dms_only".into();
        // a mute-only patch (new client) does not touch trigger/enabled/ignore
        let patch: NotifPrefsPatch = serde_json::from_str(r#"{"muted_channels":["c/#b"],"muted_networks":[]}"#).unwrap();
        p.apply_patch(patch).unwrap();
        assert_eq!(p.muted_channels, vec!["c/#b".to_string()]);
        assert_eq!(p.trigger, "dms_only");
        assert!(p.enabled);
        assert_eq!(p.ignore, vec!["evil".to_string()]);
        // a full 0.5.7-style payload (stale cached app.js) replaces those fields as before
        // and, lacking the new keys, keeps the stored ignore list
        let old: NotifPrefsPatch = serde_json::from_str(r#"{"enabled":false,"trigger":"all_messages","muted_networks":["n"],"muted_channels":[],"dnd":true,"dnd_start":"22:00","dnd_end":"07:00","dnd_tz_offset":-60}"#).unwrap();
        p.apply_patch(old).unwrap();
        assert!(!p.enabled);
        assert_eq!(p.trigger, "all_messages");
        assert_eq!(p.muted_networks, vec!["n".to_string()]);
        assert!(p.dnd);
        assert_eq!(p.dnd_tz_offset, -60);
        assert_eq!(p.ignore, vec!["evil".to_string()]);
        // filters are normalised
        let f: NotifPrefsPatch = serde_json::from_str(r#"{"ignore":[" Evil ","evil","","*!*@X"],"pm_protect":{"enabled":true,"cooldown_hours":0,"allow":["Bob"]}}"#).unwrap();
        p.apply_patch(f).unwrap();
        assert_eq!(p.ignore, vec!["evil".to_string(), "*!*@x".to_string()]);
        assert!(p.pm_protect.enabled && p.pm_protect.deliver_first);
        assert_eq!(p.pm_protect.cooldown_hours, 1);
        assert_eq!(p.pm_protect.allow, vec!["bob".to_string()]);
    }

    #[test]
    fn patch_over_caps_is_rejected_without_partial_apply() {
        let mut p = prefs();
        p.muted_channels = vec!["keep".into()];
        let many: Vec<String> = (0..(MAX_MUTED_CHANNELS + 1)).map(|i| format!("c/#{}", i)).collect();
        let patch = NotifPrefsPatch { muted_channels: Some(many), trigger: Some("all_messages".into()), ..Default::default() };
        match p.apply_patch(patch) {
            Err(PrefsUpdateError::TooLarge(m)) => assert!(m.contains("muted channels")),
            other => panic!("expected TooLarge, got {:?}", other),
        }
        assert_eq!(p.muted_channels, vec!["keep".to_string()]);
        assert_eq!(p.trigger, "mentions_and_dms");
        let long_mask = NotifPrefsPatch { ignore: Some(vec!["x".repeat(MAX_MASK_LEN + 1)]), ..Default::default() };
        assert!(matches!(p.apply_patch(long_mask), Err(PrefsUpdateError::TooLarge(_))));
        // 90 mutes (the 4 KB-body failure point in the audit) is now fine
        let ninety: Vec<String> = (0..90).map(|i| format!("{}/#chan{}", "0f8e7d6c-1111-2222-3333-444455556666", i)).collect();
        assert!(p.apply_patch(NotifPrefsPatch { muted_channels: Some(ninety), ..Default::default() }).is_ok());
        assert_eq!(p.muted_channels.len(), 90);
    }

    #[test]
    fn get_view_hides_client_owned_filters() {
        let mut p = prefs();
        p.ignore = vec!["evil".into()];
        p.pm_protect.enabled = true;
        let v = p.client_view();
        assert!(v.get("ignore").is_none() && v.get("pm_protect").is_none() && v.get("pm_protect_net").is_none());
        assert_eq!(v["enabled"], serde_json::json!(true));
        assert_eq!(v["trigger"], serde_json::json!("mentions_and_dms"));
        assert!(v.get("muted_channels").is_some() && v.get("dnd_tz_offset").is_some());
        // what a stale client PUTs back from that view keeps the stored filters
        let back: NotifPrefsPatch = serde_json::from_value(v).unwrap();
        p.apply_patch(back).unwrap();
        assert_eq!(p.ignore, vec!["evil".to_string()]);
        assert!(p.pm_protect.enabled);
    }

    #[tokio::test]
    async fn update_prefs_merges_on_disk() {
        let dir = std::env::temp_dir().join(format!("cryptirc-notif-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mgr = NotificationManager::new(dir.to_str().unwrap(), VapidKeys { public_key: String::new(), private_key: String::new() });
        // no file yet → defaults + patch
        mgr.update_prefs("alice", serde_json::from_str(r#"{"ignore":["evil"]}"#).unwrap(), || true).await.unwrap();
        let p = mgr.load_prefs("alice").await;
        assert!(!p.enabled);
        assert_eq!(p.trigger, "mentions_and_dms");
        assert_eq!(p.ignore, vec!["evil".to_string()]);
        // device A enables push; device B later syncs only its mutes → A's change survives
        mgr.update_prefs("alice", serde_json::from_str(r#"{"enabled":true,"trigger":"dms_only"}"#).unwrap(), || true).await.unwrap();
        mgr.update_prefs("alice", serde_json::from_str(r#"{"muted_channels":["c/#x"],"muted_networks":[]}"#).unwrap(), || true).await.unwrap();
        let p = mgr.load_prefs("alice").await;
        assert!(p.enabled);
        assert_eq!(p.trigger, "dms_only");
        assert_eq!(p.muted_channels, vec!["c/#x".to_string()]);
        assert_eq!(p.ignore, vec!["evil".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod r4_push_purge_tests {
    //! r4 C1-5 (codex P1 notifications.rs:543): a subscription admitted before a recovery
    //! purge can't write itself back afterwards.
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn mgr() -> (NotificationManager, PathBuf) {
        let dir = std::env::temp_dir().join(format!("cryptirc-r4push-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        (NotificationManager::new(dir.to_str().unwrap(), VapidKeys { public_key: String::new(), private_key: String::new() }), dir)
    }
    fn sub(ep: &str) -> PushSubscription {
        PushSubscription { endpoint: ep.into(), keys: PushKeys { p256dh: "x".into(), auth: "y".into() }, label: None }
    }

    /// The race from the finding, with the endpoint check already done and the write waiting
    /// for the per-user lock: the reset revokes the session and purges meanwhile — the late
    /// write is refused and nothing is re-created. (A public IP literal: no DNS needed.)
    #[tokio::test]
    async fn a_subscribe_admitted_before_a_reset_cannot_outlive_its_purge() {
        let (m, dir) = mgr();
        let m = std::sync::Arc::new(m);
        let path = dir.join("push").join("victim.json");
        m.save_subscription("victim", sub("https://93.184.216.34/own"), || true).await.unwrap();
        assert!(path.exists());
        let revoked = std::sync::Arc::new(AtomicBool::new(false));
        let lock = m.user_lock("victim");
        let g = lock.lock().await;                      // something else holds the lock …
        let (m2, r2) = (m.clone(), revoked.clone());
        let late = tokio::spawn(async move {
            m2.save_subscription("victim", sub("https://93.184.216.34/attacker"), move || !r2.load(Ordering::SeqCst)).await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        revoked.store(true, Ordering::SeqCst);          // … the reset revokes the sessions …
        let m3 = m.clone();
        let purge = tokio::spawn(async move { m3.purge_user("victim").await });
        drop(g);
        let late = late.await.unwrap();
        purge.await.unwrap();
        let left = m.load_subscriptions("victim").await;
        println!("R4 C1-5: late subscribe = {:?}; subscriptions after the purge = {}", late.as_ref().map_err(|e| e.to_string()), left.len());
        assert_eq!(late.unwrap_err().to_string(), SUBSCRIBE_SESSION_GONE);
        assert!(left.is_empty() && !path.exists(), "nothing re-created");
        // A dead-endpoint prune after the purge doesn't re-create an empty file either.
        m.remove_subscription("victim", "https://93.184.216.34/own").await.unwrap();
        assert!(!path.exists());
        // Prefs: same rule.
        let r = m.update_prefs("victim", serde_json::from_str(r#"{"enabled":true}"#).unwrap(), || false).await;
        assert!(matches!(r, Err(PrefsUpdateError::SessionGone)));
        assert!(!dir.join("notif_prefs").join("victim.json").exists());
        // A live session still subscribes normally.
        m.save_subscription("victim", sub("https://93.184.216.34/new"), || true).await.unwrap();
        assert_eq!(m.load_subscriptions("victim").await.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod r5_push_dns_tests {
    //! r5 (codex P1 notifications.rs:1246): bounded push-endpoint resolution.
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static RUNNING: AtomicUsize = AtomicUsize::new(0);
    static PEAK: AtomicUsize = AtomicUsize::new(0);
    fn stalled(_h: &str, _p: u16) -> std::io::Result<Vec<std::net::SocketAddr>> {
        let n = RUNNING.fetch_add(1, Ordering::SeqCst) + 1;
        PEAK.fetch_max(n, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(1500));   // a name server that never answers in time
        RUNNING.fetch_sub(1, Ordering::SeqCst);
        Ok(vec![])
    }

    /// 40 lookups against a stalled resolver: every caller gets an answer within the deadline
    /// (timed out / busy), and at most PUSH_DNS_MAX_CONCURRENT blocking resolutions ever run.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stalled_dns_is_bounded_and_times_out() {
        let t0 = Instant::now();
        let hs: Vec<_> = (0..40).map(|_| tokio::spawn(resolve_push_host("slow.example", 443, stalled))).collect();
        let mut errs = Vec::new();
        for h in hs { errs.push(h.await.unwrap().unwrap_err().to_string()); }
        let took = t0.elapsed();
        println!("R5 push DNS: 40 stalled lookups answered in {:?}; peak concurrent resolutions = {}", took, PEAK.load(Ordering::SeqCst));
        assert!(took < Duration::from_millis(1400), "{took:?}");
        assert!(errs.iter().all(|e| e.contains("timed out") || e.contains("busy")), "{errs:?}");
        assert!(PEAK.load(Ordering::SeqCst) <= PUSH_DNS_MAX_CONCURRENT);
    }

    /// Per-account admission before any lookup.
    #[test]
    fn subscribe_validations_are_capped_per_account() {
        let u = format!("pushdns-{}", uuid::Uuid::new_v4().simple());
        let a = SubscribeInFlight::acquire(&u).expect("1st");
        let b = SubscribeInFlight::acquire(&u).expect("2nd");
        assert!(SubscribeInFlight::acquire(&u).is_none(), "3rd refused");
        assert!(SubscribeInFlight::acquire("someone-else-pushdns").is_some(), "other accounts unaffected");
        drop(a);
        assert!(SubscribeInFlight::acquire(&u).is_some(), "slot freed");
        drop(b);
    }
}

#[cfg(test)]
mod srv_b_r9_push_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn mgr() -> (Arc<NotificationManager>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("cryptirc-r9push-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        (Arc::new(NotificationManager::new(dir.to_str().unwrap(), VapidKeys { public_key: String::new(), private_key: String::new() })), dir)
    }
    fn sub(ep: &str) -> PushSubscription {
        PushSubscription { endpoint: ep.into(), keys: PushKeys { p256dh: "x".into(), auth: "y".into() }, label: None }
    }

    /// r9 (astra P4 resetpass.sh:717): resetpass.sh holds the account lock exclusively while it
    /// revokes the sessions (sessions_valid_after) and deletes push/ + notif_prefs/. A subscribe or
    /// a settings save that arrives meanwhile must be decided AFTER the script (its session check
    /// then sees the revocation) — it used to check and write at once, beside the script.
    #[tokio::test]
    async fn notification_writes_wait_for_an_admin_script_and_recheck_after_it() {
        let (m, dir) = mgr();
        let revoked = Arc::new(AtomicBool::new(false));
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (r2, d2) = (revoked.clone(), dir.clone());
        let script = std::thread::spawn(move || {
            use std::os::unix::io::AsRawFd;
            let f = std::fs::OpenOptions::new().read(true).write(true).create(true).open(d2.join(crate::auth::ADMIN_LOCK_FILE)).unwrap();
            assert_eq!(unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) }, 0);
            held_tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(400));
            r2.store(true, Ordering::SeqCst);           // the reset revokes the sessions …
            drop(f);                                    // … and the script exits
        });
        held_rx.recv().unwrap();
        let (r3, r4) = (revoked.clone(), revoked.clone());
        let s = m.save_subscription("victim", sub("https://93.184.216.34/attacker"), move || !r3.load(Ordering::SeqCst)).await;
        let p = m.update_prefs("victim", NotifPrefsPatch { enabled: Some(true), ..Default::default() }, move || !r4.load(Ordering::SeqCst)).await;
        script.join().unwrap();
        assert!(!dir.join("push/victim.json").exists(), "a subscribe made while resetpass.sh ran was written ({:?})", s.as_ref().err());
        assert!(!dir.join("notif_prefs/victim.json").exists(), "a settings save made while resetpass.sh ran was written");
        assert_eq!(s.unwrap_err().to_string(), SUBSCRIBE_SESSION_GONE);
        assert!(matches!(p, Err(PrefsUpdateError::SessionGone)));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// r9 (astra P1 notifications.rs:1013): a push failure names the endpoint by origin and a
    /// short hash only; the token (the URL's path) is never in the message.
    #[tokio::test]
    async fn push_errors_never_carry_the_endpoint_token() {
        let token = "SECRETr9tokenAbCdEf0123456789";
        let label = endpoint_label(&format!("https://fcm.googleapis.com/fcm/send/{token}"));
        assert!(label.starts_with("https://fcm.googleapis.com #") && label.len() == "https://fcm.googleapis.com #".len() + 8, "{label}");
        assert!(!label.contains(token) && !label.contains("/fcm/send"));
        assert_ne!(label, endpoint_label("https://fcm.googleapis.com/fcm/send/other"));
        assert!(endpoint_label("not a url").starts_with("(invalid endpoint) #"));
        // what reqwest's own error says about the request: the full URL — unless stripped
        let e = reqwest::Client::new().post(format!("http://127.0.0.1:9/fcm/send/{token}")).send().await.unwrap_err();
        assert!(format!("{:?}", e).contains(token), "reqwest no longer puts the URL in its error: {:?}", e);
        assert!(!format!("{:?}", e.without_url()).contains(token));
    }
}
