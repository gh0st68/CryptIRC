//! e2e.rs — End-to-end encryption storage layer
//!
//! Fixes in this pass:
//!   S1 — bundle endpoint now authenticated (fix in main.rs)
//!   S2 — consume_one_time_prekey uses per-user Mutex to eliminate TOCTOU race
//!
//! The server stores ONLY:
//!   - Public key bundles (identity keys, signed prekeys, one-time prekeys)
//!   - Encrypted private key blobs (encrypted client-side with e2e_enc_key)
//!   - Encrypted ratchet session states
//!   - Encrypted channel PSKs
//!
//! No plaintext private key material or message content ever lives here.
//!
//! Layout:
//!   data/e2e/{username}/
//!     identity.enc           — encrypted identity key blob
//!     bundle.json            — public key bundle
//!     otpk/{id}.json         — one-time prekey public halves
//!     sessions/{partner}.enc — encrypted ratchet/spk/otpk blobs
//!     channels/{chan}.enc    — encrypted channel PSK

// #93: `bail` was imported but never used — dropped to clear the compiler warning.
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc, time::{Duration, Instant}};
use tokio::sync::Mutex;
use tracing::warn;

// #27: Bound the rate at which any third party can drain a given user's
// one-time-prekey (OTPK) pool. Each `fetch_bundle` consumes one OTPK, and the
// fetch is reachable by any authenticated user against any target, so without a
// throttle an attacker can pre-drain a victim's OTPKs and silently downgrade all
// of their future sessions to a 3-DH handshake (no one-time-prekey forward
// secrecy). The throttle is keyed on the TARGET user (the resource being
// drained), independent of the caller, so it caps drain rate regardless of how
// many distinct attacker identities are used. When the budget is exceeded we
// still return the bundle but WITHOUT consuming an OTPK — identical behaviour to
// an empty pool (the initiator falls back to 3-DH) — so legitimate lookups never
// fail, only the drain primitive is rate-limited.
const OTPK_CONSUME_WINDOW: Duration = Duration::from_secs(60);
// #23: lowered from 5 to 2. At 5/min a single attacker drains MAX_OTPK_TOTAL=1024
// in <9 min; 2/min raises that to >8h while staying well above any legitimate
// rate (a real initiator consumes one OTPK per new conversation).
const OTPK_CONSUME_MAX_PER_WINDOW: u32 = 2;
// r5 (codex P1 e2e.rs:523): the budget above is now per (REQUESTER, target) — keyed by the
// target alone, one account fetching a victim's bundle twice a minute used every other
// requester's OTPK and pushed every legitimate handshake to the 3-DH fallback while the
// pool stayed full. This per-target ceiling still bounds how fast many accounts together
// can drain a pool (1024 OTPKs > 30 min at 30/min) and is far above legitimate demand, so
// one (or a few) accounts can no longer starve the others.
const OTPK_CONSUME_MAX_PER_TARGET_WINDOW: u32 = 30;

// HIGH: cap the number of one-time-prekey files written per call. A single
// publish/add carrying an unbounded `Vec<OneTimePrekey>` would create one inode
// per key, letting any authenticated user exhaust disk/inodes. Real clients
// publish at most a small bounded refill batch (256), so any input above this is
// abusive. This is the belt-and-suspenders write-loop bound; the command
// handlers also truncate the incoming vector before reaching the store.
const MAX_OTPK_WRITES_PER_CALL: usize = 256;

// MEDIUM/HIGH: per-user on-disk caps to bound disk/inode growth. Each of these
// bounds the number of records/files a single user can accumulate. Real clients
// never approach these limits (a few trusted nicks, a handful of active sessions
// and channels), so a generous reject/evict-when-exceeded policy is
// behaviour-preserving for legitimate use while denying a disk/inode-exhaustion
// DoS primitive.
const MAX_SESSION_FILES: usize = 4096;
const MAX_OTPK_TOTAL: usize = 1024;
const MAX_CHANNEL_KEY_FILES: usize = 4096;
/// r8 (codex P1 e2e.rs:658): the private half of a one-time prekey is the session slot
/// `__otpk__<key_id>`. A private half whose public half is no longer published (consumed
/// by a bundle fetch whose handshake never came, or never published) used to stay forever,
/// so fetches without handshakes filled the account's MAX_SESSION_FILES and every new
/// session — and every new private half — was refused. Only the newest
/// MAX_UNPUBLISHED_OTPK_PRIVS of them are kept once the session directory is full (a
/// consumed key counts as new from the moment it was handed out). It equals the published
/// pool's cap: an account that is offline cannot have more than its pool handed out, so a
/// handshake started while it was away is not pushed out before it is back.
const OTPK_PRIV_PREFIX: &str = "__otpk__";
const MAX_UNPUBLISHED_OTPK_PRIVS: usize = MAX_OTPK_TOTAL;
fn otpk_priv_slot(key_id: u32) -> SlotName {
    slot_name(&format!("{}{}", OTPK_PRIV_PREFIX, key_id), partner_is_safe)
}

// ─── Public key bundle types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBundle {
    pub identity_sign_key: String,
    pub identity_dh_key:   String,
    pub signed_prekey:     SignedPrekey,
    pub one_time_prekeys:  Vec<OneTimePrekey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPrekey {
    pub key_id:     u32,
    pub public_key: String,
    pub signature:  String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePrekey {
    pub key_id:     u32,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchedBundle {
    pub identity_sign_key: String,
    pub identity_dh_key:   String,
    pub signed_prekey:     SignedPrekey,
    pub one_time_prekey:   Option<OneTimePrekey>,
}

// ─── E2E Store ────────────────────────────────────────────────────────────────

pub struct E2EStore {
    data_dir: String,
    /// S2: per-user mutex prevents TOCTOU races on OTPK consumption.
    /// DashMap<username, Mutex<()>>
    otpk_locks: Arc<DashMap<String, Arc<Mutex<()>>>>,
    /// Serializes keyring changes with encrypted slot writes for the same account.
    slot_locks: DashMap<String, Arc<Mutex<()>>>,
    /// r3: per-user mutex for creating NEW session / channel-key slots (cap check +
    /// write), see `store_slot`.
    cap_locks: Arc<DashMap<String, Arc<Mutex<()>>>>,
    #[cfg(unix)]
    protected_slot_cache: DashMap<PathBuf, ((u64, u64, i64, i64, i64, i64), Vec<String>)>,
    /// #27: per-target sliding-window counter of OTPK consumptions. Keyed by the
    /// target username (the pool being drained). Value is (window_start, count).
    /// r5: the target-wide ceiling (OTPK_CONSUME_MAX_PER_TARGET_WINDOW).
    otpk_consume_rate: Arc<DashMap<String, (Instant, u32)>>,
    /// r5 (codex P1 e2e.rs:523): the same counter per (target, requester) — the
    /// OTPK_CONSUME_MAX_PER_WINDOW budget.
    otpk_pair_rate: Arc<DashMap<(String, String), (Instant, u32)>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SessionConflict {
    pub current: String,
    pub floor_blob: Option<String>,
}

#[derive(Debug)]
pub struct SessionIdentityChanged;

impl std::fmt::Display for SessionIdentityChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the account encryption identity changed")
    }
}

impl std::error::Error for SessionIdentityChanged {}

/// #41: outcome of an OTPK rate-budget check. `Blocked { first }` carries whether
/// this is the FIRST over-budget hit in the current window, so the per-victim warn
/// is emitted at most once per window (prevents log-spam keyed on victim identity).
enum OtpkBudget {
    Allowed,
    Blocked { first: bool },
}

impl E2EStore {
    pub fn new(data_dir: &str) -> Self {
        // #32/#142: create e2e/ with mode 0700 (secret-bearing) and surface failures.
        let e2e_dir = format!("{}/e2e", data_dir);
        #[cfg(unix)]
        let res = {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&e2e_dir)
        };
        #[cfg(not(unix))]
        let res = std::fs::create_dir_all(&e2e_dir);
        if let Err(e) = res { warn!("[E2E] could not create {} (0700): {}", e2e_dir, e); }
        let _ = NETNAMES_FILE.set(PathBuf::from(&e2e_dir).join("network_names.json"));
        Self {
            data_dir:          data_dir.to_string(),
            otpk_locks:        Arc::new(DashMap::new()),
            slot_locks:        DashMap::new(),
            cap_locks:         Arc::new(DashMap::new()),
            #[cfg(unix)]
            protected_slot_cache: DashMap::new(),
            otpk_consume_rate: Arc::new(DashMap::new()),
            otpk_pair_rate:    Arc::new(DashMap::new()),
        }
    }

    fn user_dir(&self, username: &str) -> PathBuf {
        let safe: String = username.chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .take(64).collect();
        PathBuf::from(&self.data_dir).join("e2e").join(safe)
    }

    /// S2: acquire the per-user OTPK lock.
    fn otpk_lock(&self, username: &str) -> Arc<Mutex<()>> {
        self.otpk_locks
            .entry(username.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// #27/#41: consult (and, when allowed, charge) the OTPK rate budget for consuming
    /// one of `username`'s OTPKs on behalf of `requester`. Sliding 60s windows: at most
    /// OTPK_CONSUME_MAX_PER_WINDOW per (target, requester) — r5, it was per target only —
    /// and OTPK_CONSUME_MAX_PER_TARGET_WINDOW per target in all. Returns `Allowed` when the
    /// caller may consume an OTPK (both counters are charged); otherwise `Blocked` and the
    /// caller MUST NOT consume (it falls back to a 3-DH bundle instead). `Blocked { first }`
    /// is true only on the first over-budget hit of a window, so the warn is logged at most
    /// once per window. MUST be called only after confirming the pool is non-empty, so
    /// budget is charged solely when an OTPK actually exists to be consumed. Called under
    /// the target's otpk_lock (atomic with the consume).
    fn otpk_consume_allowed(&self, username: &str, requester: &str) -> OtpkBudget {
        let now = Instant::now();
        // Bound the maps: an attacker querying many distinct targets would otherwise grow
        // them without limit. Drop fully-expired windows (which would be reset to a fresh
        // window on next access anyway, so no rate decision changes). Done BEFORE taking
        // the entry guards to avoid a same-map deadlock.
        if self.otpk_consume_rate.len() > 4096 {
            self.otpk_consume_rate.retain(|_, (ws, _)| now.duration_since(*ws) < OTPK_CONSUME_WINDOW);
        }
        if self.otpk_pair_rate.len() > 4096 {
            self.otpk_pair_rate.retain(|_, (ws, _)| now.duration_since(*ws) < OTPK_CONSUME_WINDOW);
        }
        // Current counts (an expired window counts as 0).
        let live = |v: Option<(Instant, u32)>| match v {
            Some((ws, n)) if now.duration_since(ws) < OTPK_CONSUME_WINDOW => (ws, n),
            _ => (now, 0),
        };
        let pair_key = (username.to_string(), requester.to_string());
        let (pws, pn) = live(self.otpk_pair_rate.get(&pair_key).map(|e| *e));
        let (tws, tn) = live(self.otpk_consume_rate.get(username).map(|e| *e));
        if pn < OTPK_CONSUME_MAX_PER_WINDOW && tn < OTPK_CONSUME_MAX_PER_TARGET_WINDOW {
            self.otpk_pair_rate.insert(pair_key, (pws, pn + 1));
            self.otpk_consume_rate.insert(username.to_string(), (tws, tn + 1));
            return OtpkBudget::Allowed;
        }
        // Over budget — count on the exhausted counter so the first block of its window is
        // distinguishable (log once); the caller still gets a 3-DH fallback.
        if pn >= OTPK_CONSUME_MAX_PER_WINDOW {
            self.otpk_pair_rate.insert(pair_key, (pws, pn.saturating_add(1)));
            OtpkBudget::Blocked { first: pn == OTPK_CONSUME_MAX_PER_WINDOW }
        } else {
            self.otpk_consume_rate.insert(username.to_string(), (tws, tn.saturating_add(1)));
            OtpkBudget::Blocked { first: tn == OTPK_CONSUME_MAX_PER_TARGET_WINDOW }
        }
    }

    // ── Identity blob ─────────────────────────────────────────────────────────

    pub async fn store_identity_enc(&self, username: &str, blob: &str) -> Result<()> {
        self.store_identity_enc_cas(username, blob, None).await.map(|_| ())
    }

    /// r3 (codex-p3 MED e2e.js:1129): conditional identity store, so two devices doing
    /// their first unlock at the same time can't both install an identity (each kept its
    /// own in memory and published its own bundle; one of them silently lost after a
    /// reload). `expect`: None = unconditional (older clients, /encrypt reset-identity),
    /// Some("") = only if no identity is stored yet, Some(b) = only if the stored blob is
    /// exactly `b`. The compare and the write happen under the file's write lock.
    /// Returns Some(current blob) when nothing was written because of a conflict; storing
    /// the blob that is already there (a retried request) is a success.
    pub async fn store_identity_enc_cas(&self, username: &str, blob: &str, expect: Option<&str>) -> Result<Option<String>> {
        let dir = self.user_dir(username);
        create_dir_secure(&dir).await?;
        let path = dir.join("identity.enc");
        let lock = slot_lock(&path);
        let _g = lock.lock().await;
        let cur = match tokio::fs::read_to_string(&path).await {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.into()),
        };
        if cur == blob { return Ok(None); }
        if expect.is_some_and(|exp| cur != exp) { return Ok(Some(cur)); }
        if cur.starts_with("e2e3.") && blob.starts_with("e2e3.") {
            // Once an identity has rotated, cached clients must prove which
            // stored identity their ratchet uses. Persist this before rotation.
            write_secret(&dir.join("identity-rotated"), b"1").await?;
            // Stop advertising the retired identity even if the rotating
            // browser closes before it can publish the new bundle.
            remove_secret_checked(&dir.join("bundle.json")).await?;
            #[cfg(unix)]
            tokio::fs::File::open(&dir).await?.sync_all().await?;
        }
        write_secret_locked(&path, blob.as_bytes()).await?;
        Ok(None)
    }

    /// r3: SHA-256 (hex) of the stored identity blob, or None without one. A bundle
    /// published by a current client names the identity blob it belongs to, so a bundle
    /// for an identity that lost the create race (or was replaced) is refused.
    pub async fn identity_blob_hash(&self, username: &str) -> Option<String> {
        use sha2::{Digest, Sha256};
        let b = self.load_identity_enc(username).await?;
        if b.is_empty() { return None; }
        Some(Sha256::digest(b.as_bytes()).iter().map(|x| format!("{:02x}", x)).collect())
    }

    pub async fn load_identity_enc(&self, username: &str) -> Option<String> {
        self.read_identity(username).await.ok().flatten()
    }

    pub async fn read_identity(&self, username: &str) -> Result<Option<String>> {
        match tokio::fs::read_to_string(self.user_dir(username).join("identity.enc")).await {
            Ok(blob) if blob.is_empty() => anyhow::bail!("empty encryption identity"),
            Ok(blob) => Ok(Some(blob)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// An existing or unreadable identity/bundle is an unavailable-key case,
    /// since asking a configured contact to start over can disrupt their sessions.
    pub async fn needs_bundle_setup(&self, username: &str) -> bool {
        let dir = self.user_dir(username);
        for file in ["identity.enc", "bundle.json"] {
            if !matches!(tokio::fs::metadata(dir.join(file)).await, Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
                return false;
            }
        }
        true
    }

    // The browser wraps its E2E master key with its own recovery code. The
    // server holds the wrapped keyring and the migration status for v1 blobs.
    fn keyring_path(&self, username: &str) -> PathBuf {
        self.user_dir(username).join("keyring.json")
    }

    /// Returns (blob, migrated) when the user has stored a client keyring.
    #[cfg(test)]
    async fn load_keyring(&self, username: &str) -> Option<(String, bool)> {
        self.read_keyring(username).await.ok().flatten()
    }

    pub async fn read_keyring(&self, username: &str) -> Result<Option<(String, bool)>> {
        let json = match tokio::fs::read_to_string(self.keyring_path(username)).await {
            Ok(json) => json,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        #[derive(serde::Deserialize)]
        struct Keyring {
            blob: String,
            #[serde(default)]
            migrated: bool,
        }
        let record: Keyring = serde_json::from_str(&json)?;
        anyhow::ensure!(record.blob.starts_with("e2k2.") || record.blob.starts_with("e2k3."), "unrecognized encryption keyring");
        Ok(Some((record.blob, record.migrated)))
    }

    /// True once the user's E2E data was re-wrapped under the client-held key.
    /// r3 (agy-P1 e2e.rs/main.rs:5106, fail closed): also true when there is no readable
    /// keyring but the identity blob is already in the client-held-key format. An
    /// upgraded client always stores the keyring BEFORE it writes any "e2e2." blob, so
    /// this state only arises when keyring.json was lost or damaged; legacy-format
    /// writes (a stale tab regenerating an identity it can't read) and the legacy key
    /// stay withheld instead of being handed out again.
    #[cfg(test)]
    async fn is_migrated(&self, username: &str) -> bool {
        match self.load_keyring(username).await {
            Some((_, m)) => m,
            None => self.stored_identity_version(username).await != Some(1),
        }
    }

    /// A missing identity allows first setup. An unreadable file leaves the version unknown.
    pub async fn stored_identity_version(&self, username: &str) -> Option<u32> {
        let prefix = read_blob_prefix(&self.user_dir(username).join("identity.enc")).await.ok()?;
        match prefix.as_deref() {
            Some([]) => None,
            Some(p) if p.starts_with(b"e2e3.") => Some(3),
            Some(p) if p.starts_with(b"e2e2.") => Some(2),
            _ => Some(1),
        }
    }

    /// r3 (codex-p3 HIGH main.rs:5003 / agy-P1 main.rs:5170): has an upgraded client
    /// ever run for this account (a keyring, or any "e2e2." identity)? The outdated-tab
    /// send guard applies from then on.
    #[cfg(test)]
    async fn has_upgraded_e2e(&self, username: &str) -> bool {
        // keyring.json present at all (even unparseable) counts.
        tokio::fs::metadata(self.keyring_path(username)).await.is_ok()
            || self.stored_identity_version(username).await != Some(1)
    }

    /// Serializes keyring changes with encrypted slot writes.
    async fn slot_update_lock(&self, username: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = self.slot_locks.entry(username.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        lock.lock_owned().await
    }

    pub async fn write_permit(&self, username: &str, version: u32) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        let permit = self.slot_update_lock(username).await;
        let minimum = self.minimum_slot_version(username).await?;
        (version >= minimum && (version < 3 || minimum == 3)).then_some(permit)
    }

    // Call with the slot lock held so a migration cannot change the answer
    // between this check and the protected operation.
    pub(crate) async fn minimum_slot_version(&self, username: &str) -> Option<u32> {
        match self.read_keyring(username).await.ok()? {
            Some((blob, _)) if blob.starts_with("e2k3.") => Some(3),
            Some((_, true)) => Some(2),
            Some((_, false)) => Some(1),
            None => self.stored_identity_version(username).await,
        }
    }

    /// Replace an old ciphertext only while it is still the current slot value.
    /// Normal slot writes and deletes acquire the same per-user lock.
    pub async fn rewrap_v2_blob(&self, username: &str, slot: &str, name: &str, expect: &str, blob: &str) -> Result<bool> {
        if !expect.starts_with("e2e2.") || !blob.starts_with("e2e3.") {
            anyhow::bail!("invalid E2E rewrap");
        }
        let Some(_permit) = self.write_permit(username, 3).await else { return Ok(false) };
        let already_rewrapped = |current: Option<&str>| {
            current.is_none_or(|b| b.starts_with("e2e3."))
        };
        match slot {
            "identity" => {
                let conflict = self.store_identity_enc_cas(username, blob, Some(expect)).await?;
                Ok(conflict.as_ref().is_none_or(|current| current.is_empty() || already_rewrapped(Some(current))))
            }
            "session" | "channel" => {
                // Keep private-prekey slots stable against quota eviction during rewrap.
                let cap_lock = self.cap_lock(username);
                let _cap = cap_lock.lock().await;
                let (dir, safe): (&str, fn(u8) -> bool) = if slot == "session" {
                    ("sessions", partner_is_safe)
                } else {
                    ("channels", channel_is_safe)
                };
                let dir = self.user_dir(username).join(dir);
                let disk_name = slot_name(name, safe);
                let current = load_slot(&dir, &disk_name).await;
                if current.as_deref() != Some(expect) {
                    return Ok(already_rewrapped(current.as_deref()));
                }
                write_slot(&dir, &disk_name, name, blob).await?;
                Ok(true)
            }
            _ => anyhow::bail!("unknown E2E slot"),
        }
    }

    async fn has_stored_blob_matching(&self, username: &str, matches: impl Fn(&[u8]) -> bool) -> Result<bool> {
        let dir = self.user_dir(username);
        if let Some(prefix) = read_blob_prefix(&dir.join("identity.enc")).await? {
            if matches(&prefix) { return Ok(true); }
        }
        for sub in ["sessions", "channels"] {
            let mut entries = match tokio::fs::read_dir(dir.join(sub)).await {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if path.extension().and_then(|ext| ext.to_str()) != Some("enc") { continue; }
                if let Some(prefix) = read_blob_prefix(&path).await? {
                    if matches(&prefix) { return Ok(true); }
                }
            }
        }
        Ok(false)
    }

    pub async fn needs_legacy_key(&self, username: &str) -> Result<bool> {
        self.has_stored_blob_matching(username,
            |p| !p.is_empty() && !p.starts_with(b"e2e2.") && !p.starts_with(b"e2e3.")).await
    }

    fn recovery_keyring_has_previous(blob: &str) -> Result<bool> {
        let bytes = STANDARD.decode(&blob["e2k3.".len()..])?;
        let body: serde_json::Value = serde_json::from_slice(&bytes)?;
        let decode = |name: &str| -> Result<Vec<u8>> {
            let value = body[name].as_str().ok_or_else(|| anyhow::anyhow!("invalid E2E keyring field"))?;
            Ok(STANDARD.decode(value)?)
        };
        let wrapped = decode("w")?.len();
        if body["v"].as_u64() != Some(3) || decode("s")?.len() != 16
            || decode("c")?.len() != 52 || !matches!(wrapped, 60 | 92)
        {
            anyhow::bail!("invalid E2E recovery keyring");
        }
        Ok(wrapped == 92)
    }

    /// Store the wrapped keyring. `migrated` can only move false -> true; a request
    /// with migrated=false never un-migrates an already-migrated user.
    ///
    /// r2 (codex-p1 HIGH e2e.rs:269): compare-and-swap. `expect` is the keyring blob
    /// the client believes is current: `Some("")` = create only if none exists (first
    /// unlock), `Some(b)` = replace only if the stored blob is exactly `b` (re-wrap,
    /// marking migrated). If the stored keyring differs, NOTHING is written and the
    /// current one is returned so the client adopts it — two devices doing their first
    /// upgraded unlock at the same time can no longer replace each other's master key
    /// (blobs migrated under the losing key would become unreadable). `None` = a
    /// client from before this change (unconditional replace, as before).
    /// Returns (effective migrated flag, Some(current blob) on a CAS conflict).
    /// Atomic tmp+rename (write_secret).
    pub async fn store_keyring(&self, username: &str, blob: &str, migrated: bool, expect: Option<&str>) -> Result<(bool, Option<String>)> {
        if !(blob.starts_with("e2k2.") || blob.starts_with("e2k3.")) || blob.len() > 4096
            || !blob.bytes().all(|b| b.is_ascii_graphic()) {
            anyhow::bail!("invalid keyring");
        }
        let _g = self.slot_update_lock(username).await;
        let cur = self.read_keyring(username).await?;
        let prev_migrated = matches!(cur, Some((_, true)));
        if blob.starts_with("e2k3.") {
            if expect.is_none() { anyhow::bail!("E2E recovery keyring requires a compare-and-swap"); }
            if cur.is_none() && self.stored_identity_version(username).await != Some(1) {
                anyhow::bail!("E2E keyring is missing for an existing identity");
            }
        } else if matches!(&cur, Some((old, _)) if old.starts_with("e2k3.")) {
            anyhow::bail!("E2E keyring downgrade refused");
        }

        if let Some(exp) = expect {
            let cur_blob = cur.as_ref().map(|(b, _)| b.as_str()).unwrap_or("");
            if cur_blob != exp {
                if cur_blob == blob {
                    // Our own earlier store (a retried request whose reply was lost):
                    // idempotent success, still honouring the migrated upgrade below.
                } else {
                    return Ok((prev_migrated, Some(cur_blob.to_string())));
                }
            }
        }
        if blob.starts_with("e2k3.") {
            let previous = Self::recovery_keyring_has_previous(blob)?;
            let finalized = match &cur {
                Some((old, _)) if old.starts_with("e2k3.") => !Self::recovery_keyring_has_previous(old)?,
                _ => false,
            };
            if previous && finalized {
                anyhow::bail!("E2E keyring migration rollback refused");
            }
            if !previous && !finalized
                && self.has_stored_blob_matching(username, |p| p.starts_with(b"e2e2.")).await?
            {
                anyhow::bail!("E2E data still needs the previous key");
            }
        }
        let eff = prev_migrated || (migrated && !self.needs_legacy_key(username).await?);
        if migrated && !eff {
            warn!("[E2E] not marking E2E data migrated yet: a legacy-format blob is still stored (written by an outdated tab?)");
        }
        let dir = self.user_dir(username);
        create_dir_secure(&dir).await?;
        let body = serde_json::json!({ "v": 1, "blob": blob, "migrated": eff });
        write_secret(&self.keyring_path(username), serde_json::to_string(&body)?).await?;
        Ok((eff, None))
    }

    /// Names of every stored session blob (peer ratchets AND the reserved
    /// __spk__/__otpk__/__state__ blobs), decoded back to the names the client used.
    /// Used by the one-time client-side re-wrap migration. Capped.
    pub async fn list_sessions(&self, username: &str) -> Vec<String> {
        list_slots(&self.user_dir(username).join("sessions"), partner_is_safe, MAX_SESSION_FILES).await
    }

    /// r3 (agy-P1 LOW e2e.rs:512): per-user lock for the "is this a NEW slot, and is
    /// there room for it" decision + the write that creates it.
    fn cap_lock(&self, username: &str) -> Arc<Mutex<()>> {
        self.cap_locks
            .entry(username.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Store one slot file (sessions/<partner>.enc or channels/<chan>.enc).
    /// Overwriting an existing slot is always allowed; a NEW slot is created only while
    /// the directory holds fewer than `max` slots. r3: that check and the creating write
    /// run under the per-user cap lock (two new slots written at once could both pass
    /// the count before), and only real slots are counted (not in-flight temp files or
    /// long-name sidecars).
    async fn store_slot(&self, username: &str, sub: &str, name: &str, is_safe: fn(u8) -> bool,
                        blob: &str, max: usize, what: &str) -> Result<()> {
        let dir = self.user_dir(username).join(sub);
        create_dir_secure(&dir).await?;
        let sn = slot_name(name, is_safe);
        if slot_exists(&dir, &sn).await {
            return write_slot(&dir, &sn, name, blob).await;
        }
        let lock = self.cap_lock(username);
        let _g = lock.lock().await;
        if !slot_exists(&dir, &sn).await && count_slot_files(&dir).await >= max {
            // r8: a full session directory first sheds stale one-time-prekey private halves.
            let freed = if sub == "sessions" { self.evict_unpublished_otpk_privs(username, &dir).await } else { 0 };
            if freed == 0 || count_slot_files(&dir).await >= max {
                warn!("[E2E] {} file cap ({}) reached for '{}' — rejecting a new one", what, max, username);
                anyhow::bail!("{} storage limit reached", what);
            }
        }
        write_slot(&dir, &sn, name, blob).await
    }

    /// r8 (see MAX_UNPUBLISHED_OTPK_PRIVS): remove all but the newest
    /// MAX_UNPUBLISHED_OTPK_PRIVS private halves `__otpk__<id>` in `sessions` whose public
    /// half `otpk/<id>.json` is not published. Called under the cap lock when the directory
    /// is full; takes the OTPK lock so a fetch cannot hand out a key between the two
    /// listings. Returns how many were removed.
    async fn evict_unpublished_otpk_privs(&self, username: &str, sessions: &std::path::Path) -> usize {
        let lock = self.otpk_lock(username);
        let _g = lock.lock().await;
        // An incomplete list of the published keys would make their private halves look
        // stale: on any read error nothing is removed.
        let mut published = std::collections::HashSet::new();
        match tokio::fs::read_dir(self.user_dir(username).join("otpk")).await {
            Ok(mut rd) => loop {
                match rd.next_entry().await {
                    Ok(Some(e)) => {
                        let p = e.path();
                        if p.extension().and_then(|x| x.to_str()) != Some("json") { continue; }
                        if let Some(id) = p.file_stem().and_then(|s| s.to_str()).and_then(|s| s.parse::<u32>().ok()) {
                            published.insert(id);
                        }
                    }
                    Ok(None) => break,
                    Err(_) => return 0,
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return 0,
        }
        let mut stale: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
        let Ok(mut rd) = tokio::fs::read_dir(sessions).await else { return 0 };
        while let Ok(Some(e)) = rd.next_entry().await {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("enc") { continue; }
            let Some(id) = p.file_stem().and_then(|s| s.to_str())
                .and_then(|s| s.strip_prefix(OTPK_PRIV_PREFIX))
                .and_then(|s| s.parse::<u32>().ok()) else { continue };
            if published.contains(&id) { continue; }
            let mt = e.metadata().await.ok().and_then(|m| m.modified().ok()).unwrap_or(std::time::UNIX_EPOCH);
            stale.push((mt, p));
        }
        if stale.len() <= MAX_UNPUBLISHED_OTPK_PRIVS { return 0; }
        stale.sort();   // oldest first
        let n = stale.len() - MAX_UNPUBLISHED_OTPK_PRIVS;
        for (_, p) in stale.into_iter().take(n) { remove_secret(&p).await; }
        warn!("[E2E] session file cap reached: removed {} stale one-time prekey private half(s)", n);
        n
    }

    // ── Public key bundle ─────────────────────────────────────────────────────

    /// Called with the account write permit. Concurrent recovering devices
    /// must leave a matching live bundle and its signed prekey together.
    pub async fn repair_bundle(&self, username: &str, bundle: &KeyBundle, by_id: &str, current: &str) -> Result<()> {
        anyhow::ensure!(valid_key_field(&bundle.identity_sign_key) && valid_key_field(&bundle.identity_dh_key)
            && valid_signed_prekey(&bundle.signed_prekey) && bundle.one_time_prekeys.is_empty(), "invalid repair bundle");
        anyhow::ensure!([by_id,current].iter().all(|blob| blob.starts_with("e2e3.") && blob.len() <= 4096),
            "invalid sealed signed prekey");
        if self.bundle_identity_keys(username).await.as_ref().is_some_and(|(dh, sign)|
            *dh == bundle.identity_dh_key && *sign == bundle.identity_sign_key) { return Ok(()); }
        let slot = format!("__spk__{}",bundle.signed_prekey.key_id);
        let dir = self.user_dir(username).join("sessions");
        let existing = read_session_revision(&dir, &slot_name(&slot, partner_is_safe)).await?;
        anyhow::ensure!(existing.is_empty() || existing == by_id, "signed prekey ID is already in use");
        self.store_session(username, &slot, by_id).await?;
        self.store_session(username, "__spk__", current).await?;
        self.store_bundle(username, bundle).await
    }

    pub async fn store_bundle(&self, username: &str, bundle: &KeyBundle) -> Result<()> {
        // #88: reject malformed/oversized key material before persisting it.
        if !valid_key_field(&bundle.identity_sign_key)
            || !valid_key_field(&bundle.identity_dh_key)
            || !valid_signed_prekey(&bundle.signed_prekey) {
            anyhow::bail!("Invalid key bundle");
        }
        let dir = self.user_dir(username);
        create_dir_secure(&dir).await?;

        // Store main bundle without one-time prekeys
        let mut b = bundle.clone();
        b.one_time_prekeys = vec![];
        write_secret(&dir.join("bundle.json"), serde_json::to_string(&b)?).await?;

        // Store one-time prekeys individually
        let otpk_dir = dir.join("otpk");
        create_dir_secure(&otpk_dir).await?;
        // HIGH: bound the OTPK writes by BOTH the per-call cap AND the per-user TOTAL cap
        // (MAX_OTPK_TOTAL). Like add_one_time_prekeys, the per-call cap alone is bypassable
        // by repeated E2EPublishBundle calls (each carrying fresh, non-colliding key_ids),
        // which would accumulate ~256 files per call and exhaust inodes/disk on the shared
        // data volume. Serialize the count→headroom→write block under the same per-user
        // OTPK lock that consume/add take, so the total cap is correct under multi-device
        // concurrency. The main bundle.json (identity + signed prekey) is always written
        // above regardless, so republishing still refreshes the public keys — only OTPKs
        // beyond the total cap are dropped.
        let lock = self.otpk_lock(username);
        let _guard = lock.lock().await;
        let existing = self.otpk_count(username).await;
        let headroom = MAX_OTPK_TOTAL.saturating_sub(existing);
        let limit = headroom.min(MAX_OTPK_WRITES_PER_CALL);
        self.publish_otpks_with_private_half(username, bundle.one_time_prekeys.iter(), limit).await
    }

    /// r8 (codex P1 e2e.rs:658): write up to `limit` OTPK public halves, but only those
    /// whose private half (session slot `__otpk__<id>`, stored by the client just before)
    /// exists — a key whose private half could not be stored (e.g. session storage full)
    /// was still published and handed to initiators, and every handshake on it failed.
    /// Caller holds the OTPK lock.
    async fn publish_otpks_with_private_half<'a>(&self, username: &str,
            keys: impl Iterator<Item = &'a OneTimePrekey>, limit: usize) -> Result<()> {
        let dir = self.user_dir(username);
        let (otpk_dir, sessions) = (dir.join("otpk"), dir.join("sessions"));
        let (mut written, mut unbacked) = (0usize, 0usize);
        for opk in keys.filter(|o| valid_key_field(&o.public_key)) {   // #88
            if written >= limit { break; }
            if !slot_exists(&sessions, &otpk_priv_slot(opk.key_id)).await { unbacked += 1; continue; }
            write_secret(&otpk_dir.join(format!("{}.json", opk.key_id)), serde_json::to_string(opk)?).await?;
            written += 1;
        }
        if unbacked > 0 {
            warn!("[E2E] {} one-time prekey(s) not published: their private half is not stored", unbacked);
        }
        Ok(())
    }

    /// Fetch a bundle and atomically consume one OTPK.
    /// Check if a user has a published key bundle (without consuming an OTPK).
    pub async fn has_bundle(&self, username: &str) -> bool {
        let dir = self.user_dir(username);
        tokio::fs::metadata(dir.join("bundle.json")).await.is_ok()
    }

    /// #49: return this user's published identity keys as `(identity_dh_key,
    /// identity_sign_key)` (base64), or None if they have no published bundle.
    /// Used to cross-check a relayed X3DH header against what the sender actually
    /// published, so a responder cannot be made to pin a divergent identity.
    /// Reads the bundle WITHOUT consuming an OTPK (unlike `fetch_bundle`).
    pub async fn bundle_identity_keys(&self, username: &str) -> Option<(String, String)> {
        let dir  = self.user_dir(username);
        let json = tokio::fs::read_to_string(dir.join("bundle.json")).await.ok()?;
        let bundle: KeyBundle = serde_json::from_str(&json).ok()?;
        Some((bundle.identity_dh_key, bundle.identity_sign_key))
    }

    /// `requester` = the account asking (r5: the OTPK budget is per requester and target).
    pub async fn fetch_bundle(&self, username: &str, requester: &str) -> Option<FetchedBundle> {
        let dir  = self.user_dir(username);
        let json = tokio::fs::read_to_string(dir.join("bundle.json")).await.ok()?;
        let bundle: KeyBundle = serde_json::from_str(&json).ok()?;

        // #27/#23/#41: throttle OTPK consumption per target so a third party cannot
        // drain the victim's pool on demand. The rate budget is charged ONLY when an
        // OTPK is actually consumed: peek the pool first and, on an empty pool, serve
        // the bundle without an OTPK (3-DH fallback) WITHOUT charging the budget or
        // emitting a per-victim log — the same wire response an over-budget fetch
        // produces, so empty-pool / over-budget / consumed cases are indistinguishable
        // at the budget layer. Over budget → same 3-DH fallback, with the per-victim
        // warn emitted at most once per window. The check MUST run INSIDE the
        // otpk_lock critical section (atomic with the consume) — checking it before
        // acquiring the lock let concurrent fetches diverge the recorded budget from
        // actual consumption (#23).
        let lock = self.otpk_lock(username);
        let _guard = lock.lock().await;
        let otpk = if self.otpk_count(username).await == 0 {
            // Empty pool: nothing to consume — don't charge the budget, don't log.
            None
        } else {
            match self.otpk_consume_allowed(username, requester) {
                OtpkBudget::Allowed => self.consume_one_time_prekey_locked(username).await,
                OtpkBudget::Blocked { first } => {
                    if first {
                        // r2 (v-e2e INFO-1): no username — "someone fetched X's
                        // bundle" is E2E contact metadata.
                        warn!("[E2E] OTPK consume rate limit hit — serving 3-DH bundle (no OTPK consumed)");
                    }
                    None
                }
            }
        };
        drop(_guard);

        Some(FetchedBundle {
            identity_sign_key: bundle.identity_sign_key,
            identity_dh_key:   bundle.identity_dh_key,
            signed_prekey:     bundle.signed_prekey,
            one_time_prekey:   otpk,
        })
    }

    /// Must be called while holding the OTPK lock for this user.
    async fn consume_one_time_prekey_locked(&self, username: &str) -> Option<OneTimePrekey> {
        let otpk_dir = self.user_dir(username).join("otpk");
        let mut rd   = tokio::fs::read_dir(&otpk_dir).await.ok()?;
        while let Ok(Some(entry)) = rd.next_entry().await {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(json) = tokio::fs::read_to_string(&path).await {
                    if let Ok(opk) = serde_json::from_str::<OneTimePrekey>(&json) {
                        // S2: remove before returning — no window for a second caller to grab it
                        if tokio::fs::remove_file(&path).await.is_ok() {
                            // r8: the private half now waits for a handshake; date it to
                            // this moment so eviction (oldest first) keeps it longest.
                            let priv_half = self.user_dir(username).join("sessions")
                                .join(format!("{}.enc", otpk_priv_slot(opk.key_id).stem));
                            let _ = tokio::task::spawn_blocking(move || {
                                std::fs::File::options().write(true).open(&priv_half)
                                    .and_then(|f| f.set_modified(std::time::SystemTime::now()))
                            }).await;
                            return Some(opk);
                        }
                    }
                }
            }
        }
        // r2 (v-e2e INFO-1): no username (this fires when SOMEONE ELSE fetches the
        // user's bundle — contact metadata).
        tracing::debug!("[E2E] no one-time prekeys remaining");
        None
    }

    pub async fn add_one_time_prekeys(&self, username: &str, keys: Vec<OneTimePrekey>) -> Result<()> {
        let otpk_dir = self.user_dir(username).join("otpk");
        create_dir_secure(&otpk_dir).await?;
        // MEDIUM: the per-call cap (MAX_OTPK_WRITES_PER_CALL) is bypassable by
        // repeated E2EAddOTPKs calls, so cap the TOTAL OTPK files held per user.
        // Count what already exists and only write up to the remaining headroom.
        // Consumption (fetch_bundle) removes files and frees slots, so legitimate
        // refill is unaffected; a flood is simply truncated at the total cap.
        //
        // The count→headroom→write block must hold the per-user OTPK lock (the same one
        // consume and store_bundle take): a single WS recv_task is sequential, but a user
        // can open multiple sockets (multi-device), and two concurrent E2EAddOTPKs would
        // otherwise both read the same `existing`, both compute the same headroom, and each
        // write up to MAX_OTPK_WRITES_PER_CALL distinct-key_id files — overshooting
        // MAX_OTPK_TOTAL by up to (N-1)*256 and defeating the inode/disk bound. No deadlock:
        // this path never recurses into consume/store_bundle and vice versa.
        let lock = self.otpk_lock(username);
        let _guard = lock.lock().await;
        let existing = self.otpk_count(username).await;
        let headroom = MAX_OTPK_TOTAL.saturating_sub(existing);
        if headroom == 0 {
            warn!(
                "[E2E] OTPK total cap ({}) reached for '{}' — dropping refill batch",
                MAX_OTPK_TOTAL, username
            );
            return Ok(());
        }
        // HIGH: bound the write loop so an oversized batch can't exhaust
        // inodes/disk. Caps at MAX_OTPK_WRITES_PER_CALL files per call and at the
        // remaining total headroom, whichever is smaller.
        let limit = headroom.min(MAX_OTPK_WRITES_PER_CALL);
        self.publish_otpks_with_private_half(username, keys.iter(), limit).await
    }

    pub async fn otpk_count(&self, username: &str) -> usize {
        let otpk_dir = self.user_dir(username).join("otpk");
        let Ok(mut rd) = tokio::fs::read_dir(&otpk_dir).await else { return 0; };
        let mut n = 0;
        while let Ok(Some(e)) = rd.next_entry().await {
            if e.path().extension().map(|x| x == "json").unwrap_or(false) { n += 1; }
        }
        n
    }

    // ── Session blobs (ratchet state, SPK, OTPKs — all browser-encrypted) ────

    pub async fn store_session(&self, username: &str, partner: &str, blob: &str) -> Result<()> {
        // MEDIUM: one session file per partner with no cap lets a user create an
        // unbounded number of session files (one inode each). Only a NEW partner file
        // grows the set — overwriting an existing partner is always allowed — and a new
        // one is refused once the per-user cap is reached (store_slot). Legitimate users
        // have a bounded set of active conversations and never hit this.
        self.store_slot(username, "sessions", partner, partner_is_safe, blob, MAX_SESSION_FILES, "session").await
    }

    /// Keep the identity check, revision comparison and write under the account's
    /// existing write permit. Older clients omit their document revision.
    pub(crate) async fn store_account_state(&self, username: &str, blob: &str, expected: Option<&str>,
                                            identity_revision: Option<&str>, _permit: tokio::sync::OwnedMutexGuard<()>)
                                            -> Result<Option<String>> {
        self.check_session_identity(username, identity_revision).await?;
        let Some(expected) = expected else {
            self.store_session(username, "__state__", blob).await?;
            return Ok(None);
        };
        anyhow::ensure!(valid_session_revision(expected), "invalid account state revision");
        let dir = self.user_dir(username).join("sessions");
        let current = read_session_revision(&dir, &slot_name("__state__", partner_is_safe)).await?;
        if current != blob {
            if !session_revision_matches(&current, expected) {
                return Ok(Some(current));
            }
            self.store_session(username, "__state__", blob).await?;
        }
        // A retry can find its own completed rename after a directory sync failed.
        #[cfg(unix)]
        {
            sync_slot_directory(&dir).await?;
            if expected.is_empty() { sync_slot_directory(&self.user_dir(username)).await?; }
        }
        Ok(None)
    }

    /// One acknowledged transition of a peer ratchet. The same per-user permit also
    /// serializes migration and deletion. Only an authenticated browser can open the blob.
    pub async fn commit_session(&self, username: &str, partner: &str, blob: &str, expected: &str, create: bool,
                                floor_expect: Option<&str>, identity_revision: Option<&str>,
                                mut previous_for_live_receivers: Option<&mut String>) -> Result<Option<SessionConflict>> {
        if let Some(previous) = previous_for_live_receivers.as_deref_mut() { previous.clear(); }
        let version = if blob.starts_with("e2e3.") { 3 } else if blob.starts_with("e2e2.") { 2 } else { anyhow::bail!("invalid session format") };
        let _permit = self.write_permit(username, version).await.ok_or_else(|| anyhow::anyhow!("outdated session format"))?;
        if version == 3 { self.check_session_identity(username, identity_revision).await?; }
        let dir = self.user_dir(username).join("sessions");
        let slot = slot_name(partner, partner_is_safe);
        let current = read_session_revision(&dir, &slot).await?;
        if current != blob {
            if (current.is_empty() && !create) || !session_revision_matches(&current, expected) {
                return Ok(Some(SessionConflict { current, floor_blob: None }));
            }
            // A close can race a fresh launch on a different device or contact.
            // A live ratchet keeps its own epoch regardless of other conversations.
            if current.is_empty() && create {
                let floor = self.read_close_floor(username).await?;
                if !session_revision_matches(&floor, floor_expect.unwrap_or("")) {
                    return Ok(Some(SessionConflict { current, floor_blob: Some(floor) }));
                }
            }
            self.store_session(username, partner, blob).await?;
        }
        // The rename may have succeeded before a directory write failed. An
        // idempotent retry must confirm that the new ratchet will survive reboot
        // before the browser can release its ciphertext.
        #[cfg(unix)]
        {
            sync_slot_directory(&dir).await?;
            // At first use, the sessions directory itself may also be new.
            // Confirm its entry in the account directory on creation and retry.
            if create { sync_slot_directory(&self.user_dir(username)).await?; }
        }
        // A sibling may already be handling this live IRC message while its
        // explicit Resume request is still in flight. The web process can
        // forward the exact opaque revision it just replaced to open sockets.
        if let Some(previous) = previous_for_live_receivers {
            if current != blob && current.starts_with("e2e3.") { *previous = current; }
        }
        Ok(None)
    }

    /// Retire the exact observed revision. Persist the account's encrypted
    /// generation floor before removing the last record of the old ratchet.
    pub async fn close_session(&self, username: &str, partner: &str, version: u32, expected: &str,
                               floor_expect: Option<&str>, next_floor: Option<&str>, identity_revision: Option<&str>) -> Result<Option<SessionConflict>> {
        let _permit = self.write_permit(username, version).await.ok_or_else(|| anyhow::anyhow!("outdated session format"))?;
        if version == 3 { self.check_session_identity(username, identity_revision).await?; }
        let dir = self.user_dir(username).join("sessions");
        let slot = slot_name(partner, partner_is_safe);
        let current = read_session_revision(&dir, &slot).await?;
        let canonical = !partner.starts_with("__legacy__");
        let floor = if canonical { Some(self.read_close_floor(username).await?) } else { None };
        if !session_revision_matches(&current, expected)
            || floor.as_ref().is_some_and(|value| !session_revision_matches(value, floor_expect.unwrap_or(""))) {
            return Ok(Some(SessionConflict { current, floor_blob: floor }));
        }
        if let Some(floor) = floor {
            let account = self.user_dir(username);
            if !current.is_empty() && version == 3 && (floor_expect.is_none() || (floor.is_empty() && next_floor.is_none())) {
                anyhow::bail!("reload CryptIRC to close this encrypted conversation");
            }
            if let Some(blob) = next_floor {
                anyhow::ensure!(!current.is_empty() && version == 3 && floor_expect.is_some() && valid_close_floor(blob),
                                "invalid session close floor");
                create_dir_secure(&account).await?;
                write_secret(&account.join("session-close-floor.enc"), blob).await?;
            }
            // A prior attempt may have written this exact floor and failed its
            // directory sync. A retry must confirm durability before deleting
            // the live slot, even when the floor no longer needs rewriting.
            #[cfg(unix)]
            if !current.is_empty() && version == 3 {
                tokio::fs::File::open(&account).await?.sync_all().await?;
            }
        } else {
            anyhow::ensure!(floor_expect.is_none() && next_floor.is_none(), "unexpected floor for archived session");
        }
        delete_slot(&dir, &slot).await?;
        // A repeated close can find an already unlinked slot after the first
        // directory sync failed. Confirm the deletion on both attempts.
        #[cfg(unix)]
        if let Err(error) = sync_slot_directory(&dir).await {
            if error.kind() != std::io::ErrorKind::NotFound { return Err(error.into()); }
        }
        Ok(None)
    }

    /// Keep identity rotation ordered with the final IRC handoff of a queued
    /// Signal message or reaction. Callers hold the permit through that write.
    pub(crate) async fn signal_delivery_permit(&self, username: &str, revision: Option<&str>, outdated_browser: bool) -> Result<tokio::sync::OwnedMutexGuard<()>> {
        let permit = self.slot_update_lock(username).await;
        let minimum = self.minimum_slot_version(username).await.ok_or_else(|| anyhow::anyhow!("identity unavailable"))?;
        anyhow::ensure!(!outdated_browser || minimum < 3, "reload CryptIRC before sending");
        self.check_session_identity(username, revision).await?;
        Ok(permit)
    }

    pub(crate) async fn check_session_identity(&self, username: &str, expected: Option<&str>) -> Result<()> {
        let dir = self.user_dir(username);
        if let Some(revision) = expected {
            let current = tokio::fs::read_to_string(dir.join("identity.enc")).await?;
            if !current.is_empty() && session_revision_matches(&current, revision) { return Ok(()); }
        } else if !tokio::fs::try_exists(dir.join("identity-rotated")).await? {
            return Ok(()); // A cached client on an account which has never rotated.
        }
        Err(SessionIdentityChanged.into())
    }

    async fn read_close_floor(&self, username: &str) -> Result<String> {
        let path = self.user_dir(username).join("session-close-floor.enc");
        match tokio::fs::read_to_string(path).await {
            Ok(blob) if valid_close_floor(&blob) => Ok(blob),
            Ok(_) => anyhow::bail!("unreadable session close floor"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(error) => Err(error.into()),
        }
    }

    pub async fn load_session_with_floor(&self, username: &str, partner: &str) -> Result<(String, String, bool)> {
        let _guard = self.slot_update_lock(username).await;
        let unconfigured = match self.minimum_slot_version(username).await {
            Some(3) => false,
            Some(1) if self.read_keyring(username).await?.is_none() && self.read_identity(username).await?.is_none() => true,
            _ => anyhow::bail!("could not confirm current session format"),
        };
        let dir = self.user_dir(username).join("sessions");
        let current = read_session_revision(&dir, &slot_name(partner, partner_is_safe)).await?;
        let floor = self.read_close_floor(username).await?;
        // A new account can confirm a deliberate plaintext send before setting up
        // encryption. Existing slot data or a close floor contradicts that state.
        if unconfigured {
            let (channels, sessions) = self.protected_names(username).await?;
            anyhow::ensure!(current.is_empty() && floor.is_empty() && channels.is_empty() && sessions.is_empty(), "unexpected encrypted account data");
        }
        Ok((current, floor, unconfigured))
    }

    pub async fn load_session(&self, username: &str, partner: &str) -> Option<String> {
        load_slot(&self.user_dir(username).join("sessions"), &slot_name(partner, partner_is_safe)).await
    }

    pub async fn delete_session(&self, username: &str, partner: &str) -> Result<()> {
        let dir = self.user_dir(username).join("sessions");
        let slot = slot_name(partner, partner_is_safe);
        // Cached clients may still request an unconditional delete. Keep this
        // operation for migrations and private prekeys. A live v3 peer ratchet
        // can only be retired by the revision-checked close operation.
        if !partner.starts_with("__") {
            let current = read_session_revision(&dir, &slot).await?;
            anyhow::ensure!(!current.starts_with("e2e3."), "reload CryptIRC to close this encrypted conversation");
        }
        delete_slot(&dir, &slot).await
    }

    // ── Channel PSKs ──────────────────────────────────────────────────────────

    pub async fn store_channel_key(&self, username: &str, channel: &str, blob: &str) -> Result<()> {
        // MEDIUM: same per-user file cap as sessions (only a NEW channel grows the set).
        self.store_slot(username, "channels", channel, channel_is_safe, blob, MAX_CHANNEL_KEY_FILES, "channel key").await
    }

    pub async fn load_channel_key(&self, username: &str, channel: &str) -> Option<String> {
        load_slot(&self.user_dir(username).join("channels"), &slot_name(channel, channel_is_safe)).await
    }

    pub async fn delete_channel_key(&self, username: &str, channel: &str) -> Result<()> {
        delete_slot(&self.user_dir(username).join("channels"), &slot_name(channel, channel_is_safe)).await
    }

    pub async fn list_channel_keys(&self, username: &str) -> Vec<String> {
        // #89: only real `.enc` channel-key files (skip strays) and a capped vector so a
        // reconnect can't trigger an unbounded fan-out of load round-trips.
        list_slots(&self.user_dir(username).join("channels"), channel_is_safe, MAX_CHANNEL_KEY_FILES).await
    }

    pub(crate) async fn protected_names(&self, username: &str) -> Result<(Vec<String>, Vec<String>)> {
        let dir = self.user_dir(username);
        Ok((
            self.protected_slots(dir.join("channels"), channel_is_safe, MAX_CHANNEL_KEY_FILES).await?,
            self.protected_slots(dir.join("sessions"), partner_is_safe, MAX_SESSION_FILES).await?,
        ))
    }

    pub(crate) async fn check_plain_reply(&self, username: &str, cold: bool,
        unprotected: impl FnOnce(Vec<String>, Vec<String>) -> bool,
    ) -> Result<Option<(String, Option<String>)>> {
        let _guard = self.slot_update_lock(username).await;
        let (channels, peers) = self.protected_names(username).await?;
        if !unprotected(channels, peers) { return Ok(None); }
        let keyring = if cold {
            let Some((blob, true)) = self.read_keyring(username).await? else { return Ok(None); };
            if !blob.starts_with("e2k3.") { return Ok(None); }
            Some(blob)
        } else { None };
        let slots = self.user_dir(username).join("sessions");
        let settings = read_session_revision(&slots, &slot_name("__state__", partner_is_safe)).await?;
        Ok(Some((settings, keyring)))
    }

    pub(crate) async fn plain_reply_permit(&self, username: &str, revision: &str,
        unprotected: impl FnOnce(Vec<String>, Vec<String>) -> bool,
    ) -> Result<Option<tokio::sync::OwnedMutexGuard<()>>> {
        let (settings_revision, ring_revision) = revision.split_once('.')
            .map_or((revision, None), |(settings, ring)| (settings, Some(ring)));
        if !valid_session_revision(settings_revision) || ring_revision.is_some_and(|ring| ring.len()!=64 || !valid_session_revision(ring)) {
            return Ok(None);
        }
        let guard = self.slot_update_lock(username).await;
        if let Some(ring) = ring_revision {
            let Some((blob, true)) = self.read_keyring(username).await? else { return Ok(None); };
            if !blob.starts_with("e2k3.") || !session_revision_matches(&blob, ring) { return Ok(None); }
        }
        let slots = self.user_dir(username).join("sessions");
        let settings = read_session_revision(&slots, &slot_name("__state__", partner_is_safe)).await?;
        if !session_revision_matches(&settings, settings_revision) { return Ok(None); }
        let (channels, peers) = self.protected_names(username).await?;
        Ok(unprotected(channels, peers).then_some(guard))
    }

    async fn protected_slots(&self, dir: PathBuf, is_safe: fn(u8) -> bool, cap: usize) -> Result<Vec<String>> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let stamp = |m: &std::fs::Metadata| (m.dev(), m.ino(), m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec());
            let metadata = match tokio::fs::metadata(&dir).await {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    self.protected_slot_cache.remove(&dir);
                    return Ok(Vec::new());
                }
                Err(e) => return Err(e.into()),
            };
            // Rapid directory changes can share one timestamp. Wait for coarse
            // filesystem clocks to advance before trusting a cached inventory.
            let cache_before = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default()
                .as_secs().saturating_sub(2) as i64;
            if metadata.mtime().max(metadata.ctime()) >= cache_before {
                self.protected_slot_cache.remove(&dir);
                return list_slots_checked(&dir, is_safe, cap, true).await;
            }
            let before = stamp(&metadata);
            if let Some(cached) = self.protected_slot_cache.get(&dir) {
                if cached.0 == before { return Ok(cached.1.clone()); }
            }
            let names = list_slots_checked(&dir, is_safe, cap, true).await?;
            // The directory stamp tracks name changes. Long names depend on
            // sidecar contents as well, so they always use the strict scan.
            if names.iter().all(|name| !slot_name(name, is_safe).hashed)
                && tokio::fs::metadata(&dir).await.ok().as_ref().map(stamp) == Some(before)
            {
                self.protected_slot_cache.insert(dir, (before, names.clone()));
            } else {
                self.protected_slot_cache.remove(&dir);
            }
            Ok(names)
        }
        #[cfg(not(unix))]
        list_slots_checked(&dir, is_safe, cap, true).await
    }

    /// Confirmed pins live in encrypted client state. Older releases also kept
    /// an unauthenticated mirror. Retire those files, including old fallback copies.
    pub async fn remove_legacy_trust_mirrors(&self) -> std::io::Result<()> {
        let mut users = match tokio::fs::read_dir(PathBuf::from(&self.data_dir).join("e2e")).await {
            Ok(users) => users,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        while let Some(user) = users.next_entry().await? {
            match user.file_type().await {
                Ok(kind) if kind.is_dir() => {}
                Ok(_) => continue,
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        warn!("[E2E] could not check account directory {}: {}", user.path().display(), e);
                    }
                    continue;
                }
            }
            for filename in ["trust.json", "trust.json.corrupt", "trust.json.oversized"] {
                let path = user.path().join(filename);
                if let Err(e) = tokio::fs::remove_file(&path).await {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        warn!("[E2E] could not remove legacy trust mirror {}: {}", path.display(), e);
                    }
                }
            }
        }
        Ok(())
    }
}

// ─── Network identity for E2E nick resolution (F10/F11) ───────────────────────
//
// E2E bundle fetches and X3DH relays name a peer by IRC nick. A nick only means
// something on one IRC network, so lookups are scoped to the caller's network. Two
// CryptIRC users are "on the same network" when both connections reported the same
// ISUPPORT NETWORK= name (005), or — when either name is unknown (e.g. right after a
// web restart re-attached to a live daemon) — when their configured server hosts share
// a registrable domain (irc.libera.chat ~ irc.eu.libera.chat).

// The map is persisted (e2e/network_names.json, conn_id → name) because the web
// process restarts on every update while irc_core keeps the IRC connections — the 005
// line is not seen again until the next reconnect.
static NETNAMES_FILE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

fn network_names() -> &'static DashMap<String, String> {
    static M: std::sync::OnceLock<DashMap<String, String>> = std::sync::OnceLock::new();
    M.get_or_init(|| {
        let m = DashMap::new();
        if let Some(f) = NETNAMES_FILE.get() {
            if let Ok(json) = std::fs::read_to_string(f) {
                if let Ok(v) = serde_json::from_str::<std::collections::HashMap<String, String>>(&json) {
                    for (k, n) in v.into_iter().take(65536) { m.insert(k, n); }
                }
            }
        }
        m
    })
}

/// r5: connections whose server announced UTF8MAPPING=rfc8265 (see note_isupport).
fn utf8mappings() -> &'static DashMap<String, ()> {
    static M: std::sync::OnceLock<DashMap<String, ()>> = std::sync::OnceLock::new();
    M.get_or_init(DashMap::new)
}

/// r5: did `conn_id`'s server announce UTF8MAPPING=rfc8265 (in this web process)?
pub fn utf8mapping_is_rfc8265(conn_id: &str) -> bool {
    utf8mappings().contains_key(conn_id)
}

/// Record the NETWORK= token of a 005 (RPL_ISUPPORT) line for `conn_id`.
/// r2 (v-irc I2): no blocking disk I/O here (this runs on a tokio worker for every 005,
/// replays included). A change only marks the map dirty; one debounced background task
/// persists the snapshot with async I/O.
pub fn note_isupport(conn_id: &str, params: &[String]) {
    let mut changed = false;
    for p in params {
        // r5 (codex P1 main.rs:7399): UTF8MAPPING (Ergo with casemapping precis announces
        // UTF8MAPPING=rfc8265 next to CASEMAPPING=ascii), for the E2E nick fold. In memory
        // only: after a web restart it is unknown until the next 005, and the fold is then
        // the narrower CASEMAPPING one (a resolution can fail, never match wider).
        if let Some((k, v)) = p.split_once('=') {
            if k.eq_ignore_ascii_case("UTF8MAPPING") && crate::auth::validate_uuid(conn_id).is_some() {
                let m = utf8mappings();
                if v.eq_ignore_ascii_case("rfc8265") {
                    if m.len() > 65536 { m.clear(); }
                    m.insert(conn_id.to_string(), ());
                } else {
                    m.remove(conn_id);
                }
            }
        }
        if let Some((_, name)) = p.split_once('=').filter(|(key, _)| key.eq_ignore_ascii_case("NETWORK")) {
            let name: String = name.chars().filter(|c| !c.is_control()).take(64).collect::<String>().to_lowercase();
            if name.is_empty() || crate::auth::validate_uuid(conn_id).is_none() { continue; }
            let m = network_names();
            if m.get(conn_id).map(|v| *v == name).unwrap_or(false) { continue; }
            if m.len() > 65536 { m.clear(); }
            m.insert(conn_id.to_string(), name);
            changed = true;
        }
    }
    if changed { persist_network_names_soon(); }
}

fn persist_network_names_soon() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static PENDING: AtomicBool = AtomicBool::new(false);
    let Some(f) = NETNAMES_FILE.get().cloned() else { return };
    if PENDING.swap(true, Ordering::AcqRel) { return; } // a write is already scheduled
    let Ok(rt) = tokio::runtime::Handle::try_current() else {
        PENDING.store(false, Ordering::Release);
        return;
    };
    rt.spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        PENDING.store(false, Ordering::Release); // later changes schedule another write
        let snapshot: std::collections::HashMap<String, String> =
            network_names().iter().map(|e| (e.key().clone(), e.value().clone())).collect();
        if let Ok(body) = serde_json::to_string(&snapshot) {
            let _ = write_secret(&f, body).await;
        }
    });
}

pub fn network_name(conn_id: &str) -> Option<String> {
    network_names().get(conn_id).map(|v| v.clone())
}

pub(crate) fn forget_network_name(conn_id: &str) {
    if network_names().remove(conn_id).is_some() { persist_network_names_soon(); }
}

/// r2 (security review, option B): NO registrable-domain / public-suffix guessing —
/// a hand-made suffix list can't fail closed (unknown ccTLD second levels, private
/// suffixes like dyndns / github.io all yield a "domain" shared by strangers). Two
/// different host NAMES are only treated as one network when both lie under the same
/// entry of this small allowlist of domains that IRC networks themselves own (nobody
/// else can create hosts under them). Anything else needs the exact same host.
const KNOWN_NETWORK_DOMAINS: &[&[&str]] = &[
    &["libera.chat"], &["oftc.net"], &["efnet.org"], &["rizon.net"], &["quakenet.org"],
    &["undernet.org"], &["dal.net"], &["ircnet.net"], &["esper.net"], &["snoonet.org"],
    &["hackint.org"], &["geekshed.net"], &["swiftirc.net"], &["irchighway.net"],
    &["slashnet.org"], &["ergo.chat"], &["twistednet.org"],
    // r3 (w-web scoping note): the remaining built-in presets (app.js NET_PRESETS:
    // irc.gamesurge.net, irc.2600.net, irc.anonops.com, irc.chat4all.org,
    // irc.tilde.chat) — each the network's own domain.
    &["gamesurge.net"], &["2600.net"], &["anonops.com"], &["chat4all.org"], &["tilde.chat"],
];

fn norm_host(h: &str) -> String { h.trim().trim_end_matches('.').to_lowercase() }

/// Index of the allowlisted network whose domain `host` is (or is under).
fn known_network_of(host: &str) -> Option<usize> {
    let h = norm_host(host);
    KNOWN_NETWORK_DOMAINS.iter().position(|ds| ds.iter().any(|d| h == *d || h.ends_with(&format!(".{}", d))))
}

/// Network identity of a connection: ISUPPORT NETWORK= name (if seen), configured
/// server host (normalised: lowercase, no trailing dot) and port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetIdent {
    pub name: Option<String>,
    pub host: String,
    pub port: u16,
}

impl NetIdent {
    pub fn new(name: Option<String>, host: &str, port: u16) -> Self {
        NetIdent { name, host: norm_host(host), port }
    }
}

/// How strongly connection `b` is on the same IRC network as `a` (0 = not at all):
///   3 — the same server: the exact same host and port;
///   2 — the exact same host on another port when BOTH report the same NETWORK= name
///       (plain + TLS port of one ircd), or two hosts under the same allowlisted
///       network domain (irc.libera.chat ~ irc.eu.libera.chat).
/// Differing NETWORK= names veto everything. A NETWORK= name alone never links two
/// hosts (any ircd can advertise any name — NEW-4), two ircds on one host/IP without
/// matching names are not one network (NEW-5), and nothing is inferred from DNS
/// suffixes (security review).
pub fn network_match_tier(a: &NetIdent, b: &NetIdent) -> u8 {
    if a.host.is_empty() || b.host.is_empty() { return 0; }
    let names_known = a.name.is_some() && b.name.is_some();
    let names_equal = names_known && a.name == b.name;
    if names_known && !names_equal { return 0; }
    if a.host == b.host {
        if a.port == b.port { return 3; }
        return if names_equal { 2 } else { 0 };
    }
    match (known_network_of(&a.host), known_network_of(&b.host)) {
        (Some(x), Some(y)) if x == y => 2,
        _ => 0,
    }
}

#[cfg(test)]
pub fn same_network(a: &NetIdent, b: &NetIdent) -> bool { network_match_tier(a, b) > 0 }

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// audit #45: best-effort chmod 0700 on a per-user e2e dir/subdir so the
/// world-traversable data dir cannot let other local users enumerate accounts,
/// reconstruct a contact graph from session/channel filenames, or read trust.json.
/// No-op on non-unix. Mirrors certs.rs::set_dir_mode.
async fn set_dir_mode(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await;
    }
    #[cfg(not(unix))]
    { let _ = path; }
}

/// audit #45: create an e2e dir recursively, then tighten it AND its per-user
/// parent to 0700 (create_dir_all honors the umask and never re-chmods an
/// existing dir on upgrade).
async fn create_dir_secure(dir: &std::path::Path) -> std::io::Result<()> {
    tokio::fs::create_dir_all(dir).await?;
    set_dir_mode(dir).await;
    if let Some(parent) = dir.parent() { set_dir_mode(parent).await; }
    Ok(())
}

/// r2 (codex-p1 MED e2e.rs:777): per-file write lock. Every write / delete of one E2E
/// file (identity, a session or channel-key slot, the keyring, trust.json, the bundle)
/// is serialised, so two sockets saving the same slot can't interleave.
fn slot_lock(path: &std::path::Path) -> Arc<Mutex<()>> {
    static LOCKS: std::sync::OnceLock<DashMap<PathBuf, Arc<Mutex<()>>>> = std::sync::OnceLock::new();
    let m = LOCKS.get_or_init(DashMap::new);
    if m.len() > 8192 { m.retain(|_, l| Arc::strong_count(l) > 1); }
    m.entry(path.to_path_buf()).or_insert_with(|| Arc::new(Mutex::new(()))).clone()
}

/// audit #45 + r2 (codex-p1 MED e2e.rs:777): write an e2e file ATOMICALLY with mode
/// 0600. The bytes go to a fresh temp file in the same directory (created 0600,
/// fsync'd), which is then renamed over the target — a crash, a full disk or a
/// concurrent save can no longer leave an empty or half-written identity / ratchet /
/// PSK file (it used to be truncated in place by tokio::fs::write). Serialised per
/// file (slot_lock).
async fn write_secret(path: &std::path::Path, bytes: impl AsRef<[u8]>) -> std::io::Result<()> {
    let lock = slot_lock(path);
    let _g = lock.lock().await;
    write_secret_locked(path, bytes.as_ref()).await
}

/// The body of write_secret, for a caller that already holds slot_lock(path).
/// r3 (agy-P1 HIGH e2e.rs:864): the temp name is a FIXED-length hidden name
/// (".tmp-" + 16 hex = 21 bytes) instead of "<target name>.tmp-<32 hex>", which pushed
/// a long (percent-encoded) slot name past NAME_MAX (255 bytes) so its write failed
/// with ENAMETOOLONG. It has no ".enc"/".json"/".name" extension (a leading-dot name
/// has none), so listings and counters never mistake a leftover for a slot.
/// r3 (w-web INFO): the directory is fsync'd after the rename (best effort), so a
/// power loss right after a save can't bring back the previous file.
async fn write_secret_locked(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut rnd = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut rnd);
    let tmp = path.with_file_name(format!(".tmp-{}", rnd.iter().map(|b| format!("{:02x}", b)).collect::<String>()));
    let res: std::io::Result<()> = async {
        let mut opts = tokio::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut f = opts.open(&tmp).await?;
        f.write_all(bytes).await?;
        f.sync_all().await?;
        drop(f);
        tokio::fs::rename(&tmp, path).await
    }.await;
    if res.is_err() { let _ = tokio::fs::remove_file(&tmp).await; return res; }
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(d) = tokio::fs::File::open(parent).await { let _ = d.sync_all().await; }
    }
    res
}

/// Delete an e2e file under the same per-file lock as write_secret.
async fn remove_secret(path: &std::path::Path) {
    let _ = remove_secret_checked(path).await;
}

async fn remove_secret_checked(path: &std::path::Path) -> Result<()> {
    let lock = slot_lock(path);
    let _g = lock.lock().await;
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

async fn read_blob_prefix(path: &std::path::Path) -> std::io::Result<Option<Vec<u8>>> {
    use tokio::io::AsyncReadExt;
    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut buf = Vec::with_capacity(8);
    file.take(8).read_to_end(&mut buf).await?;
    Ok(Some(buf))
}

/// Count the slot files (`*.enc`) in a directory, for the per-user file caps. A
/// missing directory counts as 0 (first write always allowed). r3 (agy-P1 LOW
/// e2e.rs:512): only slots are counted — in-flight temp files and long-name sidecars
/// used to count too, so an update in flight could make a user at cap-1 look full.
async fn count_slot_files(dir: &std::path::Path) -> usize {
    let Ok(mut rd) = tokio::fs::read_dir(dir).await else { return 0; };
    let mut n = 0;
    while let Ok(Some(e)) = rd.next_entry().await {
        if e.path().extension().and_then(|x| x.to_str()) == Some("enc") { n += 1; }
    }
    n
}

// ─── Slot file names (r3, agy-P1 HIGH e2e.rs:864) ─────────────────────────────
//
// A slot (session partner / channel) is stored as <stem>.enc, stem = the injective
// percent-encoding of its name (fs_encode_full). That encoding is used verbatim, exactly
// as before, whenever it is shorter than FS_VERBATIM_MAX bytes — every name that ever
// fitted, i.e. every real nick / channel. Longer encodings used to be TRUNCATED at ~248
// bytes, so two long names sharing a prefix (e.g. ~72 non-ASCII bytes) collided on one
// file and overwrote each other's key. They now get a collision-proof stem:
//   <first ≤160 bytes of the encoding> "~" <first 32 hex of SHA-256(name)>
// ('~' never occurs in an encoding, so such a stem can't be mistaken for one), plus a
// sidecar <stem>.name holding the exact name (so listings still return it). A file
// stored under the OLD truncated name stays readable: loads fall back to it, the next
// write of that name moves it to the new stem (removing the old file, which is exactly
// what the old code's overwrite did), and a delete removes both.

const FS_VERBATIM_MAX: usize = 248;
const FS_HASHED_PREFIX: usize = 160;

struct SlotName {
    /// File stem the slot is written under.
    stem: String,
    /// The stem the pre-r3 code used for this name when it differs (truncated encoding).
    legacy: Option<String>,
    /// `stem` is a hashed long-name stem (has a .name sidecar).
    hashed: bool,
}

fn session_revision_matches(blob: &str, expected: &str) -> bool {
    use sha2::{Digest, Sha256};
    if blob.is_empty() { expected.is_empty() } else { format!("{:x}", Sha256::digest(blob.as_bytes())) == expected }
}

fn valid_close_floor(blob: &str) -> bool {
    // Twelve nonce bytes, a decimal safe integer and a 16-byte GCM tag.
    blob.len() <= 128 && blob.strip_prefix("e2e3.").is_some_and(|body|
        STANDARD.decode(body).is_ok_and(|sealed| (29..=44).contains(&sealed.len())))
}

async fn read_session_revision(dir: &std::path::Path, slot: &SlotName) -> Result<String> {
    match read_slot(dir, slot).await? {
        Some(value) if value.is_empty() => anyhow::bail!("empty session file"),
        value => Ok(value.unwrap_or_default()),
    }
}

pub(crate) fn valid_peer_revision(partner: &str, expected: &str) -> bool {
    !partner.is_empty() && !partner.starts_with("__") && partner.len() <= 256 && valid_session_revision(expected)
}

fn valid_session_revision(expected: &str) -> bool {
    expected.is_empty() || (expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn slot_name(name: &str, is_safe: fn(u8) -> bool) -> SlotName {
    use sha2::{Digest, Sha256};
    let full = fs_encode_full(name, is_safe);
    if full.len() < FS_VERBATIM_MAX {
        return SlotName { stem: full, legacy: None, hashed: false };
    }
    // Cut the readable prefix on an escape boundary (never inside "%XX").
    let b = full.as_bytes();
    let mut cut = FS_HASHED_PREFIX.min(b.len());
    while cut > 0 && ((cut >= 1 && b[cut - 1] == b'%') || (cut >= 2 && b[cut - 2] == b'%')) { cut -= 1; }
    let h: String = Sha256::digest(name.as_bytes()).iter().take(16).map(|x| format!("{:02x}", x)).collect();
    SlotName { stem: format!("{}~{}", &full[..cut], h), legacy: Some(fs_encode(name, is_safe)), hashed: true }
}

async fn slot_exists(dir: &std::path::Path, sn: &SlotName) -> bool {
    if tokio::fs::metadata(dir.join(format!("{}.enc", sn.stem))).await.is_ok() { return true; }
    match &sn.legacy {
        Some(l) => tokio::fs::metadata(dir.join(format!("{}.enc", l))).await.is_ok(),
        None => false,
    }
}

async fn write_slot(dir: &std::path::Path, sn: &SlotName, name: &str, blob: &str) -> Result<()> {
    if sn.hashed {
        write_secret(&dir.join(format!("{}.name", sn.stem)), name.as_bytes()).await?;
    }
    write_secret(&dir.join(format!("{}.enc", sn.stem)), blob).await?;
    if let Some(l) = &sn.legacy {
        remove_secret(&dir.join(format!("{}.enc", l))).await;
    }
    Ok(())
}

async fn load_slot(dir: &std::path::Path, sn: &SlotName) -> Option<String> {
    read_slot(dir, sn).await.ok().flatten()
}

async fn read_slot(dir: &std::path::Path, sn: &SlotName) -> std::io::Result<Option<String>> {
    for name in std::iter::once(&sn.stem).chain(sn.legacy.as_ref()) {
        match tokio::fs::read_to_string(dir.join(format!("{name}.enc"))).await {
            Ok(blob) => return Ok(Some(blob)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

#[cfg(unix)]
async fn sync_slot_directory(dir: &std::path::Path) -> std::io::Result<()> {
    tokio::fs::File::open(dir).await?.sync_all().await
}

async fn delete_slot(dir: &std::path::Path, sn: &SlotName) -> Result<()> {
    if let Some(l) = &sn.legacy {
        remove_secret_checked(&dir.join(format!("{}.enc", l))).await?;
    }
    remove_secret_checked(&dir.join(format!("{}.enc", sn.stem))).await?;
    if sn.hashed {
        remove_secret_checked(&dir.join(format!("{}.name", sn.stem))).await?;
    }
    Ok(())
}

/// The client-side names of the slots in `dir` (≤ cap). A hashed stem is reported by
/// its sidecar name (only when the sidecar really maps to that stem); one without a
/// valid sidecar is skipped.
async fn list_slots(dir: &std::path::Path, is_safe: fn(u8) -> bool, cap: usize) -> Vec<String> {
    list_slots_checked(dir, is_safe, cap, false).await.unwrap_or_default()
}

async fn list_slots_checked(dir: &std::path::Path, is_safe: fn(u8) -> bool, cap: usize, strict: bool) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut rd = match tokio::fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(e) if !strict || e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e.into()),
    };
    loop {
        let e = match rd.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(_) if !strict => break,
            Err(e) => return Err(e.into()),
        };
        let path = e.path();
        if path.extension().and_then(|x| x.to_str()) != Some("enc") { continue; }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            if strict { anyhow::bail!("Unreadable E2E slot name"); }
            continue;
        };
        if stem.contains('~') {
            let name = match tokio::fs::read_to_string(dir.join(format!("{}.name", stem))).await {
                Ok(name) => name,
                Err(_) if !strict => continue,
                Err(e) => return Err(e.into()),
            };
            let sn = slot_name(&name, is_safe);
            if !sn.hashed || sn.stem != stem {
                if strict { anyhow::bail!("Invalid E2E slot name"); }
                continue;
            }
            out.push(name);
        } else {
            out.push(fs_decode(stem));
        }
        if strict {
            if out.len() > cap { anyhow::bail!("Too many E2E slots"); }
        } else if out.len() >= cap {
            break;
        }
    }
    Ok(out)
}

/// #88: validate a client-supplied base64 public-key / signature field before it is
/// written to disk. The store persists these strings verbatim, ×MAX_OTPK_TOTAL files,
/// so an unbounded field is a disk-amplification primitive. We require valid base64
/// decoding to a small, sane byte length (covers raw 32-byte X25519/Ed25519 keys,
/// 65-byte uncompressed P-256 points, and 64-byte signatures) and reject anything
/// larger. Empty is rejected.
fn valid_key_field(s: &str) -> bool {
    use base64::Engine;
    if s.is_empty() || s.len() > 256 { return false; }
    let dec = base64::engine::general_purpose::STANDARD.decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s));
    matches!(dec, Ok(b) if (1..=128).contains(&b.len()))
}

fn valid_signed_prekey(spk: &SignedPrekey) -> bool {
    valid_key_field(&spk.public_key) && valid_key_field(&spk.signature)
}

// Finding #13/#36: ONE canonical, injective encoding for on-disk partner/channel
// filenames. Previously names were STRIPPED of "unsafe" chars in two DIVERGENT
// layers (main.rs kept Unicode alnum, e2e stripped to ASCII), so distinct nicks or
// channels that differ only by non-ASCII homoglyphs (and IRC-legal `[nick]`)
// collapsed onto a SINGLE `.enc` file, letting one peer's/channel's ratchet, trust,
// replay-guard, or PSK state silently overwrite another's. We percent-encode
// instead: bytes in the allow-set pass through verbatim (identity on the old safe
// set, so every file already on disk stays reachable and the ASCII case — including
// the reserved `__spk__`/`__otpk__<id>` blobs — is byte-for-byte unchanged), while
// every other byte, including the escape byte `%`, becomes `%XX`. That makes the map
// injective (losslessly decodable): distinct names can never collide, which closes
// the channel-key collision of #36 as well. Output is capped so a pathological name
// can't exceed the filesystem's per-name byte limit.
fn fs_encode(name: &str, is_safe: fn(u8) -> bool) -> String {
    // r3: this is the pre-r3 TRUNCATING encoding, kept only to find files written
    // under it (SlotName::legacy); new names come from slot_name / fs_encode_full.
    let mut out = String::new();
    for &b in name.as_bytes() {
        push_enc(&mut out, b, is_safe);
        if out.len() >= 248 { break; }
    }
    out
}

/// The full (untruncated) percent-encoding of `name`.
fn fs_encode_full(name: &str, is_safe: fn(u8) -> bool) -> String {
    let mut out = String::with_capacity(name.len());
    for &b in name.as_bytes() { push_enc(&mut out, b, is_safe); }
    out
}

fn push_enc(out: &mut String, b: u8, is_safe: fn(u8) -> bool) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    if b != b'%' && is_safe(b) {
        out.push(b as char);
    } else {
        out.push('%');
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
}

/// Inverse of `fs_encode`; used only to report stored channel names back to the
/// client verbatim. Identity on names with no `%` escape (all pre-existing ASCII
/// channel files), so behavior for real channels is unchanged.
fn fs_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) =
                ((b[i + 1] as char).to_digit(16), (b[i + 2] as char).to_digit(16))
            {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn partner_is_safe(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn channel_is_safe(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'#' || b == b'&'
}


#[cfg(test)]
mod keyring_tests {
    use super::*;

    /// r5: plant a published bundle + `n` one-time prekeys for `user`.
    fn plant_bundle(dir: &str, user: &str, n: u32) {
        let base = std::path::Path::new(dir).join("e2e").join(user);
        std::fs::create_dir_all(base.join("otpk")).unwrap();
        let b = KeyBundle {
            identity_sign_key: "sig".into(), identity_dh_key: "dh".into(),
            signed_prekey: SignedPrekey { key_id: 1, public_key: "spk".into(), signature: "s".into() },
            one_time_prekeys: vec![],
        };
        std::fs::write(base.join("bundle.json"), serde_json::to_string(&b).unwrap()).unwrap();
        for i in 0..n {
            let o = OneTimePrekey { key_id: i, public_key: format!("opk{i}") };
            std::fs::write(base.join("otpk").join(format!("{i}.json")), serde_json::to_string(&o).unwrap()).unwrap();
        }
    }

    #[tokio::test]
    async fn removes_only_legacy_trust_mirrors() {
        let dir = tmpdir();
        let store = E2EStore::new(&dir);
        let user = store.user_dir("alice");
        tokio::fs::create_dir_all(&user).await.unwrap();
        for filename in ["trust.json", "trust.json.corrupt", "trust.json.oversized"] {
            tokio::fs::write(user.join(filename), "legacy mirror").await.unwrap();
        }
        store.store_session("alice", "__state__", "e2e3.encrypted").await.unwrap();
        store.remove_legacy_trust_mirrors().await.unwrap();
        store.remove_legacy_trust_mirrors().await.unwrap();
        for filename in ["trust.json", "trust.json.corrupt", "trust.json.oversized"] {
            assert!(!user.join(filename).exists());
        }
        assert_eq!(store.load_session("alice", "__state__").await.as_deref(), Some("e2e3.encrypted"));
        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    /// r5 (codex P1 e2e.rs:523): one account fetching a victim's bundle over and over can
    /// no longer use up every other requester's one-time prekeys (the budget was keyed by
    /// the target only, so the next legitimate handshake got the 3-DH fallback); many
    /// accounts together are still bounded by the per-target ceiling.
    #[tokio::test]
    async fn otpk_budget_is_per_requester_with_a_target_ceiling() {
        let d = tmpdir();
        let st = E2EStore::new(&d);
        plant_bundle(&d, "victim", 60);
        let mut mallory = 0;
        for _ in 0..6 {
            if st.fetch_bundle("victim", "mallory").await.unwrap().one_time_prekey.is_some() { mallory += 1; }
        }
        assert_eq!(mallory, OTPK_CONSUME_MAX_PER_WINDOW as usize, "one requester: its own budget only");
        for who in ["alice", "bob"] {
            let b = st.fetch_bundle("victim", who).await.unwrap();
            assert!(b.one_time_prekey.is_some(), "{who}'s handshake still gets a one-time prekey");
        }
        // Many requesters: at most the per-target ceiling per window in all.
        let before = st.otpk_count("victim").await;
        for i in 0..40 { let _ = st.fetch_bundle("victim", &format!("u{i}")).await; }
        let consumed_total = 60 - st.otpk_count("victim").await;
        assert_eq!(consumed_total, OTPK_CONSUME_MAX_PER_TARGET_WINDOW as usize, "target-wide ceiling (before the burst: {} left)", before);
        // Over budget is still a successful (3-DH) bundle, never an error.
        assert!(st.fetch_bundle("victim", "carol").await.is_some());
        let _ = std::fs::remove_dir_all(d);
    }

    fn tmpdir() -> String {
        let d = std::env::temp_dir().join(format!("cryptirc-e2e-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }


    fn recovery_keyring(wrapped_len: usize) -> String {
        let body = serde_json::json!({
            "v": 3,
            "s": STANDARD.encode([0; 16]),
            "w": STANDARD.encode(vec![0; wrapped_len]),
            "c": STANDARD.encode([0; 52]),
        });
        format!("e2k3.{}", STANDARD.encode(body.to_string()))
    }

    #[tokio::test]
    async fn account_state_writers_merge_independent_edits_after_a_revision_conflict() {
        use sha2::{Digest, Sha256};

        async fn save(store: &E2EStore, blob: &str, expected: Option<&str>) -> Result<Option<String>> {
            let permit = store.write_permit("alice", 3).await.unwrap();
            store.store_account_state("alice", blob, expected, None, permit).await
        }

        let dir = tmpdir();
        let store = E2EStore::new(&dir);
        store.store_identity_enc("alice", "e2e3.fixture-identity").await.unwrap();
        let digest = |s: &str| format!("{:x}", Sha256::digest(s.as_bytes()));
        let base = "e2e3.initial-settings";
        let base_revision = digest(base);
        let left = "e2e3.first-display-flag";
        let right = "e2e3.second-display-flag";
        let merged = "e2e3.both-display-flags";
        assert_eq!(save(&store, left, Some(&base_revision)).await.unwrap().as_deref(), Some(""));
        assert_eq!(save(&store, base, Some("")).await.unwrap(), None);
        assert_eq!(save(&store, left, Some("")).await.unwrap().as_deref(), Some(base));

        let (a, b) = tokio::join!(save(&store, left, Some(&base_revision)), save(&store, right, Some(&base_revision)));
        let winner = match (a.unwrap(), b.unwrap()) {
            (None, Some(current)) if current == left => current,
            (Some(current), None) if current == right => current,
            other => panic!("expected one commit and the winning document in the other reply: {other:?}"),
        };
        assert_eq!(store.load_session("alice", "__state__").await.as_deref(), Some(winner.as_str()));
        let winning_revision = digest(&winner);
        assert_eq!(save(&store, merged, Some(&winning_revision)).await.unwrap(), None);
        assert_eq!(save(&store, merged, Some(&winning_revision)).await.unwrap(), None);
        assert_eq!(store.load_session("alice", "__state__").await.as_deref(), Some(merged));

        let permit = store.write_permit("alice", 3).await.unwrap();
        let rejected = store.store_account_state("alice", left, Some(&base_revision), Some(&digest("retired")), permit).await;
        assert!(rejected.unwrap_err().is::<SessionIdentityChanged>());
        assert_eq!(save(&store, base, None).await.unwrap(), None);
        let file = store.user_dir("alice").join("sessions").join("__state__.enc");
        let backup = file.with_extension("original");
        std::fs::rename(&file, &backup).unwrap();
        std::fs::create_dir(&file).unwrap();
        assert!(save(&store, left, Some("")).await.unwrap_err().is::<std::io::Error>());
        assert!(file.is_dir());
        assert_eq!(std::fs::read_to_string(backup).unwrap(), base);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_close_cannot_discard_a_newer_ratchet_that_the_device_has_never_seen() {
        use sha2::{Digest, Sha256};
        let dir = tmpdir();
        let store = E2EStore::new(&dir);
        store.store_identity_enc("alice", "e2e3.identity").await.unwrap();
        let revision = |s: &str| format!("{:x}", Sha256::digest(s.as_bytes()));
        let old = "e2e3.epoch_three";
        let new = "e2e3.epoch_seven";
        let old_revision = revision(old);
        let new_revision = revision(new);
        let floor = format!("e2e3.{}", STANDARD.encode([7u8; 40]));
        let floor_revision = revision(&floor);
        for n in 0..16 {
            let peer = format!("peer-{n}");
            let account = format!("user{n}");
            store.store_identity_enc(&account, "e2e3.identity").await.unwrap();
            store.commit_session(&account, &peer, old, "", true, Some(""), None, None).await.unwrap();
            let (sent, closed) = tokio::join!(
                store.commit_session(&account, &peer, new, &old_revision, false, None, None, None),
                store.close_session(&account, &peer, 3, &old_revision, Some(""), Some(&floor), None),
            );
            match (sent.unwrap(), closed.unwrap()) {
                (None, Some(current)) => {
                    assert_eq!(current.current, new);
                    assert_eq!(current.floor_blob.as_deref(), Some(""));
                    assert_eq!(store.load_session(&account, &peer).await.as_deref(), Some(new));
                    assert_eq!(store.close_session(&account, &peer, 3, &new_revision, Some(""), Some(&floor), None).await.unwrap(), None);
                }
                (Some(missing), None) => assert!(missing.current.is_empty()),
                other => panic!("send and close both accepted or both refused: {other:?}"),
            }
            let conflict = store.close_session(&account, &peer, 3, &new_revision, Some(""), None, None).await.unwrap().unwrap();
            assert_eq!(conflict.current, "");
            assert_eq!(conflict.floor_blob.as_deref(), Some(floor.as_str()));
            assert_eq!(store.close_session(&account, &peer, 3, "", Some(&floor_revision), None, None).await.unwrap(), None);
        }
        let unreadable = store.user_dir("alice").join("sessions").join("broken.enc");
        tokio::fs::create_dir_all(&unreadable).await.unwrap();
        assert!(store.close_session("alice", "broken", 3, "", Some(""), None, None).await.is_err());
        assert!(unreadable.is_dir());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn live_receivers_get_the_exact_revision_replaced_by_a_successful_commit() {
        use sha2::{Digest, Sha256};
        let dir = tmpdir();
        let store = E2EStore::new(&dir);
        let old = "e2e3.before";
        let new = "e2e3.after";
        let expected = format!("{:x}", Sha256::digest(old.as_bytes()));
        let mut previous = String::new();
        store.store_identity_enc("alice", "e2e3.identity").await.unwrap();
        assert!(store.commit_session("alice", "bob", old, "", true, None, None, Some(&mut previous)).await.unwrap().is_none());
        assert!(previous.is_empty());
        assert!(store.commit_session("alice", "bob", new, "", false, None, None, Some(&mut previous)).await.unwrap().is_some());
        assert!(previous.is_empty());
        assert!(store.commit_session("alice", "bob", new, &expected, false, None, None, Some(&mut previous)).await.unwrap().is_none());
        assert_eq!(previous, old);
        assert!(store.commit_session("alice", "bob", new, &expected, false, None, None, Some(&mut previous)).await.unwrap().is_none());
        assert!(previous.is_empty());
        assert_eq!(store.load_session("alice", "bob").await.as_deref(), Some(new));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn identity_rotation_retires_writes_from_open_devices_before_session_cleanup() {
        use sha2::{Digest, Sha256};
        let dir = tmpdir();
        let store = E2EStore::new(&dir);
        let revision = |blob: &str| format!("{:x}",Sha256::digest(blob.as_bytes()));
        let previous = "e2e3.previous_identity";
        let current = "e2e3.current_identity";
        let session = "e2e3.session";
        store.store_identity_enc("alice", previous).await.unwrap();
        store.store_identity_enc("carol", previous).await.unwrap();
        assert_eq!(store.commit_session("alice","bob",session,"",true,None,Some(&revision(previous)), None).await.unwrap(),None);
        assert_eq!(store.store_identity_enc_cas("alice",current,Some(previous)).await.unwrap(),None);
        drop(store);
        let store = E2EStore::new(&dir);
        for stale in [None,Some(revision(previous))] {
            assert!(store.commit_session("alice","bob","e2e3.stale",&revision(session),false,None,stale.as_deref(), None)
                .await.unwrap_err().is::<SessionIdentityChanged>());
            assert!(store.close_session("alice","bob",3,&revision(session),Some(""),None,stale.as_deref())
                .await.unwrap_err().is::<SessionIdentityChanged>());
            assert_eq!(store.load_session("alice","bob").await.as_deref(),Some(session));
        }
        assert_eq!(store.commit_session("alice","bob","e2e3.replacement",&revision(session),true,None,Some(&revision(current)), None).await.unwrap(),None);
        assert_eq!(store.commit_session("carol","bob",session,"",true,None,None, None).await.unwrap(),None);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn signal_handoff_tracks_migration_and_interrupted_bundle_publication() {
        let dir = tmpdir();
        let store = E2EStore::new(&dir);
        store.store_identity_enc("legacy","legacy").await.unwrap();
        assert!(store.signal_delivery_permit("legacy",None,true).await.is_ok());
        store.store_keyring("v2","e2k2.test",true,Some("")).await.unwrap();
        assert!(store.signal_delivery_permit("v2",None,true).await.is_ok());
        let old = "e2e3.first";
        let new = "e2e3.second";
        store.store_identity_enc("alice",old).await.unwrap();
        plant_bundle(&dir,"alice",0);
        assert!(store.signal_delivery_permit("alice",None,true).await.is_err());
        store.store_identity_enc_cas("alice",new,Some(old)).await.unwrap();
        assert!(store.fetch_bundle("alice","bob").await.is_none());
        assert!(store.signal_delivery_permit("alice",None,false).await.is_err());
        let revision = store.identity_blob_hash("alice").await.unwrap();
        let permit = store.signal_delivery_permit("alice",Some(&revision),false).await.unwrap();
        let bundle = KeyBundle {identity_sign_key:"U0lH".into(),identity_dh_key:"REg=".into(),
            signed_prekey:SignedPrekey {key_id:27,public_key:"U1BL".into(),signature:"U0lH".into()},one_time_prekeys:vec![]};
        store.repair_bundle("alice",&bundle,"e2e3.numbered","e2e3.current").await.unwrap();
        store.repair_bundle("alice",&bundle,"e2e3.other","e2e3.other-current").await.unwrap();
        assert_eq!(store.load_session("alice","__spk__27").await.as_deref(),Some("e2e3.numbered"));
        assert_eq!(store.load_session("alice","__spk__").await.as_deref(),Some("e2e3.current"));
        assert_eq!(store.bundle_identity_keys("alice").await,Some((bundle.identity_dh_key,bundle.identity_sign_key)));
        drop(permit);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn an_unconfigured_account_can_confirm_only_an_empty_contact_slot() {
        let dir = tmpdir();
        let store = E2EStore::new(&dir);
        assert_eq!(store.load_session_with_floor("new", "bob").await.unwrap(), (String::new(), String::new(), true));
        assert!(store.write_permit("new", 3).await.is_none());
        store.store_channel_key("orphan", "other-peer", "old-channel-key").await.unwrap();
        assert!(store.load_session_with_floor("orphan", "bob").await.is_err());
        assert!(store.store_keyring("enrolled", &recovery_keyring(60), true, Some("")).await.unwrap().0);
        assert_eq!(store.load_session_with_floor("enrolled", "bob").await.unwrap(), (String::new(), String::new(), false));
        store.store_session("new", "bob", "legacy-slot").await.unwrap();
        assert!(store.load_session_with_floor("new", "bob").await.is_err());
        tokio::fs::create_dir_all(store.user_dir("legacy")).await.unwrap();
        tokio::fs::write(store.user_dir("legacy").join("identity.enc"), "legacy-identity").await.unwrap();
        assert!(store.load_session_with_floor("legacy", "bob").await.is_err());
        tokio::fs::create_dir_all(store.user_dir("broken")).await.unwrap();
        tokio::fs::write(store.keyring_path("broken"), "{}").await.unwrap();
        assert!(store.load_session_with_floor("broken", "bob").await.is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn sealed_close_floor_survives_restart_and_only_guards_new_ratchets() {
        use sha2::{Digest, Sha256};
        let dir = tmpdir();
        let store = E2EStore::new(&dir);
        let seal = |n: u8| format!("e2e3.{}", STANDARD.encode([n; 40]));
        let revision = |s: &str| format!("{:x}", Sha256::digest(s.as_bytes()));
        let first = seal(1);
        let later = seal(2);
        for account in ["alice", "carol"] {
            store.store_identity_enc(account, "e2e3.identity").await.unwrap();
            for peer in ["bob", "dave"] {
                assert_eq!(store.commit_session(account, peer, "e2e3.live", "", true, None, None, None).await.unwrap(), None);
            }
        }
        let live = revision("e2e3.live");
        assert!(store.close_session("alice", "bob", 3, &live, None, None, None).await.is_err());
        assert!(store.close_session("alice", "bob", 3, &live, Some(""), Some("unsealed"), None).await.is_err());
        assert_eq!(store.load_session_with_floor("alice", "bob").await.unwrap(), ("e2e3.live".into(), "".into(), false));
        assert_eq!(store.close_session("alice", "bob", 3, &live, Some(""), Some(&first), None).await.unwrap(), None);
        drop(store); // All process-local locks and caches are gone.
        let store = E2EStore::new(&dir);
        assert_eq!(store.load_session_with_floor("alice", "bob").await.unwrap(), ("".into(), first.clone(), false));
        assert!(store.close_session("alice", "bob", 3, "", Some(&revision(&first)), Some(&later), None).await.is_err());
        assert_eq!(store.load_session_with_floor("alice", "bob").await.unwrap(), ("".into(), first.clone(), false));
        assert_eq!(store.load_session_with_floor("carol", "bob").await.unwrap(), ("e2e3.live".into(), "".into(), false));
        let stale = store.close_session("alice", "dave", 3, &live, Some(""), Some(&later), None).await.unwrap().unwrap();
        assert_eq!(stale.current, "e2e3.live");
        assert_eq!(stale.floor_blob.as_deref(), Some(first.as_str()));
        for stale_floor in [None, Some("")] {
            let stale = store.commit_session("alice", "bob", "e2e3.too_old", "", true, stale_floor, None, None).await.unwrap().unwrap();
            assert!(stale.current.is_empty());
            assert_eq!(stale.floor_blob.as_deref(), Some(first.as_str()));
        }
        assert_eq!(store.commit_session("alice", "bob", "e2e3.fresh", "", true, Some(&revision(&first)), None, None).await.unwrap(), None);
        assert_eq!(store.commit_session("alice", "dave", "e2e3.next", &live, false, None, None, None).await.unwrap(), None);
        assert_eq!(store.close_session("alice", "dave", 3, &revision("e2e3.next"), Some(&revision(&first)), Some(&later), None).await.unwrap(), None);
        // An earlier successful create can retry its identical sealed revision.
        assert_eq!(store.commit_session("alice", "bob", "e2e3.fresh", "", true, Some(&revision(&first)), None, None).await.unwrap(), None);
        assert_eq!(store.load_session_with_floor("alice", "bob").await.unwrap(), ("e2e3.fresh".into(), later, false));
        assert!(store.list_sessions("alice").await.iter().all(|peer| peer == "bob"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn unreadable_close_floor_leaves_the_live_session_in_place() {
        use sha2::{Digest, Sha256};
        let dir = tmpdir();
        let store = E2EStore::new(&dir);
        store.store_identity_enc("alice", "e2e3.identity").await.unwrap();
        store.store_session("alice", "bob", "e2e3.live").await.unwrap();
        let path = store.user_dir("alice").join("session-close-floor.enc");
        let live = format!("{:x}", Sha256::digest(b"e2e3.live"));
        let floor = format!("e2e3.{}", STANDARD.encode([3; 40]));
        tokio::fs::create_dir(&path).await.unwrap();
        assert!(store.close_session("alice", "bob", 3, &live, Some(""), Some(&floor), None).await.is_err());
        assert!(store.load_session_with_floor("alice", "other").await.is_err());
        tokio::fs::remove_dir(&path).await.unwrap();
        tokio::fs::write(&path, b"").await.unwrap();
        assert!(store.close_session("alice", "bob", 3, &live, Some(""), Some(&floor), None).await.is_err());
        assert!(store.commit_session("alice", "other", "e2e3.new", "", true, Some(""), None, None).await.is_err());
        assert_eq!(store.load_session("alice", "bob").await.as_deref(), Some("e2e3.live"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn closing_a_legacy_peer_revision_is_scoped_to_its_account_and_slot() {
        use sha2::{Digest, Sha256};
        let dir = tmpdir();
        let store = E2EStore::new(&dir);
        let archived = "__legacy__bob";
        let blob = "e2e3.archived";
        let revision = format!("{:x}", Sha256::digest(blob.as_bytes()));
        for account in ["alice", "carol"] {
            store.store_identity_enc(account, "e2e3.identity").await.unwrap();
            store.store_session(account, archived, blob).await.unwrap();
            store.store_session(account, "bob", "e2e3.active").await.unwrap();
        }
        assert_eq!(store.close_session("alice", archived, 3, &revision, None, None, None).await.unwrap(), None);
        assert_eq!(store.load_session("alice", archived).await, None);
        assert_eq!(store.load_session("carol", archived).await.as_deref(), Some(blob));
        for account in ["alice", "carol"] {
            assert_eq!(store.load_session(account, "bob").await.as_deref(), Some("e2e3.active"));
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn peer_session_commits_are_conditional_and_retryable() {
        use sha2::{Digest, Sha256};
        let dir = tmpdir();
        let store = E2EStore::new(&dir);
        store.store_identity_enc("alice", "e2e3.identity").await.unwrap();
        let (a, b) = tokio::join!(
            store.commit_session("alice", "bob", "e2e3.left", "", true, None, None, None),
            store.commit_session("alice", "bob", "e2e3.right", "", true, None, None, None),
        );
        let stored = store.load_session("alice", "bob").await.unwrap();
        let outcomes = [a.unwrap(), b.unwrap()];
        assert_eq!(outcomes.iter().filter(|result| result.is_none()).count(), 1);
        assert_eq!(outcomes.into_iter().flatten().map(|r| r.current).collect::<Vec<_>>(), [stored.clone()]);
        assert_eq!(store.commit_session("alice", "bob", &stored, "", true, None, None, None).await.unwrap(), None);
        let revision = format!("{:x}", Sha256::digest(stored.as_bytes()));
        assert_eq!(store.commit_session("alice", "bob", "e2e3.next", &revision, false, None, None, None).await.unwrap(), None);
        assert_eq!(store.commit_session("alice", "bob", "e2e3.stale", &revision, false, None, None, None).await.unwrap().map(|c| c.current).as_deref(), Some("e2e3.next"));
        assert!(store.delete_session("alice", "bob").await.is_err());
        let floor = format!("e2e3.{}", STANDARD.encode([8u8; 40]));
        let last_revision = format!("{:x}", Sha256::digest(b"e2e3.next"));
        store.close_session("alice", "bob", 3, &last_revision, Some(""), Some(&floor), None).await.unwrap();
        let floor_revision = format!("{:x}", Sha256::digest(floor.as_bytes()));
        assert_eq!(store.commit_session("alice", "bob", "e2e3.stale", &revision, false, None, None, None).await.unwrap().map(|c| c.current).as_deref(), Some(""));
        // A previously saved device record without a revision is still a
        // continuation. It cannot recreate a session deleted on another device.
        assert_eq!(store.commit_session("alice", "bob", "e2e3.unversioned", "", false, None, None, None).await.unwrap().map(|c| c.current).as_deref(), Some(""));
        assert_eq!(store.load_session("alice", "bob").await, None);
        assert!(store.load_session("alice", "bob").await.is_none());
        let contenders: Vec<_> = (0..50).map(|i| format!("e2e3.contender-{i}")).collect();
        let results = futures_util::future::join_all(contenders.iter().map(|blob|
            store.commit_session("alice", "other", blob, "", true, Some(&floor_revision), None, None))).await;
        let chosen = store.load_session("alice", "other").await.unwrap();
        let outcomes: Vec<_> = results.into_iter().map(Result::unwrap).collect();
        assert_eq!(outcomes.iter().filter(|r| r.is_none()).count(), 1);
        assert!(outcomes.iter().flatten().all(|conflict| conflict.current == chosen));
        let file = store.user_dir("alice").join("sessions").join("bob.enc");
        tokio::fs::create_dir(&file).await.unwrap();
        assert!(store.commit_session("alice", "bob", "e2e3.new", "", true, None, None, None).await.is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn recovery_keyring_rewrap_preserves_current_slots_and_refuses_downgrades() {
        let dir = tmpdir();
        let store = E2EStore::new(&dir);
        store.store_keyring("alice", "e2k2.test", true, Some("")).await.unwrap();
        store.store_identity_enc("alice", "e2e2.identity").await.unwrap();
        store.store_session("alice", "bob", "e2e2.session").await.unwrap();
        store.store_channel_key("alice", "#chat", "e2e2.channel").await.unwrap();
        let transitional = recovery_keyring(92);
        let final_blob = recovery_keyring(60);
        assert!(store.store_keyring("alice", &final_blob, true, Some("e2k2.test")).await.is_err());
        assert_eq!(store.store_keyring("alice", &transitional, true, Some("e2k2.test")).await.unwrap(), (true, None));
        assert!(store.write_permit("alice", 2).await.is_none());
        assert!(store.write_permit("alice", 3).await.is_some());
        assert!(store.store_keyring("alice", &final_blob, true, Some(&transitional)).await.is_err());

        assert!(!store.rewrap_v2_blob("alice", "identity", "", "e2e2.stale", "e2e3.identity").await.unwrap());
        assert!(!store.rewrap_v2_blob("alice", "channel", "#chat", "e2e2.stale", "e2e3.channel").await.unwrap());
        assert!(store.rewrap_v2_blob("alice", "identity", "", "e2e2.identity", "e2e3.identity").await.unwrap());
        store.store_session("alice", "bob", "e2e3.newer").await.unwrap();
        store.rewrap_v2_blob("alice", "session", "bob", "e2e2.session", "e2e3.old").await.unwrap();
        assert_eq!(store.load_session("alice", "bob").await.as_deref(), Some("e2e3.newer"));
        store.rewrap_v2_blob("alice", "channel", "#chat", "e2e2.channel", "e2e3.channel").await.unwrap();
        assert_eq!(store.load_identity_enc("alice").await.as_deref(), Some("e2e3.identity"));
        assert_eq!(store.load_channel_key("alice", "#chat").await.as_deref(), Some("e2e3.channel"));
        assert_eq!(store.store_keyring("alice", &final_blob, true, Some(&transitional)).await.unwrap(), (true, None));
        assert_eq!(store.store_keyring("alice", &final_blob, true, Some(&transitional)).await.unwrap(), (true, None));
        assert!(store.store_keyring("alice", "e2k2.test", true, None).await.is_err());
        assert!(store.store_keyring("alice", &transitional, true, Some(&final_blob)).await.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn protection_snapshot_tracks_slot_changes_and_errors() {
        let dir = tmpdir();
        let store = E2EStore::new(&dir);
        assert!(store.protected_names("alice").await.unwrap().0.is_empty());
        store.store_channel_key("alice", "#chat", "e2e3.channel").await.unwrap();
        assert_eq!(store.protected_names("alice").await.unwrap().0, ["#chat"]);
        assert_eq!(store.protected_names("alice").await.unwrap().0, ["#chat"]);
        let invalid = store.user_dir("alice").join("channels/invalid~slot.enc");
        std::fs::write(&invalid, "test").unwrap();
        assert!(store.protected_names("alice").await.is_err());
        std::fs::remove_file(invalid).unwrap();
        store.delete_channel_key("alice", "#chat").await.unwrap();
        assert!(store.protected_names("alice").await.unwrap().0.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn corrupt_keyring_refuses_slot_writes() {
        let dir = tmpdir();
        let store = E2EStore::new(&dir);
        store.store_identity_enc("alice", "e2e2.identity").await.unwrap();
        assert!(store.write_permit("alice", 2).await.is_some());
        std::fs::write(store.keyring_path("alice"), "invalid keyring").unwrap();
        assert!(store.write_permit("alice", 2).await.is_none());
        assert!(store.write_permit("alice", 3).await.is_none());
        assert!(store.store_keyring("alice", "e2k2.replacement", false, Some("")).await.is_err());
        assert_eq!(std::fs::read_to_string(store.keyring_path("alice")).unwrap(), "invalid keyring");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unknown_identity_format_holds_legacy_operations_until_storage_recovers() {
        let dir = tmpdir();
        let store = E2EStore::new(&dir);
        let identity = store.user_dir("alice").join("identity.enc");
        std::fs::create_dir_all(&identity).unwrap();
        assert!(store.write_permit("alice", 1).await.is_none());
        assert!(store.signal_delivery_permit("alice", None, true).await.is_err());
        assert!(store.needs_legacy_key("alice").await.is_err());

        std::fs::remove_dir(&identity).unwrap();
        std::fs::write(&identity, []).unwrap();
        assert!(store.stored_identity_version("alice").await.is_none());
        assert!(store.read_identity("alice").await.is_err());
        store.store_identity_enc("alice", "bGVnYWN5").await.unwrap();
        assert!(store.write_permit("alice", 1).await.is_some());
        assert!(store.signal_delivery_permit("alice", None, true).await.is_ok());
        assert!(store.needs_legacy_key("alice").await.unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn keyring_roundtrip_and_migrated_never_downgrades() {
        let dir = tmpdir();
        let st = E2EStore::new(&dir);
        assert!(st.load_keyring("alice").await.is_none());
        assert!(!st.is_migrated("alice").await);
        // pending (migrated=false)
        assert_eq!(st.store_keyring("alice", "e2k2.AAAA", false, None).await.unwrap(), (false, None));
        assert_eq!(st.load_keyring("alice").await, Some(("e2k2.AAAA".to_string(), false)));
        assert!(!st.is_migrated("alice").await);
        // complete
        assert_eq!(st.store_keyring("alice", "e2k2.BBBB", true, None).await.unwrap(), (true, None));
        assert!(st.is_migrated("alice").await);
        // a later re-wrap (passphrase change) sent with migrated=false must not un-migrate
        assert_eq!(st.store_keyring("alice", "e2k2.CCCC", false, None).await.unwrap(), (true, None));
        assert_eq!(st.load_keyring("alice").await, Some(("e2k2.CCCC".to_string(), true)));
        // other users unaffected
        assert!(!st.is_migrated("bob").await);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn keyring_rejects_garbage() {
        let dir = tmpdir();
        let st = E2EStore::new(&dir);
        assert!(st.store_keyring("alice", "not-a-keyring", true, None).await.is_err());
        assert!(st.store_keyring("alice", "e2k2.has space", true, Some("")).await.is_err());
        assert!(st.store_keyring("alice", &format!("e2k2.{}", "A".repeat(5000)), true, None).await.is_err());
        assert!(!st.is_migrated("alice").await);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn list_sessions_returns_client_names() {
        let dir = tmpdir();
        let st = E2EStore::new(&dir);
        for p in ["__spk__", "__otpk__42", "__state__", "bob", "[x]y"] {
            st.store_session("alice", p, "e2e2.blob").await.unwrap();
        }
        let mut got = st.list_sessions("alice").await;
        got.sort();
        let mut want: Vec<String> = ["__spk__", "__otpk__42", "__state__", "bob", "[x]y"].iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(got, want);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn pepper_is_distinct_and_survives_passphrase_change() {
        let dir = tmpdir();
        let cm = crate::crypto::CryptoManager::new(&dir).unwrap();
        assert!(cm.derive_e2e_kek_pepper("alice").await.is_err()); // locked
        cm.unlock("alice", "correct horse").await.unwrap();
        let legacy = cm.derive_e2e_enc_key("alice").await.unwrap();
        let pepper = cm.derive_e2e_kek_pepper("alice").await.unwrap();
        assert_ne!(legacy, pepper);
        cm.change_passphrase("alice", "correct horse", "battery staple").await.unwrap();
        assert_eq!(cm.derive_e2e_kek_pepper("alice").await.unwrap(), pepper);
        cm.lock("alice").await;
        assert!(cm.unlock("alice", "correct horse").await.is_err());
        cm.unlock("alice", "battery staple").await.unwrap();
        assert_eq!(cm.derive_e2e_kek_pepper("alice").await.unwrap(), pepper);
        // re-verifying an already-unlocked vault (what UnlockVault now does) keeps the key
        assert!(cm.unlock("alice", "wrong").await.is_err());
        assert!(cm.is_unlocked("alice").await);
        assert_eq!(cm.derive_e2e_kek_pepper("alice").await.unwrap(), pepper);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn network_scope_matching() {
        let n = |name: Option<&str>, h: &str, p: u16| NetIdent::new(name.map(|s| s.to_string()), h, p);
        let d = |h: &str| n(None, h, 6697);
        // the same server (exact host, case / trailing dot normalised, same port)
        assert_eq!(network_match_tier(&d("irc.libera.chat"), &d("IRC.Libera.Chat.")), 3);
        assert_eq!(network_match_tier(&n(None, "127.0.0.1", 24201), &n(None, "127.0.0.1", 24201)), 3);
        // allowlisted network domains: different hosts of one network
        assert_eq!(network_match_tier(&d("libera.chat"), &d("irc.libera.chat")), 2);
        assert_eq!(network_match_tier(&d("irc.libera.chat"), &d("irc.eu.libera.chat")), 2);
        assert_eq!(network_match_tier(&n(Some("efnet"), "irc.efnet.org", 6667), &n(Some("efnet"), "irc2.efnet.org", 7000)), 2);
        assert!(!same_network(&d("irc.libera.chat"), &d("irc.oftc.net")));
        // differing names veto even the same host / an allowlisted domain
        assert!(!same_network(&n(Some("a"), "irc.x.org", 1), &n(Some("b"), "irc.x.org", 1)));
        assert!(!same_network(&n(Some("a"), "irc.libera.chat", 1), &n(Some("b"), "irc.eu.libera.chat", 1)));
        // same host, other port: only when both report the same network name
        assert_eq!(network_match_tier(&n(Some("x"), "127.0.0.1", 6667), &n(Some("x"), "127.0.0.1", 6697)), 2);
        assert_eq!(network_match_tier(&n(Some("x"), "irc.example.org", 6667), &n(Some("x"), "irc.example.org", 6697)), 2);
        assert!(!same_network(&n(None, "irc.example.org", 6667), &n(None, "irc.example.org", 6697)));
        // NEW-5: two ircds on one IP (different ports, no NETWORK=) are not one network
        assert!(!same_network(&n(None, "127.0.0.1", 24206), &n(None, "127.0.0.1", 24207)));
        // NEW-4: a NETWORK= name never links different hosts — IP or DNS, look-alike or not
        assert!(!same_network(&n(Some("ergotest"), "127.0.0.3", 24204), &n(Some("ergotest"), "127.0.0.1", 24201)));
        assert!(!same_network(&n(Some("ergotest"), "127.0.0.2", 24201), &n(Some("ergotest"), "127.0.0.1", 24201)));
        assert!(!same_network(&n(Some("libera.chat"), "irc.evil.example", 6697), &n(Some("libera.chat"), "irc.libera.chat", 6697)));
        assert!(!same_network(&n(Some("libera"), "libera.attacker.example", 6697), &n(Some("libera"), "irc.libera.chat", 6697)));
        assert!(!same_network(&d("libera.chat.attacker.example"), &d("irc.libera.chat")));
        assert!(!same_network(&d("evillibera.chat"), &d("irc.libera.chat")));
        assert!(!same_network(&n(Some("efnet"), "irc.efnet.org", 6667), &n(Some("efnet"), "efnet.port80.se", 6667)));
        // no suffix inference at all: public and private suffixes never link strangers
        for (x, y) in [("x.co.uk", "y.co.uk"), ("irc.x.co.uk", "irc2.x.co.uk"), ("a.com.br", "b.com.br"),
                       ("a.com.zz", "b.com.zz"), ("irc.a.com.zz", "irc.b.com.zz"), ("x.net.qq", "y.net.qq"),
                       ("a.duckdns.org", "b.duckdns.org"), ("irc.a.dyndns.org", "irc.b.dyndns.org"),
                       ("a.github.io", "b.github.io"), ("libera.xy.de", "irc.libera.chat")] {
            assert!(!same_network(&d(x), &d(y)), "{} ~ {}", x, y);
        }
        let cid = "8b78156c-a07c-4615-b550-4b85ed1eece1";
        note_isupport(cid, &["me".into(), "CHANTYPES=#".into(), "NETWORK=EFnet".into(), "are supported".into()]);
        assert_eq!(network_name(cid).as_deref(), Some("efnet"));
        note_isupport("not-a-uuid", &["NETWORK=x".into()]);
        assert_eq!(network_name("not-a-uuid"), None);
    }

    #[tokio::test]
    async fn keyring_cas_first_writer_wins() {
        let dir = tmpdir();
        let st = E2EStore::new(&dir);
        // two devices both saw "no keyring" and race to create one
        assert_eq!(st.store_keyring("alice", "e2k2.AAAA", false, Some("")).await.unwrap(), (false, None));
        let (m, conflict) = st.store_keyring("alice", "e2k2.BBBB", false, Some("")).await.unwrap();
        assert!(!m);
        assert_eq!(conflict.as_deref(), Some("e2k2.AAAA"));
        assert_eq!(st.load_keyring("alice").await, Some(("e2k2.AAAA".to_string(), false)));
        // the loser can't mark migrated over the winner either
        let (_, conflict) = st.store_keyring("alice", "e2k2.BBBB", true, Some("e2k2.BBBB")).await.unwrap();
        assert_eq!(conflict.as_deref(), Some("e2k2.AAAA"));
        assert!(!st.is_migrated("alice").await);
        // a retried create of the SAME blob (lost reply) is idempotent
        assert_eq!(st.store_keyring("alice", "e2k2.AAAA", false, Some("")).await.unwrap(), (false, None));
        // the winner marks migrated with its own blob as the expected value
        assert_eq!(st.store_keyring("alice", "e2k2.AAAA", true, Some("e2k2.AAAA")).await.unwrap(), (true, None));
        // re-wrap (passphrase change) replaces only the expected blob
        assert_eq!(st.store_keyring("alice", "e2k2.CCCC", false, Some("e2k2.AAAA")).await.unwrap(), (true, None));
        assert_eq!(st.load_keyring("alice").await, Some(("e2k2.CCCC".to_string(), true)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn r3_long_names_no_enametoolong_no_collisions_and_old_files_readable() {
        let dir = tmpdir();
        let st = E2EStore::new(&dir);
        // '#' + 72 Cyrillic bytes-pairs: 219 bytes encoded (failed with ENAMETOOLONG
        // before: ".enc.tmp-<32hex>" pushed the temp name past 255 bytes)
        let a = format!("#{}", "ж".repeat(36));
        st.store_channel_key("alice", &a, "e2e2.A").await.unwrap();
        assert_eq!(st.load_channel_key("alice", &a).await.as_deref(), Some("e2e2.A"));
        // two long names sharing a long prefix used to collide on one truncated file
        let p = "ж".repeat(60);
        let (x, y) = (format!("#{}x", p), format!("#{}y", p));
        st.store_channel_key("alice", &x, "e2e2.X").await.unwrap();
        st.store_channel_key("alice", &y, "e2e2.Y").await.unwrap();
        assert_eq!(st.load_channel_key("alice", &x).await.as_deref(), Some("e2e2.X"));
        assert_eq!(st.load_channel_key("alice", &y).await.as_deref(), Some("e2e2.Y"));
        let mut l = st.list_channel_keys("alice").await; l.sort();
        let mut want = vec![a.clone(), x.clone(), y.clone()]; want.sort();
        assert_eq!(l, want);
        // every file name fits NAME_MAX
        let cdir = std::path::Path::new(&dir).join("e2e/alice/channels");
        for e in std::fs::read_dir(&cdir).unwrap() { assert!(e.unwrap().file_name().len() <= 255); }
        // a file written by the OLD code under its truncated name stays readable, moves
        // to the new name on the next write, and a delete removes it
        let z = format!("#{}z", "ж".repeat(80));
        let old = cdir.join(format!("{}.enc", fs_encode(&z, channel_is_safe)));
        std::fs::write(&old, "e2e2.OLD").unwrap();
        assert_eq!(st.load_channel_key("alice", &z).await.as_deref(), Some("e2e2.OLD"));
        st.store_channel_key("alice", &z, "e2e2.NEW").await.unwrap();
        assert!(!old.exists());
        assert_eq!(st.load_channel_key("alice", &z).await.as_deref(), Some("e2e2.NEW"));
        st.delete_channel_key("alice", &z).await.unwrap();
        assert_eq!(st.load_channel_key("alice", &z).await, None);
        // short names are byte-for-byte the old file names
        st.store_session("alice", "[bob]", "e2e2.s").await.unwrap();
        assert!(std::path::Path::new(&dir).join("e2e/alice/sessions/%5Bbob%5D.enc").exists());
        let long_nick = "ñ".repeat(50);
        st.store_session("alice", &long_nick, "e2e2.n").await.unwrap();
        assert!(st.list_sessions("alice").await.contains(&long_nick));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn r3_slot_cap_is_atomic_and_ignores_temp_files() {
        let dir = tmpdir();
        let st = std::sync::Arc::new(E2EStore::new(&dir));
        let sdir = std::path::Path::new(&dir).join("e2e/alice/sessions");
        for i in 0..(MAX_SESSION_FILES - 2) {
            st.store_session("alice", &format!("p{}", i), "e2e2.x").await.unwrap();
        }
        // leftovers of interrupted writes / sidecars do not count
        std::fs::write(sdir.join(".tmp-0123456789abcdef"), "x").unwrap();
        std::fs::write(sdir.join("zz~0123.name"), "x").unwrap();
        st.store_session("alice", "new1", "e2e2.x").await.unwrap();
        // 2 slots left → many concurrent new partners: exactly 1 more fits
        let mut hs = Vec::new();
        for i in 0..20 {
            let st = st.clone();
            hs.push(tokio::spawn(async move { st.store_session("alice", &format!("race{}", i), "e2e2.x").await.is_ok() }));
        }
        let mut ok = 0;
        for h in hs { if h.await.unwrap() { ok += 1; } }
        assert_eq!(ok, 1);
        assert_eq!(count_slot_files(&sdir).await, MAX_SESSION_FILES);
        // overwriting an existing slot at the cap still works
        st.store_session("alice", "p0", "e2e2.y").await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn r3_legacy_writes_are_atomic_with_the_migration_flip() {
        let dir = tmpdir();
        let st = std::sync::Arc::new(E2EStore::new(&dir));
        st.store_identity_enc("alice", "e2e2.id").await.unwrap();
        st.store_keyring("alice", "e2k2.K", false, Some("")).await.unwrap();
        // a stale tab holds a legacy-write permit while the flip is requested: the flip
        // waits for it, then sees the legacy blob and is NOT done
        let permit = st.write_permit("alice", 1).await.expect("not migrated yet");
        let st2 = st.clone();
        let flip = tokio::spawn(async move { st2.store_keyring("alice", "e2k2.K", true, Some("e2k2.K")).await.unwrap() });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!flip.is_finished(), "flip must wait for the in-flight legacy write");
        st.store_session("alice", "bob", "LEGACYBLOB").await.unwrap();
        drop(permit);
        assert_eq!(flip.await.unwrap(), (false, None));
        assert!(!st.is_migrated("alice").await);
        // once every blob is v2 the flip happens, and later legacy writes are refused
        st.store_session("alice", "bob", "e2e2.b").await.unwrap();
        assert_eq!(st.store_keyring("alice", "e2k2.K", true, Some("e2k2.K")).await.unwrap(), (true, None));
        assert!(st.write_permit("alice", 1).await.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn r3_identity_create_if_absent_and_fail_closed_migration_state() {
        let dir = tmpdir();
        let st = E2EStore::new(&dir);
        // two devices race their first identity: one wins, the other is told which
        assert_eq!(st.store_identity_enc_cas("alice", "e2e2.A", Some("")).await.unwrap(), None);
        assert_eq!(st.store_identity_enc_cas("alice", "e2e2.B", Some("")).await.unwrap().as_deref(), Some("e2e2.A"));
        assert_eq!(st.load_identity_enc("alice").await.as_deref(), Some("e2e2.A"));
        // a retried create of the same blob is a success
        assert_eq!(st.store_identity_enc_cas("alice", "e2e2.A", Some("")).await.unwrap(), None);
        // unconditional (reset-identity / older clients) still replaces
        st.store_identity_enc("alice", "e2e2.C").await.unwrap();
        assert_eq!(st.load_identity_enc("alice").await.as_deref(), Some("e2e2.C"));
        assert!(st.identity_blob_hash("alice").await.unwrap().len() == 64);
        // no keyring but an e2e2. identity (keyring lost): treated as upgraded+migrated
        assert!(st.load_keyring("alice").await.is_none());
        assert!(st.is_migrated("alice").await && st.has_upgraded_e2e("alice").await);
        assert!(st.write_permit("alice", 1).await.is_none());
        // legacy-only account (never upgraded): neither
        st.store_identity_enc("bob", "bGVnYWN5").await.unwrap();
        assert!(!st.is_migrated("bob").await && !st.has_upgraded_e2e("bob").await);
        // an unparseable keyring.json still counts as upgraded for the send guard
        std::fs::write(std::path::Path::new(&dir).join("e2e/bob/keyring.json"), "{not json").unwrap();
        assert!(st.has_upgraded_e2e("bob").await);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn r3_preset_domains_allowlisted() {
        let d = |h: &str| NetIdent::new(None, h, 6697);
        for (a, b) in [("irc.gamesurge.net", "eu.gamesurge.net"), ("irc.2600.net", "irc2.2600.net"),
                       ("irc.anonops.com", "x.anonops.com"), ("irc.chat4all.org", "irc2.chat4all.org"),
                       ("irc.tilde.chat", "ctrl-c.tilde.chat")] {
            assert_eq!(network_match_tier(&d(a), &d(b)), 2, "{} ~ {}", a, b);
        }
        assert!(!same_network(&d("irc.tilde.chat"), &d("irc.tilde.team")));
        assert!(!same_network(&d("gamesurge.net.evil.example"), &d("irc.gamesurge.net")));
    }

    #[tokio::test]
    async fn writes_are_atomic_and_leave_no_temp_files() {
        let dir = tmpdir();
        let st = E2EStore::new(&dir);
        st.store_identity_enc("alice", "e2e2.one").await.unwrap();
        // many concurrent saves of one slot: the file always holds one complete blob
        let mut hs = Vec::new();
        let st = std::sync::Arc::new(st);
        for i in 0..40 {
            let st = st.clone();
            hs.push(tokio::spawn(async move {
                st.store_session("alice", "bob", &format!("e2e2.{}{}", i, "x".repeat(2000))).await.unwrap();
            }));
        }
        for h in hs { h.await.unwrap(); }
        let b = st.load_session("alice", "bob").await.unwrap();
        assert!(b.starts_with("e2e2.") && b.ends_with(&"x".repeat(2000)));
        assert_eq!(st.load_identity_enc("alice").await.as_deref(), Some("e2e2.one"));
        let sess_dir = std::path::Path::new(&dir).join("e2e/alice/sessions");
        let names: Vec<String> = std::fs::read_dir(&sess_dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(names, vec!["bob.enc".to_string()], "{:?}", names);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(sess_dir.join("bob.enc")).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert_eq!(st.list_sessions("alice").await, vec!["bob".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod srv_b_r8_otpk_tests {
    use super::*;

    fn tmpdir() -> String {
        let d = std::env::temp_dir().join(format!("cryptirc-e2e-r8-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }
    fn set_mtime(p: &std::path::Path, t: std::time::SystemTime) {
        std::fs::File::options().write(true).open(p).unwrap().set_modified(t).unwrap();
    }
    fn opk(id: u32) -> OneTimePrekey { OneTimePrekey { key_id: id, public_key: "AAAA".into() } }

    /// r8 (codex P1 e2e.rs:658): private halves of one-time prekeys that were handed out by
    /// bundle fetches whose handshake never came used to pile up until the account's
    /// session cap (4096 files) was full; then every new session and every new private half
    /// was refused, for good. Now the oldest of them make room (the newest 1024 are kept,
    /// and a key counts as new from the moment it was handed out).
    #[tokio::test]
    async fn unused_bundle_fetches_cannot_exhaust_the_session_quota() {
        let d = tmpdir();
        let st = E2EStore::new(&d);
        let base = std::path::Path::new(&d).join("e2e/victim");
        let sess = base.join("sessions");
        st.store_session("victim", "bob", "e2e2.bob").await.unwrap();
        st.store_session("victim", "__spk__", "e2e2.spk").await.unwrap();
        // one published key whose private half is old: the next fetch hands it out
        std::fs::create_dir_all(base.join("otpk")).unwrap();
        std::fs::write(base.join("bundle.json"), serde_json::to_string(&KeyBundle {
            identity_sign_key: "sig".into(), identity_dh_key: "dh".into(),
            signed_prekey: SignedPrekey { key_id: 1, public_key: "spk".into(), signature: "s".into() },
            one_time_prekeys: vec![],
        }).unwrap()).unwrap();
        std::fs::write(base.join("otpk/7.json"), serde_json::to_string(&opk(7)).unwrap()).unwrap();
        st.store_session("victim", "__otpk__7", "e2e2.p7").await.unwrap();
        let old = std::time::SystemTime::now() - Duration::from_secs(86_400);
        set_mtime(&sess.join("__otpk__7.enc"), old - Duration::from_secs(86_400));
        // the aftermath of the attack: the directory is full of private halves of keys that
        // fetches took and nobody used
        let n_stale = MAX_SESSION_FILES - 3;
        for i in 0..n_stale {
            let p = sess.join(format!("__otpk__{}.enc", 100_000 + i));
            std::fs::write(&p, "e2e2.stale").unwrap();
            set_mtime(&p, old + Duration::from_secs(i as u64));
        }
        // a legitimate initiator fetches the bundle: key 7 is handed out now
        let got = st.fetch_bundle("victim", "alice").await.unwrap();
        assert_eq!(got.one_time_prekey.map(|o| o.key_id), Some(7));
        // a new conversation can still be stored
        let r = st.store_session("victim", "carol", "e2e2.carol").await;
        assert!(r.is_ok(), "a new session is refused once unused prekeys fill the session cap: {:?}", r.err());
        let stale_left = std::fs::read_dir(&sess).unwrap()
            .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with("__otpk__1")).count();
        assert_eq!(stale_left, 1024 - 1, "the newest unused private halves are kept, the oldest go");
        for keep in ["bob.enc", "__spk__.enc", "carol.enc", "__otpk__7.enc"] {
            assert!(sess.join(keep).exists(), "{keep} must survive (7 = the key handed out a moment ago)");
        }
        // the kept stale ones are the newest
        assert!(!sess.join(format!("__otpk__{}.enc", 100_000)).exists());
        assert!(sess.join(format!("__otpk__{}.enc", 100_000 + n_stale - 1)).exists());
        // and new private halves fit again
        assert!(st.store_session("victim", "__otpk__900001", "e2e2.new").await.is_ok());
        let _ = std::fs::remove_dir_all(d);
    }

    /// r8 (codex P1 e2e.rs:658): a refill (or a bundle) published every public half even
    /// when the private half could not be stored, so initiators were handed keys nobody
    /// holds and each of those handshakes failed. Only keys whose private half is stored
    /// are published now.
    #[tokio::test]
    async fn a_prekey_without_its_private_half_is_never_published() {
        let d = tmpdir();
        let st = E2EStore::new(&d);
        let otpk = std::path::Path::new(&d).join("e2e/victim/otpk");
        st.store_session("victim", "__otpk__11", "e2e2.p11").await.unwrap();
        st.add_one_time_prekeys("victim", vec![opk(11), opk(12)]).await.unwrap();
        assert!(otpk.join("11.json").exists(), "a key with its private half stored is published");
        assert!(!otpk.join("12.json").exists(), "a key whose private half is missing was published");
        st.store_session("victim", "__otpk__21", "e2e2.p21").await.unwrap();
        st.store_bundle("victim", &KeyBundle {
            identity_sign_key: "AAAA".into(), identity_dh_key: "AAAA".into(),
            signed_prekey: SignedPrekey { key_id: 1, public_key: "AAAA".into(), signature: "AAAA".into() },
            one_time_prekeys: vec![opk(21), opk(22)],
        }).await.unwrap();
        assert!(otpk.join("21.json").exists());
        assert!(!otpk.join("22.json").exists(), "a bundle published a key whose private half is missing");
        assert_eq!(st.otpk_count("victim").await, 2);
        // a refused private half (storage full of real sessions) leaves its key unpublished
        let sess = std::path::Path::new(&d).join("e2e/victim/sessions");
        for i in 0..MAX_SESSION_FILES { std::fs::write(sess.join(format!("peer{i}.enc")), "e2e2.x").unwrap(); }
        assert!(st.store_session("victim", "__otpk__31", "e2e2.p31").await.is_err());
        st.add_one_time_prekeys("victim", vec![opk(31)]).await.unwrap();
        assert!(!otpk.join("31.json").exists(), "published although its private half was refused");
        let _ = std::fs::remove_dir_all(d);
    }
}
