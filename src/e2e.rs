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
//!   - TOFU trust records
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
//!     trust.json             — TOFU records

// #93: `bail` was imported but never used — dropped to clear the compiler warning.
use anyhow::Result;
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
const MAX_TRUST_RECORDS: usize = 4096;
/// r6 (codex P1 main.rs:6743 / e2e.rs:711): per-field size limits of a trust record. A real
/// record is a lower-cased IRC nick and a 79-character SHA-256 fingerprint ("ABCD EF01 …");
/// without limits one account could store 4,096 records of any size, and every trust load
/// then carried a multi-megabyte snapshot.
const MAX_TRUST_NICK_BYTES: usize = 256;
const MAX_TRUST_FP_BYTES: usize = 512;
/// r6: a trust.json larger than this can only have been produced by oversized records
/// (4,096 valid records are well under 4 MiB): it is set aside instead of loaded.
const MAX_TRUST_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// r6: does a trust record fit the per-field limits?
fn trust_record_fits(nick: &str, fingerprint: &str) -> bool {
    !nick.is_empty() && nick.len() <= MAX_TRUST_NICK_BYTES && fingerprint.len() <= MAX_TRUST_FP_BYTES
}
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

// ─── Trust record ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRecord {
    pub nick:        String,
    pub fingerprint: String,
    pub first_seen:  i64,
    pub verified:    bool,
}

// ─── E2E Store ────────────────────────────────────────────────────────────────

pub struct E2EStore {
    data_dir: String,
    /// S2: per-user mutex prevents TOCTOU races on OTPK consumption.
    /// DashMap<username, Mutex<()>>
    otpk_locks: Arc<DashMap<String, Arc<Mutex<()>>>>,
    /// MEDIUM: per-user mutex serializing the load->mutate->save window in
    /// `update_trust`. Without it, concurrent same-user E2EUpdateTrust calls form
    /// an unserialized read-modify-write on trust.json and can silently drop a
    /// pin (undetected key-change). Mirrors the otpk_locks pattern.
    trust_locks: Arc<DashMap<String, Arc<Mutex<()>>>>,
    /// r3: per-user mutex for creating NEW session / channel-key slots (cap check +
    /// write), see `store_slot`.
    cap_locks: Arc<DashMap<String, Arc<Mutex<()>>>>,
    /// #27: per-target sliding-window counter of OTPK consumptions. Keyed by the
    /// target username (the pool being drained). Value is (window_start, count).
    /// r5: the target-wide ceiling (OTPK_CONSUME_MAX_PER_TARGET_WINDOW).
    otpk_consume_rate: Arc<DashMap<String, (Instant, u32)>>,
    /// r5 (codex P1 e2e.rs:523): the same counter per (target, requester) — the
    /// OTPK_CONSUME_MAX_PER_WINDOW budget.
    otpk_pair_rate: Arc<DashMap<(String, String), (Instant, u32)>>,
}

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
            trust_locks:       Arc::new(DashMap::new()),
            cap_locks:         Arc::new(DashMap::new()),
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

    /// MEDIUM: acquire the per-user trust lock, serializing the
    /// load->mutate->save window in `update_trust`.
    fn trust_lock(&self, username: &str) -> Arc<Mutex<()>> {
        self.trust_locks
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
        if let Some(exp) = expect {
            let cur = tokio::fs::read_to_string(&path).await.unwrap_or_default();
            if cur == blob { return Ok(None); }
            if cur != exp { return Ok(Some(cur)); }
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
        tokio::fs::read_to_string(self.user_dir(username).join("identity.enc")).await.ok()
    }

    // ── C1 (2026-11-01): client-held keyring ──────────────────────────────────
    //
    // The E2E blob-wrapping key is no longer derived by the server. The browser
    // generates a random E2E master key, wraps it under a key it derives itself
    // (PBKDF2 over the vault passphrase, combined with a per-user server "pepper"
    // that is only handed to a socket which just proved the passphrase), and stores
    // the WRAPPED result here as an opaque string. The server can't unwrap it.
    //
    // keyring.json = {"v":1,"blob":"e2k2.…","migrated":bool}
    //   migrated=false : the client has stored a keyring but is still re-wrapping the
    //                    user's legacy (server-key) blobs; legacy-format writes are
    //                    still accepted and the legacy key is still offered.
    //   migrated=true  : every blob was re-wrapped. From now on the server refuses
    //                    legacy-format blob writes (stale app.js can't clobber the
    //                    upgraded identity/sessions/PSKs) and stops sending the legacy
    //                    key to new sockets. It never flips back to false.

    fn keyring_path(&self, username: &str) -> PathBuf {
        self.user_dir(username).join("keyring.json")
    }

    /// Returns (blob, migrated) when the user has stored a client keyring.
    pub async fn load_keyring(&self, username: &str) -> Option<(String, bool)> {
        let json = tokio::fs::read_to_string(self.keyring_path(username)).await.ok()?;
        let v: serde_json::Value = serde_json::from_str(&json).ok()?;
        let blob = v.get("blob")?.as_str()?.to_string();
        let migrated = v.get("migrated").and_then(|m| m.as_bool()).unwrap_or(false);
        Some((blob, migrated))
    }

    /// True once the user's E2E data was re-wrapped under the client-held key.
    /// r3 (agy-P1 e2e.rs/main.rs:5106, fail closed): also true when there is no readable
    /// keyring but the identity blob is already in the client-held-key format. An
    /// upgraded client always stores the keyring BEFORE it writes any "e2e2." blob, so
    /// this state only arises when keyring.json was lost or damaged; legacy-format
    /// writes (a stale tab regenerating an identity it can't read) and the legacy key
    /// stay withheld instead of being handed out again.
    pub async fn is_migrated(&self, username: &str) -> bool {
        match self.load_keyring(username).await {
            Some((_, m)) => m,
            None => self.identity_is_v2(username).await,
        }
    }

    /// The identity blob is in the client-held-key ("e2e2.") format.
    pub async fn identity_is_v2(&self, username: &str) -> bool {
        matches!(read_prefix(&self.user_dir(username).join("identity.enc")).await, Some(p) if p.starts_with(b"e2e2."))
    }

    /// r3 (codex-p3 HIGH main.rs:5003 / agy-P1 main.rs:5170): has an upgraded client
    /// ever run for this account (a keyring, or any "e2e2." identity)? The outdated-tab
    /// send guard applies from then on.
    pub async fn has_upgraded_e2e(&self, username: &str) -> bool {
        // keyring.json present at all (even unparseable) counts.
        tokio::fs::metadata(self.keyring_path(username)).await.is_ok()
            || self.identity_is_v2(username).await
    }

    /// r3 (codex-p1 MED main.rs:5888): the "no legacy-format writes once migrated" rule,
    /// made atomic with the migration flip. The migrated check used to run before, and
    /// separately from, the storage write, so a stale tab's legacy write admitted just
    /// before the flip could land after it and overwrite an upgraded identity / session /
    /// key. Now a legacy-format write holds this per-user lock (the one store_keyring
    /// flips `migrated` under) from the check until its write is done: it either commits
    /// before the flip — which then sees it (has_legacy_blobs) and is refused — or is
    /// refused itself. Returns None when the account is migrated (refuse the write).
    pub async fn legacy_write_permit(&self, username: &str) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        let g = self.trust_lock(username).lock_owned().await;
        if self.is_migrated(username).await { None } else { Some(g) }
    }

    /// r3: is any stored E2E blob (identity, a session slot, a channel key) still in the
    /// legacy (server-key) format? Checked under the keyring lock before the account is
    /// marked migrated.
    async fn has_legacy_blobs(&self, username: &str) -> bool {
        let dir = self.user_dir(username);
        let is_legacy = |p: Option<Vec<u8>>| matches!(p, Some(b) if !b.is_empty() && !b.starts_with(b"e2e2."));
        if is_legacy(read_prefix(&dir.join("identity.enc")).await) { return true; }
        for sub in ["sessions", "channels"] {
            let Ok(mut rd) = tokio::fs::read_dir(dir.join(sub)).await else { continue };
            while let Ok(Some(e)) = rd.next_entry().await {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) != Some("enc") { continue; }
                if is_legacy(read_prefix(&p).await) { return true; }
            }
        }
        false
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
        if !blob.starts_with("e2k2.") || blob.len() > 4096
            || !blob.bytes().all(|b| b.is_ascii_graphic()) {
            anyhow::bail!("invalid keyring");
        }
        let lock = self.trust_lock(username); // same per-user serialisation as trust.json
        let _g = lock.lock().await;
        let cur = self.load_keyring(username).await;
        let prev_migrated = matches!(cur, Some((_, true)));
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
        // r3 (codex-p1 MED main.rs:5888): only flip to migrated when no legacy-format blob
        // is left. Legacy writes take this same lock (legacy_write_permit), so one that
        // landed after the client's own verification pass is seen here; the flip is then
        // not done (the client keeps the account unmigrated and retries on a later unlock)
        // instead of stranding that blob unreadable behind the flag.
        let eff = prev_migrated || (migrated && !self.has_legacy_blobs(username).await);
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

    pub async fn load_session(&self, username: &str, partner: &str) -> Option<String> {
        load_slot(&self.user_dir(username).join("sessions"), &slot_name(partner, partner_is_safe)).await
    }

    pub async fn delete_session(&self, username: &str, partner: &str) -> Result<()> {
        delete_slot(&self.user_dir(username).join("sessions"), &slot_name(partner, partner_is_safe)).await;
        Ok(())
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
        delete_slot(&self.user_dir(username).join("channels"), &slot_name(channel, channel_is_safe)).await;
        Ok(())
    }

    pub async fn list_channel_keys(&self, username: &str) -> Vec<String> {
        // #89: only real `.enc` channel-key files (skip strays) and a capped vector so a
        // reconnect can't trigger an unbounded fan-out of load round-trips.
        list_slots(&self.user_dir(username).join("channels"), channel_is_safe, MAX_CHANNEL_KEY_FILES).await
    }

    // ── TOFU trust ────────────────────────────────────────────────────────────

    pub async fn load_trust(&self, username: &str) -> Vec<TrustRecord> {
        let path = self.user_dir(username).join("trust.json");
        // r6: an oversized store (only possible with oversized records, see
        // MAX_TRUST_FILE_BYTES) is set aside, not read into memory on every load.
        if let Ok(md) = tokio::fs::metadata(&path).await {
            if md.len() > MAX_TRUST_FILE_BYTES {
                warn!("[E2E] trust.json of '{}' is {} bytes (over {}): set aside as trust.json.oversized", username, md.len(), MAX_TRUST_FILE_BYTES);
                let _ = tokio::fs::rename(&path, self.user_dir(username).join("trust.json.oversized")).await;
                return vec![];
            }
        }
        let Ok(json) = tokio::fs::read_to_string(&path).await else { return vec![]; };
        match serde_json::from_str::<Vec<TrustRecord>>(&json) {
            Ok(mut records) => {
                // r6: records over the per-field limits (stored before they existed) are
                // skipped — they can't be a real nick / fingerprint.
                let before = records.len();
                records.retain(|r| trust_record_fits(&r.nick, &r.fingerprint));
                if records.len() != before {
                    warn!("[E2E] skipped {} oversized trust record(s) of '{}'", before - records.len(), username);
                }
                records
            }
            Err(e) => {
                // #90: a corrupt trust.json must NOT silently become an empty pin set —
                // that downgrades every pinned peer to "first contact", masking a
                // key-change. Log loudly and preserve the bad file as a `.corrupt`
                // backup so update_trust's subsequent save doesn't overwrite/erase the
                // (recoverable) pins. Returning empty here is unavoidable for the
                // signature, but the operator is alerted and the data is retained.
                warn!("[E2E] CORRUPT trust.json for '{}' ({}). Backing up to trust.json.corrupt; \
                       TOFU pins are temporarily unavailable — manual recovery required.", username, e);
                let backup = self.user_dir(username).join("trust.json.corrupt");
                let _ = tokio::fs::rename(&path, &backup).await;
                vec![]
            }
        }
    }

    pub async fn save_trust(&self, username: &str, records: &[TrustRecord]) -> Result<()> {
        let dir = self.user_dir(username);
        create_dir_secure(&dir).await?;
        // #90: atomic tmp+rename so a crash mid-write can't leave a truncated
        // (corrupt) trust.json that would erase all pins on next load.
        // (write_secret is itself tmp + fsync + rename, serialised per file.)
        write_secret(&dir.join("trust.json"), serde_json::to_string_pretty(records)?).await?;
        Ok(())
    }

    pub async fn update_trust(
        &self, username: &str, nick: &str, fingerprint: &str, verified: bool
    ) -> Result<(TrustRecord, bool)> {
        // MEDIUM: serialize the entire load->mutate->save window per user so
        // concurrent same-user E2EUpdateTrust calls can't form an unserialized
        // read-modify-write that silently drops a pin (undetected key-change).
        // r6 (codex P1 e2e.rs:711): per-field size limits.
        if !trust_record_fits(nick, fingerprint) {
            anyhow::bail!("Trust record rejected (nick or fingerprint too long)");
        }
        let lock = self.trust_lock(username);
        let _g = lock.lock().await;

        let mut records = self.load_trust(username).await;
        let now = chrono::Utc::now().timestamp();

        if let Some(existing) = records.iter_mut().find(|r| r.nick == nick) {
            let fp_changed = existing.fingerprint != fingerprint;
            existing.fingerprint = fingerprint.to_string();
            if fp_changed {
                existing.verified = false;  // reset trust on key change
            } else if verified {
                existing.verified = true;
            }
            let rec = existing.clone();
            self.save_trust(username, &records).await?;
            return Ok((rec, fp_changed));
        }

        // HIGH: bound per-user trust.json growth (and its O(n^2) rewrite cost) so a
        // flood of distinct nicks can't exhaust disk/inodes. REJECT at the cap rather
        // than evicting: silently dropping a pinned fingerprint would erase TOFU
        // history and let a later key-change for the evicted peer go undetected.
        // Overwriting an existing nick (handled above) is unaffected, and legitimate
        // users with a handful of trusted nicks never reach this limit. Consistent
        // with the session/channel-key file caps.
        if records.len() >= MAX_TRUST_RECORDS {
            warn!("[E2E] trust record cap ({}) reached for '{}' — rejecting new pin", MAX_TRUST_RECORDS, username);
            anyhow::bail!("Trust record limit reached");
        }

        let rec = TrustRecord {
            nick:       nick.to_string(),
            fingerprint: fingerprint.to_string(),
            first_seen: now,
            verified,
        };
        records.push(rec.clone());
        self.save_trust(username, &records).await?;
        Ok((rec, false))
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
        if let Some(name) = p.strip_prefix("NETWORK=") {
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
    let lock = slot_lock(path);
    let _g = lock.lock().await;
    let _ = tokio::fs::remove_file(path).await;
}

/// The first bytes (≤ 8) of a file, or None if it can't be read.
async fn read_prefix(path: &std::path::Path) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(path).await.ok()?;
    let mut buf = [0u8; 8];
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..]).await { Ok(0) => break, Ok(k) => n += k, Err(_) => return None }
    }
    Some(buf[..n].to_vec())
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
    if let Ok(b) = tokio::fs::read_to_string(dir.join(format!("{}.enc", sn.stem))).await { return Some(b); }
    let l = sn.legacy.as_ref()?;
    tokio::fs::read_to_string(dir.join(format!("{}.enc", l))).await.ok()
}

async fn delete_slot(dir: &std::path::Path, sn: &SlotName) {
    remove_secret(&dir.join(format!("{}.enc", sn.stem))).await;
    if sn.hashed { remove_secret(&dir.join(format!("{}.name", sn.stem))).await; }
    if let Some(l) = &sn.legacy { remove_secret(&dir.join(format!("{}.enc", l))).await; }
}

/// The client-side names of the slots in `dir` (≤ cap). A hashed stem is reported by
/// its sidecar name (only when the sidecar really maps to that stem); one without a
/// valid sidecar is skipped.
async fn list_slots(dir: &std::path::Path, is_safe: fn(u8) -> bool, cap: usize) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(mut rd) = tokio::fs::read_dir(dir).await else { return out; };
    while let Ok(Some(e)) = rd.next_entry().await {
        let path = e.path();
        if path.extension().and_then(|x| x.to_str()) != Some("enc") { continue; }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else { continue };
        if stem.contains('~') {
            let Ok(n) = tokio::fs::read_to_string(dir.join(format!("{}.name", stem))).await else { continue };
            let sn = slot_name(&n, is_safe);
            if !sn.hashed || sn.stem != stem { continue; }
            out.push(n);
        } else {
            out.push(fs_decode(stem));
        }
        if out.len() >= cap { break; }
    }
    out
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

    /// r6 (codex P1 e2e.rs:711): trust records are size-limited on store, and oversized
    /// ones already on disk are skipped (an oversized file is set aside) instead of loaded.
    #[tokio::test]
    async fn trust_records_are_size_limited() {
        let d = tmpdir();
        let st = E2EStore::new(&d);
        let fp = "ABCD EF01 2345 6789 ABCD EF01 2345 6789 ABCD EF01 2345 6789 ABCD EF01 2345 6789";
        st.update_trust("alice", "bob", fp, false).await.unwrap();
        assert!(st.update_trust("alice", "carol", &"F".repeat(60_000), false).await.is_err(), "60 KB fingerprint refused");
        assert!(st.update_trust("alice", &"n".repeat(300), fp, false).await.is_err(), "300-byte nick refused");
        assert!(st.update_trust("alice", "", fp, false).await.is_err());
        assert_eq!(st.load_trust("alice").await.len(), 1);
        // records written before the limits existed: oversized ones are skipped, the rest kept
        let path = std::path::Path::new(&d).join("e2e/alice/trust.json");
        let recs = vec![
            TrustRecord { nick: "bob".into(), fingerprint: fp.into(), first_seen: 1, verified: true },
            TrustRecord { nick: "big".into(), fingerprint: "F".repeat(60_000), first_seen: 2, verified: false },
        ];
        std::fs::write(&path, serde_json::to_string(&recs).unwrap()).unwrap();
        let got = st.load_trust("alice").await;
        assert_eq!(got.iter().map(|r| r.nick.as_str()).collect::<Vec<_>>(), vec!["bob"]);
        // a file only oversized records can produce is set aside, not read
        let big: Vec<TrustRecord> = (0..200).map(|i| TrustRecord { nick: format!("n{i}"), fingerprint: "F".repeat(60_000), first_seen: i, verified: false }).collect();
        std::fs::write(&path, serde_json::to_string(&big).unwrap()).unwrap();
        assert!(st.load_trust("alice").await.is_empty());
        assert!(std::path::Path::new(&d).join("e2e/alice/trust.json.oversized").exists());
        let _ = std::fs::remove_dir_all(d);
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
        let permit = st.legacy_write_permit("alice").await.expect("not migrated yet");
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
        assert!(st.legacy_write_permit("alice").await.is_none());
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
        assert!(st.legacy_write_permit("alice").await.is_none());
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
