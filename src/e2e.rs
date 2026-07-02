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
const MAX_SESSION_FILES: usize = 4096;
const MAX_OTPK_TOTAL: usize = 1024;
const MAX_CHANNEL_KEY_FILES: usize = 4096;

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
    /// #27: per-target sliding-window counter of OTPK consumptions. Keyed by the
    /// target username (the pool being drained). Value is (window_start, count).
    otpk_consume_rate: Arc<DashMap<String, (Instant, u32)>>,
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
        Self {
            data_dir:          data_dir.to_string(),
            otpk_locks:        Arc::new(DashMap::new()),
            trust_locks:       Arc::new(DashMap::new()),
            otpk_consume_rate: Arc::new(DashMap::new()),
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

    /// #27/#41: consult (and, when allowed, charge) the per-target OTPK rate budget
    /// for `username`. Sliding 60s window, max OTPK_CONSUME_MAX_PER_WINDOW
    /// consumptions per target per window. Returns `Allowed` when the caller may
    /// consume an OTPK (the consumption is recorded); otherwise returns `Blocked`
    /// and the caller MUST NOT consume (it falls back to a 3-DH bundle instead).
    /// `Blocked { first }` is true only on the first over-budget hit in the current
    /// window, so the per-victim warn is logged at most once per window. MUST be
    /// called only after confirming the pool is non-empty, so budget is charged
    /// solely when an OTPK actually exists to be consumed.
    fn otpk_consume_allowed(&self, username: &str) -> OtpkBudget {
        let now = Instant::now();
        // Bound the map: an attacker querying many distinct target usernames would
        // otherwise grow it without limit. Drop fully-expired windows (which would be
        // reset to a fresh window on next access anyway, so no rate decision changes).
        // Done BEFORE taking the entry guard to avoid a same-map deadlock.
        if self.otpk_consume_rate.len() > 4096 {
            self.otpk_consume_rate.retain(|_, (ws, _)| now.duration_since(*ws) < OTPK_CONSUME_WINDOW);
        }
        let mut entry = self
            .otpk_consume_rate
            .entry(username.to_string())
            .or_insert((now, 0));
        let (window_start, count) = *entry;
        if now.duration_since(window_start) >= OTPK_CONSUME_WINDOW {
            // window expired — start a fresh window with this consumption
            *entry = (now, 1);
            OtpkBudget::Allowed
        } else if count < OTPK_CONSUME_MAX_PER_WINDOW {
            *entry = (window_start, count + 1);
            OtpkBudget::Allowed
        } else {
            // over budget — keep counting so the first block in this window is
            // distinguishable (log once); caller still gets a 3-DH fallback.
            *entry = (window_start, count.saturating_add(1));
            OtpkBudget::Blocked { first: count == OTPK_CONSUME_MAX_PER_WINDOW }
        }
    }

    // ── Identity blob ─────────────────────────────────────────────────────────

    pub async fn store_identity_enc(&self, username: &str, blob: &str) -> Result<()> {
        let dir = self.user_dir(username);
        create_dir_secure(&dir).await?;
        write_secret(&dir.join("identity.enc"), blob).await?;
        Ok(())
    }

    pub async fn load_identity_enc(&self, username: &str) -> Option<String> {
        tokio::fs::read_to_string(self.user_dir(username).join("identity.enc")).await.ok()
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
        for opk in bundle.one_time_prekeys.iter().filter(|o| valid_key_field(&o.public_key)).take(limit) {
            write_secret(&otpk_dir.join(format!("{}.json", opk.key_id)), serde_json::to_string(opk)?).await?;
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

    pub async fn fetch_bundle(&self, username: &str) -> Option<FetchedBundle> {
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
            match self.otpk_consume_allowed(username) {
                OtpkBudget::Allowed => self.consume_one_time_prekey_locked(username).await,
                OtpkBudget::Blocked { first } => {
                    if first {
                        warn!(
                            "[E2E] OTPK consume rate limit hit for '{}' — serving 3-DH bundle (no OTPK consumed)",
                            username
                        );
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
                            return Some(opk);
                        }
                    }
                }
            }
        }
        warn!("[E2E] No one-time prekeys remaining for {}", username);
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
        for opk in keys.into_iter().filter(|o| valid_key_field(&o.public_key)).take(limit) { // #88
            write_secret(&otpk_dir.join(format!("{}.json", opk.key_id)), serde_json::to_string(&opk)?).await?;
        }
        Ok(())
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
        let dir = self.user_dir(username).join("sessions");
        create_dir_secure(&dir).await?;
        let safe = safe_partner(partner);
        let path = dir.join(format!("{}.enc", safe));
        // MEDIUM: one session file per partner with no cap lets a user create an
        // unbounded number of session files (one inode each). Only a NEW partner
        // file grows the set — overwriting an existing partner is always allowed —
        // so we count existing files only when the target file doesn't yet exist,
        // and reject once the per-user cap is reached. Legitimate users have a
        // bounded set of active conversations and never hit this.
        if tokio::fs::metadata(&path).await.is_err()
            && count_dir_entries(&dir).await >= MAX_SESSION_FILES
        {
            warn!(
                "[E2E] session file cap ({}) reached for '{}' — rejecting new partner '{}'",
                MAX_SESSION_FILES, username, safe
            );
            anyhow::bail!("session storage limit reached");
        }
        write_secret(&path, blob).await?;
        Ok(())
    }

    pub async fn load_session(&self, username: &str, partner: &str) -> Option<String> {
        let safe = safe_partner(partner);
        tokio::fs::read_to_string(
            self.user_dir(username).join("sessions").join(format!("{}.enc", safe))
        ).await.ok()
    }

    pub async fn delete_session(&self, username: &str, partner: &str) -> Result<()> {
        let safe = safe_partner(partner);
        let _ = tokio::fs::remove_file(
            self.user_dir(username).join("sessions").join(format!("{}.enc", safe))
        ).await;
        Ok(())
    }

    // ── Channel PSKs ──────────────────────────────────────────────────────────

    pub async fn store_channel_key(&self, username: &str, channel: &str, blob: &str) -> Result<()> {
        let dir = self.user_dir(username).join("channels");
        create_dir_secure(&dir).await?;
        let safe = safe_channel(channel);
        let path = dir.join(format!("{}.enc", safe));
        // MEDIUM: one channel-key file per channel with no cap lets a user create
        // an unbounded number of files (one inode each). Only a NEW channel grows
        // the set — overwriting an existing channel is always allowed — so count
        // existing files only when the target file doesn't yet exist, and reject
        // once the per-user cap is reached. Legitimate users join a bounded number
        // of channels and never hit this.
        if tokio::fs::metadata(&path).await.is_err()
            && count_dir_entries(&dir).await >= MAX_CHANNEL_KEY_FILES
        {
            warn!(
                "[E2E] channel-key file cap ({}) reached for '{}' — rejecting new channel '{}'",
                MAX_CHANNEL_KEY_FILES, username, safe
            );
            anyhow::bail!("channel key storage limit reached");
        }
        write_secret(&path, blob).await?;
        Ok(())
    }

    pub async fn load_channel_key(&self, username: &str, channel: &str) -> Option<String> {
        let safe = safe_channel(channel);
        tokio::fs::read_to_string(
            self.user_dir(username).join("channels").join(format!("{}.enc", safe))
        ).await.ok()
    }

    pub async fn delete_channel_key(&self, username: &str, channel: &str) -> Result<()> {
        let safe = safe_channel(channel);
        let _ = tokio::fs::remove_file(
            self.user_dir(username).join("channels").join(format!("{}.enc", safe))
        ).await;
        Ok(())
    }

    pub async fn list_channel_keys(&self, username: &str) -> Vec<String> {
        let dir = self.user_dir(username).join("channels");
        let mut out = Vec::new();
        if let Ok(mut rd) = tokio::fs::read_dir(&dir).await {
            while let Ok(Some(e)) = rd.next_entry().await {
                let path = e.path();
                // #89: only real `.enc` channel-key files (skip strays) — the `.enc`
                // extension filter is the load-bearing part — and cap the vector so a
                // reconnect can't trigger an unbounded fan-out of load round-trips.
                // (L11: the prior `foo.bar.enc → foo.bar` example can't actually arise —
                // safe_channel strips `.` from channel names before they become filenames.)
                if path.extension().and_then(|x| x.to_str()) != Some("enc") { continue; }
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    out.push(fs_decode(stem));
                    if out.len() >= MAX_CHANNEL_KEY_FILES { break; }
                }
            }
        }
        out
    }

    // ── TOFU trust ────────────────────────────────────────────────────────────

    pub async fn load_trust(&self, username: &str) -> Vec<TrustRecord> {
        let path = self.user_dir(username).join("trust.json");
        let Ok(json) = tokio::fs::read_to_string(&path).await else { return vec![]; };
        match serde_json::from_str(&json) {
            Ok(records) => records,
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
        let final_path = dir.join("trust.json");
        let tmp = dir.join(format!("trust.json.tmp.{}", uuid::Uuid::new_v4()));
        write_secret(&tmp, serde_json::to_string_pretty(records)?).await?;
        if let Err(e) = tokio::fs::rename(&tmp, &final_path).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e.into());
        }
        Ok(())
    }

    pub async fn update_trust(
        &self, username: &str, nick: &str, fingerprint: &str, verified: bool
    ) -> Result<(TrustRecord, bool)> {
        // MEDIUM: serialize the entire load->mutate->save window per user so
        // concurrent same-user E2EUpdateTrust calls can't form an unserialized
        // read-modify-write that silently drops a pin (undetected key-change).
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

/// audit #45: write an e2e file then chmod 0600. No-op mode on non-unix.
async fn write_secret(path: &std::path::Path, bytes: impl AsRef<[u8]>) -> std::io::Result<()> {
    tokio::fs::write(path, bytes).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await;
    }
    Ok(())
}

/// Cheaply count the number of entries in a directory. Used to enforce per-user
/// on-disk file caps. A missing/unreadable directory counts as 0 (nothing stored
/// yet), so a first write is always allowed.
async fn count_dir_entries(dir: &std::path::Path) -> usize {
    let Ok(mut rd) = tokio::fs::read_dir(dir).await else { return 0; };
    let mut n = 0;
    while let Ok(Some(_)) = rd.next_entry().await {
        n += 1;
    }
    n
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
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::new();
    for &b in name.as_bytes() {
        if b != b'%' && is_safe(b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        if out.len() >= 248 { break; } // + ".enc" stays within the 255-byte limit
    }
    out
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

fn safe_partner(partner: &str) -> String { fs_encode(partner, partner_is_safe) }

fn safe_channel(channel: &str) -> String { fs_encode(channel, channel_is_safe) }
