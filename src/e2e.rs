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

use anyhow::{bail, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::Mutex;
use tracing::warn;

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
}

impl E2EStore {
    pub fn new(data_dir: &str) -> Self {
        std::fs::create_dir_all(format!("{}/e2e", data_dir)).ok();
        Self {
            data_dir:   data_dir.to_string(),
            otpk_locks: Arc::new(DashMap::new()),
        }
    }

    fn user_dir(&self, username: &str) -> PathBuf {
        let safe: String = username.chars()
            .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
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

    // ── Identity blob ─────────────────────────────────────────────────────────

    pub async fn store_identity_enc(&self, username: &str, blob: &str) -> Result<()> {
        let dir = self.user_dir(username);
        tokio::fs::create_dir_all(&dir).await?;
        tokio::fs::write(dir.join("identity.enc"), blob).await?;
        Ok(())
    }

    pub async fn load_identity_enc(&self, username: &str) -> Option<String> {
        tokio::fs::read_to_string(self.user_dir(username).join("identity.enc")).await.ok()
    }

    // ── Public key bundle ─────────────────────────────────────────────────────

    pub async fn store_bundle(&self, username: &str, bundle: &KeyBundle) -> Result<()> {
        let dir = self.user_dir(username);
        tokio::fs::create_dir_all(&dir).await?;

        // Store main bundle without one-time prekeys
        let mut b = bundle.clone();
        b.one_time_prekeys = vec![];
        tokio::fs::write(dir.join("bundle.json"), serde_json::to_string(&b)?).await?;

        // Store one-time prekeys individually
        let otpk_dir = dir.join("otpk");
        tokio::fs::create_dir_all(&otpk_dir).await?;
        for opk in &bundle.one_time_prekeys {
            tokio::fs::write(
                otpk_dir.join(format!("{}.json", opk.key_id)),
                serde_json::to_string(opk)?,
            ).await?;
        }
        Ok(())
    }

    /// Fetch a bundle and atomically consume one OTPK.
    pub async fn fetch_bundle(&self, username: &str) -> Option<FetchedBundle> {
        let dir  = self.user_dir(username);
        let json = tokio::fs::read_to_string(dir.join("bundle.json")).await.ok()?;
        let bundle: KeyBundle = serde_json::from_str(&json).ok()?;

        // S2: hold lock while reading + deleting OTPK
        let lock = self.otpk_lock(username);
        let _guard = lock.lock().await;
        let otpk   = self.consume_one_time_prekey_locked(username).await;

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
        tokio::fs::create_dir_all(&otpk_dir).await?;
        for opk in keys {
            tokio::fs::write(
                otpk_dir.join(format!("{}.json", opk.key_id)),
                serde_json::to_string(&opk)?,
            ).await?;
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
        tokio::fs::create_dir_all(&dir).await?;
        let safe: String = partner.chars()
            .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
            .take(128).collect();
        tokio::fs::write(dir.join(format!("{}.enc", safe)), blob).await?;
        Ok(())
    }

    pub async fn load_session(&self, username: &str, partner: &str) -> Option<String> {
        let safe: String = partner.chars()
            .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
            .take(128).collect();
        tokio::fs::read_to_string(
            self.user_dir(username).join("sessions").join(format!("{}.enc", safe))
        ).await.ok()
    }

    pub async fn delete_session(&self, username: &str, partner: &str) -> Result<()> {
        let safe: String = partner.chars()
            .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
            .take(128).collect();
        let _ = tokio::fs::remove_file(
            self.user_dir(username).join("sessions").join(format!("{}.enc", safe))
        ).await;
        Ok(())
    }

    // ── Channel PSKs ──────────────────────────────────────────────────────────

    pub async fn store_channel_key(&self, username: &str, channel: &str, blob: &str) -> Result<()> {
        let dir = self.user_dir(username).join("channels");
        tokio::fs::create_dir_all(&dir).await?;
        let safe = safe_channel(channel);
        tokio::fs::write(dir.join(format!("{}.enc", safe)), blob).await?;
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
                if let Some(stem) = e.path().file_stem().and_then(|s| s.to_str()) {
                    out.push(stem.to_string());
                }
            }
        }
        out
    }

    // ── TOFU trust ────────────────────────────────────────────────────────────

    pub async fn load_trust(&self, username: &str) -> Vec<TrustRecord> {
        let path = self.user_dir(username).join("trust.json");
        let Ok(json) = tokio::fs::read_to_string(path).await else { return vec![]; };
        serde_json::from_str(&json).unwrap_or_default()
    }

    pub async fn save_trust(&self, username: &str, records: &[TrustRecord]) -> Result<()> {
        let dir = self.user_dir(username);
        tokio::fs::create_dir_all(&dir).await?;
        tokio::fs::write(dir.join("trust.json"), serde_json::to_string_pretty(records)?).await?;
        Ok(())
    }

    pub async fn update_trust(
        &self, username: &str, nick: &str, fingerprint: &str, verified: bool
    ) -> Result<(TrustRecord, bool)> {
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

fn safe_channel(channel: &str) -> String {
    channel.chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '#' || *c == '&')
        .take(64)
        .collect()
}
