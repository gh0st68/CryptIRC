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
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};
use tracing::{error, info, warn};
use web_push::*;

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
    std::fs::write(&path, serde_json::to_string_pretty(&keys)?)?;
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
}

// ─── Notification manager ─────────────────────────────────────────────────────

pub struct NotificationManager {
    data_dir:    String,
    vapid_keys:  VapidKeys,
}

impl NotificationManager {
    pub fn new(data_dir: &str, vapid_keys: VapidKeys) -> Self {
        std::fs::create_dir_all(format!("{}/push", data_dir)).ok();
        std::fs::create_dir_all(format!("{}/notif_prefs", data_dir)).ok();
        Self { data_dir: data_dir.to_string(), vapid_keys }
    }

    pub fn vapid_public_key(&self) -> &str {
        &self.vapid_keys.public_key
    }

    // ── Subscriptions ─────────────────────────────────────────────────────────

    pub async fn save_subscription(&self, username: &str, sub: PushSubscription) -> Result<()> {
        let mut subs = self.load_subscriptions(username).await;
        // Replace existing subscription with same endpoint
        subs.retain(|s| s.endpoint != sub.endpoint);
        subs.push(sub);
        let path = self.subs_path(username);
        tokio::fs::write(&path, serde_json::to_string_pretty(&subs)?).await?;
        Ok(())
    }

    pub async fn remove_subscription(&self, username: &str, endpoint: &str) -> Result<()> {
        let mut subs = self.load_subscriptions(username).await;
        subs.retain(|s| s.endpoint != endpoint);
        let path = self.subs_path(username);
        tokio::fs::write(&path, serde_json::to_string_pretty(&subs)?).await?;
        Ok(())
    }

    pub async fn load_subscriptions(&self, username: &str) -> Vec<PushSubscription> {
        let path = self.subs_path(username);
        let Ok(json) = tokio::fs::read_to_string(&path).await else { return vec![]; };
        serde_json::from_str(&json).unwrap_or_default()
    }

    // ── Preferences ───────────────────────────────────────────────────────────

    pub async fn load_prefs(&self, username: &str) -> NotifPrefs {
        let path = self.prefs_path(username);
        let Ok(json) = tokio::fs::read_to_string(&path).await else {
            return NotifPrefs {
                enabled: false,
                trigger: "mentions_and_dms".to_string(),
                muted_networks: vec![],
                muted_channels: vec![],
            };
        };
        serde_json::from_str(&json).unwrap_or_default()
    }

    pub async fn save_prefs(&self, username: &str, prefs: &NotifPrefs) -> Result<()> {
        let path = self.prefs_path(username);
        tokio::fs::write(&path, serde_json::to_string_pretty(prefs)?).await?;
        Ok(())
    }

    // ── Send notification ─────────────────────────────────────────────────────

    /// Called on every incoming PRIVMSG. Decides whether to push based on prefs.
    pub async fn maybe_notify(
        &self,
        username:  &str,
        user_nick: &str,
        conn_id:   &str,
        net_label: &str,
        target:    &str,
        from:      &str,
        text:      &str,
    ) {
        let prefs = self.load_prefs(username).await;
        if !prefs.enabled { return; }

        // Check muted network
        if prefs.muted_networks.contains(&conn_id.to_string()) { return; }
        // Check muted channel
        let chan_key = format!("{}/{}", conn_id, target);
        if prefs.muted_channels.contains(&chan_key) { return; }

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
            "is_dm":    is_dm,
            "tag":      format!("{}-{}", conn_id, target),
        });

        let subs = self.load_subscriptions(username).await;
        let mut stale = vec![];
        for sub in &subs {
            if let Err(e) = self.send_push(sub, &payload.to_string()).await {
                let msg = e.to_string();
                warn!("Push send failed for {}: {}", username, msg);
                // Remove expired/unsubscribed endpoints
                if msg.contains("410") || msg.contains("404") || msg.contains("Gone") {
                    stale.push(sub.endpoint.clone());
                }
            }
        }
        for endpoint in &stale {
            let _ = self.remove_subscription(username, endpoint).await;
        }
    }

    pub async fn send_test_notification(&self, username: &str) {
        let subs = self.load_subscriptions(username).await;
        let payload = serde_json::json!({
            "title": "CryptIRC",
            "body": "Test notification — push is working!",
            "tag": "cryptirc-test",
        }).to_string();
        for sub in &subs {
            if let Err(e) = self.send_push(sub, &payload).await {
                warn!("Test push failed for {}: {}", username, e);
            }
        }
    }

    async fn send_push(&self, sub: &PushSubscription, payload: &str) -> Result<()> {
        let p256dh = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &sub.keys.p256dh,
        )?;
        let auth = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &sub.keys.auth,
        )?;

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
        sig_builder.add_claim("sub", "mailto:cryptirc@localhost");
        let signature = sig_builder.build()?;

        let mut builder = WebPushMessageBuilder::new(&subscription_info)?;
        builder.set_payload(ContentEncoding::Aes128Gcm, payload.as_bytes());
        builder.set_vapid_signature(signature);
        let message = builder.build()?;

        let client = WebPushClient::new()?;
        client.send(message).await?;
        Ok(())
    }

    fn subs_path(&self, username: &str) -> PathBuf {
        let safe: String = username.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-').collect();
        PathBuf::from(&self.data_dir).join("push").join(format!("{}.json", safe))
    }
    fn prefs_path(&self, username: &str) -> PathBuf {
        let safe: String = username.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-').collect();
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

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max { return s; }
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None         => s,
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
    let mut ctx = openssl::bn::BigNumContext::new()?;
    let mut pub_point = openssl::ec::EcPoint::new(&group)?;
    pub_point.mul_generator(&group, &bn, &ctx)?;
    let key   = EcKey::from_private_components(&group, &bn, &pub_point)?;
    Ok(key.private_key_to_pem()?)
}
