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
use std::net::IpAddr;
use std::path::PathBuf;
use tracing::{info, warn};
use web_push::*;

/// Cap stored push subscriptions per user (#83). Each subscription is an
/// outbound POST target on every notification, so the list must be bounded.
const MAX_SUBSCRIPTIONS_PER_USER: usize = 20;

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
    std::fs::write(&path, serde_json::to_string_pretty(&keys)?)?;
    // vapid.json holds the VAPID EC PRIVATE key in cleartext; restrict it to
    // owner-only so the world-traversable data dir cannot leak it to other
    // local users (which would let them forge web-push to all users) — #7/#71.
    set_secret_mode_sync(&path);
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
    data_dir:     String,
    vapid_keys:   VapidKeys,
    push_client:  WebPushClient,
}

impl NotificationManager {
    pub fn new(data_dir: &str, vapid_keys: VapidKeys) -> Self {
        std::fs::create_dir_all(format!("{}/push", data_dir)).ok();
        std::fs::create_dir_all(format!("{}/notif_prefs", data_dir)).ok();
        Self {
            data_dir: data_dir.to_string(),
            vapid_keys,
            push_client: WebPushClient::new().expect("Failed to create WebPushClient"),
        }
    }

    pub fn vapid_public_key(&self) -> &str {
        &self.vapid_keys.public_key
    }

    // ── Subscriptions ─────────────────────────────────────────────────────────

    pub async fn save_subscription(&self, username: &str, sub: PushSubscription) -> Result<()> {
        // #83: the endpoint is a client-supplied outbound URL that send_push will
        // POST to. Without validation an authenticated user could register an
        // internal target and turn the server into a blind-SSRF probe. Require
        // https and reject loopback/private/link-local/internal hosts.
        validate_push_endpoint(&sub.endpoint)?;

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
        tokio::fs::write(&path, serde_json::to_string_pretty(&subs)?).await?;
        set_secret_mode(&path).await; // push endpoints are privacy-sensitive (#7)
        Ok(())
    }

    pub async fn remove_subscription(&self, username: &str, endpoint: &str) -> Result<()> {
        let mut subs = self.load_subscriptions(username).await;
        subs.retain(|s| s.endpoint != endpoint);
        let path = self.subs_path(username);
        tokio::fs::write(&path, serde_json::to_string_pretty(&subs)?).await?;
        set_secret_mode(&path).await; // push endpoints are privacy-sensitive (#7)
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
        set_secret_mode(&path).await; // muted-channel list leaks metadata (#7)
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
        ts:        i64,
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
            "ts":       ts,
            "is_dm":    is_dm,
            "tag":      format!("{}/{}", conn_id, target),
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

    pub async fn send_monitor_notification(&self, username: &str, nick: &str, status: &str) {
        let subs = self.load_subscriptions(username).await;
        if subs.is_empty() { return; }
        let icon = if status == "online" { "🟢" } else { "🔴" };
        let payload = serde_json::json!({
            "title": format!("CryptIRC — Monitor"),
            "body": format!("{} {} is {}", icon, nick, status),
            "tag": format!("monitor-{}", nick.to_lowercase()),
        }).to_string();
        let mut stale = vec![];
        for sub in &subs {
            if let Err(e) = self.send_push(sub, &payload).await {
                let msg = e.to_string();
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

        match self.push_client.send(message).await {
            Ok(_) => Ok(()),
            Err(e) => {
                // char-safe truncation: byte-slicing a client-supplied endpoint at
                // offset 60 would panic if a multibyte char straddles the boundary.
                let endpoint: String = sub.endpoint.chars().take(60).collect();
                anyhow::bail!("Push to {} failed: {:?}", endpoint, e)
            }
        }
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

/// Best-effort chmod 0600 on a secret file written via the sync std::fs API
/// (audit #7). No-op on non-unix targets.
fn set_secret_mode_sync(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    { let _ = path; }
}

/// Best-effort chmod 0600 on a secret file written via tokio::fs (audit #7).
async fn set_secret_mode(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await;
    }
    #[cfg(not(unix))]
    { let _ = path; }
}

/// Validate a client-supplied web-push endpoint before storing it (#83).
/// Require https and reject hosts that resolve to a private/internal address
/// literal (loopback, RFC1918, link-local incl. cloud metadata, CGNAT, ...)
/// or obvious internal names, so the endpoint cannot be used as an SSRF probe.
fn validate_push_endpoint(endpoint: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(endpoint)
        .map_err(|_| anyhow::anyhow!("Invalid push endpoint URL"))?;
    if parsed.scheme() != "https" {
        bail!("Push endpoint must use https");
    }
    let host = parsed.host_str().ok_or_else(|| anyhow::anyhow!("Push endpoint has no host"))?;

    // Reject obvious internal names outright.
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".internal") || lower.ends_with(".local") {
        bail!("Push endpoint host is not allowed");
    }

    // If the host is an IP literal, reject private/internal ranges. (DNS-name
    // hosts are not resolved here — the web-push client connects to the public
    // push service; this guard blocks the direct-IP SSRF primitive.)
    // host_str() serializes IPv6 with surrounding brackets; strip them so the
    // literal parses (e.g. "[::1]" -> "::1").
    let host_ip = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if let Ok(ip) = host_ip.parse::<IpAddr>() {
        if is_private_ip(&ip) {
            bail!("Push endpoint host is not allowed");
        }
    }
    Ok(())
}

/// Conservative private/internal IP check for #83 (kept local to this file to
/// avoid cross-module coupling; mirrors the spirit of preview.rs::is_private_ip).
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()        // 169.254.0.0/16 (incl. 169.254.169.254 metadata)
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.octets()[0] == 0       // 0.0.0.0/8
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64) // 100.64.0.0/10 CGNAT
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || v6.to_ipv4_mapped().map(|m| is_private_ip(&IpAddr::V4(m))).unwrap_or(false)
        }
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
