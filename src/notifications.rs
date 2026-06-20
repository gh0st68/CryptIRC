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
use tokio::sync::Mutex;
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

    /// Persist a JSON value to `path` via temp-file + atomic rename so a crash
    /// mid-write cannot truncate the file and a concurrent reader never observes
    /// a partial file. Tightens perms after rename (push endpoints / muted lists
    /// are privacy-sensitive, #7). Returns the write result.
    async fn write_json_atomic<T: Serialize>(path: &std::path::Path, value: &T) -> Result<()> {
        let json = serde_json::to_string_pretty(value)?;
        let tmp = path.with_extension("json.tmp");
        if tokio::fs::write(&tmp, &json).await.is_ok() {
            if tokio::fs::rename(&tmp, path).await.is_err() {
                // Rename can fail across some filesystems; fall back to direct write.
                tokio::fs::write(path, &json).await?;
                let _ = tokio::fs::remove_file(&tmp).await;
            }
        } else {
            // Could not stage the temp file; write directly so we still persist.
            tokio::fs::write(path, &json).await?;
        }
        set_secret_mode(path).await;
        Ok(())
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
        validate_push_endpoint(&sub.endpoint).await?;

        // Serialize the load→mutate→write window per user so a concurrent
        // subscribe and a notify-time dead-endpoint prune cannot clobber each
        // other (last-writer-wins data loss).
        let lock = self.user_lock(username);
        let _guard = lock.lock().await;

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
        let lock = self.user_lock(username);
        let _guard = lock.lock().await;

        let mut subs = self.load_subscriptions(username).await;
        subs.retain(|s| s.endpoint != endpoint);
        let path = self.subs_path(username);
        Self::write_json_atomic(&path, &subs).await // push endpoints are privacy-sensitive (#7)
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
        let lock = self.user_lock(username);
        let _guard = lock.lock().await;

        let path = self.prefs_path(username);
        Self::write_json_atomic(&path, prefs).await // muted-channel list leaks metadata (#7)
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

        let resp = client
            .post(sub.endpoint.as_str())
            .headers(parts.headers)
            .body(body)
            .send()
            .await
            .map_err(|e| {
                // char-safe truncation: byte-slicing a client-supplied endpoint at
                // offset 60 would panic if a multibyte char straddles the boundary.
                let endpoint: String = sub.endpoint.chars().take(60).collect();
                anyhow::anyhow!("Push to {} failed: {:?}", endpoint, e)
            })?;

        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            // Surface the numeric status so the caller's dead-endpoint prune
            // (checks for "410"/"404"/"Gone") still fires for 410 Gone / 404
            // Not Found push subscriptions, matching the prior behavior.
            let endpoint: String = sub.endpoint.chars().take(60).collect();
            anyhow::bail!("Push to {} failed: {}", endpoint, status)
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
    let host = parsed.host_str().ok_or_else(|| anyhow::anyhow!("Push endpoint has no host"))?;

    // Reject obvious internal names outright.
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".internal") || lower.ends_with(".local") {
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
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await
        .map_err(|_| anyhow::anyhow!("Push endpoint host resolution failed"))?
        .collect();
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
