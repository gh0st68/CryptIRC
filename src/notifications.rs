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
use tracing::{info, warn};
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
                muted_networks: vec![],
                muted_channels: vec![],
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
        if subs.is_empty() { return; }
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
                let endpoint: String = sub.endpoint.chars().take(60).collect();
                Err(PushSendError::Other(anyhow::anyhow!(
                    "Push to {} failed: {}",
                    endpoint,
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
