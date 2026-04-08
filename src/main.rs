//! main.rs — CryptIRC server v0.3
//! Adds: SASL PLAIN/EXTERNAL, client cert fingerprint auth, heartbeat + auto-reconnect

use anyhow::Result;
use axum::{
    body::Body,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        DefaultBodyLimit, Multipart, Path, Query, State,
    },
    http::{header, HeaderMap, HeaderName, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use dashmap::{DashMap, DashSet};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::{Arc, atomic::{AtomicUsize, Ordering}}};
use tokio::sync::{broadcast, Mutex};
use tracing::{error, info};
use uuid::Uuid;

mod auth;
mod certs;
mod crypto;
mod e2e;
mod email;
mod irc;
mod logs;
mod notifications;
mod paste;
mod preview;
mod upload;

use auth::{validate_uuid, AuthManager};
use certs::CertStore;
use crypto::CryptoManager;
use e2e::{E2EStore, FetchedBundle, KeyBundle, OneTimePrekey};
use logs::EncryptedLogger;
use notifications::{NotificationManager, NotifPrefs, PushSubscription};

// ─── App State ────────────────────────────────────────────────────────────────

pub type UserEventMap = Arc<DashMap<String, broadcast::Sender<ServerEvent>>>;

#[derive(Clone)]
pub struct AppState {
    pub connections:         Arc<DashMap<String, Arc<Mutex<irc::IrcConnection>>>>,
    pub conn_owners:         Arc<DashMap<String, String>>,
    /// Set of conn_ids that have been explicitly disconnected (suppresses auto-reconnect)
    pub disconnect_requests: Arc<DashSet<String>>,
    pub crypto:              Arc<CryptoManager>,
    pub certs:               Arc<CertStore>,
    pub logger:              Arc<EncryptedLogger>,
    pub auth:                Arc<AuthManager>,
    pub notifier:            Arc<NotificationManager>,
    pub e2e_store:           Arc<E2EStore>,
    pub paste_store:         Arc<paste::PasteStore>,
    pub preview_service:     Arc<preview::PreviewService>,
    pub user_events:         UserEventMap,
    /// Count of non-idle WS sessions per user. Push fires when this is 0.
    pub active_sessions:     Arc<DashMap<String, Arc<AtomicUsize>>>,
    pub upload_dir:          String,
    pub base_url:            String,
    pub from_email:          String,
    pub data_dir:            String,
    pub registration_open:   Arc<tokio::sync::RwLock<bool>>,
    pub registration_code:   Arc<tokio::sync::RwLock<String>>,
    pub admin_settings_lock: Arc<tokio::sync::Mutex<()>>,
}

impl AppState {
    pub fn user_tx(&self, username: &str) -> broadcast::Sender<ServerEvent> {
        self.user_events
            .entry(username.to_string())
            .or_insert_with(|| broadcast::channel(128).0)
            .clone()
    }
    pub fn send_to_user(&self, username: &str, evt: ServerEvent) {
        let _ = self.user_tx(username).send(evt);
    }
    /// M11: Prune stale user_events entries with no active subscribers
    pub fn prune_user_events(&self) {
        let stale: Vec<String> = self.user_events.iter()
            .filter(|e| e.value().receiver_count() == 0)
            .map(|e| e.key().clone())
            .collect();
        for k in stale { self.user_events.remove(&k); }
    }
    /// Get the active-session counter for a user (creates if needed).
    pub fn active_counter(&self, username: &str) -> Arc<AtomicUsize> {
        self.active_sessions
            .entry(username.to_string())
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone()
    }
    /// Returns true if the user has zero active (non-idle) WS sessions.
    pub fn user_is_idle(&self, username: &str) -> bool {
        self.active_sessions
            .get(username)
            .map_or(true, |c| c.load(Ordering::Acquire) == 0)
    }
    pub fn disconnect_requested(&self, conn_id: &str) -> bool {
        self.disconnect_requests.contains(conn_id)
    }
    pub fn request_disconnect(&self, conn_id: &str) {
        self.disconnect_requests.insert(conn_id.to_string());
    }
    pub fn clear_disconnect_request(&self, conn_id: &str) {
        self.disconnect_requests.remove(conn_id);
    }
}

// ─── Protocol types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Auth             { token: String },
    UnlockVault      { passphrase: String },
    LockVault        {},
    ChangePassphrase { old: String, new: String },
    AddNetwork       { network: NetworkConfig },
    UpdateNetwork    { network: NetworkConfig },
    RemoveNetwork    { id: String },
    Connect          { id: String },
    Disconnect       { id: String },
    Send             { conn_id: String, raw: String },
    JoinChannel      { conn_id: String, channel: String, key: Option<String> },
    PartChannel      { conn_id: String, channel: String },
    GetLogs          { conn_id: String, target: String, limit: Option<usize>, before: Option<i64> },
    Sync             { conn_id: String, target: String, after_id: u64 },
    GetState         {},
    // Certificate management
    GenerateCert     { conn_id: String },
    DeleteCert       { conn_id: String },
    GetCertInfo      { conn_id: String },
    // E2E encryption — explicit renames because snake_case turns E2E into e2_e
    #[serde(rename = "e2e_store_identity")]
    E2EStoreIdentity  { blob: String },
    #[serde(rename = "e2e_load_identity")]
    E2ELoadIdentity   {},
    #[serde(rename = "e2e_publish_bundle")]
    E2EPublishBundle  { bundle: KeyBundle },
    #[serde(rename = "e2e_add_otpks")]
    E2EAddOTPKs       { keys: Vec<OneTimePrekey> },
    #[serde(rename = "e2e_fetch_bundle")]
    E2EFetchBundle    { username: String },
    #[serde(rename = "e2e_store_session")]
    E2EStoreSession   { partner: String, blob: String },
    #[serde(rename = "e2e_load_session")]
    E2ELoadSession    { partner: String },
    #[serde(rename = "e2e_delete_session")]
    E2EDeleteSession  { partner: String },
    #[serde(rename = "e2e_store_channel_key")]
    E2EStoreChannelKey  { channel: String, blob: String },
    #[serde(rename = "e2e_load_channel_key")]
    E2ELoadChannelKey   { channel: String },
    #[serde(rename = "e2e_delete_channel_key")]
    E2EDeleteChannelKey { channel: String },
    #[serde(rename = "e2e_list_channel_keys")]
    E2EListChannelKeys  {},
    #[serde(rename = "e2e_update_trust")]
    E2EUpdateTrust    { nick: String, fingerprint: String, verified: bool },
    #[serde(rename = "e2e_load_trust")]
    E2ELoadTrust      {},
    #[serde(rename = "e2e_relay_x3dh")]
    E2ERelayX3DH      { target_nick: String, header: serde_json::Value },
    #[serde(rename = "e2e_check_otpk_count")]
    E2ECheckOTPKCount {},
    // Appearance
    SaveAppearance    { settings: String },
    LoadAppearance    {},
    SavePreferences   { prefs: String },
    LoadPreferences   {},
    // Account
    DeleteAccount     { password: String },
    // Monitor push
    MonitorPush       { nick: String, status: String },
    // Notepad (encrypted per-user)
    SaveNotepad       { content: String },
    LoadNotepad       {},
    // Channel stats (encrypted)
    SaveStats         { data: String },
    LoadStats         {},
    // Password safe (encrypted with vault key)
    SavePasswords     { data: String },
    LoadPasswords     {},
    // Clear all user data (logs, notepad, pastes)
    ClearAllData      {},
    // Channel order
    SaveChannelOrder  { conn_id: String, order: Vec<String> },
    // Idle/active status for push notification gating
    Idle              {},
    Active            {},
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerEvent {
    AuthRequired     {},
    AuthOk           { username: String },
    AuthFailed       { message: String },
    VaultLocked      {},
    /// e2e_enc_key is a 32-byte subkey derived from the vault master key,
    /// base64-encoded. The client uses it to encrypt/decrypt private E2E key blobs.
    VaultUnlocked    { e2e_enc_key: String },
    VaultError       { message: String },
    IrcMessage       { conn_id: String, from: String, target: String, text: String, ts: i64, kind: MessageKind, msg_id: u64, #[serde(skip_serializing_if = "Option::is_none")] prefix: Option<String> },
    /// Echo of user's own sent message — for multi-device sync
    IrcEcho          { conn_id: String, from: String, target: String, text: String, ts: i64, kind: MessageKind, msg_id: u64 },
    IrcJoin          { conn_id: String, nick: String,  channel: String, ts: i64 },
    /// IRCv3 extended-join: includes account and realname
    IrcJoinEx        { conn_id: String, nick: String,  channel: String, account: String, realname: String, ts: i64 },
    /// IRCv3 away-notify
    IrcAway          { conn_id: String, nick: String,  away: bool, message: String, ts: i64 },
    /// IRCv3 account-notify
    IrcAccount       { conn_id: String, nick: String,  account: String, ts: i64 },
    /// IRCv3 invite-notify
    IrcInvite        { conn_id: String, from: String,  target: String, channel: String, ts: i64 },
    /// IRCv3 setname
    IrcSetname       { conn_id: String, nick: String,  realname: String, ts: i64 },
    /// IRCv3 typing indicator
    IrcTyping        { conn_id: String, nick: String,  target: String, state: String },
    /// IRCv3 MONITOR online
    IrcMonitorOnline { conn_id: String, nick: String,  ts: i64 },
    /// IRCv3 MONITOR offline
    IrcMonitorOffline{ conn_id: String, nick: String,  ts: i64 },
    IrcPart          { conn_id: String, nick: String,  channel: String, reason: String, ts: i64 },
    IrcQuit          { conn_id: String, nick: String,  reason: String,  ts: i64 },
    IrcNick          { conn_id: String, old: String,   new: String,     ts: i64 },
    IrcTopic         { conn_id: String, channel: String, topic: String, set_by: String, ts: i64 },
    IrcNames         { conn_id: String, channel: String, names: Vec<String> },
    IrcMode          { conn_id: String, target: String,  modes: String, ts: i64 },
    IrcKick          { conn_id: String, channel: String, kicked: String, by: String, reason: String, ts: i64 },
    /// 367 — single ban list entry (for /unbanall accumulation)
    IrcBanEntry      { conn_id: String, channel: String, mask: String, set_by: String, ts: i64 },
    /// 368 — end of ban list
    IrcBanEnd        { conn_id: String, channel: String },
    /// 322 — channel list entry
    IrcListEntry     { conn_id: String, channel: String, users: u32, topic: String },
    /// 323 — end of channel list
    IrcListEnd       { conn_id: String },
    LagUpdate        { conn_id: String, ms: u64 },
    SaslStatus       { conn_id: String, success: bool, message: String },
    Connected        { conn_id: String, server: String, nick: String },
    Disconnected     { conn_id: String, reason: String },
    Connecting       { conn_id: String, server: String },
    Reconnecting     { conn_id: String, attempt: u32, delay_secs: u64, reason: String },
    State            { networks: Vec<NetworkState>, vault_unlocked: bool },
    LogLines         { conn_id: String, target: String, lines: Vec<LogLine> },
    SyncLines        { conn_id: String, target: String, lines: Vec<LogLine> },
    CertInfo         { conn_id: String, fingerprint: String, cert_pem: String },
    // ── E2E events — explicit renames because snake_case turns E2E into e2_e
    #[serde(rename = "e2e_bundle")]
    E2EBundle        { username: String, bundle: FetchedBundle },
    #[serde(rename = "e2e_identity_blob")]
    E2EIdentityBlob  { blob: String },
    #[serde(rename = "e2e_session")]
    E2ESession       { partner: String, blob: String },
    #[serde(rename = "e2e_channel_key")]
    E2EChannelKey    { channel: String, blob: String },
    #[serde(rename = "e2e_channel_list")]
    E2EChannelList   { channels: Vec<String> },
    #[serde(rename = "e2e_trust")]
    E2ETrust         { nick: String, fingerprint: String, verified: bool, key_changed: bool },
    #[serde(rename = "e2e_otpk_low")]
    E2EOTPKLow       { remaining: usize },
    #[serde(rename = "e2e_x3dh_header")]
    E2EX3DHHeader    { from_nick: String, header: serde_json::Value },
    Appearance       { settings: String },
    Preferences      { prefs: String },
    Notepad          { content: String },
    StatsData        { data: String },
    PasswordSafe     { data: String },
    AccountDeleted   {},
    DataCleared      {},
    Error            { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageKind { Privmsg, Notice, Action }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub id:                    String,
    pub label:                 String,
    pub server:                String,
    pub port:                  u16,
    pub tls:                   bool,
    pub tls_accept_invalid_certs: bool,
    pub nick:                  String,
    pub realname:              String,
    pub username:              String,
    pub password:              Option<String>,
    // SASL PLAIN
    pub sasl_plain:            Option<SaslConfig>,
    // SASL EXTERNAL (client cert) — set to true + set client_cert_id
    pub sasl_external:         bool,
    pub client_cert_id:        Option<String>,
    pub auto_join:             Vec<String>,
    pub auto_reconnect:        bool,
    #[serde(default)]
    pub oper_login:            Option<String>,
    #[serde(default)]
    pub oper_pass:             Option<String>,
    #[serde(default)]
    pub channel_order:         Vec<String>,
    #[serde(default)]
    pub nickserv_pass:         Option<String>,
    #[serde(default)]
    pub auto_identify:         bool,
    #[serde(default)]
    pub disabled_caps:         Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            id: String::new(), label: String::new(),
            server: String::new(), port: 6697, tls: true,
            tls_accept_invalid_certs: false,
            nick: String::new(), realname: String::new(), username: String::new(),
            password: None, sasl_plain: None,
            sasl_external: false, client_cert_id: None,
            auto_join: vec![], auto_reconnect: true,
            oper_login: None, oper_pass: None,
            channel_order: vec![],
            nickserv_pass: None, auto_identify: false,
            disabled_caps: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaslConfig { pub account: String, pub password: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkState {
    pub config:       NetworkConfig,
    pub connected:    bool,
    pub nick:         String,
    pub channels:     Vec<ChannelState>,
    pub lag_ms:       Option<u64>,
    pub has_cert:     bool,
    pub cert_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelState { pub name: String, pub topic: String, pub names: Vec<String> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLine { pub id: u64, pub ts: i64, pub from: String, pub text: String, pub kind: String }

// ─── HTTP types ───────────────────────────────────────────────────────────────

#[derive(Deserialize)] struct RegisterBody      { username: String, email: String, password: String, #[serde(default)] code: String }
#[derive(Deserialize)] struct LoginBody          { username: String, password: String }
#[derive(Deserialize)] struct VerifyQuery        { token: String }
#[derive(Deserialize)] struct ForgotBody         { email: String }
#[derive(Deserialize)] struct ResetQuery         { token: String }
#[derive(Deserialize)] struct ResetPasswordBody  { token: String, password: String }
#[derive(Deserialize)] struct FileQuery    { token: Option<String> }
#[derive(Serialize)]   struct AuthOkBody   { token: String, username: String }
#[derive(Serialize)]   struct MeOk         { username: String }
#[derive(Serialize)]   struct Msg          { message: String }

/// S6: Maximum size of a single inbound WebSocket text message.
/// Prevents a client from sending a huge JSON payload to exhaust parser memory.
const WS_MAX_MSG_BYTES: usize = 64 * 1024; // 64 KB


async fn security_headers_mw(req: Request<Body>, next: Next) -> Response {
    let mut response = next.run(req).await;
    let h = response.headers_mut();
    h.insert(HeaderName::from_static("x-frame-options"),          HeaderValue::from_static("DENY"));
    h.insert(HeaderName::from_static("x-content-type-options"),   HeaderValue::from_static("nosniff"));
    h.insert(HeaderName::from_static("referrer-policy"),          HeaderValue::from_static("no-referrer"));
    h.insert(HeaderName::from_static("permissions-policy"),       HeaderValue::from_static("camera=(), microphone=(), geolocation=()"));
    h.insert(HeaderName::from_static("content-security-policy"),  HeaderValue::from_static(
        "default-src 'self'; script-src 'self' 'unsafe-inline'; \
         style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
         font-src https://fonts.gstatic.com; img-src 'self' data: https:; \
         connect-src 'self' wss: ws: https://noembed.com https://returnyoutubedislikeapi.com; \
         frame-src https://www.youtube.com https://www.youtube-nocookie.com; frame-ancestors 'none';"
    ));
    response
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let data_dir   = std::env::var("CRYPTIRC_DATA").unwrap_or_else(|_| "./data".into());
    let upload_dir = format!("{}/uploads", data_dir);
    let base_url    = std::env::var("CRYPTIRC_BASE_URL").unwrap_or_else(|_| "http://localhost:9000".into());
    let from_email  = std::env::var("CRYPTIRC_FROM_EMAIL").unwrap_or_else(|_| "noreply@cryptirc.local".into());
    // Load admin settings from disk (persisted), fall back to env vars
    let admin_settings_path = std::path::PathBuf::from(&data_dir).join("admin_settings.json");
    let (registration_open, reg_code) = if admin_settings_path.exists() {
        let json = std::fs::read_to_string(&admin_settings_path).unwrap_or_default();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
        let open = v.get("registration_open").and_then(|v| v.as_bool()).unwrap_or(true);
        let code = v.get("registration_code").and_then(|v| v.as_str()).unwrap_or("").to_string();
        info!("Loaded admin settings from disk (registration_open={}, has_code={})", open, !code.is_empty());
        (open, code)
    } else {
        let open = std::env::var("CRYPTIRC_REGISTRATION").unwrap_or_else(|_| "open".into()) != "closed";
        let code = std::env::var("CRYPTIRC_REG_CODE").unwrap_or_default();
        (open, code)
    };
    std::fs::create_dir_all(&data_dir)?;
    std::fs::create_dir_all(&upload_dir)?;
    std::fs::create_dir_all(format!("{}/certs", data_dir))?;

    let crypto   = Arc::new(CryptoManager::new(&data_dir)?);
    // Migrate legacy shared vault to per-user vaults if needed
    crypto.migrate_legacy_vault().await?;
    std::fs::create_dir_all(format!("{}/vaults", data_dir))?;
    let certs    = Arc::new(CertStore::new(&data_dir, crypto.clone()));
    let logger   = Arc::new(EncryptedLogger::new(&data_dir, crypto.clone()));
    let auth     = Arc::new(AuthManager::new(&data_dir)?);
    let vapid    = notifications::load_or_generate_vapid(&data_dir)?;
    let notifier = Arc::new(NotificationManager::new(&data_dir, vapid));
    let e2e_store = Arc::new(E2EStore::new(&data_dir));
    let paste_store = Arc::new(paste::PasteStore::new(&data_dir));
    let preview_service = Arc::new(preview::PreviewService::new(&data_dir));

    let state = AppState {
        connections:         Arc::new(DashMap::new()),
        conn_owners:         Arc::new(DashMap::new()),
        disconnect_requests: Arc::new(DashSet::new()),
        crypto, certs, logger, auth, notifier, e2e_store, paste_store, preview_service,
        user_events:         Arc::new(DashMap::new()),
        active_sessions:     Arc::new(DashMap::new()),
        upload_dir, base_url, from_email,
        data_dir: data_dir.clone(),
        registration_open: Arc::new(tokio::sync::RwLock::new(registration_open)),
        registration_code: Arc::new(tokio::sync::RwLock::new(reg_code)),
        admin_settings_lock: Arc::new(tokio::sync::Mutex::new(())),
    };

    // Background: purge expired sessions and stale user events hourly
    { let a = state.auth.clone(); let s = state.clone();
      tokio::spawn(async move {
          let mut iv = tokio::time::interval(tokio::time::Duration::from_secs(3600));
          loop { iv.tick().await; a.purge_expired_sessions(); s.prune_user_events(); s.paste_store.cleanup_expired().await; }
      });
    }

    let base_path = std::env::var("CRYPTIRC_BASE_PATH").unwrap_or_else(|_| "/cryptirc".into());
    let inner = Router::new()
        .route("/",                      get(serve_index))
        .route("/Sortable.min.js",       get(serve_sortable_js))
        .route("/e2e.js",                get(serve_e2e_js))
        .route("/manifest.json",         get(serve_manifest))
        .route("/sw.js",                 get(serve_sw))
        .route("/icon.svg",              get(serve_icon))
        .route("/icon-192.png",          get(serve_icon_192))
        .route("/icon-512.png",          get(serve_icon_512))
        .route("/auth/register",         post(route_register).layer(DefaultBodyLimit::max(8_192)))
        .route("/auth/status",           get(route_auth_status))
        .route("/admin/users",           get(route_admin_users))
        .route("/admin/user/:username",  axum::routing::delete(route_admin_delete_user))
        .route("/admin/user/:username/disable", post(route_admin_disable_user))
        .route("/admin/user/:username/upload-permission", post(route_admin_toggle_upload))
        .route("/admin/settings",        get(route_admin_get_settings).put(route_admin_put_settings))
        .route("/admin/adduser",         post(route_admin_add_user).layer(DefaultBodyLimit::max(4_096)))
        .route("/auth/login",            post(route_login).layer(DefaultBodyLimit::max(8_192)))
        .route("/auth/logout",           post(route_logout))
        .route("/auth/verify",           get(route_verify))
        .route("/auth/forgot",           post(route_forgot).layer(DefaultBodyLimit::max(8_192)))
        .route("/auth/reset",            get(route_reset_page))
        .route("/auth/reset",            post(route_reset_password).layer(DefaultBodyLimit::max(8_192)))
        .route("/auth/me",               get(route_me))
        .route("/auth/change-password",  post(route_change_password).layer(DefaultBodyLimit::max(8_192)))
        .route("/upload",                post(route_upload).layer(DefaultBodyLimit::max(26_214_400)))
        .route("/uploads",               get(route_uploads_list))
        .route("/uploads/delete",        post(route_uploads_delete).layer(DefaultBodyLimit::max(4_096)))
        .route("/uploads/clear",         post(route_uploads_clear))
        .route("/auth/sessions",         get(route_sessions_list))
        .route("/auth/sessions/revoke",  post(route_sessions_revoke).layer(DefaultBodyLimit::max(4_096)))
        .route("/files/:name",           get(serve_file))
        .route("/pub/:name",            get(serve_file_public))
        .route("/paste",                post(route_paste_create).layer(DefaultBodyLimit::max(524_288)))
        .route("/paste/:id",            get(route_paste_view))
        .route("/paste/:id/raw",        get(route_paste_raw))
        .route("/s",                    post(route_short_create).layer(DefaultBodyLimit::max(4_096)))
        .route("/s/:id",                get(route_short_redirect))
        .route("/preview",              get(route_link_preview))
        .route("/admin/link-preview",   get(route_admin_get_preview_settings).put(route_admin_put_preview_settings))
        .route("/push/vapid-public-key", get(route_push_vapid_key))
        .route("/push/subscribe",        post(route_push_subscribe).layer(DefaultBodyLimit::max(4_096)))
        .route("/push/subscribe",        axum::routing::delete(route_push_unsubscribe).layer(DefaultBodyLimit::max(2_048)))
        .route("/push/settings",         get(route_push_get_settings))
        .route("/push/settings",         axum::routing::put(route_push_put_settings).layer(DefaultBodyLimit::max(4_096)))
        .route("/push/test",             post(route_push_test))
        // E2E public key bundle (unauthenticated — public keys are public)
        .route("/e2e/bundle/:username",  get(route_e2e_get_bundle))
        .route("/ws",                    get(ws_handler));

    let app = Router::new()
        .nest(&base_path, inner)
        .route(&format!("{}/", base_path), get(serve_index))
        .layer(middleware::from_fn(security_headers_mw))
        .with_state(state);

    let port: u16 = std::env::var("CRYPTIRC_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(9001);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    info!("CryptIRC v0.3 listening on http://{}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

// ─── Static assets ────────────────────────────────────────────────────────────

async fn serve_index()    -> Html<&'static str> { Html(include_str!("../static/index.html")) }
async fn serve_manifest() -> impl IntoResponse { ([(header::CONTENT_TYPE,"application/manifest+json")], include_str!("../static/manifest.json")) }
async fn serve_sw()       -> impl IntoResponse { ([(header::CONTENT_TYPE,"application/javascript; charset=utf-8")], include_str!("../static/sw.js")) }
async fn serve_icon()     -> impl IntoResponse { ([(header::CONTENT_TYPE,"image/svg+xml")], include_str!("../static/icon.svg")) }
async fn serve_icon_192() -> impl IntoResponse { ([(header::CONTENT_TYPE,"image/png")], include_bytes!("../static/icon-192.png").as_slice()) }
async fn serve_icon_512() -> impl IntoResponse { ([(header::CONTENT_TYPE,"image/png")], include_bytes!("../static/icon-512.png").as_slice()) }
async fn serve_e2e_js()   -> impl IntoResponse { ([(header::CONTENT_TYPE,"application/javascript; charset=utf-8")], include_str!("../static/e2e.js")) }
async fn serve_sortable_js() -> impl IntoResponse { ([(header::CONTENT_TYPE,"application/javascript; charset=utf-8")], include_str!("../static/Sortable.min.js")) }

async fn serve_file_public(Path(name): Path<String>, State(state): State<AppState>) -> impl IntoResponse {
    let name: String = name.chars().filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.').collect();
    if name.contains("..") || name.starts_with('.') { return StatusCode::BAD_REQUEST.into_response(); }
    let path = std::path::PathBuf::from(&state.upload_dir).join(&name);
    match tokio::fs::read(&path).await {
        Ok(data) => Response::builder()
            .header(header::CONTENT_TYPE, upload::content_type_for(&name))
            .header(header::CACHE_CONTROL, "public, max-age=86400")
            .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
            .header(HeaderName::from_static("content-disposition"),
                     if upload::is_image(&name) { "inline" } else { "attachment" })
            .body(Body::from(data))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn serve_file(Path(name): Path<String>, Query(q): Query<FileQuery>, headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    // Accept token from query param, cookie, or Authorization header
    let token = q.token.clone()
        .or_else(|| headers.get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(';').find_map(|c| {
                let c = c.trim();
                c.strip_prefix("cryptirc_token=").map(|t| t.to_string())
            })))
        .or_else(|| bearer_token(&headers).map(|s| s.to_string()))
        .unwrap_or_default();
    if state.auth.validate_session(&token).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let name: String = name.chars().filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.').collect();
    if name.contains("..") || name.starts_with('.') { return StatusCode::BAD_REQUEST.into_response(); }
    let path = std::path::PathBuf::from(&state.upload_dir).join(&name);
    match tokio::fs::read(&path).await {
        Ok(data) => Response::builder()
            .header(header::CONTENT_TYPE, upload::content_type_for(&name))
            .header(header::CACHE_CONTROL, "private, max-age=86400")
            .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
            .header(HeaderName::from_static("content-disposition"),
                     if upload::is_image(&name) { "inline" } else { "attachment" })
            .body(Body::from(data))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

// ─── Auth routes ──────────────────────────────────────────────────────────────

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers.get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .and_then(validate_uuid)
}

async fn route_auth_status(State(state): State<AppState>) -> impl IntoResponse {
    let open = *state.registration_open.read().await;
    let has_code = !state.registration_code.read().await.is_empty();
    Json(serde_json::json!({ "registration_open": open, "requires_code": has_code }))
}

// ── Admin endpoints ──────────────────────────────────────────────────────────

fn extract_session_user(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let token = bearer_token(headers)?;
    state.auth.validate_session(&token)
}

async fn route_admin_users(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let Some(user) = extract_session_user(&state, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !state.auth.is_admin(&user).await {
        return StatusCode::FORBIDDEN.into_response();
    }
    Json(state.auth.list_users().await).into_response()
}

async fn route_admin_delete_user(State(state): State<AppState>, headers: HeaderMap, Path(target): Path<String>) -> impl IntoResponse {
    let Some(user) = extract_session_user(&state, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !state.auth.is_admin(&user).await {
        return StatusCode::FORBIDDEN.into_response();
    }
    if target.to_lowercase() == user.to_lowercase() {
        return (StatusCode::BAD_REQUEST, Json(Msg { message: "Cannot delete yourself.".into() })).into_response();
    }
    state.auth.delete_account(&target).await;
    (StatusCode::OK, Json(Msg { message: format!("User '{}' deleted.", target) })).into_response()
}

async fn route_admin_disable_user(State(state): State<AppState>, headers: HeaderMap, Path(target): Path<String>) -> impl IntoResponse {
    let Some(user) = extract_session_user(&state, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !state.auth.is_admin(&user).await {
        return StatusCode::FORBIDDEN.into_response();
    }
    if target.to_lowercase() == user.to_lowercase() {
        return (StatusCode::BAD_REQUEST, Json(Msg { message: "Cannot disable yourself.".into() })).into_response();
    }
    match state.auth.disable_user(&target).await {
        Ok(_) => (StatusCode::OK, Json(Msg { message: format!("User '{}' disabled.", target) })).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(Msg { message: e.to_string() })).into_response(),
    }
}

#[derive(Deserialize)]
struct ToggleUpload { allow: bool }

async fn route_admin_toggle_upload(State(state): State<AppState>, headers: HeaderMap, Path(target): Path<String>, Json(body): Json<ToggleUpload>) -> impl IntoResponse {
    let Some(user) = extract_session_user(&state, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !state.auth.is_admin(&user).await {
        return StatusCode::FORBIDDEN.into_response();
    }
    match state.auth.set_can_upload(&target, body.allow).await {
        Ok(_) => (StatusCode::OK, Json(Msg { message: format!("Upload permission for '{}' set to {}.", target, body.allow) })).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(Msg { message: e.to_string() })).into_response(),
    }
}

async fn route_admin_get_settings(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let Some(user) = extract_session_user(&state, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !state.auth.is_admin(&user).await {
        return StatusCode::FORBIDDEN.into_response();
    }
    let open = *state.registration_open.read().await;
    let code = state.registration_code.read().await.clone();
    Json(serde_json::json!({
        "registration_open": open,
        "registration_code": code,
    })).into_response()
}

#[derive(Deserialize)]
struct AdminSettings { registration_open: Option<bool>, registration_code: Option<String> }

#[derive(Deserialize)]
struct AdminAddUser { username: String, password: String, #[serde(default)] email: String }

async fn route_admin_add_user(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<AdminAddUser>) -> impl IntoResponse {
    let Some(user) = extract_session_user(&state, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !state.auth.is_admin(&user).await {
        return StatusCode::FORBIDDEN.into_response();
    }
    let email = if body.email.is_empty() { format!("{}@localhost", body.username) } else { body.email };
    match state.auth.register(&body.username, &email, &body.password).await {
        Ok(_token) => {
            // Auto-verify (admin-created users don't need email verification)
            let path = std::path::PathBuf::from(&state.data_dir)
                .join("users").join(format!("{}.json", body.username.to_lowercase()));
            if let Ok(json) = tokio::fs::read_to_string(&path).await {
                if let Ok(mut u) = serde_json::from_str::<auth::User>(&json) {
                    u.verified = true;
                    let _ = tokio::fs::write(&path, serde_json::to_string_pretty(&u).unwrap_or_default()).await;
                }
            }
            (StatusCode::OK, Json(Msg { message: format!("User '{}' created.", body.username) })).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(Msg { message: e.to_string() })).into_response(),
    }
}

async fn route_admin_put_settings(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<AdminSettings>) -> impl IntoResponse {
    let Some(user) = extract_session_user(&state, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !state.auth.is_admin(&user).await {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Some(open) = body.registration_open {
        *state.registration_open.write().await = open;
    }
    if let Some(code) = body.registration_code {
        *state.registration_code.write().await = code;
    }
    // Persist admin settings to disk under lock to prevent concurrent read-modify-write races
    let _guard = state.admin_settings_lock.lock().await;
    let path = std::path::PathBuf::from(&state.data_dir).join("admin_settings.json");
    let mut existing: serde_json::Value = if let Ok(json) = tokio::fs::read_to_string(&path).await {
        serde_json::from_str(&json).unwrap_or_default()
    } else { serde_json::json!({}) };
    existing["registration_open"] = serde_json::json!(*state.registration_open.read().await);
    existing["registration_code"] = serde_json::json!(*state.registration_code.read().await);
    let _ = tokio::fs::write(&path, serde_json::to_string_pretty(&existing).unwrap_or_default()).await;
    drop(_guard);
    (StatusCode::OK, Json(Msg { message: "Settings updated.".into() })).into_response()
}

async fn route_register(State(state): State<AppState>, Json(body): Json<RegisterBody>) -> impl IntoResponse {
    if !*state.registration_open.read().await {
        return (StatusCode::FORBIDDEN, Json(Msg { message: "Registration is closed. Contact the server admin.".into() })).into_response();
    }
    let req_code = state.registration_code.read().await.clone();
    if !req_code.is_empty() {
        // Timing-safe comparison with no length oracle — always compare max(len) bytes
        let a = req_code.as_bytes();
        let b = body.code.as_bytes();
        let max_len = a.len().max(b.len()).max(1);
        let mut mismatch = (a.len() != b.len()) as u8;
        for i in 0..max_len {
            let x = if i < a.len() { a[i] } else { 0xFF };
            let y = if i < b.len() { b[i] } else { 0x00 };
            mismatch |= x ^ y;
        }
        if mismatch != 0 {
            return (StatusCode::FORBIDDEN, Json(Msg { message: "Invalid registration code.".into() })).into_response();
        }
    }
    match state.auth.register(&body.username, &body.email, &body.password).await {
        Ok(token) => {
            let (email, uname, base, from) = (body.email.clone(), body.username.to_lowercase(), state.base_url.clone(), state.from_email.clone());
            tokio::spawn(async move {
                if let Err(e) = email::send_verification(&email, &uname, &token, &base, &from) { error!("Email: {}", e); }
            });
            (StatusCode::OK, Json(Msg { message: "Registered! Check your email.".into() })).into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            let safe = if ["Username","Password","Email","taken","already","attempts","Invalid"].iter().any(|w| msg.contains(w)) { msg } else { "Registration failed".into() };
            (StatusCode::BAD_REQUEST, Json(Msg { message: safe })).into_response()
        }
    }
}

async fn route_login(State(state): State<AppState>, Json(body): Json<LoginBody>) -> impl IntoResponse {
    match state.auth.login(&body.username, &body.password).await {
        Ok(token) => (StatusCode::OK, Json(AuthOkBody { token, username: body.username.to_lowercase() })).into_response(),
        Err(e) => {
            let msg = e.to_string();
            let safe = if ["Invalid","verified","attempts"].iter().any(|w| msg.contains(w)) { msg } else { "Login failed".into() };
            (StatusCode::UNAUTHORIZED, Json(Msg { message: safe })).into_response()
        }
    }
}

async fn route_logout(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(t) = bearer_token(&headers) { state.auth.logout(&t); }
    (StatusCode::OK, Json(Msg { message: "Logged out".into() }))
}

async fn route_sessions_list(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let user = match bearer_token(&headers).and_then(|t| state.auth.validate_session(&t)) {
        Some(u) => u, None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"}))).into_response(),
    };
    let current_token = bearer_token(&headers).unwrap_or_default();
    let current_prefix = if current_token.len() >= 8 { format!("{}…{}", &current_token[..4], &current_token[current_token.len()-4..]) } else { String::new() };
    let sessions: Vec<_> = state.auth.list_sessions(&user).iter().map(|(prefix, created, last_used)| {
        serde_json::json!({"prefix": prefix, "created_at": created, "last_used": last_used, "current": *prefix == current_prefix})
    }).collect();
    Json(serde_json::json!({"sessions": sessions})).into_response()
}

async fn route_sessions_revoke(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> impl IntoResponse {
    let user = match bearer_token(&headers).and_then(|t| state.auth.validate_session(&t)) {
        Some(u) => u, None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"}))).into_response(),
    };
    let prefix = body.get("prefix").and_then(|v| v.as_str()).unwrap_or("");
    if prefix.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"Missing prefix"}))).into_response();
    }
    state.auth.revoke_session_by_prefix(&user, prefix);
    Json(serde_json::json!({"ok": true})).into_response()
}

async fn route_verify(State(state): State<AppState>, Query(q): Query<VerifyQuery>) -> impl IntoResponse {
    match state.auth.verify_email(&q.token).await {
        Ok(_) => Html(r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Verified</title>
<style>body{background:#0b0d0f;color:#c8d8e8;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}
.b{background:#111418;border:1px solid #2a3444;border-radius:12px;padding:32px 40px;text-align:center;}
h2{background:linear-gradient(135deg,#00d4aa,#0099ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
a{color:#00d4aa;text-decoration:none;}</style></head>
<body><div class="b"><h2>✓ Email Verified</h2><p>Your account is now active.</p><br><a href="/cryptirc">Open CryptIRC →</a></div></body></html>"#.to_string()),
        Err(e) => Html(format!(r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Error</title>
<style>body{{background:#0b0d0f;color:#ff4466;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}}
a{{color:#00d4aa;}}</style></head><body><p>{}</p><a href="/cryptirc">← Back</a></body></html>"#, html_escape(&e.to_string()))),
    }
}

async fn route_forgot(State(state): State<AppState>, Json(body): Json<ForgotBody>) -> impl IntoResponse {
    let (email_addr, base, from) = (body.email.clone(), state.base_url.clone(), state.from_email.clone());
    match state.auth.request_password_reset(&body.email).await {
        Ok(Some((token, username))) => {
            tokio::spawn(async move {
                if let Err(e) = email::send_password_reset(&email_addr, &username, &token, &base, &from) { error!("Reset email: {}", e); }
            });
        }
        _ => {} // Don't reveal whether the email exists
    }
    // Always return success to prevent email enumeration
    (StatusCode::OK, Json(Msg { message: "If that email is registered, a reset link has been sent.".into() }))
}

async fn route_reset_page(Query(q): Query<ResetQuery>) -> impl IntoResponse {
    Html(format!(r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Reset Password — CryptIRC</title>
<style>
body{{background:#0b0d0f;color:#c8d8e8;font-family:'JetBrains Mono',monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}}
.b{{background:#111418;border:1px solid #2a3444;border-radius:14px;padding:32px 36px;width:100%;max-width:380px;box-shadow:0 24px 64px rgba(0,0,0,.7);}}
h2{{background:linear-gradient(135deg,#00d4aa,#0099ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;text-align:center;margin:0 0 8px;font-size:20px;}}
.sub{{color:#6a7a8a;font-size:11px;text-align:center;margin-bottom:20px;}}
label{{color:#8899aa;font-size:11px;display:block;margin-bottom:4px;}}
input{{width:100%;padding:10px 12px;background:#0b0d0f;border:1px solid #2a3444;border-radius:8px;color:#c8d8e8;font-family:inherit;font-size:13px;margin-bottom:12px;box-sizing:border-box;}}
input:focus{{outline:none;border-color:#00d4aa;}}
button{{width:100%;padding:12px;background:linear-gradient(135deg,#00d4aa,#0099ff);border:none;border-radius:8px;color:#0b0d0f;font-weight:700;font-size:14px;cursor:pointer;font-family:inherit;}}
button:hover{{opacity:.9;}}
button:disabled{{opacity:.5;cursor:default;}}
.err{{color:#ff4466;font-size:12px;text-align:center;margin-bottom:8px;min-height:16px;}}
.ok{{color:#44cc88;font-size:12px;text-align:center;line-height:1.7;}}
a{{color:#00d4aa;text-decoration:none;}}
</style></head><body><div class="b">
<h2>Reset Password</h2>
<div class="sub">Enter your new password</div>
<div id="reset-form">
  <label>New Password</label>
  <input type="password" id="rp-pass" placeholder="Min. 10 characters" autocomplete="new-password">
  <label>Confirm Password</label>
  <input type="password" id="rp-pass2" placeholder="Repeat password" autocomplete="new-password">
  <div class="err" id="rp-err"></div>
  <button id="rp-btn" onclick="doReset()">Set New Password</button>
</div>
<div id="reset-ok" style="display:none" class="ok">
  ✓ Password reset!<br>You can now <a href="/cryptirc">sign in</a> with your new password.
</div>
<script>
const TOKEN="{}";
async function doReset(){{
  const pass=document.getElementById('rp-pass').value;
  const pass2=document.getElementById('rp-pass2').value;
  const err=document.getElementById('rp-err');
  err.textContent='';
  if(!pass||!pass2){{err.textContent='Fill in both fields';return;}}
  if(pass!==pass2){{err.textContent='Passwords do not match';return;}}
  if(pass.length<10){{err.textContent='Password must be at least 10 characters';return;}}
  const btn=document.getElementById('rp-btn');
  btn.disabled=true;btn.textContent='Resetting…';
  try{{
    const r=await fetch('/cryptirc/auth/reset',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{token:TOKEN,password:pass}})}});
    const d=await r.json();
    if(!r.ok){{err.textContent=d.message||'Reset failed';return;}}
    document.getElementById('reset-form').style.display='none';
    document.getElementById('reset-ok').style.display='';
  }}catch(e){{err.textContent='Network error';}}
  finally{{btn.disabled=false;btn.textContent='Set New Password';}}
}}
document.querySelectorAll('input').forEach(i=>i.addEventListener('keydown',e=>{{if(e.key==='Enter')doReset();}}));
</script>
</div></body></html>"#, js_escape(&q.token)))
}

async fn route_reset_password(State(state): State<AppState>, Json(body): Json<ResetPasswordBody>) -> impl IntoResponse {
    match state.auth.reset_password(&body.token, &body.password).await {
        Ok(username) => {
            info!("Password reset for user: {}", username);
            (StatusCode::OK, Json(Msg { message: "Password reset successfully.".into() })).into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            let safe = if ["Invalid","expired","Password","10 characters"].iter().any(|w| msg.contains(w)) { msg } else { "Reset failed".into() };
            (StatusCode::BAD_REQUEST, Json(Msg { message: safe })).into_response()
        }
    }
}

async fn route_me(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    match bearer_token(&headers).and_then(|t| state.auth.validate_session(&t)) {
        Some(u) => (StatusCode::OK, Json(MeOk { username: u })).into_response(),
        None    => (StatusCode::UNAUTHORIZED, Json(Msg { message: "Not authenticated".into() })).into_response(),
    }
}

#[derive(Deserialize)]
struct ChangePasswordBody { old_password: String, new_password: String }

async fn route_change_password(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<ChangePasswordBody>) -> impl IntoResponse {
    let user = match bearer_token(&headers).and_then(|t| state.auth.validate_session(&t)) {
        Some(u) => u,
        None => return (StatusCode::UNAUTHORIZED, Json(Msg { message: "Not authenticated".into() })).into_response(),
    };
    match state.auth.change_password(&user, &body.old_password, &body.new_password).await {
        Ok(_) => (StatusCode::OK, Json(Msg { message: "Password changed successfully.".into() })).into_response(),
        Err(e) => {
            let msg = e.to_string();
            let safe = if ["incorrect","10 characters","uppercase","lowercase","number","special"].iter().any(|w| msg.contains(w)) { msg } else { "Password change failed".into() };
            (StatusCode::BAD_REQUEST, Json(Msg { message: safe })).into_response()
        }
    }
}

async fn route_upload(State(state): State<AppState>, headers: HeaderMap, multipart: Multipart) -> impl IntoResponse {
    match bearer_token(&headers).and_then(|t| state.auth.validate_session(&t)) {
        None    => (StatusCode::UNAUTHORIZED, Json(Msg { message: "Not authenticated".into() })).into_response(),
        Some(user) => {
            if !state.auth.can_upload(&user).await {
                return (StatusCode::FORBIDDEN, Json(Msg { message: "Upload permission not granted. Contact an admin.".into() })).into_response();
            }
            match upload::handle_upload(&state.upload_dir, multipart).await {
                Ok(r)  => {
                    // Track upload for the user
                    let _ = upload::record_upload(&state.data_dir, &user, &r).await;
                    (StatusCode::OK, Json(r)).into_response()
                }
                Err(e) => (StatusCode::BAD_REQUEST, Json(Msg { message: e.to_string() })).into_response(),
            }
        }
    }
}

async fn route_uploads_list(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let user = match bearer_token(&headers).and_then(|t| state.auth.validate_session(&t)) {
        Some(u) => u, None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"}))).into_response(),
    };
    let files = upload::list_user_uploads(&state.data_dir, &user).await;
    Json(serde_json::json!({"files": files})).into_response()
}

async fn route_uploads_delete(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> impl IntoResponse {
    let user = match bearer_token(&headers).and_then(|t| state.auth.validate_session(&t)) {
        Some(u) => u, None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"}))).into_response(),
    };
    let filename = body.get("filename").and_then(|v| v.as_str()).unwrap_or("");
    if filename.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"Missing filename"}))).into_response();
    }
    upload::delete_user_upload(&state.data_dir, &state.upload_dir, &user, filename).await;
    Json(serde_json::json!({"ok": true})).into_response()
}

async fn route_uploads_clear(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let user = match bearer_token(&headers).and_then(|t| state.auth.validate_session(&t)) {
        Some(u) => u, None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"}))).into_response(),
    };
    upload::clear_user_uploads(&state.data_dir, &state.upload_dir, &user).await;
    Json(serde_json::json!({"ok": true})).into_response()
}

async fn route_e2e_get_bundle(
    Path(target_user): Path<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // S1: authenticated callers only — prevents anonymous OTPK exhaustion DoS
    if bearer_token(&headers).and_then(|t| state.auth.validate_session(&t)).is_none() {
        return (StatusCode::UNAUTHORIZED, Json(Msg { message: "Not authenticated".into() })).into_response();
    }
    let safe: String = target_user.chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .take(64).collect();
    match state.e2e_store.fetch_bundle(&safe).await {
        Some(bundle) => (StatusCode::OK, Json(bundle)).into_response(),
        None         => (StatusCode::NOT_FOUND, Json(Msg { message: "No key bundle for this user".into() })).into_response(),
    }
}

// ─── Paste routes ────────────────────────────────────────────────────────────

async fn route_paste_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<paste::CreatePasteRequest>,
) -> impl IntoResponse {
    let token = headers.get("authorization").and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ")).unwrap_or("");
    let user = match state.auth.validate_session(token) {
        Some(u) => u, None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"}))).into_response(),
    };
    match state.paste_store.create(&body, &user).await {
        Ok(paste) => {
            let url = format!("{}/paste/{}", state.base_url, paste.id);
            Json(serde_json::json!({
                "id": paste.id,
                "url": url,
                "has_password": paste.password_hash.is_some(),
                "expires_at": paste.expires_at,
            })).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

async fn route_paste_view(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    match state.paste_store.get(&id).await {
        Ok(Some(paste)) => {
            if paste.password_hash.is_some() {
                let pw = params.get("password").map(|s| s.as_str()).unwrap_or("");
                if !paste::PasteStore::verify_password(&paste, pw) {
                    return (StatusCode::FORBIDDEN, Html(format!(
                        "<!DOCTYPE html><html><head><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>CryptIRC Paste</title>\
                         <style>body{{background:#0b0d0f;color:#e0e0e0;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}\
                         .box{{background:#141620;padding:24px;border-radius:12px;border:1px solid #2a2e3e;max-width:300px;width:90%}}\
                         input{{width:100%;padding:8px;margin:8px 0;background:#1a1e2e;border:1px solid #2a2e3e;color:#e0e0e0;border-radius:6px;font-size:16px}}\
                         button{{width:100%;padding:8px;background:#00d4aa;color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:700}}</style></head>\
                         <body><div class=\"box\"><h3>🔒 Password Required</h3>\
                         <form method=\"get\"><input type=\"password\" name=\"password\" placeholder=\"Enter password\" autofocus>\
                         <button type=\"submit\">Unlock</button></form></div></body></html>"
                    ))).into_response();
                }
            }
            let escaped = html_escape(&paste.content);
            let lang = html_escape(&paste.language);
            let created = chrono::DateTime::from_timestamp(paste.created_at, 0)
                .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string()).unwrap_or_default();
            let expires = paste.expires_at.and_then(|t| chrono::DateTime::from_timestamp(t, 0))
                .map(|d| format!("Expires: {}", d.format("%Y-%m-%d %H:%M UTC"))).unwrap_or_else(|| "No expiration".into());
            Html(format!(
                "<!DOCTYPE html><html><head><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>CryptIRC Paste — {}</title>\
                 <style>body{{background:#0b0d0f;color:#e0e0e0;font-family:monospace;margin:0;padding:16px}}\
                 .hdr{{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid #2a2e3e;margin-bottom:12px;flex-wrap:wrap;gap:8px}}\
                 .meta{{font-size:12px;color:#888}}\
                 pre{{background:#141620;padding:16px;border-radius:8px;overflow-x:auto;border:1px solid #2a2e3e;white-space:pre-wrap;word-break:break-word;line-height:1.5}}\
                 a{{color:#00d4aa}}</style></head>\
                 <body><div class=\"hdr\"><span><a href=\"/cryptirc/\">CryptIRC</a> Paste</span>\
                 <span class=\"meta\">{} · {} · by {} · {} · <a href=\"/cryptirc/paste/{}/raw\">raw</a></span></div>\
                 <pre>{}</pre></body></html>",
                id, lang, created, html_escape(&paste.author), expires, id, escaped
            )).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, Html("Paste not found or expired.".to_string())).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Html("Error loading paste.".to_string())).into_response(),
    }
}

async fn route_paste_raw(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    match state.paste_store.get(&id).await {
        Ok(Some(paste)) => {
            if paste.password_hash.is_some() {
                let pw = params.get("password").map(|s| s.as_str()).unwrap_or("");
                if !paste::PasteStore::verify_password(&paste, pw) {
                    return (StatusCode::FORBIDDEN, "Password required").into_response();
                }
            }
            ([(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")], paste.content).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "Not found").into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response(),
    }
}

// ─── URL shortener routes ────────────────────────────────────────────────────

async fn route_short_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let token = headers.get("authorization").and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ")).unwrap_or("");
    let user = match state.auth.validate_session(token) {
        Some(u) => u, None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"}))).into_response(),
    };
    let url = body.get("url").and_then(|v| v.as_str()).unwrap_or("");
    if url.is_empty() || url.len() > 4096 || (!url.starts_with("http://") && !url.starts_with("https://")) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"Invalid URL"}))).into_response();
    }
    let id = Uuid::new_v4().to_string().replace('-', "")[..10].to_string(); // 10-char hex ID
    let dir = format!("{}/shorts", state.data_dir);
    let _ = tokio::fs::create_dir_all(&dir).await;
    let data = serde_json::json!({"url": url, "created_at": chrono::Utc::now().timestamp(), "creator": user});
    let _ = tokio::fs::write(format!("{}/{}.json", dir, id), serde_json::to_string(&data).unwrap_or_default()).await;
    let short_url = format!("{}/s/{}", state.base_url, id);
    Json(serde_json::json!({"id": id, "url": short_url, "original": url})).into_response()
}

async fn route_short_redirect(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let safe_id: String = id.chars().filter(|c| c.is_alphanumeric() || *c == '-').take(10).collect();
    let path = format!("{}/shorts/{}.json", state.data_dir, safe_id);
    match tokio::fs::read_to_string(&path).await {
        Ok(json) => {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&json) {
                if let Some(url) = data.get("url").and_then(|v| v.as_str()) {
                    let escaped = html_escape(url);
                    // Interstitial warning page instead of raw redirect to prevent open redirect abuse
                    return Html(format!(
                        "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
                         <title>CryptIRC — Redirect</title>\
                         <style>body{{background:#000004;color:#d0d0e8;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}\
                         .box{{background:#080814;border:1px solid #1a1a38;border-radius:12px;padding:28px 36px;max-width:500px;width:90%;text-align:center}}\
                         a{{color:#00d4aa;word-break:break-all}} .warn{{color:#ffaa00;font-size:12px;margin:12px 0}}\
                         .btn{{display:inline-block;background:#00d4aa;color:#000;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:700;margin-top:8px}}</style></head>\
                         <body><div class=\"box\"><h3>🔗 External Link</h3>\
                         <div class=\"warn\">You are about to leave CryptIRC and visit:</div>\
                         <div style=\"margin:12px 0;padding:10px;background:#04040c;border-radius:6px\"><a href=\"{0}\">{0}</a></div>\
                         <a class=\"btn\" href=\"{0}\">Continue →</a>\
                         <div style=\"margin-top:12px;font-size:11px;color:#4a4a78\">This link was shortened by a CryptIRC user.</div>\
                         </div></body></html>", escaped
                    )).into_response();
                }
            }
            (StatusCode::NOT_FOUND, Html("Not found".to_string())).into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, Html("Not found".to_string())).into_response(),
    }
}

// ─── Link preview routes ─────────────────────────────────────────────────────

async fn route_link_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    // Require auth
    let token = headers.get("authorization").and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ")).unwrap_or("");
    if state.auth.validate_session(token).is_none() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"}))).into_response();
    }
    let url = match params.get("url") {
        Some(u) => u.clone(),
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"Missing url parameter"}))).into_response(),
    };
    match state.preview_service.fetch_preview(&url).await {
        Ok(preview) => Json(serde_json::json!(preview)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

async fn route_admin_get_preview_settings(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let Some(user) = extract_session_user(&state, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !state.auth.is_admin(&user).await {
        return StatusCode::FORBIDDEN.into_response();
    }
    let settings = state.preview_service.load_settings().await;
    Json(serde_json::json!(settings)).into_response()
}

async fn route_admin_put_preview_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<preview::PreviewSettings>,
) -> impl IntoResponse {
    let Some(user) = extract_session_user(&state, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !state.auth.is_admin(&user).await {
        return StatusCode::FORBIDDEN.into_response();
    }
    // Load existing admin settings and merge preview settings — under lock
    let _guard = state.admin_settings_lock.lock().await;
    let path = std::path::PathBuf::from(&state.data_dir).join("admin_settings.json");
    let mut existing: serde_json::Value = if let Ok(json) = tokio::fs::read_to_string(&path).await {
        serde_json::from_str(&json).unwrap_or_default()
    } else { serde_json::json!({}) };
    existing["link_preview_mode"] = serde_json::json!(body.mode);
    existing["link_preview_whitelist"] = serde_json::json!(body.whitelist);
    let _ = tokio::fs::write(&path, serde_json::to_string_pretty(&existing).unwrap_or_default()).await;
    drop(_guard);
    Json(serde_json::json!({"message":"Settings saved"})).into_response()
}

// ─── Push notification routes ─────────────────────────────────────────────────

async fn route_push_vapid_key(State(state): State<AppState>) -> impl IntoResponse {
    Json(serde_json::json!({ "publicKey": state.notifier.vapid_public_key() }))
}

async fn route_push_subscribe(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<PushSubscription>) -> impl IntoResponse {
    match bearer_token(&headers).and_then(|t| state.auth.validate_session(&t)) {
        None => (StatusCode::UNAUTHORIZED, Json(Msg { message: "Not authenticated".into() })).into_response(),
        Some(user) => match state.notifier.save_subscription(&user, body).await {
            Ok(_)  => (StatusCode::OK, Json(Msg { message: "Subscribed".into() })).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(Msg { message: e.to_string() })).into_response(),
        }
    }
}

async fn route_push_unsubscribe(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> impl IntoResponse {
    match bearer_token(&headers).and_then(|t| state.auth.validate_session(&t)) {
        None => (StatusCode::UNAUTHORIZED, Json(Msg { message: "Not authenticated".into() })).into_response(),
        Some(user) => {
            let endpoint = body.get("endpoint").and_then(|v| v.as_str()).unwrap_or("");
            match state.notifier.remove_subscription(&user, endpoint).await {
                Ok(_)  => (StatusCode::OK, Json(Msg { message: "Unsubscribed".into() })).into_response(),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(Msg { message: e.to_string() })).into_response(),
            }
        }
    }
}

async fn route_push_get_settings(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    match bearer_token(&headers).and_then(|t| state.auth.validate_session(&t)) {
        None => (StatusCode::UNAUTHORIZED, Json(Msg { message: "Not authenticated".into() })).into_response(),
        Some(user) => {
            let prefs = state.notifier.load_prefs(&user).await;
            (StatusCode::OK, Json(prefs)).into_response()
        }
    }
}

async fn route_push_put_settings(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<NotifPrefs>) -> impl IntoResponse {
    match bearer_token(&headers).and_then(|t| state.auth.validate_session(&t)) {
        None => (StatusCode::UNAUTHORIZED, Json(Msg { message: "Not authenticated".into() })).into_response(),
        Some(user) => match state.notifier.save_prefs(&user, &body).await {
            Ok(_)  => (StatusCode::OK, Json(Msg { message: "Settings saved".into() })).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(Msg { message: e.to_string() })).into_response(),
        }
    }
}

async fn route_push_test(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    match bearer_token(&headers).and_then(|t| state.auth.validate_session(&t)) {
        None => (StatusCode::UNAUTHORIZED, Json(Msg { message: "Not authenticated".into() })).into_response(),
        Some(user) => {
            state.notifier.send_test_notification(&user).await;
            (StatusCode::OK, Json(Msg { message: "Test notification sent".into() })).into_response()
        }
    }
}

// ─── WebSocket ────────────────────────────────────────────────────────────────

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();

    // Demand auth as first message
    let _ = sender.send(Message::Text(serde_json::to_string(&ServerEvent::AuthRequired {}).unwrap())).await;

    let auth_msg = tokio::time::timeout(
        tokio::time::Duration::from_secs(10),
        receiver.next()
    ).await;

    let username = match auth_msg {
        Ok(Some(Ok(Message::Text(txt)))) => {
            match serde_json::from_str::<ClientMessage>(&txt) {
                Ok(ClientMessage::Auth { token }) => {
                    match state.auth.validate_session(&token) {
                        Some(u) => u,
                        None => {
                            let _ = sender.send(Message::Text(serde_json::to_string(&ServerEvent::AuthFailed { message: "Invalid session".into() }).unwrap())).await;
                            return;
                        }
                    }
                }
                _ => return,
            }
        }
        _ => return,
    };

    info!("WS authenticated: {}", username);
    let _ = sender.send(Message::Text(serde_json::to_string(&ServerEvent::AuthOk { username: username.clone() }).unwrap())).await;
    let vault_unlocked = state.crypto.is_unlocked(&username).await;
    let _ = sender.send(Message::Text(serde_json::to_string(&ServerEvent::State {
        networks: state.user_network_states(&username).await,
        vault_unlocked,
    }).unwrap())).await;
    // If vault is already unlocked, send the e2e key so the frontend can init E2E
    if vault_unlocked {
        if let Ok(k) = state.crypto.derive_e2e_enc_key(&username).await {
            let e2e_enc_key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, k);
            let _ = sender.send(Message::Text(serde_json::to_string(&ServerEvent::VaultUnlocked { e2e_enc_key }).unwrap())).await;
        }
    }

    // Track this session as active (non-idle) — increment BEFORE subscribing
    // so the IRC thread never sees receiver_count>0 with active_sessions==0
    let active_counter = state.active_counter(&username);
    active_counter.fetch_add(1, Ordering::Release);

    let mut event_rx = state.user_tx(&username).subscribe();
    let session_is_active = Arc::new(std::sync::atomic::AtomicBool::new(true));

    let mut send_task = tokio::spawn(async move {
        while let Ok(evt) = event_rx.recv().await {
            if sender.send(Message::Text(serde_json::to_string(&evt).unwrap())).await.is_err() { break; }
        }
    });

    let state2 = state.clone();
    let user2  = username.clone();
    let counter2 = active_counter.clone();
    let active2 = session_is_active.clone();
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            // S6: reject oversized messages before parsing
            if let Message::Text(ref text) = msg {
                if text.len() > WS_MAX_MSG_BYTES { continue; }
                match serde_json::from_str::<ClientMessage>(text) {
                    Ok(ClientMessage::Idle {}) => {
                        if active2.swap(false, Ordering::Release) {
                            counter2.fetch_sub(1, Ordering::Release);
                        }
                    }
                    Ok(ClientMessage::Active {}) => {
                        if !active2.swap(true, Ordering::Release) {
                            counter2.fetch_add(1, Ordering::Release);
                        }
                    }
                    Ok(cmd) => handle_command(cmd, &user2, &state2).await,
                    Err(e) => {
                        let preview = if text.len() > 100 { &text[..100] } else { text };
                        info!("[WS] parse error for {}: {} — msg: {}", user2, e, preview);
                    }
                }
            }
        }
    });

    tokio::select! {
        _ = &mut send_task => recv_task.abort(),
        _ = &mut recv_task => send_task.abort(),
    }

    // Session disconnecting — decrement active count if this session was still active
    if session_is_active.load(Ordering::Acquire) {
        active_counter.fetch_sub(1, Ordering::Release);
    }
}

// ─── Command handler ──────────────────────────────────────────────────────────

async fn handle_command(cmd: ClientMessage, username: &str, state: &AppState) {
    let send = |evt: ServerEvent| state.send_to_user(username, evt);

    match cmd {
        ClientMessage::Auth { .. } => {}
        // Idle/Active handled in handle_ws before reaching here
        ClientMessage::Idle {} | ClientMessage::Active {} => {}

        ClientMessage::UnlockVault { passphrase } => {
            match state.crypto.unlock(username, &passphrase).await {
                Ok(_)  => {
                    // Derive E2E sub-key and send to client
                    let e2e_enc_key = match state.crypto.derive_e2e_enc_key(username).await {
                        Ok(k)  => base64::Engine::encode(&base64::engine::general_purpose::STANDARD, k),
                        Err(_) => String::new(),
                    };
                    send(ServerEvent::VaultUnlocked { e2e_enc_key });
                    // Per-user vault: only connect THIS user's networks
                    state.reconnect_for_user(username).await;
                }
                Err(_) => send(ServerEvent::VaultError { message: "Incorrect passphrase".into() }),
            }
        }
        ClientMessage::LockVault {} => {
            info!("Vault locked for {}", username);
            state.crypto.lock(username).await;
            send(ServerEvent::VaultLocked {});
        }
        ClientMessage::ChangePassphrase { old, new } => {
            match state.crypto.change_passphrase(username, &old, &new).await {
                Ok(_)  => {
                    let e2e_enc_key = match state.crypto.derive_e2e_enc_key(username).await {
                        Ok(k)  => base64::Engine::encode(&base64::engine::general_purpose::STANDARD, k),
                        Err(_) => String::new(),
                    };
                    send(ServerEvent::VaultUnlocked { e2e_enc_key });
                }
                Err(e) => send(ServerEvent::VaultError { message: e.to_string() }),
            }
        }

        ClientMessage::AddNetwork { mut network } => {
            if network.id.is_empty() { network.id = Uuid::new_v4().to_string(); }
            if validate_uuid(&network.id).is_none() { network.id = Uuid::new_v4().to_string(); }
            if let Err(e) = state.save_network(&network, username).await {
                send(ServerEvent::Error { message: e.to_string() }); return;
            }
            // Auto-generate client cert if SASL EXTERNAL is enabled
            if network.sasl_external && state.crypto.is_unlocked(username).await {
                let has_cert = state.certs.load_info(&network.id).await.is_ok();
                if !has_cert {
                    let nick = network.nick.clone();
                    if let Ok(info) = state.certs.generate(username, &network.id, &nick).await {
                        let mut cfg = network.clone();
                        cfg.client_cert_id = Some(network.id.clone());
                        let _ = state.save_network(&cfg, username).await;
                        send(ServerEvent::CertInfo {
                            conn_id: network.id.clone(),
                            fingerprint: info.fingerprint,
                            cert_pem: info.cert_pem,
                        });
                    }
                }
            }
            send(ServerEvent::State {
                networks: state.user_network_states(username).await,
                vault_unlocked: state.crypto.is_unlocked(username).await,
            });
        }
        ClientMessage::UpdateNetwork { mut network } => {
            if !state.owns_network(username, &network.id).await { return; }
            // Preserve client_cert_id from existing config (UI doesn't send it)
            if let Some(existing) = state.get_network_config(&network.id, username).await {
                if network.client_cert_id.is_none() {
                    network.client_cert_id = existing.client_cert_id;
                }
            }
            if let Err(e) = state.save_network(&network, username).await {
                send(ServerEvent::Error { message: e.to_string() }); return;
            }
            // Auto-generate client cert if SASL EXTERNAL is enabled and no cert exists
            if network.sasl_external && state.crypto.is_unlocked(username).await {
                let has_cert = state.certs.load_info(&network.id).await.is_ok();
                if !has_cert {
                    let nick = network.nick.clone();
                    if let Ok(info) = state.certs.generate(username, &network.id, &nick).await {
                        let mut cfg = network.clone();
                        cfg.client_cert_id = Some(network.id.clone());
                        let _ = state.save_network(&cfg, username).await;
                        send(ServerEvent::CertInfo {
                            conn_id: network.id.clone(),
                            fingerprint: info.fingerprint,
                            cert_pem: info.cert_pem,
                        });
                    }
                }
            }
            send(ServerEvent::State {
                networks: state.user_network_states(username).await,
                vault_unlocked: state.crypto.is_unlocked(username).await,
            });
        }
        ClientMessage::RemoveNetwork { id } => {
            if !state.owns_network(username, &id).await { return; }
            state.request_disconnect(&id);
            if let Some(conn) = state.connections.get(&id) {
                let mut c = conn.lock().await;
                let _ = c.send_raw("QUIT :CryptIRC\r\n").await;
            }
            state.connections.remove(&id);
            state.conn_owners.remove(&id);
            state.remove_network(&id, username).await;
            send(ServerEvent::State {
                networks: state.user_network_states(username).await,
                vault_unlocked: state.crypto.is_unlocked(username).await,
            });
        }
        ClientMessage::Connect { id } => {
            if !state.owns_network(username, &id).await { return; }
            // Kill any existing connection first to prevent ghost sessions
            state.request_disconnect(&id);
            if let Some(conn) = state.connections.get(&id) {
                let mut c = conn.lock().await;
                let _ = c.send_raw("QUIT :CryptIRC\r\n").await;
            }
            state.connections.remove(&id);
            state.conn_owners.remove(&id);
            // Small delay to let the old reconnect loop see the disconnect flag
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            state.clear_disconnect_request(&id);
            if let Some(cfg) = state.get_network_config(&id, username).await {
                send(ServerEvent::Connecting { conn_id: id.clone(), server: cfg.server.clone() });
                let (s2, u2) = (state.clone(), username.to_string());
                tokio::spawn(async move {
                    if let Err(e) = irc::connect(id, cfg, u2, s2).await { error!("IRC: {}", e); }
                });
            }
        }
        ClientMessage::Disconnect { id } => {
            if !state.owns_network(username, &id).await { return; }
            state.request_disconnect(&id);
            if let Some(conn) = state.connections.get(&id) {
                let mut c = conn.lock().await;
                let _ = c.send_raw("QUIT :CryptIRC\r\n").await;
            }
            state.connections.remove(&id);
            state.conn_owners.remove(&id);
            send(ServerEvent::Disconnected { conn_id: id, reason: "User requested".into() });
        }
        ClientMessage::Send { conn_id, raw } => {
            if !state.owns_conn(username, &conn_id) { return; }
            if let Some(conn) = state.connections.get(&conn_id) {
                let safe = strip_crlf(&raw);
                if safe.is_empty() { return; }
                // Skip TAGMSG from logging (typing indicators etc)
                let is_tagmsg = safe.contains("TAGMSG");
                // Silently drop TAGMSG for connections that don't support message-tags
                if is_tagmsg {
                    let c = conn.lock().await;
                    if !c.message_tags { return; }
                    drop(c);
                }
                info!("[{}] SEND ({}B): {}", conn_id, safe.len(), &safe[..safe.len().min(80)]);
                let mut c = conn.lock().await;
                let nick = c.nick.clone();
                let _ = c.send_raw(&format!("{}\r\n", safe)).await;
                drop(c);
                // Broadcast PRIVMSG/NOTICE to all user sessions so other devices see them
                if !is_tagmsg {
                    let upper = safe.to_uppercase();
                    let is_privmsg = upper.starts_with("PRIVMSG ");
                    let is_notice_out = upper.starts_with("NOTICE ");
                    let is_action = safe.contains("\x01ACTION ");
                    if is_privmsg || is_notice_out {
                        let parts: Vec<&str> = safe.splitn(3, ' ').collect();
                        if parts.len() >= 3 {
                            let target = parts[1].to_string();
                            let mut text = parts[2].to_string();
                            if text.starts_with(':') { text = text[1..].to_string(); }
                            let ts = chrono::Utc::now().timestamp();
                            let (kind, clean) = if is_action && text.starts_with("\x01ACTION ") && text.ends_with('\x01') {
                                (MessageKind::Action, text[8..text.len()-1].to_string())
                            } else if is_notice_out {
                                (MessageKind::Notice, text)
                            } else {
                                (MessageKind::Privmsg, text)
                            };
                            let display_target = if target.starts_with('#') || target.starts_with('&') {
                                target.clone()
                            } else {
                                target.clone()  // PM: target is the recipient nick
                            };
                            // Log our own sent messages so they appear in history
                            let msg_id = state.logger.append(username, &conn_id, &display_target, ts, &nick, &clean, match &kind {
                                MessageKind::Privmsg => "privmsg",
                                MessageKind::Notice => "notice",
                                MessageKind::Action => "action",
                            }).await;
                            state.send_to_user(username, ServerEvent::IrcEcho {
                                conn_id: conn_id.clone(),
                                from: nick.clone(),
                                target: display_target,
                                text: clean,
                                ts,
                                kind,
                                msg_id,
                            });
                        }
                    }
                }
                // Persist JOIN/PART in auto_join
                let upper = safe.to_uppercase();
                if upper.starts_with("JOIN ") || upper.starts_with("PART ") {
                    let parts: Vec<&str> = safe.splitn(3, ' ').collect();
                    if parts.len() >= 2 {
                        let ch = parts[1].split(',').next().unwrap_or("");
                        if !ch.is_empty() && is_valid_channel(ch) {
                            if let Some(mut cfg) = state.get_network_config(&conn_id, username).await {
                                let lc = ch.to_lowercase();
                                if upper.starts_with("JOIN ") {
                                    if !cfg.auto_join.iter().any(|c| c.to_lowercase() == lc) && cfg.auto_join.len() < 100 {
                                        cfg.auto_join.push(ch.to_string());
                                        let _ = state.save_network(&cfg, username).await;
                                    }
                                } else {
                                    cfg.auto_join.retain(|c| c.to_lowercase() != lc);
                                    let _ = state.save_network(&cfg, username).await;
                                }
                            }
                        }
                    }
                }
            } else {
                info!("[{}] SEND failed: no connection found", conn_id);
            }
        }
        ClientMessage::JoinChannel { conn_id, channel, key } => {
            if !state.owns_conn(username, &conn_id) { return; }
            if let Some(conn) = state.connections.get(&conn_id) {
                let safe_ch = strip_crlf(&channel);
                if safe_ch.is_empty() || !is_valid_channel(&safe_ch) { return; }
                let cmd = match key.as_deref() {
                    Some(k) if !k.is_empty() => format!("JOIN {} {}\r\n", safe_ch, strip_crlf(k)),
                    _ => format!("JOIN {}\r\n", safe_ch),
                };
                let _ = conn.lock().await.send_raw(&cmd).await;
                // Persist channel in auto_join
                if let Some(mut cfg) = state.get_network_config(&conn_id, username).await {
                    let lc = safe_ch.to_lowercase();
                    if !cfg.auto_join.iter().any(|c| c.to_lowercase() == lc) {
                        cfg.auto_join.push(safe_ch);
                        let _ = state.save_network(&cfg, username).await;
                    }
                }
            }
        }
        ClientMessage::PartChannel { conn_id, channel } => {
            if !state.owns_conn(username, &conn_id) { return; }
            let safe = strip_crlf(&channel);
            if safe.is_empty() { return; }
            if let Some(conn) = state.connections.get(&conn_id) {
                let _ = conn.lock().await.send_raw(&format!("PART {}\r\n", safe)).await;
            }
            // Remove channel from auto_join
            if let Some(mut cfg) = state.get_network_config(&conn_id, username).await {
                let lc = safe.to_lowercase();
                cfg.auto_join.retain(|c| c.to_lowercase() != lc);
                let _ = state.save_network(&cfg, username).await;
            }
        }
        ClientMessage::GetLogs { conn_id, target, limit, before } => {
            if !state.owns_network(username, &conn_id).await { return; }
            let lim = limit.unwrap_or(200).min(500);
            // Read all logs (up to internal cap), then filter and slice
            let all_lines = state.logger.read_logs(username, &conn_id, &target, 10000).await.unwrap_or_default();
            let filtered: Vec<LogLine> = if let Some(ts) = before {
                all_lines.into_iter().filter(|l| l.ts < ts).collect()
            } else {
                all_lines
            };
            let start = filtered.len().saturating_sub(lim);
            let lines = filtered[start..].to_vec();
            send(ServerEvent::LogLines { conn_id, target, lines });
        }
        ClientMessage::Sync { conn_id, target, after_id } => {
            if !state.owns_network(username, &conn_id).await { return; }
            let lines = state.logger.read_logs_since(username, &conn_id, &target, after_id).await.unwrap_or_default();
            send(ServerEvent::SyncLines { conn_id, target, lines });
        }
        ClientMessage::GetState {} => {
            send(ServerEvent::State {
                networks: state.user_network_states(username).await,
                vault_unlocked: state.crypto.is_unlocked(username).await,
            });
        }

        // ── Certificate management ────────────────────────────────────────
        ClientMessage::GenerateCert { conn_id } => {
            if !state.owns_network(username, &conn_id).await { return; }
            if !state.crypto.is_unlocked(username).await {
                send(ServerEvent::Error { message: "Vault must be unlocked to generate certificates".into() }); return;
            }
            // Use network nick as CN, fall back to username
            let nick = state.get_network_config(&conn_id, username).await
                .map(|c| c.nick)
                .unwrap_or_else(|| username.to_string());
            match state.certs.generate(username, &conn_id, &nick).await {
                Ok(info) => {
                    // Set client_cert_id on the network config so it's used on next connect
                    if let Some(mut cfg) = state.get_network_config(&conn_id, username).await {
                        cfg.client_cert_id = Some(conn_id.clone());
                        let _ = state.save_network(&cfg, username).await;
                    }
                    send(ServerEvent::CertInfo {
                        conn_id, fingerprint: info.fingerprint, cert_pem: info.cert_pem,
                    });
                }
                Err(e) => send(ServerEvent::Error { message: format!("Cert generate failed: {}", e) }),
            }
        }
        ClientMessage::DeleteCert { conn_id } => {
            if !state.owns_network(username, &conn_id).await { return; }
            match state.certs.delete(&conn_id).await {
                Ok(_) => send(ServerEvent::State {
                    networks: state.user_network_states(username).await,
                    vault_unlocked: state.crypto.is_unlocked(username).await,
                }),
                Err(e) => send(ServerEvent::Error { message: format!("Cert delete failed: {}", e) }),
            }
        }
        ClientMessage::GetCertInfo { conn_id } => {
            if !state.owns_network(username, &conn_id).await { return; }
            match state.certs.load_info(&conn_id).await {
                Ok(info) => send(ServerEvent::CertInfo {
                    conn_id, fingerprint: info.fingerprint, cert_pem: info.cert_pem,
                }),
                Err(_) => send(ServerEvent::Error { message: "No certificate found for this network".into() }),
            }
        }

        // ── E2E: identity key blob (browser-encrypted private keys) ───────────
        ClientMessage::E2EStoreIdentity { blob } => {
            info!("[E2E] store_identity for {} ({} bytes)", username, blob.len());
            match state.e2e_store.store_identity_enc(username, &blob).await {
                Ok(_)  => info!("[E2E] identity stored for {}", username),
                Err(e) => { info!("[E2E] identity store FAILED for {}: {}", username, e); send(ServerEvent::Error { message: format!("E2E store identity: {}", e) }); },
            }
        }
        ClientMessage::E2ELoadIdentity {} => {
            match state.e2e_store.load_identity_enc(username).await {
                Some(blob) => send(ServerEvent::E2EIdentityBlob { blob }),
                None       => send(ServerEvent::E2EIdentityBlob { blob: String::new() }),
            }
        }

        // ── E2E: public key bundle + one-time prekeys ─────────────────────────
        ClientMessage::E2EPublishBundle { bundle } => {
            info!("[E2E] publish_bundle for {}", username);
            match state.e2e_store.store_bundle(username, &bundle).await {
                Ok(_) => { info!("[E2E] bundle published for {}", username);
                    // L5: use same threshold as client OTPK_REFILL_BELOW = 10
                    let remaining = state.e2e_store.otpk_count(username).await;
                    if remaining < 10 {
                        send(ServerEvent::E2EOTPKLow { remaining });
                    }
                }
                Err(e) => send(ServerEvent::Error { message: format!("E2E publish bundle: {}", e) }),
            }
        }
        ClientMessage::E2EAddOTPKs { keys } => {
            match state.e2e_store.add_one_time_prekeys(username, keys).await {
                Ok(_)  => {}
                Err(e) => send(ServerEvent::Error { message: format!("E2E add OTPKs: {}", e) }),
            }
        }
        ClientMessage::E2EFetchBundle { username: target_user } => {
            // Sanitize target username/nick
            let safe: String = target_user.chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .take(64).collect();
            // Try direct username lookup first, then resolve IRC nick to username
            info!("[E2E] fetch_bundle request for '{}' from {}", safe, username);
            let resolved = if state.e2e_store.has_bundle(&safe).await {
                info!("[E2E] direct lookup found bundle for '{}'", safe);
                safe.clone()
            } else if let Some(real_user) = state.resolve_nick_to_username(&safe).await {
                info!("[E2E] nick resolved '{}' → '{}'", safe, real_user);
                real_user
            } else {
                info!("[E2E] no bundle and no nick resolution for '{}'", safe);
                safe.clone()
            };
            match state.e2e_store.fetch_bundle(&resolved).await {
                Some(bundle) => {
                    send(ServerEvent::E2EBundle { username: safe.clone(), bundle });
                    // Check if the target user's prekeys are running low and notify them
                    let remaining = state.e2e_store.otpk_count(&resolved).await;
                    if remaining < 10 {
                        state.send_to_user(&resolved, ServerEvent::E2EOTPKLow { remaining });
                    }
                }
                None => send(ServerEvent::Error { message: format!("No E2E key bundle for {} — they may need to unlock their vault first", safe) }),
            }
        }

        // ── E2E: ratchet session state ────────────────────────────────────────
        ClientMessage::E2EStoreSession { partner, blob } => {
            let safe_partner = partner.chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .take(128).collect::<String>();
            match state.e2e_store.store_session(username, &safe_partner, &blob).await {
                Ok(_)  => {}
                Err(e) => send(ServerEvent::Error { message: format!("E2E store session: {}", e) }),
            }
        }
        ClientMessage::E2ELoadSession { partner } => {
            let safe_partner = partner.chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .take(128).collect::<String>();
            match state.e2e_store.load_session(username, &safe_partner).await {
                Some(blob) => send(ServerEvent::E2ESession { partner: safe_partner, blob }),
                None       => send(ServerEvent::E2ESession { partner: safe_partner, blob: String::new() }),
            }
        }
        ClientMessage::E2EDeleteSession { partner } => {
            let safe_partner = partner.chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .take(128).collect::<String>();
            let _ = state.e2e_store.delete_session(username, &safe_partner).await;
        }

        // ── E2E: channel pre-shared keys ──────────────────────────────────────
        ClientMessage::E2EStoreChannelKey { channel, blob } => {
            let safe_chan = channel.chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '#' || *c == '&')
                .take(64).collect::<String>();
            match state.e2e_store.store_channel_key(username, &safe_chan, &blob).await {
                Ok(_)  => {
                    // Notify ALL sessions so other devices load the new key
                    state.send_to_user(username, ServerEvent::E2EChannelKey {
                        channel: safe_chan.clone(), blob,
                    });
                }
                Err(e) => send(ServerEvent::Error { message: format!("E2E store channel key: {}", e) }),
            }
        }
        ClientMessage::E2ELoadChannelKey { channel } => {
            let safe_chan = channel.chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '#' || *c == '&')
                .take(64).collect::<String>();
            match state.e2e_store.load_channel_key(username, &safe_chan).await {
                Some(blob) => send(ServerEvent::E2EChannelKey { channel: safe_chan, blob }),
                None       => {} // no key — channel not encrypted
            }
        }
        ClientMessage::E2EDeleteChannelKey { channel } => {
            let safe_chan = channel.chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '#' || *c == '&')
                .take(64).collect::<String>();
            let _ = state.e2e_store.delete_channel_key(username, &safe_chan).await;
            // Notify ALL sessions of this user so other devices update the lock icon
            state.send_to_user(username, ServerEvent::E2EChannelList {
                channels: state.e2e_store.list_channel_keys(username).await,
            });
        }
        ClientMessage::E2EListChannelKeys {} => {
            let channels = state.e2e_store.list_channel_keys(username).await;
            send(ServerEvent::E2EChannelList { channels });
        }

        // ── E2E: TOFU trust management ────────────────────────────────────────
        ClientMessage::E2EUpdateTrust { nick, fingerprint, verified } => {
            let safe_nick = nick.chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .take(64).collect::<String>();
            match state.e2e_store.update_trust(username, &safe_nick, &fingerprint, verified).await {
                Ok((rec, key_changed)) => send(ServerEvent::E2ETrust {
                    nick:        rec.nick,
                    fingerprint: rec.fingerprint,
                    verified:    rec.verified,
                    key_changed,
                }),
                Err(e) => send(ServerEvent::Error { message: e.to_string() }),
            }
        }
        ClientMessage::E2ELoadTrust {} => {
            let records = state.e2e_store.load_trust(username).await;
            for rec in records {
                send(ServerEvent::E2ETrust {
                    nick:        rec.nick,
                    fingerprint: rec.fingerprint,
                    verified:    rec.verified,
                    key_changed: false,
                });
            }
        }
        ClientMessage::E2ERelayX3DH { target_nick, header } => {
            // Relay X3DH header to target user via server (too large for IRC)
            let safe: String = target_nick.chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '[' || *c == ']' || *c == '\\' || *c == '`' || *c == '^')
                .take(64).collect();
            // Find the target user's CryptIRC username from their IRC nick
            if let Some(target_user) = state.resolve_nick_to_username(&safe).await {
                // Get sender's IRC nick to include in the relay
                let sender_nick = {
                    let mut found = String::new();
                    let conn_ids: Vec<String> = state.conn_owners.iter()
                        .filter(|e| e.value() == username)
                        .map(|e| e.key().clone()).collect();
                    for cid in conn_ids {
                        if let Some(conn) = state.connections.get(&cid) {
                            found = conn.lock().await.nick.clone();
                            break;
                        }
                    }
                    found
                };
                info!("[E2E] Relaying x3dh header from {} ({}) to {} ({})", username, sender_nick, target_user, safe);
                state.send_to_user(&target_user, ServerEvent::E2EX3DHHeader {
                    from_nick: sender_nick,
                    header,
                });
            }
        }
        // L7: dedicated handler so client can proactively check OTPK level
        ClientMessage::E2ECheckOTPKCount {} => {
            let remaining = state.e2e_store.otpk_count(username).await;
            if remaining < 10 {
                send(ServerEvent::E2EOTPKLow { remaining });
            }
        }
        ClientMessage::SaveAppearance { settings } => {
            // Limit to 4KB to prevent abuse; validate it's well-formed JSON
            if settings.len() <= 4096 && serde_json::from_str::<serde_json::Value>(&settings).is_ok() {
                let dir = std::path::PathBuf::from(&state.data_dir)
                    .join("users").join(&safe_username(username));
                let _ = tokio::fs::create_dir_all(&dir).await;
                let _ = tokio::fs::write(dir.join("appearance.json"), &settings).await;
                // Broadcast to all sessions so other devices update instantly
                state.send_to_user(username, ServerEvent::Appearance { settings });
            }
        }
        ClientMessage::LoadAppearance {} => {
            let path = std::path::PathBuf::from(&state.data_dir)
                .join("users").join(&safe_username(username)).join("appearance.json");
            if let Ok(data) = tokio::fs::read_to_string(&path).await {
                send(ServerEvent::Appearance { settings: data });
            }
        }
        ClientMessage::SavePreferences { prefs } => {
            if prefs.len() <= 65536 && serde_json::from_str::<serde_json::Value>(&prefs).is_ok() {
                let dir = std::path::PathBuf::from(&state.data_dir)
                    .join("users").join(&safe_username(username));
                let _ = tokio::fs::create_dir_all(&dir).await;
                let _ = tokio::fs::write(dir.join("preferences.json"), &prefs).await;
                // Broadcast to all sessions so other devices update instantly
                state.send_to_user(username, ServerEvent::Preferences { prefs });
            }
        }
        ClientMessage::LoadPreferences {} => {
            let path = std::path::PathBuf::from(&state.data_dir)
                .join("users").join(&safe_username(username)).join("preferences.json");
            if let Ok(data) = tokio::fs::read_to_string(&path).await {
                send(ServerEvent::Preferences { prefs: data });
            }
        }
        ClientMessage::SaveNotepad { content } => {
            if content.len() > 1_000_000 { send(ServerEvent::Error { message: "Notepad too large (max 1MB)".into() }); }
            else if state.crypto.is_unlocked(username).await {
                match state.crypto.encrypt(username, content.as_bytes()).await {
                    Ok(enc) => {
                        let dir = std::path::PathBuf::from(&state.data_dir).join("users").join(&safe_username(username));
                        let _ = tokio::fs::create_dir_all(&dir).await;
                        let _ = tokio::fs::write(dir.join("notepad.enc"), &enc).await;
                    }
                    Err(e) => send(ServerEvent::Error { message: format!("Save failed: {}", e) }),
                }
            } else { send(ServerEvent::Error { message: "Vault locked".into() }); }
        }
        ClientMessage::LoadNotepad {} => {
            if state.crypto.is_unlocked(username).await {
                let path = std::path::PathBuf::from(&state.data_dir).join("users").join(&safe_username(username)).join("notepad.enc");
                if let Ok(enc) = tokio::fs::read_to_string(&path).await {
                    match state.crypto.decrypt(username, enc.trim()).await {
                        Ok(pt) => send(ServerEvent::Notepad { content: String::from_utf8_lossy(&pt).to_string() }),
                        Err(_) => send(ServerEvent::Notepad { content: String::new() }),
                    }
                } else {
                    send(ServerEvent::Notepad { content: String::new() });
                }
            } else { send(ServerEvent::Error { message: "Vault locked".into() }); }
        }
        ClientMessage::SaveStats { data } => {
            if data.len() > 2_000_000 { send(ServerEvent::Error { message: "Stats too large (max 2MB)".into() }); }
            else if state.crypto.is_unlocked(username).await {
                match state.crypto.encrypt(username, data.as_bytes()).await {
                    Ok(enc) => {
                        let dir = std::path::PathBuf::from(&state.data_dir).join("users").join(&safe_username(username));
                        let _ = tokio::fs::create_dir_all(&dir).await;
                        let _ = tokio::fs::write(dir.join("stats.enc"), &enc).await;
                    }
                    Err(e) => send(ServerEvent::Error { message: format!("Save failed: {}", e) }),
                }
            } else { send(ServerEvent::Error { message: "Vault locked".into() }); }
        }
        ClientMessage::LoadStats {} => {
            if state.crypto.is_unlocked(username).await {
                let path = std::path::PathBuf::from(&state.data_dir).join("users").join(&safe_username(username)).join("stats.enc");
                if let Ok(enc) = tokio::fs::read_to_string(&path).await {
                    match state.crypto.decrypt(username, enc.trim()).await {
                        Ok(pt) => send(ServerEvent::StatsData { data: String::from_utf8_lossy(&pt).to_string() }),
                        Err(_) => send(ServerEvent::StatsData { data: String::new() }),
                    }
                } else {
                    send(ServerEvent::StatsData { data: String::new() });
                }
            } else { send(ServerEvent::Error { message: "Vault locked".into() }); }
        }
        ClientMessage::SavePasswords { data } => {
            if data.len() > 1_000_000 { send(ServerEvent::Error { message: "Password safe too large (max 1MB)".into() }); }
            else if state.crypto.is_unlocked(username).await {
                match state.crypto.encrypt(username, data.as_bytes()).await {
                    Ok(enc) => {
                        let dir = std::path::PathBuf::from(&state.data_dir).join("users").join(&safe_username(username));
                        let _ = tokio::fs::create_dir_all(&dir).await;
                        let _ = tokio::fs::write(dir.join("passwords.enc"), &enc).await;
                    }
                    Err(e) => send(ServerEvent::Error { message: format!("Save failed: {}", e) }),
                }
            } else { send(ServerEvent::Error { message: "Vault locked".into() }); }
        }
        ClientMessage::LoadPasswords {} => {
            if state.crypto.is_unlocked(username).await {
                let path = std::path::PathBuf::from(&state.data_dir).join("users").join(&safe_username(username)).join("passwords.enc");
                if let Ok(enc) = tokio::fs::read_to_string(&path).await {
                    match state.crypto.decrypt(username, enc.trim()).await {
                        Ok(pt) => send(ServerEvent::PasswordSafe { data: String::from_utf8_lossy(&pt).to_string() }),
                        Err(_) => send(ServerEvent::PasswordSafe { data: String::new() }),
                    }
                } else {
                    send(ServerEvent::PasswordSafe { data: String::new() });
                }
            } else { send(ServerEvent::Error { message: "Vault locked".into() }); }
        }
        ClientMessage::ClearAllData {} => {
            info!("Clearing all data for user: {}", username);
            // Delete logs for all this user's connections
            for cfg in state.load_user_configs(username).await {
                let log_dir = std::path::PathBuf::from(&state.data_dir)
                    .join("logs").join(&cfg.id);
                let _ = tokio::fs::remove_dir_all(&log_dir).await;
            }
            // Delete notepad
            let notepad_path = std::path::PathBuf::from(&state.data_dir)
                .join("users").join(&safe_username(username)).join("notepad.enc");
            let _ = tokio::fs::remove_file(&notepad_path).await;
            // Delete pastes by this user
            let paste_dir = std::path::PathBuf::from(&state.data_dir).join("pastes");
            if let Ok(mut rd) = tokio::fs::read_dir(&paste_dir).await {
                while let Ok(Some(entry)) = rd.next_entry().await {
                    let path = entry.path();
                    if let Ok(json) = tokio::fs::read_to_string(&path).await {
                        if let Ok(paste) = serde_json::from_str::<serde_json::Value>(&json) {
                            if paste.get("author").and_then(|a| a.as_str()) == Some(username) {
                                let _ = tokio::fs::remove_file(&path).await;
                            }
                        }
                    }
                }
            }
            info!("All data cleared for user: {}", username);
            // Broadcast to all user's sessions so other devices clear too
            state.send_to_user(username, ServerEvent::DataCleared {});
        }
        ClientMessage::MonitorPush { nick, status } => {
            let safe_nick: String = nick.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '[' || *c == ']' || *c == '\\' || *c == '`' || *c == '^').take(32).collect();
            let safe_status = if status == "online" { "online" } else { "offline" };
            state.notifier.send_monitor_notification(username, &safe_nick, safe_status).await;
        }
        ClientMessage::SaveChannelOrder { conn_id, order } => {
            if !state.owns_network(username, &conn_id).await { return; }
            if let Some(mut cfg) = state.get_network_config(&conn_id, username).await {
                cfg.channel_order = order;
                let _ = state.save_network(&cfg, username).await;
                // Broadcast updated state to all sessions
                state.send_to_user(username, ServerEvent::State {
                    networks: state.user_network_states(username).await,
                    vault_unlocked: state.crypto.is_unlocked(username).await,
                });
            }
        }
        ClientMessage::DeleteAccount { password } => {
            // Verify password before deleting (login creates a session, so logout it immediately)
            match state.auth.login(username, &password).await {
                Ok(temp_token) => {
                    state.auth.logout(&temp_token); // L35: clean up orphaned session
                    // Disconnect all IRC connections for this user
                    let conns: Vec<String> = state.conn_owners.iter()
                        .filter(|e| e.value() == username)
                        .map(|e| e.key().clone())
                        .collect();
                    for cid in &conns {
                        state.request_disconnect(cid);
                        if let Some(conn) = state.connections.get(cid) {
                            let mut c = conn.lock().await;
                            let _ = c.send_raw("QUIT :Account deleted\r\n").await;
                        }
                        state.connections.remove(cid);
                        state.conn_owners.remove(cid);
                    }
                    // Delete account data
                    state.auth.delete_account(username).await;
                    send(ServerEvent::AccountDeleted {});
                }
                Err(_) => {
                    send(ServerEvent::AuthFailed { message: "Incorrect password".into() });
                }
            }
        }
    }
}

// ─── AppState helpers ─────────────────────────────────────────────────────────

impl AppState {
    fn owns_conn(&self, username: &str, conn_id: &str) -> bool {
        self.conn_owners.get(conn_id).map(|v| v.as_str() == username).unwrap_or(false)
    }

    /// Resolve an IRC nick to a CryptIRC username by searching active connections.
    /// Returns the CryptIRC username if an online user with that nick is found.
    async fn resolve_nick_to_username(&self, nick: &str) -> Option<String> {
        let nick_lower = nick.to_lowercase();
        // Collect connection IDs first to avoid holding DashMap shard locks while awaiting Mutex
        let conn_ids: Vec<String> = self.connections.iter()
            .map(|e| e.key().clone())
            .collect();
        for conn_id in conn_ids {
            if let Some(conn) = self.connections.get(&conn_id) {
                let conn_nick = {
                    let c = conn.lock().await;
                    c.nick.clone()
                };
                if conn_nick.to_lowercase() == nick_lower {
                    if let Some(owner) = self.conn_owners.get(&conn_id) {
                        return Some(owner.clone());
                    }
                }
            }
        }
        None
    }

    async fn owns_network(&self, username: &str, id: &str) -> bool {
        if validate_uuid(id).is_none() { return false; }
        if let Some(owner) = self.conn_owners.get(id) {
            return owner.as_str() == username;
        }
        self.get_network_config(id, username).await.is_some()
    }

    pub async fn user_network_states(&self, username: &str) -> Vec<NetworkState> {
        let mut out = Vec::new();
        for cfg in self.load_user_configs(username).await {
            let (connected, nick, channels, lag_ms) = if let Some(conn) = self.connections.get(&cfg.id) {
                let c   = conn.lock().await;
                let chs = c.channels.iter().map(|(n, cs)| ChannelState {
                    name: n.clone(), topic: cs.topic.clone(), names: cs.names.clone()
                }).collect();
                (c.connected, c.nick.clone(), chs, c.lag_ms)
            } else { (false, cfg.nick.clone(), vec![], None) };

            // Include cert info
            let has_cert = self.certs.exists(&cfg.id).await;
            let cert_fingerprint = if has_cert {
                self.certs.load_info(&cfg.id).await.ok().map(|i| i.fingerprint)
            } else { None };

            out.push(NetworkState { config: cfg, connected, nick, channels, lag_ms, has_cert, cert_fingerprint });
        }
        out
    }

    pub async fn reconnect_for_user(&self, username: &str) {
        for cfg in self.load_user_configs(username).await {
            let id = cfg.id.clone();
            // Kill any existing connection first to prevent duplicate sessions
            self.request_disconnect(&id);
            if let Some(conn) = self.connections.get(&id) {
                let mut c = conn.lock().await;
                let _ = c.send_raw("QUIT :CryptIRC\r\n").await;
            }
            self.connections.remove(&id);
            self.conn_owners.remove(&id);
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            self.clear_disconnect_request(&id);
            self.send_to_user(username, ServerEvent::Connecting { conn_id: id.clone(), server: cfg.server.clone() });
            let (s, u) = (self.clone(), username.to_string());
            tokio::spawn(async move {
                if let Err(e) = irc::connect(id, cfg, u, s).await { error!("{}", e); }
            });
        }
    }

    pub async fn save_network(&self, cfg: &NetworkConfig, username: &str) -> anyhow::Result<()> {
        let safe_id = validate_uuid(&cfg.id).ok_or_else(|| anyhow::anyhow!("Invalid network id"))?;
        let dir     = format!("{}/networks/{}", self.data_dir, username);
        tokio::fs::create_dir_all(&dir).await?;

        // S2: If vault is unlocked, encrypt sensitive fields before persisting.
        // We store an encrypted variant so server-password and SASL credentials
        // are never written to disk in plaintext.
        let mut persisted = cfg.clone();
        if self.crypto.is_unlocked(username).await {
            if let Some(ref p) = cfg.password {
                let enc = self.crypto.encrypt(username, p.as_bytes()).await?;
                persisted.password = Some(format!("enc:{}", enc));
            }
            if let Some(ref sc) = cfg.sasl_plain {
                let enc = self.crypto.encrypt(username, sc.password.as_bytes()).await?;
                persisted.sasl_plain = Some(crate::SaslConfig {
                    account:  sc.account.clone(),
                    password: format!("enc:{}", enc),
                });
            }
            if let Some(ref p) = cfg.oper_pass {
                if !p.is_empty() {
                    let enc = self.crypto.encrypt(username, p.as_bytes()).await?;
                    persisted.oper_pass = Some(format!("enc:{}", enc));
                }
            }
            if let Some(ref p) = cfg.nickserv_pass {
                if !p.is_empty() {
                    let enc = self.crypto.encrypt(username, p.as_bytes()).await?;
                    persisted.nickserv_pass = Some(format!("enc:{}", enc));
                }
            }
        }

        tokio::fs::write(
            format!("{}/{}.json", dir, safe_id),
            serde_json::to_string_pretty(&persisted)?,
        ).await?;
        Ok(())
    }

    pub async fn remove_network(&self, id: &str, username: &str) {
        if let Some(safe_id) = validate_uuid(id) {
            let _ = tokio::fs::remove_file(format!("{}/networks/{}/{}.json", self.data_dir, username, safe_id)).await;
        }
    }

    pub async fn get_network_config(&self, id: &str, username: &str) -> Option<NetworkConfig> {
        let safe_id = validate_uuid(id)?;
        let path    = format!("{}/networks/{}/{}.json", self.data_dir, username, safe_id);
        let json    = tokio::fs::read_to_string(path).await.ok()?;
        let mut cfg: NetworkConfig = serde_json::from_str(&json).ok()?;

        // S2: decrypt encrypted fields if vault is unlocked
        if self.crypto.is_unlocked(username).await {
            if let Some(ref p) = cfg.password.clone() {
                if let Some(enc) = p.strip_prefix("enc:") {
                    if let Ok(plain) = self.crypto.decrypt(username, enc).await {
                        cfg.password = Some(String::from_utf8_lossy(&plain).into_owned());
                    }
                }
            }
            if let Some(ref sc) = cfg.sasl_plain.clone() {
                if let Some(enc) = sc.password.strip_prefix("enc:") {
                    if let Ok(plain) = self.crypto.decrypt(username, enc).await {
                        cfg.sasl_plain = Some(crate::SaslConfig {
                            account:  sc.account.clone(),
                            password: String::from_utf8_lossy(&plain).into_owned(),
                        });
                    }
                }
            }
            if let Some(ref p) = cfg.oper_pass.clone() {
                if let Some(enc) = p.strip_prefix("enc:") {
                    if let Ok(plain) = self.crypto.decrypt(username, enc).await {
                        cfg.oper_pass = Some(String::from_utf8_lossy(&plain).into_owned());
                    }
                }
            }
            if let Some(ref p) = cfg.nickserv_pass.clone() {
                if let Some(enc) = p.strip_prefix("enc:") {
                    if let Ok(plain) = self.crypto.decrypt(username, enc).await {
                        cfg.nickserv_pass = Some(String::from_utf8_lossy(&plain).into_owned());
                    }
                }
            }
        }
        Some(cfg)
    }

    pub async fn load_user_configs(&self, username: &str) -> Vec<NetworkConfig> {
        let dir = format!("{}/networks/{}", self.data_dir, username);
        let mut out = Vec::new();
        if let Ok(mut rd) = tokio::fs::read_dir(&dir).await {
            while let Ok(Some(e)) = rd.next_entry().await {
                // Extract id from filename to use the decrypt path
                if let Some(stem) = e.path().file_stem().and_then(|s| s.to_str()) {
                    if let Some(cfg) = self.get_network_config(stem, username).await {
                        out.push(cfg);
                    }
                }
            }
        }
        out
    }
}

// ─── String sanitization ──────────────────────────────────────────────────────

/// Sanitize a username for safe filesystem path usage (defense-in-depth)
pub fn safe_username(s: &str) -> String {
    s.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-').take(64).collect()
}

pub fn strip_crlf(s: &str) -> String {
    s.chars().filter(|&c| c != '\r' && c != '\n' && c != '\0').collect()
}

fn is_valid_channel(s: &str) -> bool {
    if s.is_empty() || s.len() > 200 { return false; }
    let first = s.chars().next().unwrap_or(' ');
    "#&+!".contains(first) && !s.contains(' ') && !s.contains('\0') && !s.contains(',')
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
     .replace('"', "&#34;").replace('\'', "&#39;")
}

/// Escape a string for safe embedding inside a JavaScript string literal (double-quoted).
/// Prevents injection in `<script>` blocks where HTML entities are NOT decoded.
fn js_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"'  => out.push_str("\\\""),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '<'  => out.push_str("\\x3c"),  // prevent </script> breakout
            '>'  => out.push_str("\\x3e"),
            _    => out.push(c),
        }
    }
    out
}
