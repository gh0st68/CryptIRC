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
use std::{net::SocketAddr, sync::Arc};
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
    pub global_tx:           broadcast::Sender<ServerEvent>,
    pub user_events:         UserEventMap,
    pub upload_dir:          String,
    pub base_url:            String,
    pub data_dir:            String,
}

impl AppState {
    pub fn user_tx(&self, username: &str) -> broadcast::Sender<ServerEvent> {
        self.user_events
            .entry(username.to_string())
            .or_insert_with(|| broadcast::channel(512).0)
            .clone()
    }
    pub fn send_to_user(&self, username: &str, evt: ServerEvent) {
        let _ = self.user_tx(username).send(evt);
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
    ChangePassphrase { old: String, new: String },
    AddNetwork       { network: NetworkConfig },
    UpdateNetwork    { network: NetworkConfig },
    RemoveNetwork    { id: String },
    Connect          { id: String },
    Disconnect       { id: String },
    Send             { conn_id: String, raw: String },
    JoinChannel      { conn_id: String, channel: String, key: Option<String> },
    PartChannel      { conn_id: String, channel: String },
    GetLogs          { conn_id: String, target: String, limit: Option<usize> },
    GetState         {},
    // Certificate management
    GenerateCert     { conn_id: String },
    DeleteCert       { conn_id: String },
    GetCertInfo      { conn_id: String },
    // E2E encryption
    E2EStoreIdentity  { blob: String },
    E2ELoadIdentity   {},
    E2EPublishBundle  { bundle: KeyBundle },
    #[serde(rename = "e2e_add_otpks")]
    E2EAddOTPKs       { keys: Vec<OneTimePrekey> },
    E2EFetchBundle    { username: String },
    E2EStoreSession   { partner: String, blob: String },
    E2ELoadSession    { partner: String },
    E2EDeleteSession  { partner: String },
    E2EStoreChannelKey  { channel: String, blob: String },
    E2ELoadChannelKey   { channel: String },
    E2EDeleteChannelKey { channel: String },
    E2EListChannelKeys  {},
    E2EUpdateTrust    { nick: String, fingerprint: String, verified: bool },
    E2ELoadTrust      {},
    #[serde(rename = "e2e_check_otpk_count")]
    E2ECheckOTPKCount {},
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
    IrcMessage       { conn_id: String, from: String, target: String, text: String, ts: i64, kind: MessageKind },
    IrcJoin          { conn_id: String, nick: String,  channel: String, ts: i64 },
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
    CertInfo         { conn_id: String, fingerprint: String, cert_pem: String },
    // ── E2E events ──────────────────────────────────────────────────────────
    /// Fetched key bundle for another user (to initiate X3DH)
    E2EBundle        { username: String, bundle: FetchedBundle },
    /// Our stored encrypted identity key blob (load on unlock)
    E2EIdentityBlob  { blob: String },
    /// Encrypted ratchet session state for a DM partner
    E2ESession       { partner: String, blob: String },
    /// Encrypted channel PSK blob
    E2EChannelKey    { channel: String, blob: String },
    /// List of channels for which we have a stored key
    E2EChannelList   { channels: Vec<String> },
    /// Trust record update result
    E2ETrust         { nick: String, fingerprint: String, verified: bool, key_changed: bool },
    /// Low one-time prekey warning
    #[serde(rename = "e2e_otpk_low")]
    E2EOTPKLow       { remaining: usize },
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
pub struct LogLine { pub ts: i64, pub from: String, pub text: String, pub kind: String }

// ─── HTTP types ───────────────────────────────────────────────────────────────

#[derive(Deserialize)] struct RegisterBody { username: String, email: String, password: String }
#[derive(Deserialize)] struct LoginBody    { username: String, password: String }
#[derive(Deserialize)] struct VerifyQuery  { token: String }
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
         connect-src 'self' wss: ws:; frame-ancestors 'none';"
    ));
    response
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let data_dir   = std::env::var("CRYPTIRC_DATA").unwrap_or_else(|_| "./data".into());
    let upload_dir = format!("{}/uploads", data_dir);
    let base_url   = std::env::var("CRYPTIRC_BASE_URL").unwrap_or_else(|_| "http://localhost:9000".into());
    std::fs::create_dir_all(&data_dir)?;
    std::fs::create_dir_all(&upload_dir)?;
    std::fs::create_dir_all(format!("{}/certs", data_dir))?;

    let crypto   = Arc::new(CryptoManager::new(&data_dir)?);
    let certs    = Arc::new(CertStore::new(&data_dir, crypto.clone()));
    let logger   = Arc::new(EncryptedLogger::new(&data_dir, crypto.clone()));
    let auth     = Arc::new(AuthManager::new(&data_dir)?);
    let vapid    = notifications::load_or_generate_vapid(&data_dir)?;
    let notifier = Arc::new(NotificationManager::new(&data_dir, vapid));
    let e2e_store = Arc::new(E2EStore::new(&data_dir));
    let (global_tx, _) = broadcast::channel(64);

    let state = AppState {
        connections:         Arc::new(DashMap::new()),
        conn_owners:         Arc::new(DashMap::new()),
        disconnect_requests: Arc::new(DashSet::new()),
        crypto, certs, logger, auth, notifier, e2e_store, global_tx,
        user_events:         Arc::new(DashMap::new()),
        upload_dir, base_url,
        data_dir: data_dir.clone(),
    };

    // Background: purge expired sessions hourly
    { let a = state.auth.clone();
      tokio::spawn(async move {
          let mut iv = tokio::time::interval(tokio::time::Duration::from_secs(3600));
          loop { iv.tick().await; a.purge_expired_sessions(); }
      });
    }

    let base_path = std::env::var("CRYPTIRC_BASE_PATH").unwrap_or_else(|_| "/cryptirc".into());
    let inner = Router::new()
        .route("/",                      get(serve_index))
        .route("/e2e.js",                get(serve_e2e_js))
        .route("/manifest.json",         get(serve_manifest))
        .route("/sw.js",                 get(serve_sw))
        .route("/icon.svg",              get(serve_icon))
        .route("/auth/register",         post(route_register).layer(DefaultBodyLimit::max(8_192)))
        .route("/auth/login",            post(route_login).layer(DefaultBodyLimit::max(8_192)))
        .route("/auth/logout",           post(route_logout))
        .route("/auth/verify",           get(route_verify))
        .route("/auth/me",               get(route_me))
        .route("/upload",                post(route_upload).layer(DefaultBodyLimit::max(26_214_400)))
        .route("/files/:name",           get(serve_file))
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
async fn serve_e2e_js()   -> impl IntoResponse { ([(header::CONTENT_TYPE,"application/javascript; charset=utf-8")], include_str!("../static/e2e.js")) }

async fn serve_file(Path(name): Path<String>, Query(q): Query<FileQuery>, State(state): State<AppState>) -> impl IntoResponse {
    if state.auth.validate_session(&q.token.unwrap_or_default()).is_none() {
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
            .header(HeaderName::from_static("content-disposition"), "attachment")
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

async fn route_register(State(state): State<AppState>, Json(body): Json<RegisterBody>) -> impl IntoResponse {
    match state.auth.register(&body.username, &body.email, &body.password).await {
        Ok(token) => {
            let (email, uname, base) = (body.email.clone(), body.username.to_lowercase(), state.base_url.clone());
            tokio::spawn(async move {
                if let Err(e) = email::send_verification(&email, &uname, &token, &base) { error!("Email: {}", e); }
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

async fn route_verify(State(state): State<AppState>, Query(q): Query<VerifyQuery>) -> impl IntoResponse {
    match state.auth.verify_email(&q.token).await {
        Ok(_) => Html(r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Verified</title>
<style>body{background:#0b0d0f;color:#c8d8e8;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}
.b{background:#111418;border:1px solid #2a3444;border-radius:12px;padding:32px 40px;text-align:center;}
h2{background:linear-gradient(135deg,#00d4aa,#0099ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
a{color:#00d4aa;text-decoration:none;}</style></head>
<body><div class="b"><h2>✓ Email Verified</h2><p>Your account is now active.</p><br><a href="/">Open CryptIRC →</a></div></body></html>"#.to_string()),
        Err(e) => Html(format!(r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Error</title>
<style>body{{background:#0b0d0f;color:#ff4466;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}}
a{{color:#00d4aa;}}</style></head><body><p>{}</p><a href="/">← Back</a></body></html>"#, html_escape(&e.to_string()))),
    }
}

async fn route_me(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    match bearer_token(&headers).and_then(|t| state.auth.validate_session(&t)) {
        Some(u) => (StatusCode::OK, Json(MeOk { username: u })).into_response(),
        None    => (StatusCode::UNAUTHORIZED, Json(Msg { message: "Not authenticated".into() })).into_response(),
    }
}

async fn route_upload(State(state): State<AppState>, headers: HeaderMap, multipart: Multipart) -> impl IntoResponse {
    match bearer_token(&headers).and_then(|t| state.auth.validate_session(&t)) {
        None    => (StatusCode::UNAUTHORIZED, Json(Msg { message: "Not authenticated".into() })).into_response(),
        Some(_) => match upload::handle_upload(&state.upload_dir, multipart).await {
            Ok(r)  => (StatusCode::OK, Json(r)).into_response(),
            Err(e) => (StatusCode::BAD_REQUEST, Json(Msg { message: e.to_string() })).into_response(),
        }
    }
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
    let vault_unlocked = state.crypto.is_unlocked().await;
    let _ = sender.send(Message::Text(serde_json::to_string(&ServerEvent::State {
        networks: state.user_network_states(&username).await,
        vault_unlocked,
    }).unwrap())).await;
    // If vault is already unlocked, send the e2e key so the frontend can init E2E
    if vault_unlocked {
        if let Ok(k) = state.crypto.derive_e2e_enc_key().await {
            let e2e_enc_key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, k);
            let _ = sender.send(Message::Text(serde_json::to_string(&ServerEvent::VaultUnlocked { e2e_enc_key }).unwrap())).await;
        }
    }

    let mut event_rx = state.user_tx(&username).subscribe();

    let mut send_task = tokio::spawn(async move {
        while let Ok(evt) = event_rx.recv().await {
            if sender.send(Message::Text(serde_json::to_string(&evt).unwrap())).await.is_err() { break; }
        }
    });

    let state2 = state.clone();
    let user2  = username.clone();
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            // S6: reject oversized messages before parsing
            if let Message::Text(ref text) = msg {
                if text.len() > WS_MAX_MSG_BYTES { continue; }
                if let Ok(cmd) = serde_json::from_str::<ClientMessage>(text) {
                    handle_command(cmd, &user2, &state2).await;
                }
            }
        }
    });

    tokio::select! {
        _ = &mut send_task => recv_task.abort(),
        _ = &mut recv_task => send_task.abort(),
    }
}

// ─── Command handler ──────────────────────────────────────────────────────────

async fn handle_command(cmd: ClientMessage, username: &str, state: &AppState) {
    let send = |evt: ServerEvent| state.send_to_user(username, evt);

    match cmd {
        ClientMessage::Auth { .. } => {}

        ClientMessage::UnlockVault { passphrase } => {
            match state.crypto.unlock(&passphrase).await {
                Ok(_)  => {
                    // Derive E2E sub-key and send to client
                    let e2e_enc_key = match state.crypto.derive_e2e_enc_key().await {
                        Ok(k)  => base64::Engine::encode(&base64::engine::general_purpose::STANDARD, k),
                        Err(_) => String::new(),
                    };
                    send(ServerEvent::VaultUnlocked { e2e_enc_key });
                    state.reconnect_for_user(username).await;
                }
                Err(_) => send(ServerEvent::VaultError { message: "Incorrect passphrase".into() }),
            }
        }
        ClientMessage::ChangePassphrase { old, new } => {
            match state.crypto.change_passphrase(&old, &new, &state.data_dir).await {
                Ok(_)  => {
                    let e2e_enc_key = match state.crypto.derive_e2e_enc_key().await {
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
            send(ServerEvent::State {
                networks: state.user_network_states(username).await,
                vault_unlocked: state.crypto.is_unlocked().await,
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
            send(ServerEvent::State {
                networks: state.user_network_states(username).await,
                vault_unlocked: state.crypto.is_unlocked().await,
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
                vault_unlocked: state.crypto.is_unlocked().await,
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
                info!("[{}] SEND: {}", conn_id, &safe[..safe.len().min(200)]);
                let mut c = conn.lock().await;
                let _ = c.send_raw(&format!("{}\r\n", safe)).await;
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
            }
        }
        ClientMessage::PartChannel { conn_id, channel } => {
            if !state.owns_conn(username, &conn_id) { return; }
            let safe = strip_crlf(&channel);
            if safe.is_empty() { return; }
            if let Some(conn) = state.connections.get(&conn_id) {
                let _ = conn.lock().await.send_raw(&format!("PART {}\r\n", safe)).await;
            }
        }
        ClientMessage::GetLogs { conn_id, target, limit } => {
            if !state.owns_network(username, &conn_id).await { return; }
            let lines = state.logger.read_logs(&conn_id, &target, limit.unwrap_or(200)).await.unwrap_or_default();
            send(ServerEvent::LogLines { conn_id, target, lines });
        }
        ClientMessage::GetState {} => {
            send(ServerEvent::State {
                networks: state.user_network_states(username).await,
                vault_unlocked: state.crypto.is_unlocked().await,
            });
        }

        // ── Certificate management ────────────────────────────────────────
        ClientMessage::GenerateCert { conn_id } => {
            if !state.owns_network(username, &conn_id).await { return; }
            if !state.crypto.is_unlocked().await {
                send(ServerEvent::Error { message: "Vault must be unlocked to generate certificates".into() }); return;
            }
            // Use network nick as CN, fall back to username
            let nick = state.get_network_config(&conn_id, username).await
                .map(|c| c.nick)
                .unwrap_or_else(|| username.to_string());
            match state.certs.generate(&conn_id, &nick).await {
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
                    vault_unlocked: state.crypto.is_unlocked().await,
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
            match state.e2e_store.store_identity_enc(username, &blob).await {
                Ok(_)  => {} // silent success
                Err(e) => send(ServerEvent::Error { message: format!("E2E store identity: {}", e) }),
            }
        }
        ClientMessage::E2ELoadIdentity {} => {
            match state.e2e_store.load_identity_enc(username).await {
                Some(blob) => send(ServerEvent::E2EIdentityBlob { blob }),
                None       => {} // no blob yet — client will generate fresh keys
            }
        }

        // ── E2E: public key bundle + one-time prekeys ─────────────────────────
        ClientMessage::E2EPublishBundle { bundle } => {
            match state.e2e_store.store_bundle(username, &bundle).await {
                Ok(info) => {
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
            // Sanitize target username
            let safe: String = target_user.chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .take(64).collect();
            match state.e2e_store.fetch_bundle(&safe).await {
                Some(bundle) => {
                    send(ServerEvent::E2EBundle { username: safe.clone(), bundle });
                    // Check if the target user's prekeys are running low and notify them
                    let remaining = state.e2e_store.otpk_count(&safe).await;
                    if remaining < 10 {
                        state.send_to_user(&safe, ServerEvent::E2EOTPKLow { remaining });
                    }
                }
                None => send(ServerEvent::Error { message: format!("No E2E key bundle for {}", safe) }),
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
                None       => {} // no session yet — client will initiate X3DH
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
                Ok(_)  => {}
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
            send(ServerEvent::State {
                networks: state.user_network_states(username).await,
                vault_unlocked: state.crypto.is_unlocked().await,
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
        // L7: dedicated handler so client can proactively check OTPK level
        ClientMessage::E2ECheckOTPKCount {} => {
            let remaining = state.e2e_store.otpk_count(username).await;
            if remaining < 10 {
                send(ServerEvent::E2EOTPKLow { remaining });
            }
        }
    }
}

// ─── AppState helpers ─────────────────────────────────────────────────────────

impl AppState {
    fn owns_conn(&self, username: &str, conn_id: &str) -> bool {
        self.conn_owners.get(conn_id).map(|v| v.as_str() == username).unwrap_or(false)
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
        if self.crypto.is_unlocked().await {
            if let Some(ref p) = cfg.password {
                let enc = self.crypto.encrypt(p.as_bytes()).await?;
                persisted.password = Some(format!("enc:{}", enc));
            }
            if let Some(ref sc) = cfg.sasl_plain {
                let enc = self.crypto.encrypt(sc.password.as_bytes()).await?;
                persisted.sasl_plain = Some(crate::SaslConfig {
                    account:  sc.account.clone(),
                    password: format!("enc:{}", enc),
                });
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
        if self.crypto.is_unlocked().await {
            if let Some(ref p) = cfg.password.clone() {
                if let Some(enc) = p.strip_prefix("enc:") {
                    if let Ok(plain) = self.crypto.decrypt(enc).await {
                        cfg.password = Some(String::from_utf8_lossy(&plain).into_owned());
                    }
                }
            }
            if let Some(ref sc) = cfg.sasl_plain.clone() {
                if let Some(enc) = sc.password.strip_prefix("enc:") {
                    if let Ok(plain) = self.crypto.decrypt(enc).await {
                        cfg.sasl_plain = Some(crate::SaslConfig {
                            account:  sc.account.clone(),
                            password: String::from_utf8_lossy(&plain).into_owned(),
                        });
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
