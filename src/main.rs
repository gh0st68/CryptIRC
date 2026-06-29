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
use tokio::sync::{broadcast, Mutex, Semaphore};
use tracing::{error, info, warn};
use uuid::Uuid;

mod auth;
mod captcha;
mod certs;
mod crypto;
mod e2e;
mod email;
mod irc;
mod lastfm;
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
    /// JoinHandle of the currently-running connect() task per conn_id.
    /// Aborting this handle kills the reconnect loop deterministically — replaces
    /// the old "set flag + sleep 200ms + clear flag" race that let zombie tasks
    /// survive a disconnect and reconnect in parallel with the new task.
    pub connect_tasks:       Arc<DashMap<String, tokio::task::JoinHandle<()>>>,
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
    pub max_upload_mb:       Arc<tokio::sync::RwLock<usize>>,
    /// Whether an email address is required to self-register (admin-toggleable; default OFF).
    pub email_required:      Arc<tokio::sync::RwLock<bool>>,
    /// Whether the signup captcha is enforced (admin-toggleable; default ON).
    pub captcha_enabled:     Arc<tokio::sync::RwLock<bool>>,
    /// Last.fm now-playing: feature on/off + the shared API key (admin-controlled).
    pub lastfm_enabled:      Arc<tokio::sync::RwLock<bool>>,
    pub lastfm_api_key:      Arc<tokio::sync::RwLock<String>>,
    /// Live signup captchas: id -> (answer, expires_at unix secs). One-time use, short TTL.
    pub captchas:            Arc<DashMap<String, (i64, i64)>>,
    pub admin_settings_lock: Arc<tokio::sync::Mutex<()>>,
    pub base_path:           String,
    pub static_index:        Arc<String>,
    pub static_manifest:     Arc<String>,
    pub static_sw:           Arc<String>,
    pub static_app_js:       Arc<String>,
    /// #33: global cap on the number of in-flight outbound link-preview fetches.
    /// Bounds how many slow (up to 5s) outbound sockets / DNS lookups a flood of
    /// /preview requests can hold open at once across all users.
    pub preview_sem:         Arc<Semaphore>,
    /// #33: per-user sliding-window limiter for /preview, keyed by username. Previews
    /// are auto-fetched on render so they're bursty; a dedicated generous bucket here
    /// (rather than the tight 10/60s auth limiter) throttles abuse without breaking
    /// normal scrolling.
    pub preview_rate:        Arc<DashMap<String, (std::time::Instant, u32)>>,
    /// Admin-controlled GIF picker provider/policy. provider = "giphy" | "tenor";
    /// mode = "off" | "user" (each user supplies their own key) | "server" (the
    /// instance proxies through the admin's shared key, with a user's personal key
    /// taking precedence if they set one). Server keys are held here and NEVER sent
    /// to non-admin clients — only the active provider + mode are exposed.
    pub gif_provider:        Arc<tokio::sync::RwLock<String>>,
    pub gif_mode:            Arc<tokio::sync::RwLock<String>>,
    pub giphy_server_key:    Arc<tokio::sync::RwLock<String>>,
    pub tenor_server_key:    Arc<tokio::sync::RwLock<String>>,
    /// Per-user sliding-window limiter for the GIF search proxy — protects the
    /// shared server key's quota from one user hammering it.
    pub gif_rate:            Arc<DashMap<String, (std::time::Instant, u32)>>,
    /// Shared outbound HTTP client for the GIF proxy (fixed hosts, so no SSRF risk).
    pub gif_client:          reqwest::Client,
}

/// #33: max simultaneous outbound link-preview fetches, process-wide.
const PREVIEW_MAX_CONCURRENT: usize = 8;
/// #33: per-user /preview budget and window. Generous enough for normal
/// auto-preview-on-render scrolling, tight enough to stop an abuse loop.
const PREVIEW_RATE_MAX: u32 = 30;
const PREVIEW_RATE_WINDOW_SECS: u64 = 60;
/// Per-user GIF-search budget (the picker debounces, so this is per live search).
const GIF_RATE_MAX: u32 = 40;
const GIF_RATE_WINDOW_SECS: u64 = 60;

impl AppState {
    pub fn user_tx(&self, username: &str) -> broadcast::Sender<ServerEvent> {
        self.user_events
            .entry(username.to_string())
            .or_insert_with(|| broadcast::channel(128).0)
            .clone()
    }
    /// Subscribe to a user's broadcast WITHOUT a remove race. Subscribing while the
    /// DashMap entry guard is still held means receiver_count() becomes 1 before the
    /// shard lock is released, so a concurrent prune_user_events (which must take the
    /// same shard lock for remove_if) can never observe count==0 and delete the sender
    /// in the window between create and subscribe — which would have orphaned this
    /// receiver (its sender dropped, future events routed to a freshly-created channel).
    /// Behaviorally identical to `user_tx(u).subscribe()`, just race-free.
    pub fn user_subscribe(&self, username: &str) -> broadcast::Receiver<ServerEvent> {
        self.user_events
            .entry(username.to_string())
            .or_insert_with(|| broadcast::channel(128).0)
            .subscribe()
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
        for k in stale {
            // Re-check receiver_count under remove: a WS subscribe in the window between
            // the snapshot and here may have created a receiver on this exact sender.
            // An unconditional remove() would drop that live sender and orphan the
            // subscriber (its events would silently vanish). remove_if only deletes if
            // the channel still has no receivers at removal time.
            self.user_events.remove_if(&k, |_, tx| tx.receiver_count() == 0);
        }
    }

    /// #87: Drop finished/aborted connect-task JoinHandles so connect_tasks doesn't
    /// accumulate dead handles for the process lifetime.
    pub fn prune_finished_connect_tasks(&self) {
        let dead: Vec<String> = self.connect_tasks.iter()
            .filter(|e| e.value().is_finished())
            .map(|e| e.key().clone())
            .collect();
        for k in dead {
            // Re-check under remove to tolerate a concurrent re-insert for the same id.
            self.connect_tasks.remove_if(&k, |_, h| h.is_finished());
        }
    }

    /// #106: Drop per-user active-session counters that are back at zero so the
    /// active_sessions map doesn't retain one entry per username forever.
    pub fn prune_idle_active_sessions(&self) {
        let idle: Vec<String> = self.active_sessions.iter()
            .filter(|e| e.value().load(Ordering::Acquire) == 0)
            .map(|e| e.key().clone())
            .collect();
        for k in idle {
            // Re-check under remove to avoid racing a concurrent connect that just
            // incremented the counter on this same Arc. Also require the Arc to be
            // uniquely owned (strong_count==1 => only the map holds it): a live socket
            // may hold a clone of an idle (count==0) counter, and detaching it would
            // orphan that socket's counter so user_is_idle() spuriously returns true.
            self.active_sessions.remove_if(&k, |_, c| {
                c.load(Ordering::Acquire) == 0 && Arc::strong_count(c) == 1
            });
        }
    }
    /// #33: per-user sliding-window check for outbound link-preview fetches.
    /// Returns true if the caller is within budget (and counts this call), false if
    /// over budget. Pruned opportunistically: the entry resets once its window
    /// elapses, so the map self-cleans for active users without a sweeper.
    pub fn preview_rate_ok(&self, username: &str) -> bool {
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(PREVIEW_RATE_WINDOW_SECS);
        let mut e = self.preview_rate.entry(username.to_string()).or_insert((now, 0));
        let (start, count) = &mut *e;
        if now.duration_since(*start) > window {
            *start = now;
            *count = 0;
        }
        *count += 1;
        *count <= PREVIEW_RATE_MAX
    }
    /// Per-user sliding-window rate gate for the GIF search proxy.
    pub fn gif_rate_ok(&self, username: &str) -> bool {
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(GIF_RATE_WINDOW_SECS);
        let mut e = self.gif_rate.entry(username.to_string()).or_insert((now, 0));
        let (start, count) = &mut *e;
        if now.duration_since(*start) > window {
            *start = now;
            *count = 0;
        }
        *count += 1;
        *count <= GIF_RATE_MAX
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
    /// Abort and drop the tracked connect() task for this conn_id, if any.
    /// Callers MUST also remove state.connections / state.conn_owners since the
    /// aborted task won't run its cleanup path.
    pub fn abort_connect_task(&self, conn_id: &str) {
        if let Some((_, handle)) = self.connect_tasks.remove(conn_id) {
            handle.abort();
        }
    }

    /// Fully tear down and erase an account: QUIT + drop its live IRC connections,
    /// delete its auth/vault/network/e2e/log data, and remove all on-disk residue
    /// (uploads, push subscriptions, notification prefs, abandoned chunked uploads).
    /// Shared by the self-service WS DeleteAccount handler and the admin delete route
    /// so the two paths can never drift — an admin delete must leave no more residue,
    /// and no more auto-reconnecting ghost connection, than a self-service delete.
    /// `username` is canonicalised (trim+lowercase) and rejected if not a legitimate
    /// username, so an admin-supplied path component can't escape the data dir.
    pub async fn purge_account(&self, username: &str) {
        let uname = username.trim().to_lowercase();
        if !crate::auth::is_safe_username(&uname) { return; }
        // Disconnect every IRC connection owned by this user FIRST, so no auto-
        // reconnecting task survives to keep a ghost session online as the deleted user.
        let conns: Vec<String> = self.conn_owners.iter()
            .filter(|e| e.value() == &uname)
            .map(|e| e.key().clone())
            .collect();
        for cid in &conns {
            // #20: clone the Arc out and drop the DashMap Ref before awaiting.
            let conn = self.connections.get(cid).map(|c| c.clone());
            if let Some(conn) = conn {
                let mut c = conn.lock().await;
                let _ = c.send_raw("QUIT :Account deleted\r\n").await;
            }
            self.abort_connect_task(cid);
            self.connections.remove(cid);
            self.conn_owners.remove(cid);
            self.clear_disconnect_request(cid);
        }
        // Delete account data (auth/vault/networks/e2e/logs/sessions).
        self.auth.delete_account(&uname).await;
        // delete_account leaves uploaded files, push subscriptions, notif prefs and
        // abandoned chunked uploads on disk. Clear them too so deletion leaves no
        // residue — critical because a later re-registration of the SAME username
        // would otherwise inherit them (e.g. push notifications routed to the prior
        // owner's devices). Mirrors the path scheme notifications.rs uses
        // ({data_dir}/push/{safe}.json, {data_dir}/notif_prefs/{safe}.json).
        upload::clear_user_uploads(&self.data_dir, &self.upload_dir, &uname).await;
        let safe_name: String = uname.chars()
            .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
            .collect();
        let push_file = std::path::PathBuf::from(&self.data_dir)
            .join("push").join(format!("{}.json", safe_name));
        let prefs_file = std::path::PathBuf::from(&self.data_dir)
            .join("notif_prefs").join(format!("{}.json", safe_name));
        let _ = tokio::fs::remove_file(&push_file).await;
        let _ = tokio::fs::remove_file(&prefs_file).await;
        if let Some(inprog) = upload::user_inprogress_dir(&self.data_dir, &uname) {
            let _ = tokio::fs::remove_dir_all(&inprog).await;
        }
        // Tear down the crypto vault (zeroize+drop the in-memory master key AND remove the
        // on-disk vault salt/canary/mkey) so a re-registered same-name account can't inherit
        // the prior owner's still-unlocked vault: the WS handshake calls is_unlocked(username)
        // and, if true, hands the new session VaultUnlocked + derive_e2e_enc_key(username) —
        // the PRIOR owner's E2E key — with no passphrase. (A stale on-disk vault.mkey would
        // also permanently lock the re-registered user out of their own vault.) This MUST run
        // under the vault_lock — hence purge_vault, not a bare lock()+remove_dir_all — so a
        // concurrent unlock()/change_passphrase() can't re-insert the key after teardown.
        self.crypto.purge_vault(&uname).await;
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
    SearchLogs       { conn_id: String, target: String, query: String, limit: Option<usize> },
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
    // Permanently delete logs for a single chat/PM target
    ClearTargetLogs   { conn_id: String, target: String },
    // Uploads channel — list seed + remove
    UploadListGet     {},
    UploadRemove      { id: String },
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
    /// Away snapshot from a WHO poll — for servers without away-notify (e.g. ircd-ratbox).
    /// `away_nicks` are the members of `channel` currently flagged away (G in the WHO reply);
    /// every other current member of `channel` is implicitly back/here.
    IrcAwaySnapshot  { conn_id: String, channel: String, away_nicks: Vec<String> },
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
    /// 367/348/346 — single list entry; `list` is "b" (ban), "e" (exempt) or "I" (invex)
    IrcBanEntry      { conn_id: String, channel: String, mask: String, set_by: String, ts: i64, list: String },
    /// 368/349/347 — end of a list; `list` matches the entry list letter
    IrcBanEnd        { conn_id: String, channel: String, list: String },
    /// 324 — RPL_CHANNELMODEIS: the channel's current mode string (e.g. "+mnt" or "+ntkl key 50")
    IrcChannelModes  { conn_id: String, channel: String, modes: String },
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
    SearchResults    { conn_id: String, target: String, query: String, lines: Vec<LogLine> },
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
    TargetCleared    { conn_id: String, target: String },
    /// Initial seed of the user's persistent upload list. Sent on auth, and
    /// in response to `UploadListGet`.
    UploadState      { records: Vec<upload::UploadRecord> },
    /// One row changed — created, progressed, completed, errored, canceled.
    UploadUpdate     { record: upload::UploadRecord },
    /// A row was removed from the list entirely (Remove button).
    UploadRemoved    { id: String },
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
    #[serde(default)]
    pub channel_keys:          std::collections::HashMap<String, String>,
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
    // Perform: raw IRC (or /slash) commands fired once, after registration + NickServ, before auto-join
    #[serde(default)]
    pub perform_commands:      Vec<String>,
    // Per-network user-configurable QUIT reason. None / empty → bot uses
    // DEFAULT_QUIT_MESSAGE (advertises CryptIRC). Account-deletion has its
    // own fixed reason and ignores this.
    #[serde(default)]
    pub quit_message:          Option<String>,
}

/// Default QUIT reason sent when the user hasn't customized one. Doubles as
/// soft advertising for CryptIRC on every disconnect, reconnect, or network
/// switch — keep it short (well under 200 chars) so no server truncates it.
pub const DEFAULT_QUIT_MESSAGE: &str = "CryptIRC — end-to-end encrypted IRC client — https://github.com/gh0st68/CryptIRC";

/// Pick the QUIT reason for a given network config: custom (trimmed, non-empty)
/// if set, else the default advertising string.
pub fn quit_reason_for(cfg: &NetworkConfig) -> &str {
    match cfg.quit_message.as_deref() {
        Some(s) if !s.trim().is_empty() => s,
        _ => DEFAULT_QUIT_MESSAGE,
    }
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
            auto_join: vec![], auto_reconnect: true, channel_keys: std::collections::HashMap::new(),
            oper_login: None, oper_pass: None,
            channel_order: vec![],
            nickserv_pass: None, auto_identify: false,
            disabled_caps: vec![],
            perform_commands: vec![],
            quit_message: None,
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

#[derive(Deserialize)] struct RegisterBody      { username: String, #[serde(default)] email: String, password: String, #[serde(default)] code: String, #[serde(default)] captcha_id: String, #[serde(default)] captcha_answer: String }
#[derive(Deserialize)] struct LoginBody          { username: String, password: String, #[serde(default)] captcha_id: String, #[serde(default)] captcha_answer: String }
#[derive(Deserialize)] struct VerifyQuery        { token: String }
#[derive(Deserialize)] struct ForgotBody         { email: String }
#[derive(Deserialize)] struct ResetQuery         { token: String }
#[derive(Deserialize)] struct ResetPasswordBody  { token: String, password: String }
#[derive(Deserialize)] struct FileQuery    { token: Option<String> }
#[derive(Serialize)]   struct AuthOkBody   { token: String, username: String }
#[derive(Serialize)]   struct LoginErr     { message: String, captcha_required: bool }
#[derive(Serialize)]   struct MeOk         { username: String, email: String, admin: bool, lastfm_user: String, lastfm_enabled: bool, lastfm_own_key: bool }
#[derive(Serialize)]   struct Msg          { message: String }

/// S6: Maximum size of a single inbound WebSocket text message.
/// Prevents a client from sending a huge JSON payload to exhaust parser memory.
const WS_MAX_MSG_BYTES: usize = 64 * 1024; // 64 KB

/// #34: Maximum number of saved networks per user. Each network spawns one
/// outbound IRC connection on vault unlock, so this bounds the connection /
/// file-descriptor / task fan-out a single account can force.
const MAX_NETWORKS_PER_USER: usize = 20;

/// #35: Maximum WebSocket commands a single socket may dispatch per second.
/// Several commands do real per-message disk I/O (Send → log append, JOIN/PART
/// → config rewrite, SaveNotepad/Stats/Passwords → AES-GCM + file write), so an
/// unthrottled flood degrades the shared runtime for all users.
const WS_MAX_CMDS_PER_SEC: u32 = 40;

/// Process-wide cap on concurrent 64-MiB Argon2id derivations (UnlockVault /
/// ChangePassphrase). The per-user KDF rate limit bounds one account, but many
/// accounts unlocking at once could still hold a large number of 64-MiB
/// allocations live simultaneously and exhaust RAM. This global semaphore bounds
/// the number of in-flight KDF derivations across ALL users; per-user behavior is
/// unchanged (a permit is acquired only for the duration of the derive).
const KDF_MAX_CONCURRENT: usize = 4;
static KDF_SEM: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();
fn kdf_sem() -> &'static Semaphore {
    KDF_SEM.get_or_init(|| Semaphore::new(KDF_MAX_CONCURRENT))
}


async fn security_headers_mw(req: Request<Body>, next: Next) -> Response {
    let mut response = next.run(req).await;
    let h = response.headers_mut();
    h.insert(HeaderName::from_static("x-frame-options"),          HeaderValue::from_static("DENY"));
    h.insert(HeaderName::from_static("x-content-type-options"),   HeaderValue::from_static("nosniff"));
    h.insert(HeaderName::from_static("referrer-policy"),          HeaderValue::from_static("no-referrer"));
    h.insert(HeaderName::from_static("permissions-policy"),       HeaderValue::from_static("camera=(), microphone=(), geolocation=()"));
    // #54: HSTS. The app is served over HTTPS behind a reverse proxy (the :80
    // vhost 301s to https). Without HSTS the first request is sent in cleartext
    // and is SSL-strippable — directly undermining the transit-confidentiality
    // threat model that protects the bearer token and vault passphrase.
    //
    // Gated by CRYPTIRC_HSTS so a SELF-SIGNED / bare-IP deployment can turn it
    // OFF: with a self-signed cert, HSTS makes the browser refuse the cert-warning
    // click-through and would lock every visitor out for 2 years. Default = on.
    static HSTS_ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *HSTS_ON.get_or_init(|| std::env::var("CRYPTIRC_HSTS").map(|v| v != "off").unwrap_or(true)) {
        h.insert(HeaderName::from_static("strict-transport-security"),
                 HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"));
    }
    // NOTE (#55): script-src still includes 'unsafe-inline' because the frontend
    // (static/app.js inline onclick handlers + static/index.html theme bootstrap
    // script) currently requires it. 'unsafe-inline' cannot be dropped here until
    // those inline handlers/scripts are removed/nonce'd (frontend change, see #3/#9/#10).
    h.insert(HeaderName::from_static("content-security-policy"),  HeaderValue::from_static(
        "default-src 'self'; object-src 'none'; base-uri 'self'; script-src 'self' 'unsafe-inline'; \
         style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
         font-src https://fonts.gstatic.com; img-src 'self' data: https:; \
         connect-src 'self' wss: ws: https://noembed.com https://returnyoutubedislikeapi.com https://api.urbandictionary.com https://api.giphy.com https://tenor.googleapis.com; \
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
    let (registration_open, reg_code, max_upload_mb) = if admin_settings_path.exists() {
        let json = std::fs::read_to_string(&admin_settings_path).unwrap_or_default();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
        let open = v.get("registration_open").and_then(|v| v.as_bool()).unwrap_or(true);
        let code = v.get("registration_code").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let upload_mb = v.get("max_upload_mb").and_then(|v| v.as_u64()).unwrap_or(25) as usize;
        info!("Loaded admin settings from disk (registration_open={}, has_code={}, max_upload_mb={})", open, !code.is_empty(), upload_mb);
        (open, code, upload_mb)
    } else {
        let open = std::env::var("CRYPTIRC_REGISTRATION").unwrap_or_else(|_| "open".into()) != "closed";
        let code = std::env::var("CRYPTIRC_REG_CODE").unwrap_or_default();
        (open, code, 25)
    };
    // GIF picker policy (admin-controlled). Defaults preserve today's behavior
    // exactly: provider=giphy, mode=user (everyone uses their own key). Loaded
    // from the same admin_settings.json so it survives restarts.
    let (gif_provider, gif_mode, giphy_server_key, tenor_server_key) = {
        let v: serde_json::Value = if admin_settings_path.exists() {
            serde_json::from_str(&std::fs::read_to_string(&admin_settings_path).unwrap_or_default()).unwrap_or_default()
        } else { serde_json::json!({}) };
        let provider = v.get("gif_provider").and_then(|x| x.as_str()).unwrap_or("giphy").to_string();
        let mode = v.get("gif_mode").and_then(|x| x.as_str()).unwrap_or("user").to_string();
        let gk = v.get("giphy_server_key").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let tk = v.get("tenor_server_key").and_then(|x| x.as_str()).unwrap_or("").to_string();
        (provider, mode, gk, tk)
    };
    // Email-required + signup-captcha policy (admin-controlled). Defaults: email OPTIONAL
    // (email_required=false) and captcha ON. Persisted in the same admin_settings.json.
    let (email_required, captcha_enabled) = {
        let v: serde_json::Value = if admin_settings_path.exists() {
            serde_json::from_str(&std::fs::read_to_string(&admin_settings_path).unwrap_or_default()).unwrap_or_default()
        } else { serde_json::json!({}) };
        let er = v.get("email_required").and_then(|x| x.as_bool()).unwrap_or(false);
        let ce = v.get("captcha_enabled").and_then(|x| x.as_bool()).unwrap_or(true);
        (er, ce)
    };
    // Last.fm now-playing (admin-controlled). Default OFF; shared API key blank.
    let (lastfm_enabled, lastfm_api_key) = {
        let v: serde_json::Value = if admin_settings_path.exists() {
            serde_json::from_str(&std::fs::read_to_string(&admin_settings_path).unwrap_or_default()).unwrap_or_default()
        } else { serde_json::json!({}) };
        let en = v.get("lastfm_enabled").and_then(|x| x.as_bool()).unwrap_or(false);
        let key = v.get("lastfm_api_key").and_then(|x| x.as_str()).unwrap_or("").to_string();
        (en, key)
    };
    let gif_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build().unwrap_or_else(|_| reqwest::Client::new());
    // #7: create the data dir and all subtrees with mode 0700 so at-rest secrets
    // (vault salts, Argon2 hashes, VAPID key, client TLS keys, encrypted configs)
    // are not world-readable. On a host shared with other local accounts, the
    // inherited umask (0022) would otherwise leave these 0755/0644.
    create_dir_secure(&data_dir)?;
    create_dir_secure(&upload_dir)?;
    create_dir_secure(&format!("{}/certs", data_dir))?;
    // Tighten the top-level data dir itself in case it pre-existed at 0755.
    harden_dir_perms(&data_dir);

    let crypto   = Arc::new(CryptoManager::new(&data_dir)?);
    // Migrate legacy shared vault to per-user vaults if needed
    crypto.migrate_legacy_vault().await?;
    create_dir_secure(&format!("{}/vaults", data_dir))?;
    let certs    = Arc::new(CertStore::new(&data_dir, crypto.clone()));
    let logger   = Arc::new(EncryptedLogger::new(&data_dir, crypto.clone()));
    let auth     = Arc::new(AuthManager::new(&data_dir)?);
    let vapid    = notifications::load_or_generate_vapid(&data_dir)?;
    let notifier = Arc::new(NotificationManager::new(&data_dir, vapid));
    let e2e_store = Arc::new(E2EStore::new(&data_dir));
    let paste_store = Arc::new(paste::PasteStore::new(&data_dir));
    let preview_service = Arc::new(preview::PreviewService::new(&data_dir));

    let base_path = std::env::var("CRYPTIRC_BASE_PATH").unwrap_or_else(|_| "/cryptirc".into());
    let bp_trimmed = base_path.trim_end_matches('/');
    let static_index    = Arc::new(include_str!("../static/index.html").replace("/cryptirc", bp_trimmed));
    let static_manifest = Arc::new(include_str!("../static/manifest.json").replace("/cryptirc", bp_trimmed));
    let static_sw       = Arc::new(include_str!("../static/sw.js").replace("/cryptirc", bp_trimmed));
    // app.js holds the main frontend script (extracted verbatim from index.html).
    // It contains /cryptirc asset/WS paths, so it needs the same base-path rewrite.
    let static_app_js   = Arc::new(include_str!("../static/app.js").replace("/cryptirc", bp_trimmed).replace("__CRYPTIRC_BUILD__", option_env!("CRYPTIRC_BUILD").unwrap_or("dev")));

    let state = AppState {
        connections:         Arc::new(DashMap::new()),
        conn_owners:         Arc::new(DashMap::new()),
        disconnect_requests: Arc::new(DashSet::new()),
        connect_tasks:       Arc::new(DashMap::new()),
        crypto, certs, logger, auth, notifier, e2e_store, paste_store, preview_service,
        user_events:         Arc::new(DashMap::new()),
        active_sessions:     Arc::new(DashMap::new()),
        upload_dir, base_url, from_email,
        data_dir: data_dir.clone(),
        registration_open: Arc::new(tokio::sync::RwLock::new(registration_open)),
        registration_code: Arc::new(tokio::sync::RwLock::new(reg_code)),
        max_upload_mb:     Arc::new(tokio::sync::RwLock::new(max_upload_mb)),
        email_required:    Arc::new(tokio::sync::RwLock::new(email_required)),
        captcha_enabled:   Arc::new(tokio::sync::RwLock::new(captcha_enabled)),
        lastfm_enabled:    Arc::new(tokio::sync::RwLock::new(lastfm_enabled)),
        lastfm_api_key:    Arc::new(tokio::sync::RwLock::new(lastfm_api_key)),
        captchas:          Arc::new(DashMap::new()),
        admin_settings_lock: Arc::new(tokio::sync::Mutex::new(())),
        base_path: bp_trimmed.to_string(),
        static_index, static_manifest, static_sw, static_app_js,
        // #33: bound outbound link-preview fetch concurrency + per-user rate.
        preview_sem:  Arc::new(Semaphore::new(PREVIEW_MAX_CONCURRENT)),
        preview_rate: Arc::new(DashMap::new()),
        gif_provider:     Arc::new(tokio::sync::RwLock::new(gif_provider)),
        gif_mode:         Arc::new(tokio::sync::RwLock::new(gif_mode)),
        giphy_server_key: Arc::new(tokio::sync::RwLock::new(giphy_server_key)),
        tenor_server_key: Arc::new(tokio::sync::RwLock::new(tenor_server_key)),
        gif_rate:         Arc::new(DashMap::new()),
        gif_client,
    };

    // #31: sweep abandoned in-progress chunked uploads once at startup so a restart
    // reclaims disk left by uploads whose client died before finalize/cancel.
    {
        let dd = data_dir.clone();
        tokio::spawn(async move {
            let n = upload::sweep_stale_inprogress(&dd, std::time::Duration::from_secs(86400)).await;
            if n > 0 { info!("[upload] swept {} stale in-progress upload(s) at startup", n); }
        });
    }

    // Background: purge expired sessions and stale user events hourly
    { let a = state.auth.clone(); let s = state.clone();
      tokio::spawn(async move {
          let mut iv = tokio::time::interval(tokio::time::Duration::from_secs(3600));
          loop {
              iv.tick().await;
              a.purge_expired_sessions();
              // Prune expired on-disk reset tokens + abandoned pending email-verifications
              // (resets/, pending/) so they don't accumulate forever or slow the auth scans.
              a.sweep_expired_tokens().await;
              s.prune_user_events();
              s.paste_store.cleanup_expired().await;
              // #87/#106: prune finished/aborted connect tasks and idle per-user
              // active-session counters so these maps don't grow unboundedly.
              s.prune_finished_connect_tasks();
              s.prune_idle_active_sessions();
              // #31: reclaim disk from abandoned in-progress chunked uploads whose
              // client never finalized/canceled (TTL 24h). Clears the dead_code
              // warning on sweep_stale_inprogress.
              let _ = upload::sweep_stale_inprogress(&s.data_dir, std::time::Duration::from_secs(86400)).await;
              // Prune the per-network-config lock map: an AddNetwork→RemoveNetwork
              // loop mints a fresh (username:conn_id) entry each cycle and never
              // removed it, growing this static map without bound. Entries with
              // strong_count==1 have no in-flight holder (a live op always holds a
              // clone, so count>=2) and are safe to drop.
              prune_network_config_locks();
          }
      });
    }

    // Outer body cap for the legacy multipart /upload endpoint. handle_upload
    // buffers the whole field in RAM before its own size check, so a fixed 500MB
    // layer let any uploader force ~500MB allocations regardless of the admin's
    // max_upload_mb. Track the configured size (+1MB multipart framing overhead)
    // instead. The chunked path (/upload/init+chunk, what the frontend actually
    // uses) is unaffected; the live per-request limit is still re-checked inside
    // handle_upload against the runtime max_upload_mb.
    let legacy_upload_limit = max_upload_mb
        .clamp(1, 500)
        .saturating_mul(1024 * 1024)
        .saturating_add(1024 * 1024);

    let inner = Router::new()
        .route("/",                      get(serve_index))
        .route("/Sortable.min.js",       get(serve_sortable_js))
        .route("/e2e.js",                get(serve_e2e_js))
        .route("/esheep.js",             get(serve_esheep_js))
        .route("/crab.js",               get(serve_crab_js))
        .route("/ghost.js",              get(serve_ghost_js))
        .route("/fish.js",               get(serve_fish_js))
        .route("/alien.js",              get(serve_alien_js))
        .route("/app.js",                get(serve_app_js))
        .route("/manifest.json",         get(serve_manifest))
        .route("/sw.js",                 get(serve_sw))
        .route("/icon.svg",              get(serve_icon))
        .route("/icon-192.png",          get(serve_icon_192))
        .route("/icon-512.png",          get(serve_icon_512))
        .route("/sounds/:name",          get(serve_sound))
        .route("/fonts/:name",           get(serve_font))
        .route("/auth/register",         post(route_register).layer(DefaultBodyLimit::max(8_192)))
        .route("/auth/status",           get(route_auth_status))
        .route("/auth/captcha",          get(route_captcha))
        .route("/auth/set-email",        post(route_set_email).layer(DefaultBodyLimit::max(8_192)))
        .route("/auth/lastfm",           post(route_set_lastfm).layer(DefaultBodyLimit::max(4_096)))
        .route("/api/lastfm/np",         get(route_lastfm_np))
        .route("/admin/users",           get(route_admin_users))
        .route("/admin/user/:username",  axum::routing::delete(route_admin_delete_user))
        .route("/admin/user/:username/disable", post(route_admin_disable_user))
        .route("/admin/user/:username/approve", post(route_admin_approve_user))
        .route("/admin/user/:username/email", post(route_admin_set_email).layer(DefaultBodyLimit::max(8_192)))
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
        .route("/upload",                post(route_upload).layer(DefaultBodyLimit::max(legacy_upload_limit)))
        .route("/upload/init",           post(route_upload_init).layer(DefaultBodyLimit::max(4_096)))
        .route("/upload/chunk/:id",      post(route_upload_chunk).layer(DefaultBodyLimit::max(64 * 1024 * 1024)))
        .route("/upload/status/:id",     get(route_upload_status))
        .route("/upload/finalize/:id",   post(route_upload_finalize))
        .route("/upload/cancel/:id",     post(route_upload_cancel))
        .route("/upload/error/:id",      post(route_upload_error).layer(DefaultBodyLimit::max(4_096)))
        .route("/uploads",               get(route_uploads_list))
        .route("/uploads/delete",        post(route_uploads_delete).layer(DefaultBodyLimit::max(4_096)))
        .route("/uploads/clear",         post(route_uploads_clear))
        .route("/auth/sessions",         get(route_sessions_list))
        .route("/auth/sessions/revoke",  post(route_sessions_revoke).layer(DefaultBodyLimit::max(4_096)))
        .route("/files/:name",           get(serve_file))
        .route("/pub/:name",            get(serve_file_public))
        .route("/paste",                post(route_paste_create).layer(DefaultBodyLimit::max(524_288)))
        .route("/paste/:id",            get(route_paste_view).post(route_paste_view_post))
        .route("/paste/:id/raw",        get(route_paste_raw))
        .route("/s",                    post(route_short_create).layer(DefaultBodyLimit::max(4_096)))
        .route("/s/:id",                get(route_short_redirect))
        .route("/preview",              get(route_link_preview))
        .route("/admin/link-preview",   get(route_admin_get_preview_settings).put(route_admin_put_preview_settings))
        .route("/api/gif/config",       get(route_gif_config))
        .route("/api/gif/search",       get(route_gif_search))
        .route("/push/vapid-public-key", get(route_push_vapid_key))
        .route("/push/subscribe",        post(route_push_subscribe).layer(DefaultBodyLimit::max(4_096)))
        .route("/push/subscribe",        axum::routing::delete(route_push_unsubscribe).layer(DefaultBodyLimit::max(2_048)))
        .route("/push/settings",         get(route_push_get_settings))
        .route("/push/settings",         axum::routing::put(route_push_put_settings).layer(DefaultBodyLimit::max(4_096)))
        .route("/push/test",             post(route_push_test))
        // E2E public key bundle (unauthenticated — public keys are public)
        .route("/e2e/bundle/:username",  get(route_e2e_get_bundle))
        .route("/ws",                    get(ws_handler));

    let bp = &state.base_path;
    let app = if bp.is_empty() || bp == "/" {
        // Base path is root — no nesting needed
        inner
            .layer(middleware::from_fn(security_headers_mw))
            .with_state(state)
    } else {
        Router::new()
            .nest(bp, inner)
            .route(&format!("{}/", bp), get(serve_index))
            .layer(middleware::from_fn(security_headers_mw))
            .with_state(state)
    };

    let port: u16 = std::env::var("CRYPTIRC_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(9001);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    info!("CryptIRC v0.3 listening on http://{}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

// ─── Static assets ────────────────────────────────────────────────────────────

// no-store on the HTML + service-worker + JS bundles so Electron's Chromium
// (and Safari/Chrome) don't keep serving a stale build after we deploy.
// Without an explicit Cache-Control header, Chromium uses heuristic caching
// (~10% of (now - Last-Modified)) which kept users pinned to old JS for
// minutes-to-hours.
const NO_CACHE: &str = "no-store, no-cache, must-revalidate";
async fn serve_index(State(state): State<AppState>) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8"),
      (header::CACHE_CONTROL, NO_CACHE)],
     (*state.static_index).clone())
}
async fn serve_manifest(State(state): State<AppState>) -> impl IntoResponse { ([(header::CONTENT_TYPE,"application/manifest+json"),(header::CACHE_CONTROL,NO_CACHE)], (*state.static_manifest).clone()) }
async fn serve_sw(State(state): State<AppState>) -> impl IntoResponse { ([(header::CONTENT_TYPE,"application/javascript; charset=utf-8"),(header::CACHE_CONTROL,NO_CACHE)], (*state.static_sw).clone()) }
async fn serve_icon()     -> impl IntoResponse { ([(header::CONTENT_TYPE,"image/svg+xml")], include_str!("../static/icon.svg")) }
async fn serve_icon_192() -> impl IntoResponse { ([(header::CONTENT_TYPE,"image/png")], include_bytes!("../static/icon-192.png").as_slice()) }
async fn serve_icon_512() -> impl IntoResponse { ([(header::CONTENT_TYPE,"image/png")], include_bytes!("../static/icon-512.png").as_slice()) }
async fn serve_e2e_js()   -> impl IntoResponse { ([(header::CONTENT_TYPE,"application/javascript; charset=utf-8"),(header::CACHE_CONTROL,NO_CACHE)], include_str!("../static/e2e.js")) }
async fn serve_app_js(State(state): State<AppState>) -> impl IntoResponse { ([(header::CONTENT_TYPE,"application/javascript; charset=utf-8"),(header::CACHE_CONTROL,NO_CACHE)], (*state.static_app_js).clone()) }
async fn serve_sortable_js() -> impl IntoResponse { ([(header::CONTENT_TYPE,"application/javascript; charset=utf-8"),(header::CACHE_CONTROL,NO_CACHE)], include_str!("../static/Sortable.min.js")) }
// Self-contained eSheep desktop-pet engine (sprite + behaviours embedded). No base-path
// rewrite needed: it has no /cryptirc refs and loads its pet inline (no network).
async fn serve_esheep_js() -> impl IntoResponse { ([(header::CONTENT_TYPE,"application/javascript; charset=utf-8"),(header::CACHE_CONTROL,NO_CACHE)], include_str!("../static/esheep.js")) }
async fn serve_crab_js()   -> impl IntoResponse { ([(header::CONTENT_TYPE,"application/javascript; charset=utf-8"),(header::CACHE_CONTROL,NO_CACHE)], include_str!("../static/crab.js")) }
async fn serve_ghost_js()  -> impl IntoResponse { ([(header::CONTENT_TYPE,"application/javascript; charset=utf-8"),(header::CACHE_CONTROL,NO_CACHE)], include_str!("../static/ghost.js")) }
async fn serve_fish_js()   -> impl IntoResponse { ([(header::CONTENT_TYPE,"application/javascript; charset=utf-8"),(header::CACHE_CONTROL,NO_CACHE)], include_str!("../static/fish.js")) }
async fn serve_alien_js()  -> impl IntoResponse { ([(header::CONTENT_TYPE,"application/javascript; charset=utf-8"),(header::CACHE_CONTROL,NO_CACHE)], include_str!("../static/alien.js")) }

// Bundled notification sounds — shipped in the binary so deploys don't need
// external asset files. Served at /sounds/<name>.mp3.
async fn serve_sound(Path(name): Path<String>) -> impl IntoResponse {
    let bytes: Option<&'static [u8]> = match name.as_str() {
        "water-drop.mp3"    => Some(include_bytes!("../static/sounds/water-drop.mp3")),
        "ding.mp3"          => Some(include_bytes!("../static/sounds/ding.mp3")),
        "bell.mp3"          => Some(include_bytes!("../static/sounds/bell.mp3")),
        "pop.mp3"           => Some(include_bytes!("../static/sounds/pop.mp3")),
        "click.mp3"         => Some(include_bytes!("../static/sounds/click.mp3")),
        "ping.mp3"          => Some(include_bytes!("../static/sounds/ping.mp3")),
        "alert.mp3"         => Some(include_bytes!("../static/sounds/alert.mp3")),
        "notice.mp3"        => Some(include_bytes!("../static/sounds/notice.mp3")),
        "correct.mp3"       => Some(include_bytes!("../static/sounds/correct.mp3")),
        "swoosh.mp3"        => Some(include_bytes!("../static/sounds/swoosh.mp3")),
        "door-knock.mp3"    => Some(include_bytes!("../static/sounds/door-knock.mp3")),
        "icq-uhoh.mp3"      => Some(include_bytes!("../static/sounds/icq-uhoh.mp3")),
        "splash.mp3"        => Some(include_bytes!("../static/sounds/splash.mp3")),
        "thud.mp3"          => Some(include_bytes!("../static/sounds/thud.mp3")),
        "pebble.mp3"        => Some(include_bytes!("../static/sounds/pebble.mp3")),
        "cash-register.mp3" => Some(include_bytes!("../static/sounds/cash-register.mp3")),
        "explosion.mp3"     => Some(include_bytes!("../static/sounds/explosion.mp3")),
        "lightning.mp3"     => Some(include_bytes!("../static/sounds/lightning.mp3")),
        _ => None,
    };
    match bytes {
        Some(b) => ([(header::CONTENT_TYPE, "audio/mpeg"), (header::CACHE_CONTROL, "public, max-age=604800")], b).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
async fn serve_font(Path(name): Path<String>) -> impl IntoResponse {
    let (ct, bytes): (&str, Option<&'static [u8]>) = match name.as_str() {
        "spooky.ttf"           => ("font/ttf",  Some(include_bytes!("../static/fonts/spooky.ttf"))),
        "spooky-halloween.ttf" => ("font/ttf",  Some(include_bytes!("../static/fonts/spooky-halloween.ttf"))),
        "spooky-magic.ttf"     => ("font/ttf",  Some(include_bytes!("../static/fonts/spooky-magic.ttf"))),
        "spooky-mother.otf"    => ("font/otf",  Some(include_bytes!("../static/fonts/spooky-mother.otf"))),
        _ => ("application/octet-stream", None),
    };
    match bytes {
        Some(b) => ([(header::CONTENT_TYPE, ct), (header::CACHE_CONTROL, "public, max-age=604800")], b).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

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

/// #15: Extract the real client IP from the proxy headers nginx forwards
/// (X-Real-IP, or the first hop of X-Forwarded-For). Returns None if neither
/// header is present (e.g. a direct-to-:9001 request that bypassed nginx), in
/// which case the auth limiter falls back to a shared bucket. The value is used
/// only as a rate-limit dimension — never logged or persisted (see audit #108).
fn client_ip(headers: &HeaderMap) -> Option<String> {
    if let Some(ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let ip = ip.trim();
        if !ip.is_empty() { return Some(ip.to_string()); }
    }
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        // XFF is a comma-separated list; the left-most entry is the original client.
        if let Some(first) = xff.split(',').next() {
            let first = first.trim();
            if !first.is_empty() { return Some(first.to_string()); }
        }
    }
    None
}

async fn route_auth_status(State(state): State<AppState>) -> impl IntoResponse {
    let open = *state.registration_open.read().await;
    let has_code = !state.registration_code.read().await.is_empty();
    Json(serde_json::json!({
        "registration_open": open,
        "requires_code": has_code,
        "email_required": *state.email_required.read().await,
        "captcha_enabled": *state.captcha_enabled.read().await,
    }))
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
    // Full teardown (disconnect live IRC connections + delete data + clear residue),
    // identical to the self-service path — not just delete_account, which would leave an
    // auto-reconnecting ghost connection online and orphaned push/prefs/upload files that
    // a re-registered same-name account could inherit.
    state.purge_account(&target).await;
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

async fn route_admin_approve_user(State(state): State<AppState>, headers: HeaderMap, Path(target): Path<String>) -> impl IntoResponse {
    let Some(user) = extract_session_user(&state, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !state.auth.is_admin(&user).await {
        return StatusCode::FORBIDDEN.into_response();
    }
    // Approve = verify the account without requiring the email link, and clear its pending
    // verification record. Idempotent; harmless if the user is already verified.
    match state.auth.approve_user(&target).await {
        Ok(_) => (StatusCode::OK, Json(Msg { message: format!("User '{}' approved.", target) })).into_response(),
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
    let upload_mb = *state.max_upload_mb.read().await;
    let giphy_key = state.giphy_server_key.read().await.clone();
    let tenor_key = state.tenor_server_key.read().await.clone();
    let lastfm_key = state.lastfm_api_key.read().await.clone();
    Json(serde_json::json!({
        "registration_open": open,
        "registration_code": code,
        "max_upload_mb": upload_mb,
        "email_required": *state.email_required.read().await,
        "captcha_enabled": *state.captcha_enabled.read().await,
        // GIF policy: provider + mode + whether each shared key is set (masked, never raw).
        "gif_provider": state.gif_provider.read().await.clone(),
        "gif_mode": state.gif_mode.read().await.clone(),
        "giphy_key_set": !giphy_key.is_empty(),
        "tenor_key_set": !tenor_key.is_empty(),
        "giphy_key_masked": mask_key(&giphy_key),
        "tenor_key_masked": mask_key(&tenor_key),
        "lastfm_enabled": *state.lastfm_enabled.read().await,
        "lastfm_key_set": !lastfm_key.is_empty(),
        "lastfm_key_masked": mask_key(&lastfm_key),
    })).into_response()
}

#[derive(Deserialize)]
struct AdminSettings {
    registration_open: Option<bool>,
    registration_code: Option<String>,
    max_upload_mb: Option<usize>,
    // Signup policy (optional; omitted = keep current).
    email_required: Option<bool>,
    captcha_enabled: Option<bool>,
    // GIF picker policy (all optional; omitted/blank = keep current).
    gif_provider: Option<String>,
    gif_mode: Option<String>,
    giphy_server_key: Option<String>,
    tenor_server_key: Option<String>,
    // Last.fm (optional; omitted = keep current, blank key = keep current).
    lastfm_enabled: Option<bool>,
    lastfm_api_key: Option<String>,
}

/// Mask a secret for display in the admin UI: "abcd…yz", never the full key.
fn mask_key(k: &str) -> String {
    if k.is_empty() { return String::new(); }
    // Slice by chars, not bytes — a non-ASCII key would panic on a byte boundary.
    let chars: Vec<char> = k.chars().collect();
    if chars.len() < 8 { return format!("{}…", chars[0]); }
    let first: String = chars[..4].iter().collect();
    let last:  String = chars[chars.len()-2..].iter().collect();
    format!("{}…{}", first, last)
}

#[derive(Deserialize)]
struct AdminAddUser { username: String, password: String, #[serde(default)] email: String }

async fn route_admin_add_user(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<AdminAddUser>) -> impl IntoResponse {
    let Some(user) = extract_session_user(&state, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !state.auth.is_admin(&user).await {
        return StatusCode::FORBIDDEN.into_response();
    }
    // Admin-created users: email is genuinely optional (blank = no email on file, not a fake
    // @localhost address). email_required=false so register() never demands one and auto-
    // verifies; set_verified(true) below is then a belt-and-suspenders.
    let email = body.email.trim().to_string();
    match state.auth.register(&body.username, &email, &body.password, None, false).await {
        Ok(_outcome) => {
            // Auto-verify (admin-created users don't need email verification). Go through
            // set_verified so the read-modify-write runs under the per-user lock + atomic
            // write like every other mutator — the old raw unlocked write here could race a
            // concurrent mutator and left a crash-truncation window. Best-effort as before.
            let _ = state.auth.set_verified(&body.username.to_lowercase(), true).await;
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
    if let Some(mb) = body.max_upload_mb {
        // Clamp to 1–500 MB
        let clamped = mb.clamp(1, 500);
        *state.max_upload_mb.write().await = clamped;
    }
    if let Some(er) = body.email_required {
        *state.email_required.write().await = er;
    }
    if let Some(ce) = body.captcha_enabled {
        *state.captcha_enabled.write().await = ce;
    }
    // GIF policy. Provider/mode are validated against the allowed sets; an unknown
    // value is ignored (keeps current). Keys are blank-to-keep so the admin can flip
    // provider/mode without re-typing a key, and the masked GET never round-trips a
    // real key back as an update. NOTE: this never touches per-user personal keys.
    if let Some(p) = body.gif_provider {
        let p = p.to_lowercase();
        if p == "giphy" || p == "tenor" { *state.gif_provider.write().await = p; }
    }
    if let Some(m) = body.gif_mode {
        let m = m.to_lowercase();
        if m == "off" || m == "user" || m == "server" { *state.gif_mode.write().await = m; }
    }
    if let Some(k) = body.giphy_server_key {
        let k = k.trim();
        if !k.is_empty() { *state.giphy_server_key.write().await = k.to_string(); }
    }
    if let Some(k) = body.tenor_server_key {
        let k = k.trim();
        if !k.is_empty() { *state.tenor_server_key.write().await = k.to_string(); }
    }
    if let Some(e) = body.lastfm_enabled { *state.lastfm_enabled.write().await = e; }
    if let Some(k) = body.lastfm_api_key {
        let k = k.trim();
        if !k.is_empty() { *state.lastfm_api_key.write().await = k.to_string(); }
    }
    // Persist admin settings to disk under lock to prevent concurrent read-modify-write races
    let _guard = state.admin_settings_lock.lock().await;
    let path = std::path::PathBuf::from(&state.data_dir).join("admin_settings.json");
    let mut existing: serde_json::Value = if let Ok(json) = tokio::fs::read_to_string(&path).await {
        serde_json::from_str(&json).unwrap_or_default()
    } else { serde_json::json!({}) };
    existing["registration_open"] = serde_json::json!(*state.registration_open.read().await);
    existing["registration_code"] = serde_json::json!(*state.registration_code.read().await);
    existing["max_upload_mb"] = serde_json::json!(*state.max_upload_mb.read().await);
    existing["email_required"] = serde_json::json!(*state.email_required.read().await);
    existing["captcha_enabled"] = serde_json::json!(*state.captcha_enabled.read().await);
    existing["gif_provider"] = serde_json::json!(*state.gif_provider.read().await);
    existing["gif_mode"] = serde_json::json!(*state.gif_mode.read().await);
    existing["giphy_server_key"] = serde_json::json!(*state.giphy_server_key.read().await);
    existing["tenor_server_key"] = serde_json::json!(*state.tenor_server_key.read().await);
    existing["lastfm_enabled"] = serde_json::json!(*state.lastfm_enabled.read().await);
    existing["lastfm_api_key"] = serde_json::json!(*state.lastfm_api_key.read().await);
    let _ = tokio::fs::write(&path, serde_json::to_string_pretty(&existing).unwrap_or_default()).await;
    drop(_guard);
    (StatusCode::OK, Json(Msg { message: "Settings updated.".into() })).into_response()
}

async fn route_register(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<RegisterBody>) -> impl IntoResponse {
    let ip = client_ip(&headers);
    if !*state.registration_open.read().await {
        return (StatusCode::FORBIDDEN, Json(Msg { message: "Registration is closed. Contact the server admin.".into() })).into_response();
    }
    // Throttle EVERY registration attempt per IP up front, so a wrong captcha (or any bad
    // attempt) consumes budget too — otherwise blind captcha-guessing would be unbounded.
    if state.auth.check_ip_rate_limit("reg_attempt", ip.as_deref()).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, Json(Msg { message: "Too many attempts — try again later.".into() })).into_response();
    }
    let req_code = state.registration_code.read().await.clone();
    if !req_code.is_empty() {
        // Per-IP rate limit BEFORE the code compare so a closed-registration code
        // can't be brute-forced online (the register() rate limits only run after the
        // code passes). Generous bucket (10/60s) — unaffected for a real user typing it.
        if state.auth.check_ip_rate_limit("reg_code", ip.as_deref()).is_err() {
            return (StatusCode::TOO_MANY_REQUESTS, Json(Msg { message: "Too many attempts — try again later.".into() })).into_response();
        }
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
    // Signup captcha (admin-toggleable). Verified + consumed here, after the registration
    // code but before any account work, so a bad captcha costs nothing downstream.
    if *state.captcha_enabled.read().await {
        if !verify_captcha(&state, &body.captcha_id, &body.captcha_answer) {
            return (StatusCode::BAD_REQUEST, Json(Msg { message: "Incorrect captcha — please try again.".into() })).into_response();
        }
    }
    let email_required = *state.email_required.read().await;
    match state.auth.register(&body.username, &body.email, &body.password, ip.as_deref(), email_required).await {
        Ok(outcome) => {
            if let Some(token) = outcome.verify_token {
                // Email verification required → mail the link (email is non-empty here).
                let (email, uname, base, from) = (body.email.clone(), body.username.to_lowercase(), state.base_url.clone(), state.from_email.clone());
                tokio::spawn(async move {
                    if let Err(e) = email::send_verification(&email, &uname, &token, &base, &from) { error!("Email: {}", e); }
                });
                (StatusCode::OK, Json(Msg { message: "Registered! Check your email to verify your account.".into() })).into_response()
            } else {
                // Auto-verified (email optional / not required) → active immediately.
                (StatusCode::OK, Json(Msg { message: "Account created! You can sign in now.".into() })).into_response()
            }
        }
        Err(e) => {
            let msg = e.to_string();
            // #76: keep validation messages but never leak internal error detail.
            let safe = if ["Username","Password","Email","email","taken","already","attempts","Invalid","required"].iter().any(|w| msg.contains(w)) { msg } else { "Registration failed".into() };
            (StatusCode::BAD_REQUEST, Json(Msg { message: safe })).into_response()
        }
    }
}

/// GET /auth/captcha — issue a fresh signup captcha: an id + a distorted PNG (data URL).
/// The answer lives only server-side, keyed by the id, with a short one-time-use TTL.
async fn route_captcha(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let ip = client_ip(&headers);
    if state.auth.check_ip_rate_limit("captcha", ip.as_deref()).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, Json(Msg { message: "Too many captcha requests — slow down.".into() })).into_response();
    }
    let now = chrono::Utc::now().timestamp();
    // Opportunistic prune of expired entries + a hard cap so the map can't grow unbounded.
    state.captchas.retain(|_, v| v.1 >= now);
    if state.captchas.len() > 10_000 {
        // Evict the soonest-to-expire half rather than clearing everything, so a flood can't
        // wipe a just-issued legitimate challenge out from under an honest user mid-signup.
        let mut ents: Vec<(String, i64)> = state.captchas.iter().map(|e| (e.key().clone(), e.value().1)).collect();
        ents.sort_by_key(|(_, exp)| *exp);
        for (k, _) in ents.into_iter().take(5_000) { state.captchas.remove(&k); }
    }
    let cap = captcha::generate();
    let id = uuid::Uuid::new_v4().to_string();
    state.captchas.insert(id.clone(), (cap.answer, now + 300)); // 5-minute TTL
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&cap.png);
    (StatusCode::OK, Json(serde_json::json!({ "id": id, "image": format!("data:image/png;base64,{}", b64) }))).into_response()
}

/// Verify + consume a signup captcha. The id is removed whether or not the answer matches,
/// so each challenge is one-shot — a wrong answer needs a fresh image (no brute-forcing one).
fn verify_captcha(state: &AppState, id: &str, answer: &str) -> bool {
    if id.is_empty() { return false; }
    let now = chrono::Utc::now().timestamp();
    let Some((_, (ans, exp))) = state.captchas.remove(id) else { return false; };
    if exp < now { return false; }
    answer.trim().parse::<i64>().map(|a| a == ans).unwrap_or(false)
}

#[derive(Deserialize)] struct EmailBody { #[serde(default)] email: String }

/// POST /auth/set-email — the logged-in user sets / updates / clears their own email (Profile).
async fn route_set_email(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<EmailBody>) -> impl IntoResponse {
    let Some(user) = extract_session_user(&state, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // Throttle email changes (per IP + per user) so this can't be used to spray reset mail
    // to many addresses or churn the email-lock table.
    let ip = client_ip(&headers);
    if state.auth.check_ip_rate_limit("set_email", ip.as_deref()).is_err()
        || state.auth.check_user_create_rate_limit(&user, "set_email").is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, Json(Msg { message: "Too many changes — try again later.".into() })).into_response();
    }
    match state.auth.set_email(&user, &body.email).await {
        Ok(_) => {
            let msg = if body.email.trim().is_empty() { "Email removed." } else { "Email saved." };
            (StatusCode::OK, Json(Msg { message: msg.into() })).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(Msg { message: e.to_string() })).into_response(),
    }
}

/// POST /admin/user/:username/email — admin sets / updates an account's email (e.g. for a
/// member who signed up without one). Same validator + uniqueness as the self path.
async fn route_admin_set_email(State(state): State<AppState>, headers: HeaderMap, Path(target): Path<String>, Json(body): Json<EmailBody>) -> impl IntoResponse {
    let Some(user) = extract_session_user(&state, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !state.auth.is_admin(&user).await {
        return StatusCode::FORBIDDEN.into_response();
    }
    match state.auth.set_email(&target, &body.email).await {
        Ok(_) => (StatusCode::OK, Json(Msg { message: format!("Email updated for '{}'.", target) })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(Msg { message: e.to_string() })).into_response(),
    }
}

#[derive(Deserialize)] struct LastfmBody { #[serde(default)] user: String, key: Option<String> }

/// POST /auth/lastfm — link/unlink the caller's Last.fm username (+ optional own key).
async fn route_set_lastfm(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<LastfmBody>) -> impl IntoResponse {
    let Some(user) = extract_session_user(&state, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let ip = client_ip(&headers);
    if state.auth.check_ip_rate_limit("set_lastfm", ip.as_deref()).is_err()
        || state.auth.check_user_create_rate_limit(&user, "set_lastfm").is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, Json(Msg { message: "Too many changes — try again later.".into() })).into_response();
    }
    match state.auth.set_lastfm(&user, &body.user, body.key.as_deref()).await {
        Ok(_) => {
            let msg = if body.user.trim().is_empty() { "Last.fm disconnected." } else { "Last.fm username saved." };
            (StatusCode::OK, Json(Msg { message: msg.into() })).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(Msg { message: e.to_string() })).into_response(),
    }
}

/// GET /api/lastfm/np?user=<lastfm-user> — server-side now-playing lookup. ?user overrides
/// the caller's linked username. Key resolves: caller's own key -> server shared key.
async fn route_lastfm_np(State(state): State<AppState>, headers: HeaderMap, Query(params): Query<std::collections::HashMap<String, String>>) -> impl IntoResponse {
    let Some(user) = extract_session_user(&state, &headers) else {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"}))).into_response();
    };
    if !*state.lastfm_enabled.read().await {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"Last.fm is not enabled on this server"}))).into_response();
    }
    if state.auth.check_user_create_rate_limit(&user, "lastfm_np").is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({"error":"Too many requests — slow down"}))).into_response();
    }
    let me = state.auth.get_user(&user).await;
    // Whose now-playing? ?user= overrides; else the caller's own linked username.
    let target = params.get("user").map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
        .or_else(|| me.as_ref().map(|u| u.lastfm_user.clone()).filter(|s| !s.is_empty()));
    let Some(target) = target else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"Set your Last.fm username in Profile first, or use /np <lastfm-user>."}))).into_response();
    };
    // Validate before it goes into the outbound API URL (reqwest encodes, but keep it clean).
    if target.len() > 32 || !target.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"Invalid Last.fm username"}))).into_response();
    }
    // Key: the caller's own key wins, else the admin's shared key.
    let key = {
        let own = me.as_ref().map(|u| u.lastfm_key.clone()).unwrap_or_default();
        if !own.is_empty() { own } else { state.lastfm_api_key.read().await.clone() }
    };
    if key.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error":"No Last.fm API key — set your own in Profile, or ask the admin to add a shared key."}))).into_response();
    }
    match lastfm::now_playing(&state.gif_client, &key, &target).await {
        Ok(t) => (StatusCode::OK, Json(serde_json::json!({
            "user": target, "artist": t.artist, "track": t.track, "album": t.album, "now_playing": t.now_playing
        }))).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

async fn route_login(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<LoginBody>) -> impl IntoResponse {
    let ip = client_ip(&headers);
    // Throttle every login POST per IP up front — bounds brute force AND the wrong-captcha
    // early-return path below (which would otherwise never reach login()'s own rate limit).
    if state.auth.check_ip_rate_limit("login_attempt", ip.as_deref()).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, Json(LoginErr { message: "Too many attempts — try again later.".into(), captcha_required: state.auth.login_captcha_required(ip.as_deref(), &body.username) })).into_response();
    }
    // After enough recent failures from this IP, require a captcha BEFORE checking the
    // password, so password-guessing is captcha-gated. Normal logins are unaffected.
    if state.auth.login_captcha_required(ip.as_deref(), &body.username) {
        if !verify_captcha(&state, &body.captcha_id, &body.captcha_answer) {
            return (StatusCode::UNAUTHORIZED, Json(LoginErr { message: "Please complete the captcha to continue.".into(), captcha_required: true })).into_response();
        }
    }
    match state.auth.login(&body.username, &body.password, ip.as_deref()).await {
        // login() resolves the identifier (username OR email) to the real account
        // username — return THAT so the client's identity isn't set to an email.
        Ok((token, username)) => {
            state.auth.reset_login_fails(ip.as_deref(), &body.username);
            (StatusCode::OK, Json(AuthOkBody { token, username })).into_response()
        }
        Err(e) => {
            state.auth.record_login_fail(ip.as_deref(), &body.username);
            let msg = e.to_string();
            // #56: login now returns one generic "Invalid username or password" for
            // nonexistent/unverified/wrong-password — "verified" is no longer emitted,
            // so drop it from the whitelist to avoid ever reflecting that oracle.
            let safe = if ["Invalid","attempts"].iter().any(|w| msg.contains(w)) { msg } else { "Login failed".into() };
            // Tell the client whether the NEXT attempt will need a captcha (>= threshold fails).
            (StatusCode::UNAUTHORIZED, Json(LoginErr { message: safe, captcha_required: state.auth.login_captcha_required(ip.as_deref(), &body.username) })).into_response()
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

async fn route_verify(State(state): State<AppState>, headers: HeaderMap, Query(q): Query<VerifyQuery>) -> impl IntoResponse {
    let ip = client_ip(&headers);
    match state.auth.verify_email(&q.token, ip.as_deref()).await {
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

async fn route_forgot(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<ForgotBody>) -> impl IntoResponse {
    let ip = client_ip(&headers);
    let (email_addr, base, from) = (body.email.clone(), state.base_url.clone(), state.from_email.clone());
    match state.auth.request_password_reset(&body.email, ip.as_deref()).await {
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

async fn route_reset_password(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<ResetPasswordBody>) -> impl IntoResponse {
    let ip = client_ip(&headers);
    match state.auth.reset_password(&body.token, &body.password, ip.as_deref()).await {
        Ok(username) => {
            info!("Password reset for user: {}", username);
            (StatusCode::OK, Json(Msg { message: "Password reset successfully.".into() })).into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            let safe = if ["Invalid","expired","Password","10 characters","attempts"].iter().any(|w| msg.contains(w)) { msg } else { "Reset failed".into() };
            (StatusCode::BAD_REQUEST, Json(Msg { message: safe })).into_response()
        }
    }
}

async fn route_me(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    match bearer_token(&headers).and_then(|t| state.auth.validate_session(&t)) {
        Some(u) => {
            let (email, admin, lfm_user, lfm_own_key) = match state.auth.get_user(&u).await {
                Some(usr) => (usr.email, usr.admin, usr.lastfm_user, !usr.lastfm_key.is_empty()),
                None => (String::new(), false, String::new(), false),
            };
            let lfm_enabled = *state.lastfm_enabled.read().await;
            (StatusCode::OK, Json(MeOk { username: u, email, admin, lastfm_user: lfm_user, lastfm_enabled: lfm_enabled, lastfm_own_key: lfm_own_key })).into_response()
        }
        None => (StatusCode::UNAUTHORIZED, Json(Msg { message: "Not authenticated".into() })).into_response(),
    }
}

#[derive(Deserialize)]
struct ChangePasswordBody { old_password: String, new_password: String }

async fn route_change_password(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<ChangePasswordBody>) -> impl IntoResponse {
    let ip = client_ip(&headers);
    let user = match bearer_token(&headers).and_then(|t| state.auth.validate_session(&t)) {
        Some(u) => u,
        None => return (StatusCode::UNAUTHORIZED, Json(Msg { message: "Not authenticated".into() })).into_response(),
    };
    match state.auth.change_password(&user, &body.old_password, &body.new_password, ip.as_deref()).await {
        Ok(_) => {
            // change_password() purges ALL sessions (incl. this caller's) for security; re-issue
            // a fresh session so the user who just changed their own password stays logged in
            // (other devices remain logged out — that's the intent). Client swaps to this token.
            let token = state.auth.issue_session(&user);
            (StatusCode::OK, Json(AuthOkBody { token, username: user })).into_response()
        }
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
            let max_bytes = *state.max_upload_mb.read().await * 1024 * 1024;
            match upload::handle_upload(&state.upload_dir, multipart, max_bytes).await {
                Ok(r)  => {
                    // #16: record_upload now rejects (returns Err) when this completed
                    // upload would push the user over their storage quota. The bytes are
                    // already written to disk at this point, so on quota failure we must
                    // delete the orphan file (no record was created, so delete_user_upload
                    // would skip it) and surface the error to the client instead of
                    // silently leaking disk and returning success. r.filename is a
                    // server-generated "{uuid}.{ext}" with no path separators.
                    if let Err(e) = upload::record_upload(&state.data_dir, &user, &r).await {
                        let orphan = std::path::PathBuf::from(&state.upload_dir).join(&r.filename);
                        let _ = tokio::fs::remove_file(&orphan).await;
                        return (StatusCode::BAD_REQUEST, Json(Msg { message: e.to_string() })).into_response();
                    }
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

// ─── Chunked / resumable upload routes ───────────────────────────────────────

#[derive(Deserialize)]
struct ChunkedInitBody {
    id:             String,
    original_name:  String,
    size:           usize,
    #[serde(default)] source_conn_id: String,
    #[serde(default)] source_target:  String,
}

async fn upload_auth(state: &AppState, headers: &HeaderMap) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let user = bearer_token(headers).and_then(|t| state.auth.validate_session(&t))
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"}))))?;
    if !state.auth.can_upload(&user).await {
        return Err((StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"Upload permission not granted."}))));
    }
    Ok(user)
}

async fn route_upload_init(
    State(state): State<AppState>, headers: HeaderMap,
    Json(body): Json<ChunkedInitBody>,
) -> impl IntoResponse {
    let user = match upload_auth(&state, &headers).await { Ok(u) => u, Err(e) => return e.into_response() };
    let max_bytes = *state.max_upload_mb.read().await * 1024 * 1024;
    if body.size > max_bytes {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("File too large (max {} MB)", max_bytes / (1024 * 1024))
        }))).into_response();
    }
    match upload::init_chunked_upload(
        &state.data_dir, &user, &body.id,
        &body.original_name, body.size,
        &body.source_conn_id, &body.source_target,
    ).await {
        Ok(rec) => {
            state.send_to_user(&user, ServerEvent::UploadUpdate { record: rec.clone() });
            (StatusCode::OK, Json(serde_json::json!(rec))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

#[derive(Deserialize)]
struct ChunkQuery { offset: usize }

async fn route_upload_chunk(
    State(state): State<AppState>, headers: HeaderMap,
    Path(id): Path<String>, Query(q): Query<ChunkQuery>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let user = match upload_auth(&state, &headers).await { Ok(u) => u, Err(e) => return e.into_response() };
    // Enforce the admin max-upload limit against the cumulative file size.
    let max_bytes = *state.max_upload_mb.read().await * 1024 * 1024;
    if q.offset.saturating_add(body.len()) > max_bytes {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("File too large (max {} MB)", max_bytes / (1024 * 1024))
        }))).into_response();
    }
    match upload::append_chunk(&state.data_dir, &user, &id, q.offset, &body).await {
        Ok(rec) => {
            state.send_to_user(&user, ServerEvent::UploadUpdate { record: rec.clone() });
            (StatusCode::OK, Json(serde_json::json!(rec))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

async fn route_upload_status(
    State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>,
) -> impl IntoResponse {
    let user = match upload_auth(&state, &headers).await { Ok(u) => u, Err(e) => return e.into_response() };
    match upload::get_record(&state.data_dir, &user, &id).await {
        Some(rec) => (StatusCode::OK, Json(serde_json::json!(rec))).into_response(),
        None      => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"Unknown upload"}))).into_response(),
    }
}

async fn route_upload_finalize(
    State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>,
) -> impl IntoResponse {
    let user = match upload_auth(&state, &headers).await { Ok(u) => u, Err(e) => return e.into_response() };
    match upload::finalize_chunked_upload(&state.data_dir, &state.upload_dir, &user, &id).await {
        Ok(rec) => {
            state.send_to_user(&user, ServerEvent::UploadUpdate { record: rec.clone() });
            (StatusCode::OK, Json(serde_json::json!(rec))).into_response()
        }
        Err(e) => {
            // On finalize failure, flip the record to error state so other
            // sessions see it instead of an indefinite "Uploading".
            let _ = upload::error_chunked_upload(&state.data_dir, &user, &id, &e.to_string()).await;
            if let Some(rec) = upload::get_record(&state.data_dir, &user, &id).await {
                state.send_to_user(&user, ServerEvent::UploadUpdate { record: rec });
            }
            (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        }
    }
}

async fn route_upload_cancel(
    State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>,
) -> impl IntoResponse {
    let user = match upload_auth(&state, &headers).await { Ok(u) => u, Err(e) => return e.into_response() };
    match upload::cancel_chunked_upload(&state.data_dir, &user, &id).await {
        Ok(rec) => {
            state.send_to_user(&user, ServerEvent::UploadUpdate { record: rec.clone() });
            (StatusCode::OK, Json(serde_json::json!(rec))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

#[derive(Deserialize)]
struct UploadErrorBody { message: String }

async fn route_upload_error(
    State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>,
    Json(body): Json<UploadErrorBody>,
) -> impl IntoResponse {
    let user = match upload_auth(&state, &headers).await { Ok(u) => u, Err(e) => return e.into_response() };
    match upload::error_chunked_upload(&state.data_dir, &user, &id, &body.message).await {
        Ok(rec) => {
            state.send_to_user(&user, ServerEvent::UploadUpdate { record: rec.clone() });
            (StatusCode::OK, Json(serde_json::json!(rec))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

async fn route_e2e_get_bundle(
    Path(target_user): Path<String>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // S1: authenticated callers only — prevents anonymous OTPK exhaustion DoS
    let caller = match bearer_token(&headers).and_then(|t| state.auth.validate_session(&t)) {
        Some(u) => u,
        None => return (StatusCode::UNAUTHORIZED, Json(Msg { message: "Not authenticated".into() })).into_response(),
    };
    // #27: rate-limit bundle fetches per CALLER on this HTTP path too. Each fetch
    // consumes one of the target's one-time prekeys, so an uncapped caller could
    // drain a victim's OTPK pool and silently downgrade their forward secrecy.
    if state.auth.check_ws_kdf_rate_limit(&caller, "e2e_bundle_http").is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, Json(Msg { message: "Too many key-bundle requests — slow down".into() })).into_response();
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
    // Per-user rate limit: each paste writes a file, so cap creation to keep one
    // account from filling the disk. The budget is generous for normal use.
    if state.auth.check_user_create_rate_limit(&user, "paste").is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({"error":"Too many pastes — slow down"}))).into_response();
    }
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
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    // GET still reads ?password for an unprotected paste / direct link; the unlock FORM
    // now POSTs (see route_paste_view_post) so a typed password never lands in the URL.
    let pw = params.get("password").map(|s| s.as_str()).unwrap_or("");
    render_paste(&state, &id, &headers, pw).await
}

// POST unlock: the password arrives in the form body, never the query string — so it
// can't leak into the reverse-proxy access log, browser history, or the Referer header
// the way a GET ?password= submission would. Same verify + rate-limit + render logic.
async fn route_paste_view_post(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let pw = form.get("password").map(|s| s.as_str()).unwrap_or("");
    render_paste(&state, &id, &headers, pw).await
}

async fn render_paste(state: &AppState, id: &str, headers: &HeaderMap, pw: &str) -> axum::response::Response {
    match state.paste_store.get(id).await {
        Ok(Some(paste)) => {
            if paste.password_hash.is_some() {
                // This endpoint is unauthenticated, and verify_password runs a
                // 64-MiB Argon2id derive. Without a limit an attacker can spray
                // guesses to exhaust CPU. Rate-limit per client IP BEFORE the
                // derive, and run the derive off the async workers so it can't pin
                // one. A legitimate single unlock stays well under the budget.
                if state.auth.check_ip_rate_limit("paste_unlock", client_ip(headers).as_deref()).is_err() {
                    return (StatusCode::TOO_MANY_REQUESTS,
                        Html("Too many attempts — try again later.".to_string())).into_response();
                }
                let verify_ok = {
                    let paste = paste.clone();
                    let pw = pw.to_string();
                    tokio::task::spawn_blocking(move || paste::PasteStore::verify_password(&paste, &pw))
                        .await
                        .unwrap_or(false)
                };
                if !verify_ok {
                    return (StatusCode::FORBIDDEN, Html(format!(
                        "<!DOCTYPE html><html><head><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>CryptIRC Paste</title>\
                         <style>body{{background:#0b0d0f;color:#e0e0e0;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}\
                         .box{{background:#141620;padding:24px;border-radius:12px;border:1px solid #2a2e3e;max-width:300px;width:90%}}\
                         input{{width:100%;padding:8px;margin:8px 0;background:#1a1e2e;border:1px solid #2a2e3e;color:#e0e0e0;border-radius:6px;font-size:16px}}\
                         button{{width:100%;padding:8px;background:#00d4aa;color:#000;border:none;border-radius:6px;cursor:pointer;font-weight:700}}</style></head>\
                         <body><div class=\"box\"><h3>🔒 Password Required</h3>\
                         <form method=\"post\"><input type=\"password\" name=\"password\" placeholder=\"Enter password\" autofocus>\
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
                html_escape(id), lang, created, html_escape(&paste.author), expires, html_escape(id), escaped
            )).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, Html("Paste not found or expired.".to_string())).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Html("Error loading paste.".to_string())).into_response(),
    }
}

async fn route_paste_raw(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    match state.paste_store.get(&id).await {
        Ok(Some(paste)) => {
            if paste.password_hash.is_some() {
                let pw = params.get("password").map(|s| s.as_str()).unwrap_or("");
                // Unauthenticated + 64-MiB Argon2id derive: rate-limit per client
                // IP before the derive and run the derive off the async workers.
                if state.auth.check_ip_rate_limit("paste_unlock", client_ip(&headers).as_deref()).is_err() {
                    return (StatusCode::TOO_MANY_REQUESTS, "Too many attempts").into_response();
                }
                let verify_ok = {
                    let paste = paste.clone();
                    let pw = pw.to_string();
                    tokio::task::spawn_blocking(move || paste::PasteStore::verify_password(&paste, &pw))
                        .await
                        .unwrap_or(false)
                };
                if !verify_ok {
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
    // Per-user rate limit: each short link writes a file, so cap creation to keep
    // one account from filling the disk. The budget is generous for normal use.
    if state.auth.check_user_create_rate_limit(&user, "short").is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({"error":"Too many short links — slow down"}))).into_response();
    }
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
    let user = match state.auth.validate_session(token) {
        Some(u) => u,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"}))).into_response(),
    };
    // #33: per-user rate limit — an authenticated user must not be able to loop
    // /preview as an unthrottled SSRF/port-scan/DoS request engine.
    if !state.preview_rate_ok(&user) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({"error": "Too many preview requests — slow down"}))).into_response();
    }
    let url = match params.get("url") {
        Some(u) => u.clone(),
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"Missing url parameter"}))).into_response(),
    };
    // #33: global concurrency cap — at most PREVIEW_MAX_CONCURRENT outbound preview
    // fetches in flight process-wide, so a burst of slow (5s) fetches can't tie up
    // unbounded sockets/DNS lookups and starve the runtime. If the cap is saturated
    // we shed load rather than queueing (which would amplify the DoS). The permit is
    // held only for the duration of the fetch and released on drop.
    let _permit = match state.preview_sem.clone().try_acquire_owned() {
        Ok(p)  => p,
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Preview unavailable"}))).into_response(),
    };
    match state.preview_service.fetch_preview(&url).await {
        Ok(preview) => Json(serde_json::json!(preview)).into_response(),
        // #33/#76: do NOT reflect the raw fetch error — distinguishing timeout vs
        // connection-refused vs HTTP is a port-scan oracle (and can leak internals).
        // Log the detail server-side; return one generic message.
        Err(e) => {
            info!("[preview] fetch failed: {}", e);
            (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Preview unavailable"}))).into_response()
        }
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

// ─── GIF picker (Giphy / Tenor) ───────────────────────────────────────────────

/// Tells the client which provider is active and how keys are sourced, WITHOUT
/// exposing any server key. server_available is true only when mode=="server" and
/// the active provider's shared key is configured (so the client may use the proxy).
async fn route_gif_config(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if extract_session_user(&state, &headers).is_none() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"}))).into_response();
    }
    let provider = state.gif_provider.read().await.clone();
    let mode = state.gif_mode.read().await.clone();
    let server_available = mode == "server" && match provider.as_str() {
        "tenor" => !state.tenor_server_key.read().await.is_empty(),
        _       => !state.giphy_server_key.read().await.is_empty(),
    };
    Json(serde_json::json!({
        "provider": provider,
        "mode": mode,
        "server_available": server_available,
    })).into_response()
}

/// Map a Giphy-style rating (g|pg|pg-13|r) to a Tenor contentfilter level.
fn tenor_contentfilter(rating: &str) -> &'static str {
    match rating {
        "g"  => "high",
        "pg" => "medium",
        "r"  => "low",
        _    => "medium", // pg-13 and anything unknown
    }
}

/// Flatten a Giphy or Tenor search response into [{preview,url,title}].
fn normalize_gif_results(provider: &str, body: &serde_json::Value) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    if provider == "tenor" {
        if let Some(arr) = body.get("results").and_then(|v| v.as_array()) {
            for g in arr {
                let mf = g.get("media_formats");
                let preview = mf.and_then(|m| m.get("tinygif")).and_then(|x| x.get("url")).and_then(|x| x.as_str())
                    .or_else(|| mf.and_then(|m| m.get("nanogif")).and_then(|x| x.get("url")).and_then(|x| x.as_str()));
                let full = mf.and_then(|m| m.get("gif")).and_then(|x| x.get("url")).and_then(|x| x.as_str())
                    .or_else(|| mf.and_then(|m| m.get("mediumgif")).and_then(|x| x.get("url")).and_then(|x| x.as_str()));
                let title = g.get("content_description").and_then(|x| x.as_str()).unwrap_or("");
                if let Some(full) = full {
                    out.push(serde_json::json!({ "preview": preview.unwrap_or(full), "url": full, "title": title }));
                }
            }
        }
    } else if let Some(arr) = body.get("data").and_then(|v| v.as_array()) {
        for g in arr {
            let images = g.get("images");
            let preview = images.and_then(|i| i.get("fixed_height_small")).and_then(|x| x.get("url")).and_then(|x| x.as_str())
                .or_else(|| images.and_then(|i| i.get("preview_gif")).and_then(|x| x.get("url")).and_then(|x| x.as_str()));
            let full = images.and_then(|i| i.get("original")).and_then(|x| x.get("url")).and_then(|x| x.as_str());
            let title = g.get("title").and_then(|x| x.as_str()).unwrap_or("");
            if let Some(full) = full {
                out.push(serde_json::json!({ "preview": preview.unwrap_or(full), "url": full, "title": title }));
            }
        }
    }
    out
}

/// Server-side GIF search proxy. Only serves in mode=="server", spending the admin's
/// shared key for the active provider; normalizes both providers to a common
/// {results:[{preview,url,title}]} shape so the frontend parsing is provider-agnostic.
async fn route_gif_search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let Some(user) = extract_session_user(&state, &headers) else {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"}))).into_response();
    };
    // The proxy exists only to spend the admin's shared key; refuse outside server mode.
    if *state.gif_mode.read().await != "server" {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"Shared GIF key is not enabled"}))).into_response();
    }
    if !state.gif_rate_ok(&user) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({"error":"Too many GIF requests — slow down"}))).into_response();
    }
    let q = params.get("q").map(|s| s.trim()).unwrap_or("");
    if q.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"Missing q"}))).into_response();
    }
    let q: String = q.chars().take(100).collect();
    let limit: u32 = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(12).clamp(1, 50);
    let limit_s = limit.to_string();
    let rating = match params.get("rating").map(|s| s.as_str()).unwrap_or("pg-13") {
        r @ ("g" | "pg" | "pg-13" | "r") => r,
        _ => "pg-13",
    };
    let provider = state.gif_provider.read().await.clone();
    let resp = if provider == "tenor" {
        let key = state.tenor_server_key.read().await.clone();
        if key.is_empty() {
            return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error":"No shared GIF key configured"}))).into_response();
        }
        state.gif_client.get("https://tenor.googleapis.com/v2/search")
            .query(&[("key", key.as_str()), ("q", q.as_str()), ("limit", limit_s.as_str()),
                     ("contentfilter", tenor_contentfilter(rating)), ("media_filter", "tinygif,gif"), ("client_key", "cryptirc")])
            .send().await
    } else {
        let key = state.giphy_server_key.read().await.clone();
        if key.is_empty() {
            return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error":"No shared GIF key configured"}))).into_response();
        }
        state.gif_client.get("https://api.giphy.com/v1/gifs/search")
            .query(&[("api_key", key.as_str()), ("q", q.as_str()), ("limit", limit_s.as_str()), ("rating", rating)])
            .send().await
    };
    let resp = match resp {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => { info!("[gif] {} upstream status {}", provider, r.status());
            return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error":"GIF search failed"}))).into_response(); }
        // Do NOT log the raw reqwest::Error — its Display includes the request URL,
        // which carries the shared key in ?key=/?api_key=. Log a sanitized class only.
        Err(e) => { info!("[gif] {} fetch error: timeout={} connect={}", provider, e.is_timeout(), e.is_connect());
            return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error":"GIF search failed"}))).into_response(); }
    };
    let body: serde_json::Value = match resp.text().await {
        // reqwest's `json` feature isn't enabled in this build, so parse the text ourselves.
        Ok(t) => serde_json::from_str(&t).unwrap_or_else(|_| serde_json::json!({})),
        Err(_) => return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error":"GIF search failed"}))).into_response(),
    };
    Json(serde_json::json!({ "results": normalize_gif_results(&provider, &body) })).into_response()
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
            // Throttle: this HTTP route is NOT behind the WS per-socket limiter, and each
            // call fans out a DNS+TLS+VAPID web-push to every stored subscription (up to
            // MAX_SUBSCRIPTIONS_PER_USER). A dedicated per-user bucket caps abuse without
            // affecting a human pressing "send test notification" (well under 10/60s).
            if state.auth.check_user_create_rate_limit(&user, "push_test").is_err() {
                return (StatusCode::TOO_MANY_REQUESTS, Json(Msg { message: "Too many requests — try again shortly".into() })).into_response();
            }
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

    // #5: retain the raw handshake token so each subsequent command can cheaply
    // re-validate the session. Validating only once at handshake left a
    // revoked/expired token with full access on an already-open socket.
    let (username, session_token) = match auth_msg {
        // S6: bound the UNAUTHENTICATED handshake frame by the same WS_MAX_MSG_BYTES cap the
        // post-auth recv loop enforces — otherwise an anonymous client could send an up-to-
        // 64-MiB Text frame and force the allocation + serde_json parse before any auth.
        Ok(Some(Ok(Message::Text(txt)))) if txt.len() <= WS_MAX_MSG_BYTES => {
            match serde_json::from_str::<ClientMessage>(&txt) {
                Ok(ClientMessage::Auth { token }) => {
                    match state.auth.validate_session(&token) {
                        Some(u) => (u, token),
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

    // Seed the Uploads channel with this user's persistent upload list.
    {
        let records = upload::list_all_records(&state.data_dir, &username).await;
        if !records.is_empty() {
            let _ = sender.send(Message::Text(
                serde_json::to_string(&ServerEvent::UploadState { records }).unwrap()
            )).await;
        }
    }

    // Track this session as active (non-idle) — increment BEFORE subscribing
    // so the IRC thread never sees receiver_count>0 with active_sessions==0
    let active_counter = state.active_counter(&username);
    active_counter.fetch_add(1, Ordering::Release);

    let mut event_rx = state.user_subscribe(&username);
    let session_is_active = Arc::new(std::sync::atomic::AtomicBool::new(true));

    // #60: per-socket event channel for key material that must reach ONLY the
    // originating session (not every device subscribed to the user broadcast).
    // The send_task drains both the broadcast and this per-socket channel.
    let (socket_tx, mut socket_rx) = tokio::sync::mpsc::unbounded_channel::<ServerEvent>();

    // #5b: handles for periodic re-validation of the OUTBOUND stream. The inbound path
    // (recv_task) re-validates per command, but Idle/Active presence frames are exempt
    // and an attacker can simply send NOTHING — leaving recv_task parked forever while
    // send_task keeps streaming the victim's live messages. So the outbound task must
    // independently re-check the session and close the socket when it is no longer valid
    // (logout / password change / admin disable / age/idle expiry).
    let state_sv = state.clone();
    let user_sv  = username.clone();
    let token_sv = session_token.clone();

    let mut send_task = tokio::spawn(async move {
        // Re-validate roughly every 30s; this bounds post-revocation read exposure to
        // the interval. A non-mutating check (session_valid_for) is used so this polling
        // never itself refreshes the session's idle timer.
        let mut revalidate = tokio::time::interval(tokio::time::Duration::from_secs(30));
        revalidate.tick().await; // consume the immediate first tick
        loop {
            tokio::select! {
                evt = event_rx.recv() => {
                    match evt {
                        // #103: serialize gracefully — a serialization regression in a
                        // future ServerEvent variant should skip that event, not panic
                        // and drop the socket.
                        Ok(evt) => match serde_json::to_string(&evt) {
                            Ok(s)  => { if sender.send(Message::Text(s)).await.is_err() { break; } }
                            Err(_) => continue,
                        },
                        // A slow/backgrounded consumer that overflows the 128-event
                        // buffer gets Lagged(n) — skip the dropped events and keep the
                        // socket; the client's sync watchdog backfills what it missed.
                        // Only a genuinely closed channel tears the socket down.
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed)    => break,
                    }
                }
                Some(evt) = socket_rx.recv() => {
                    match serde_json::to_string(&evt) {
                        Ok(s)  => { if sender.send(Message::Text(s)).await.is_err() { break; } }
                        Err(_) => continue,
                    }
                }
                _ = revalidate.tick() => {
                    if !state_sv.auth.session_valid_for(&token_sv, &user_sv) { break; }
                }
            }
        }
    });

    let state2 = state.clone();
    let user2  = username.clone();
    let counter2 = active_counter.clone();
    let active2 = session_is_active.clone();
    let socket_tx2 = socket_tx.clone();
    // #5: token used to re-validate the session on each non-presence command.
    let session_token2 = session_token.clone();
    let mut recv_task = tokio::spawn(async move {
        // #35: per-socket sliding-window command rate limiter. Commands above the
        // budget within a 1-second window are dropped, capping the disk-I/O /
        // broadcast fan-out a single flooding socket can impose on the runtime.
        let mut window_start = tokio::time::Instant::now();
        let mut cmds_in_window: u32 = 0;
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
                    Ok(cmd) => {
                        // #5: re-validate the session on every non-presence command.
                        // The handshake validated once; a token revoked/expired
                        // afterwards (logout, password change, admin disable, idle/age
                        // timeout) must lose access on the already-open socket. Idle/
                        // Active presence toggles are handled above and never reach
                        // here, so they stay exempt to avoid churn. If the token no
                        // longer validates — or now maps to a different username — stop
                        // processing and let the socket close.
                        match state2.auth.validate_session(&session_token2) {
                            Some(u) if u == user2 => {}
                            _ => break,
                        }
                        // #35: throttle command dispatch (Idle/Active above are cheap
                        // presence toggles and are intentionally exempt).
                        let now = tokio::time::Instant::now();
                        if now.duration_since(window_start) >= std::time::Duration::from_secs(1) {
                            window_start = now;
                            cmds_in_window = 0;
                        }
                        cmds_in_window += 1;
                        if cmds_in_window > WS_MAX_CMDS_PER_SEC {
                            // Over budget — drop silently to shed the flood.
                            continue;
                        }
                        handle_command(cmd, &user2, &state2, &socket_tx2).await;
                    }
                    Err(e) => {
                        // #73: do NOT log the message body on parse error — a near-valid
                        // UnlockVault{passphrase}/DeleteAccount{password} frame would leak
                        // the leading secret characters into journald. Log only the error
                        // and frame length.
                        info!("[WS] parse error for {}: {} ({}B)", user2, e, text.len());
                    }
                }
            }
        }
    });

    tokio::select! {
        _ = &mut send_task => recv_task.abort(),
        _ = &mut recv_task => send_task.abort(),
    }

    // Session disconnecting — decrement active count if this session was still active.
    // Atomic check-and-act (swap, not load-then-sub): the recv_task's Idle/Active arms
    // use the same swap-based pattern on the SAME atomics, and abort() can't interrupt a
    // match arm already running on another worker thread. A non-atomic load+fetch_sub
    // here would race a concurrent Idle decrement, double-subtract, and underflow the
    // counter to usize::MAX (permanent push suppression + leaked map entry).
    if session_is_active.swap(false, Ordering::AcqRel) {
        active_counter.fetch_sub(1, Ordering::Release);
    }
}

// ─── Command handler ──────────────────────────────────────────────────────────

async fn handle_command(
    cmd: ClientMessage,
    username: &str,
    state: &AppState,
    socket_tx: &tokio::sync::mpsc::UnboundedSender<ServerEvent>,
) {
    let send = |evt: ServerEvent| state.send_to_user(username, evt);
    // #60: send an event to ONLY the originating socket (used for vault-unlock key
    // material so it isn't broadcast to other, possibly-stale, sessions).
    let send_self = |evt: ServerEvent| { let _ = socket_tx.send(evt); };

    match cmd {
        ClientMessage::Auth { .. } => {}
        // Idle/Active handled in handle_ws before reaching here
        ClientMessage::Idle {} | ClientMessage::Active {} => {}

        ClientMessage::UnlockVault { passphrase } => {
            // #13: short-circuit if already unlocked so a flood can't force a full
            // 64-MiB Argon2id derivation on every message.
            if state.crypto.is_unlocked(username).await {
                let e2e_enc_key = match state.crypto.derive_e2e_enc_key(username).await {
                    Ok(k)  => base64::Engine::encode(&base64::engine::general_purpose::STANDARD, k),
                    Err(_) => String::new(),
                };
                // #60: deliver the E2E key only to THIS socket, never the broadcast.
                send_self(ServerEvent::VaultUnlocked { e2e_enc_key });
                return;
            }
            // #13: rate-limit the KDF path per user so an authenticated client cannot
            // spam UnlockVault over one or many WebSockets to saturate worker threads
            // and exhaust RAM (each unlock pins a thread on Argon2 + allocates 64 MiB).
            if state.auth.check_ws_kdf_rate_limit(username, "unlock").is_err() {
                send_self(ServerEvent::VaultError { message: "Too many unlock attempts — try again shortly".into() });
                return;
            }
            // #13: the Argon2id derive inside unlock() (64-MiB m_cost, t=3) is a
            // synchronous CPU-heavy pass. Running it directly on a tokio worker thread
            // lets a flood pin every worker and stall the whole runtime (IRC, uploads,
            // HTTP). Move it to the blocking pool via spawn_blocking + block_on so the
            // async workers stay free. Clone the Arc<CryptoManager> + inputs in.
            let unlock_res = {
                // #4: bound the number of concurrent 64-MiB Argon2id derivations
                // process-wide. Holding the permit only around the derive keeps
                // per-user behavior unchanged while preventing many accounts from
                // pinning that much RAM at once.
                let _kdf_permit = kdf_sem().acquire().await;
                let crypto = state.crypto.clone();
                let uname  = username.to_string();
                let pass   = passphrase.clone();
                match tokio::task::spawn_blocking(move || {
                    tokio::runtime::Handle::current().block_on(crypto.unlock(&uname, &pass))
                }).await {
                    Ok(r)  => r,
                    Err(_) => Err(anyhow::anyhow!("unlock task failed")),
                }
            };
            match unlock_res {
                Ok(_)  => {
                    // Derive E2E sub-key and send to client (also Argon2-backed via the
                    // master key path — keep it off the async workers too).
                    let e2e_enc_key = {
                        let crypto = state.crypto.clone();
                        let uname  = username.to_string();
                        match tokio::task::spawn_blocking(move || {
                            tokio::runtime::Handle::current().block_on(crypto.derive_e2e_enc_key(&uname))
                        }).await {
                            Ok(Ok(k))  => base64::Engine::encode(&base64::engine::general_purpose::STANDARD, k),
                            _          => String::new(),
                        }
                    };
                    // #60: the e2e_enc_key decrypts the user's private E2E key blobs —
                    // deliver it ONLY to the unlocking socket, not to every active
                    // session (a stale device shouldn't silently receive it). Other
                    // sessions get a key-less State refresh so they observe the unlock
                    // and can prompt the user to unlock locally.
                    send_self(ServerEvent::VaultUnlocked { e2e_enc_key });
                    send(ServerEvent::State {
                        networks: state.user_network_states(username).await,
                        vault_unlocked: true,
                    });
                    // Per-user vault: only connect THIS user's networks
                    state.reconnect_for_user(username).await;
                }
                Err(_) => send_self(ServerEvent::VaultError { message: "Incorrect passphrase".into() }),
            }
        }
        ClientMessage::LockVault {} => {
            info!("Vault locked for {}", username);
            state.crypto.lock(username).await;
            send(ServerEvent::VaultLocked {});
        }
        ClientMessage::ChangePassphrase { old, new } => {
            // #13: rate-limit — change_passphrase runs Argon2id TWICE plus a full
            // log-tree re-encrypt, so it is even more expensive than unlock.
            if state.auth.check_ws_kdf_rate_limit(username, "chpass").is_err() {
                send_self(ServerEvent::VaultError { message: "Too many attempts — try again shortly".into() });
                return;
            }
            // #13: change_passphrase runs the synchronous 64-MiB Argon2id KDF twice
            // (derive old + new) plus a log-tree re-encrypt — move it to the blocking
            // pool so it cannot stall the async runtime. Clone the Arc + inputs in.
            let chpass_res = {
                // #4: bound concurrent 64-MiB Argon2id derivations process-wide.
                // change_passphrase runs the KDF twice, so hold one permit around
                // the whole derive; per-user behavior is unchanged.
                let _kdf_permit = kdf_sem().acquire().await;
                let crypto = state.crypto.clone();
                let uname  = username.to_string();
                let (oldp, newp) = (old.clone(), new.clone());
                match tokio::task::spawn_blocking(move || {
                    tokio::runtime::Handle::current().block_on(crypto.change_passphrase(&uname, &oldp, &newp))
                }).await {
                    Ok(r)  => r,
                    Err(_) => Err(anyhow::anyhow!("passphrase-change task failed")),
                }
            };
            match chpass_res {
                Ok(_)  => {
                    let e2e_enc_key = {
                        let crypto = state.crypto.clone();
                        let uname  = username.to_string();
                        match tokio::task::spawn_blocking(move || {
                            tokio::runtime::Handle::current().block_on(crypto.derive_e2e_enc_key(&uname))
                        }).await {
                            Ok(Ok(k))  => base64::Engine::encode(&base64::engine::general_purpose::STANDARD, k),
                            _          => String::new(),
                        }
                    };
                    // #60: deliver the (changed) E2E key only to the originating socket.
                    send_self(ServerEvent::VaultUnlocked { e2e_enc_key });
                }
                Err(e) => send_self(ServerEvent::VaultError { message: e.to_string() }),
            }
        }

        ClientMessage::AddNetwork { mut network } => {
            // #34: cap the number of networks per user. Each saved network spawns an
            // outbound IRC connection on unlock; an unbounded count lets one account
            // exhaust file descriptors/sockets/memory and get the server K-lined.
            if state.user_network_count(username).await >= MAX_NETWORKS_PER_USER {
                send(ServerEvent::Error { message: format!("Network limit reached ({} max).", MAX_NETWORKS_PER_USER) });
                return;
            }
            // #23: ALWAYS server-generate the network id and ignore any client-supplied
            // value. Previously a client could supply another user's network UUID,
            // creating networks/<attacker>/<victim_uuid>.json; because cert/log storage
            // is keyed by conn_id alone (no username component), owns_network would then
            // return true and DeleteCert/ClearTargetLogs/GenerateCert could destroy or
            // overwrite the victim's data while they were offline. Generate a fresh,
            // collision-free UUID so a conn_id can never be aimed at another user's data.
            network.id = loop {
                let candidate = Uuid::new_v4().to_string();
                // Extremely unlikely, but never reuse an id already owned anywhere.
                if !state.conn_owners.contains_key(&candidate)
                    && !std::path::Path::new(&format!("{}/networks/{}/{}.json", state.data_dir, username, candidate)).exists() {
                    break candidate;
                }
            };
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
            // #4: serialize the read-existing → save → (cert-gen) → save sequence
            // behind the per-config lock so a concurrent Join/Part/UpdateNetwork
            // can't last-writer-wins clobber it.
            let cfg_lock = network_config_lock(username, &network.id);
            let _cfg_guard = cfg_lock.lock().await;
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
            // #20: resolve the reason and clone the Arc out before locking, so the
            // DashMap Ref is dropped before any await.
            let reason = match state.get_network_config(&id, username).await {
                Some(cfg) => strip_crlf(quit_reason_for(&cfg)),
                None => DEFAULT_QUIT_MESSAGE.to_string(),
            };
            let conn = state.connections.get(&id).map(|c| c.clone());
            if let Some(conn) = conn {
                let mut c = conn.lock().await;
                let _ = c.send_raw(&format!("QUIT :{}\r\n", reason)).await;
            }
            state.abort_connect_task(&id);
            state.connections.remove(&id);
            state.conn_owners.remove(&id);
            state.clear_disconnect_request(&id);
            // #4: serialize the config-file DELETE behind the SAME per-config lock
            // every save_network writer takes. Without it, a concurrent
            // JoinChannel/PartChannel/SaveChannelOrder/Send/GenerateCert/UpdateNetwork
            // for this id (from another socket of the same user) can interleave
            // get_network_config (read) → remove_network (this delete) → save_network
            // (write), RESURRECTING the just-removed network's <id>.json on disk. The
            // resurrected file reappears in user_network_states and is auto-reconnected
            // by reconnect_for_user on the next vault unlock. Holding the lock across
            // the delete makes delete and save mutually exclusive. The QUIT/abort/map
            // removal above don't touch the config file, so they stay outside the lock.
            {
                let _cfg_lock = network_config_lock(username, &id);
                let _cfg_guard = _cfg_lock.lock().await;
                state.remove_network(&id, username).await;
            }
            send(ServerEvent::State {
                networks: state.user_network_states(username).await,
                vault_unlocked: state.crypto.is_unlocked(username).await,
            });
        }
        ClientMessage::Connect { id } => {
            if !state.owns_network(username, &id).await { return; }
            // Kill any existing connection first to prevent ghost sessions.
            // Order matters: send QUIT while the socket is still alive, then abort
            // the task so its reconnect loop can't resurrect itself.
            // #20: resolve reason + clone the Arc out before locking (drop Ref pre-await).
            let reason = match state.get_network_config(&id, username).await {
                Some(cfg) => strip_crlf(quit_reason_for(&cfg)),
                None => DEFAULT_QUIT_MESSAGE.to_string(),
            };
            let conn = state.connections.get(&id).map(|c| c.clone());
            if let Some(conn) = conn {
                let mut c = conn.lock().await;
                let _ = c.send_raw(&format!("QUIT :{}\r\n", reason)).await;
            }
            // #84: set the disconnect flag before aborting the old task so its
            // reconnect loop is guaranteed to bail and can't resurrect after QUIT
            // and wipe the new task's map entry. Cleared again just below before
            // the new connect spawns.
            state.request_disconnect(&id);
            state.abort_connect_task(&id);
            state.connections.remove(&id);
            state.conn_owners.remove(&id);
            state.clear_disconnect_request(&id);
            if let Some(cfg) = state.get_network_config(&id, username).await {
                // irc::connect() emits Connecting at the top of each attempt — don't double-emit here.
                let (s2, u2) = (state.clone(), username.to_string());
                let id2 = id.clone();
                let handle = tokio::spawn(async move {
                    if let Err(e) = irc::connect(id2, cfg, u2, s2).await { error!("IRC: {}", e); }
                });
                // Abort any predecessor handle this insert displaces. Normally
                // abort_connect_task above already emptied the slot so this returns
                // None, but if a concurrent Connect/reconnect_for_user for the SAME
                // conn_id raced in between, the displaced task would otherwise be
                // dropped-but-not-aborted, leaving an untracked ghost IRC socket that
                // auto-reconnects forever and can never be killed. Aborting it here
                // closes that hole; it is a no-op in the normal (uncontended) path.
                if let Some(old) = state.connect_tasks.insert(id, handle) { old.abort(); }
            }
        }
        ClientMessage::Disconnect { id } => {
            if !state.owns_network(username, &id).await { return; }
            // Send QUIT first (while socket is alive), then abort the reconnect loop.
            // abort() is deterministic — no sleep/flag race.
            // #20: resolve reason + clone the Arc out before locking (drop Ref pre-await).
            let reason = match state.get_network_config(&id, username).await {
                Some(cfg) => strip_crlf(quit_reason_for(&cfg)),
                None => DEFAULT_QUIT_MESSAGE.to_string(),
            };
            // #84: set the disconnect flag before aborting so the old task's
            // reconnect loop bails and can't resurrect the connection.
            state.request_disconnect(&id);
            let conn = state.connections.get(&id).map(|c| c.clone());
            if let Some(conn) = conn {
                let mut c = conn.lock().await;
                let _ = c.send_raw(&format!("QUIT :{}\r\n", reason)).await;
            }
            state.abort_connect_task(&id);
            state.connections.remove(&id);
            state.conn_owners.remove(&id);
            state.clear_disconnect_request(&id);
            send(ServerEvent::Disconnected { conn_id: id, reason: "User requested".into() });
        }
        ClientMessage::Send { conn_id, raw } => {
            if !state.owns_conn(username, &conn_id) { return; }
            // #20: clone the Arc out and DROP the DashMap Ref immediately so we never
            // hold a shard read-guard across send_raw / logger.append / save_network
            // awaits (which would block synchronous insert/remove on the same shard).
            let conn = state.connections.get(&conn_id).map(|c| c.clone());
            if let Some(conn) = conn {
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
                // #5/#74: redact credential-bearing commands (NickServ/ChanServ
                // IDENTIFY/REGISTER/GHOST/REGAIN, OPER, PASS) before logging, and
                // never log message bodies — log only verb+target+byte-count. Use a
                // char-safe truncation so a multibyte byte at the boundary can't panic.
                info!("[{}] SEND ({}B): {}", conn_id, safe.len(), redact_for_log(&safe));
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
                // Persist JOIN/PART in auto_join (with channel key if provided)
                let upper = safe.to_uppercase();
                if upper.starts_with("JOIN ") || upper.starts_with("PART ") {
                    let parts: Vec<&str> = safe.splitn(3, ' ').collect();
                    if parts.len() >= 2 {
                        let ch = parts[1].split(',').next().unwrap_or("");
                        if !ch.is_empty() && is_valid_channel(ch) {
                            // Serialize this auto_join/channel_keys RMW behind the same
                            // per-config lock the JoinChannel/PartChannel handlers use — the
                            // raw `/join`/`/part` SEND path does the identical mutation and
                            // would otherwise race them (last-writer-wins + shared .tmp).
                            // send_raw already happened above, so the lock isn't held across
                            // the IRC round-trip.
                            let _cfg_lock = network_config_lock(username, &conn_id);
                            let _cfg_guard = _cfg_lock.lock().await;
                            if let Some(mut cfg) = state.get_network_config(&conn_id, username).await {
                                let lc = ch.to_lowercase();
                                if upper.starts_with("JOIN ") {
                                    let mut changed = false;
                                    if !cfg.auto_join.iter().any(|c| c.to_lowercase() == lc) && cfg.auto_join.len() < 100 {
                                        cfg.auto_join.push(ch.to_string());
                                        changed = true;
                                    }
                                    // Save channel key if provided (JOIN #chan key)
                                    if parts.len() >= 3 && !parts[2].is_empty() {
                                        cfg.channel_keys.insert(lc, parts[2].to_string());
                                        changed = true;
                                    }
                                    if changed { let _ = state.save_network(&cfg, username).await; }
                                } else {
                                    cfg.auto_join.retain(|c| c.to_lowercase() != lc);
                                    cfg.channel_keys.remove(&lc);
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
            // #20: clone the Arc out and drop the DashMap Ref before awaiting.
            let conn = state.connections.get(&conn_id).map(|c| c.clone());
            if let Some(conn) = conn {
                let safe_ch = strip_crlf(&channel);
                if safe_ch.is_empty() || !is_valid_channel(&safe_ch) { return; }
                let cmd = match key.as_deref() {
                    Some(k) if !k.is_empty() => format!("JOIN {} {}\r\n", safe_ch, strip_crlf(k)),
                    _ => format!("JOIN {}\r\n", safe_ch),
                };
                let _ = conn.lock().await.send_raw(&cmd).await;
                // Persist channel in auto_join (with key if provided).
                // #4: serialize the read-modify-write behind the per-config lock so a
                // concurrent Join/Part/UpdateNetwork can't last-writer-wins clobber it.
                let cfg_lock = network_config_lock(username, &conn_id);
                let _cfg_guard = cfg_lock.lock().await;
                if let Some(mut cfg) = state.get_network_config(&conn_id, username).await {
                    let lc = safe_ch.to_lowercase();
                    let mut changed = false;
                    if !cfg.auto_join.iter().any(|c| c.to_lowercase() == lc) && cfg.auto_join.len() < 100 {
                        cfg.auto_join.push(safe_ch.clone());
                        changed = true;
                    }
                    match key.as_deref() {
                        Some(k) if !k.is_empty() => { cfg.channel_keys.insert(lc, strip_crlf(k).to_string()); changed = true; }
                        _ => {}
                    }
                    if changed { let _ = state.save_network(&cfg, username).await; }
                }
            }
        }
        ClientMessage::PartChannel { conn_id, channel } => {
            // Use owns_network (persistent config) instead of owns_conn (live conn)
            // so offline parts still work — previously this bailed out when
            // disconnected because conn_owners is cleared on disconnect.
            if !state.owns_network(username, &conn_id).await { return; }
            let safe = strip_crlf(&channel);
            if safe.is_empty() { return; }
            // #20: clone the Arc out and drop the DashMap Ref before awaiting.
            let conn = state.connections.get(&conn_id).map(|c| c.clone());
            let live = conn.is_some();
            if let Some(conn) = conn {
                let _ = conn.lock().await.send_raw(&format!("PART {}\r\n", safe)).await;
            }
            // Always strip from auto_join so reconnect doesn't re-join it.
            let mut user_nick = String::new();
            {
                // #4: serialize the read-modify-write behind the per-config lock.
                let cfg_lock = network_config_lock(username, &conn_id);
                let _cfg_guard = cfg_lock.lock().await;
                if let Some(mut cfg) = state.get_network_config(&conn_id, username).await {
                    user_nick = cfg.nick.clone();
                    let lc = safe.to_lowercase();
                    cfg.auto_join.retain(|c| c.to_lowercase() != lc);
                    cfg.channel_keys.remove(&lc);
                    let _ = state.save_network(&cfg, username).await;
                }
            }
            // When offline, no server will echo the PART back — synthesize the
            // event so the frontend removes the channel from the sidebar and
            // switches away if it was active.
            if !live {
                let ts = chrono::Utc::now().timestamp();
                state.send_to_user(username, ServerEvent::IrcPart {
                    conn_id: conn_id.clone(),
                    nick:    user_nick,
                    channel: safe.clone(),
                    reason:  "Left while offline".into(),
                    ts,
                });
            }
        }
        ClientMessage::GetLogs { conn_id, target, limit, before } => {
            if !state.owns_network(username, &conn_id).await { return; }
            let lim = limit.unwrap_or(200).min(500);
            let lines = if let Some(ts) = before {
                // Paging / jump-to-message: scan the FULL history so we can reach
                // any depth (read_logs would cap the look-back to the last 10k and
                // hide older messages — the bug behind "message no longer in
                // history" when search finds something far back).
                state.logger.read_logs_before(username, &conn_id, &target, ts, lim).await.unwrap_or_default()
            } else {
                // Initial load: just the most-recent `lim` messages.
                let all_lines = state.logger.read_logs(username, &conn_id, &target, 10000).await.unwrap_or_default();
                let start = all_lines.len().saturating_sub(lim);
                all_lines[start..].to_vec()
            };
            send(ServerEvent::LogLines { conn_id, target, lines });
        }
        ClientMessage::SearchLogs { conn_id, target, query, limit } => {
            if !state.owns_network(username, &conn_id).await { return; }
            // 0 = no limit: search and return EVERY match across the full history.
            let lim = limit.unwrap_or(0);
            let lines = state.logger.search_logs(username, &conn_id, &target, &query, lim).await.unwrap_or_default();
            send(ServerEvent::SearchResults { conn_id, target, query, lines });
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
                    // Set client_cert_id on the network config so it's used on next connect.
                    // Guarded by the per-config lock (re-read inside the guard) so this RMW
                    // can't race the JoinChannel/PartChannel/UpdateNetwork/SEND config writers.
                    let _cfg_lock = network_config_lock(username, &conn_id);
                    let _cfg_guard = _cfg_lock.lock().await;
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
        ClientMessage::E2EPublishBundle { mut bundle } => {
            info!("[E2E] publish_bundle for {}", username);
            // HIGH: cap OTPKs carried in a bundle so one publish can't exhaust
            // inodes/disk (one file per key). Real clients publish a small bounded
            // batch; 256 matches the client refill batch size.
            if bundle.one_time_prekeys.len() > 256 {
                warn!("[E2E] publish_bundle from {} carried {} OTPKs — truncating to 256",
                    username, bundle.one_time_prekeys.len());
                bundle.one_time_prekeys.truncate(256);
            }
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
        ClientMessage::E2EAddOTPKs { mut keys } => {
            // HIGH: cap per-call OTPK count so a single add can't exhaust
            // inodes/disk (one file per key). 256 matches the client refill batch.
            if keys.len() > 256 {
                warn!("[E2E] add_otpks from {} carried {} keys — truncating to 256",
                    username, keys.len());
                keys.truncate(256);
            }
            match state.e2e_store.add_one_time_prekeys(username, keys).await {
                Ok(_)  => {}
                Err(e) => send(ServerEvent::Error { message: format!("E2E add OTPKs: {}", e) }),
            }
        }
        ClientMessage::E2EFetchBundle { username: target_user } => {
            // #27: rate-limit bundle fetches per CALLER. Each fetch consumes one of the
            // target's one-time prekeys, so without a cap a single account can loop this
            // to drain a victim's OTPK pool on demand (silently downgrading future
            // sessions to reduced forward secrecy). 10/60s per caller via the shared
            // limiter is ample for legitimate use.
            if state.auth.check_ws_kdf_rate_limit(username, "e2e_bundle").is_err() {
                send(ServerEvent::Error { message: "Too many key-bundle requests — slow down".into() });
                return;
            }
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
            // Per-caller rate limit (mirrors E2EFetchBundle #27): this is the only
            // unthrottled high-volume, large-payload (<=64KiB) cross-user WRITE primitive.
            // Without a cap, an authenticated caller can flood a victim's 128-slot
            // broadcast faster than send_task drains it; a broadcast Lagged is treated as
            // fatal (Err(_) => break), force-closing the victim's WebSocket. 10/60s per
            // caller is ample — a real X3DH relay fires once per newly-initiated conversation.
            if state.auth.check_ws_kdf_rate_limit(username, "e2e_relay").is_err() {
                send(ServerEvent::Error { message: "Too many relay requests — slow down".into() });
                return;
            }
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
                        // #20: clone the Arc out and drop the DashMap Ref before awaiting.
                        let conn = state.connections.get(&cid).map(|c| c.clone());
                        if let Some(conn) = conn {
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
                // Atomic write (tmp + rename) so a crash mid-write can't leave a
                // truncated appearance.json that fails to parse on next load —
                // matches the rest of the persistence layer.
                let dest = dir.join("appearance.json");
                let tmp  = dir.join(format!("appearance.json.tmp.{}", Uuid::new_v4()));
                if tokio::fs::write(&tmp, &settings).await.is_ok() {
                    if tokio::fs::rename(&tmp, &dest).await.is_err() {
                        let _ = tokio::fs::write(&dest, &settings).await;
                        let _ = tokio::fs::remove_file(&tmp).await;
                    }
                }
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
            // Encrypt at rest using the user's vault key — matches notepad.enc,
            // stats.enc, passwords.enc, and the E2E keys. Requires the vault
            // to be unlocked (same UX gate as other sensitive prefs).
            if prefs.len() > 65536 {
                send(ServerEvent::Error { message: "Preferences too large (max 64KB)".into() });
            } else if serde_json::from_str::<serde_json::Value>(&prefs).is_err() {
                send(ServerEvent::Error { message: "Preferences not valid JSON".into() });
            } else if state.crypto.is_unlocked(username).await {
                match state.crypto.encrypt(username, prefs.as_bytes()).await {
                    Ok(enc) => {
                        let dir = std::path::PathBuf::from(&state.data_dir)
                            .join("users").join(&safe_username(username));
                        let _ = tokio::fs::create_dir_all(&dir).await;
                        // Only delete the legacy plaintext file AFTER the encrypted
                        // write succeeds, so a failed write (disk full, etc.) can't
                        // orphan the user's data.
                        match tokio::fs::write(dir.join("preferences.enc"), &enc).await {
                            Ok(_) => {
                                let _ = tokio::fs::remove_file(dir.join("preferences.json")).await;
                                // Broadcast to all sessions so other devices update instantly
                                state.send_to_user(username, ServerEvent::Preferences { prefs });
                            }
                            Err(e) => send(ServerEvent::Error { message: format!("Prefs save failed: {}", e) }),
                        }
                    }
                    Err(e) => send(ServerEvent::Error { message: format!("Prefs encrypt failed: {}", e) }),
                }
            }
            // Vault locked → drop silently (same policy as other encrypted prefs).
        }
        ClientMessage::LoadPreferences {} => {
            if state.crypto.is_unlocked(username).await {
                let dir = std::path::PathBuf::from(&state.data_dir)
                    .join("users").join(&safe_username(username));
                let enc_path = dir.join("preferences.enc");
                // Prefer the encrypted file if present
                if let Ok(enc) = tokio::fs::read_to_string(&enc_path).await {
                    if let Ok(pt) = state.crypto.decrypt(username, enc.trim()).await {
                        send(ServerEvent::Preferences { prefs: String::from_utf8_lossy(&pt).to_string() });
                    } else {
                        send(ServerEvent::Preferences { prefs: String::new() });
                    }
                } else {
                    // Legacy plaintext migration: if an old preferences.json exists
                    // from before prefs-encryption was added, read it, send it to
                    // the client, and re-encrypt it on disk. The client will also
                    // trigger a save on next prefs change which re-writes .enc too.
                    let legacy = dir.join("preferences.json");
                    if let Ok(data) = tokio::fs::read_to_string(&legacy).await {
                        send(ServerEvent::Preferences { prefs: data.clone() });
                        if let Ok(enc) = state.crypto.encrypt(username, data.as_bytes()).await {
                            let _ = tokio::fs::write(&enc_path, &enc).await;
                            let _ = tokio::fs::remove_file(&legacy).await;
                        }
                    }
                }
            } else {
                // Vault locked — return empty so client can proceed with defaults.
                send(ServerEvent::Preferences { prefs: String::new() });
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
            // Rate-limit: this handler scans the GLOBAL pastes dir (work proportional to
            // the server's total paste count, not the caller's data), so without a cap an
            // authenticated user could spam it at the 40/s socket limit for a global-
            // resource DoS. 10/60s is transparent for the rare, deliberate clear action.
            if state.auth.check_user_create_rate_limit(username, "cleardata").is_err() { return; }
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
        ClientMessage::ClearTargetLogs { conn_id, target } => {
            if !state.owns_network(username, &conn_id).await { return; }
            match state.logger.delete_target(username, &conn_id, &target).await {
                Ok(_) => {
                    state.send_to_user(username, ServerEvent::TargetCleared {
                        conn_id: conn_id.clone(),
                        target:  target.clone(),
                    });
                }
                Err(e) => send(ServerEvent::Error { message: format!("Clear failed: {}", e) }),
            }
        }
        ClientMessage::UploadListGet {} => {
            let records = upload::list_all_records(&state.data_dir, username).await;
            send(ServerEvent::UploadState { records });
        }
        ClientMessage::UploadRemove { id } => {
            if upload::remove_record(&state.data_dir, &state.upload_dir, username, &id).await {
                state.send_to_user(username, ServerEvent::UploadRemoved { id });
            }
        }
        ClientMessage::MonitorPush { nick, status } => {
            let safe_nick: String = nick.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '[' || *c == ']' || *c == '\\' || *c == '`' || *c == '^').take(32).collect();
            let safe_status = if status == "online" { "online" } else { "offline" };
            state.notifier.send_monitor_notification(username, &safe_nick, safe_status).await;
        }
        ClientMessage::SaveChannelOrder { conn_id, order } => {
            if !state.owns_network(username, &conn_id).await { return; }
            // Serialize this RMW behind the per-config lock like every other
            // get_network_config->save_network writer, so a concurrent
            // Join/Part/UpdateNetwork/Send/GenerateCert can't last-writer-wins clobber
            // it (or race the shared .tmp). This was the only remaining unguarded site.
            let _cfg_lock = network_config_lock(username, &conn_id);
            let _cfg_guard = _cfg_lock.lock().await;
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
            // Pass the authenticated username as the IP-dimension key so this password
            // verification uses an isolated ip:login:<username> bucket, not the single
            // shared ip:login:noip bucket (ip=None collapses to "noip"). Otherwise one
            // user's repeated DeleteAccount attempts fill the shared bucket and block
            // every other user's self-service deletion for the rest of the window.
            match state.auth.login(username, &password, Some(username)).await {
                Ok((temp_token, _)) => {
                    state.auth.logout(&temp_token); // L35: clean up orphaned session
                    // Full teardown: disconnect IRC connections + delete account data +
                    // clear all on-disk residue. Shared with the admin delete route so the
                    // two paths can't drift (see AppState::purge_account).
                    state.purge_account(username).await;
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
            // Clone the Arc out and DROP the DashMap Ref before awaiting the Mutex —
            // holding a shard read-guard across .await blocks same-shard insert/remove
            // (connect/disconnect) and risks deadlock. Matches every other call site.
            let conn = self.connections.get(&conn_id).map(|c| c.clone());
            if let Some(conn) = conn {
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
            // #20: clone the Arc out and drop the DashMap Ref before awaiting the
            // connection Mutex, so we never hold a shard read-guard across the await.
            let conn = self.connections.get(&cfg.id).map(|c| c.clone());
            let (connected, nick, channels, lag_ms) = if let Some(conn) = conn {
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
            // Kill any existing connection first to prevent duplicate sessions.
            // #20: clone the Arc out and drop the DashMap Ref before awaiting.
            let conn = self.connections.get(&id).map(|c| c.clone());
            if let Some(conn) = conn {
                let mut c = conn.lock().await;
                let reason = quit_reason_for(&cfg);
                // #24: defense-in-depth — strip CRLF from the reason at the send site too.
                let _ = c.send_raw(&format!("QUIT :{}\r\n", strip_crlf(reason))).await;
            }
            self.abort_connect_task(&id);
            self.connections.remove(&id);
            self.conn_owners.remove(&id);
            self.clear_disconnect_request(&id);
            // irc::connect() emits Connecting at the top of each attempt — don't double-emit here.
            let (s, u) = (self.clone(), username.to_string());
            let id2 = id.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) = irc::connect(id2, cfg, u, s).await { error!("{}", e); }
            });
            // Abort any predecessor handle displaced by a concurrent Connect/reconnect
            // for the same conn_id (see the Connect handler note). No-op in the normal
            // path since abort_connect_task above just emptied the slot.
            if let Some(old) = self.connect_tasks.insert(id, handle) { old.abort(); }
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

        // #24: sanitize free-text config fields at the trust boundary so a value
        // containing \r\n cannot smuggle extra IRC protocol lines when these are
        // later interpolated into raw commands (QUIT :<reason>, JOIN <chan> <key>,
        // auto-join, perform, etc.) — auto-replayed on every reconnect.
        if let Some(ref qm) = persisted.quit_message {
            persisted.quit_message = Some(strip_crlf(qm));
        }
        persisted.channel_keys = persisted.channel_keys.iter()
            .map(|(k, v)| (strip_crlf(k), strip_crlf(v)))
            .collect();
        persisted.nick     = strip_crlf(&persisted.nick);
        persisted.realname = strip_crlf(&persisted.realname);
        persisted.username = strip_crlf(&persisted.username);
        if let Some(ref ol) = persisted.oper_login {
            persisted.oper_login = Some(strip_crlf(ol));
        }
        persisted.auto_join = persisted.auto_join.iter().map(|c| strip_crlf(c)).collect();
        persisted.perform_commands = persisted.perform_commands.iter().map(|c| strip_crlf(c)).collect();
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

        // Atomic write: serialize to a temp file then rename over the target so a
        // crash mid-write can never leave a truncated/partial config on disk.
        let final_path = format!("{}/{}.json", dir, safe_id);
        let tmp_path   = format!("{}/{}.json.tmp", dir, safe_id);
        let body = serde_json::to_string_pretty(&persisted)?;
        tokio::fs::write(&tmp_path, body).await?;
        if let Err(e) = tokio::fs::rename(&tmp_path, &final_path).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e.into());
        }
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

    /// #34: count the user's saved network config files (cheap — no decrypt).
    pub async fn user_network_count(&self, username: &str) -> usize {
        let dir = format!("{}/networks/{}", self.data_dir, username);
        let mut count = 0usize;
        if let Ok(mut rd) = tokio::fs::read_dir(&dir).await {
            while let Ok(Some(e)) = rd.next_entry().await {
                if e.path().extension().map(|x| x == "json").unwrap_or(false) {
                    count += 1;
                }
            }
        }
        count
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

/// #7: create a directory (recursively) with mode 0700 so at-rest secrets are not
/// world-readable, regardless of the inherited umask. The mode applies to dirs
/// created by this call; parents that already exist are tightened by
/// `harden_dir_perms`.
fn create_dir_secure(path: &str) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

/// #7: best-effort chmod 0700 on a directory that may pre-exist with looser perms.
fn harden_dir_perms(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

/// #5/#74: Produce a log-safe rendering of an outgoing raw IRC command.
/// - Credential-bearing commands (services IDENTIFY/REGISTER/GHOST/REGAIN, OPER,
///   PASS) have their secret parameters replaced with <redacted> so passwords are
///   never written to journald.
/// - PRIVMSG/NOTICE bodies (which may carry non-E2E plaintext) are dropped — only
///   the verb + target are logged.
/// - Everything else is char-truncated to 80 chars (char-safe: never byte-slices
///   across a multibyte boundary, which could panic).
// ─── Per-network-config read-modify-write serialization (#4) ─────────────────
// JoinChannel/PartChannel/UpdateNetwork all do get_network_config → mutate →
// save_network. Without a lock, concurrent calls last-writer-wins and silently
// drop auto_join/channel_key updates. One async mutex per (username, network id)
// serializes that sequence. Mirrors upload.rs user_record_lock; file-local so it
// does not touch AppState.
fn network_config_locks() -> &'static DashMap<String, Arc<Mutex<()>>> {
    static LOCKS: std::sync::OnceLock<DashMap<String, Arc<Mutex<()>>>> = std::sync::OnceLock::new();
    LOCKS.get_or_init(DashMap::new)
}

/// Acquire (creating if needed) the per-config lock for one user's network.
pub(crate) fn network_config_lock(username: &str, conn_id: &str) -> Arc<Mutex<()>> {
    network_config_locks()
        .entry(format!("{}:{}", username, conn_id))
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

/// Drop idle per-network-config locks so the static map can't grow without bound
/// across AddNetwork/RemoveNetwork churn. An entry whose Arc has strong_count==1
/// is held only by the map (every caller of `network_config_lock` keeps a clone
/// for the duration of its critical section → count>=2), so removing it cannot
/// race a live read-modify-write. Called hourly from the background sweep.
fn prune_network_config_locks() {
    network_config_locks().retain(|_, v| Arc::strong_count(v) > 1);
}

pub fn redact_for_log(line: &str) -> String {
    let upper = line.to_uppercase();
    // OPER <login> <pass>  → redact everything after the verb
    if upper.starts_with("OPER ") {
        return "OPER <redacted>".to_string();
    }
    // PASS <pass>
    if upper.starts_with("PASS ") {
        return "PASS <redacted>".to_string();
    }
    // JOIN #chan <key> — the channel key is a shared secret; drop it (other redacted
    // commands cover PASS/OPER/services, but JOIN fell through to the default branch
    // which logged the key verbatim).
    if upper.starts_with("JOIN ") {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        let verb  = parts.first().copied().unwrap_or("JOIN");
        let chans = parts.get(1).copied().unwrap_or("");
        if parts.len() >= 3 && !parts[2].is_empty() {
            return format!("{} {} <key redacted>", verb, chans);
        }
        return format!("{} {}", verb, chans);
    }
    // AUTHENTICATE <base64 SASL payload> — manual SASL exchange carries credentials.
    if upper.starts_with("AUTHENTICATE") {
        return "AUTHENTICATE <redacted>".to_string();
    }
    // WEBIRC <pass> <gateway> <host> <ip> — first field is a shared password.
    if upper.starts_with("WEBIRC ") {
        return "WEBIRC <redacted>".to_string();
    }
    // SQUERY <service> :<text> — RFC-2812 "server query"; only ever addressed to a
    // service (ratbox-services), so the tail may carry account credentials. Mirrors the
    // client-side redactSensitive rule (E). Keep verb + service token, drop the rest.
    if upper.starts_with("SQUERY ") {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        let verb = parts.first().copied().unwrap_or("SQUERY");
        let svc  = parts.get(1).copied().unwrap_or("");
        return format!("{} {} <redacted>", verb, svc);
    }
    // PRIVMSG NICKSERV/CHANSERV :IDENTIFY/REGISTER/GHOST/REGAIN ...  (services auth)
    if upper.starts_with("PRIVMSG ") || upper.starts_with("NOTICE ") {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        let verb   = parts.first().copied().unwrap_or("");
        let target = parts.get(1).copied().unwrap_or("");
        let tgt_up = target.to_uppercase();
        // Strip an optional @server suffix (NickServ@services.net) before matching.
        let tgt_base = tgt_up.split('@').next().unwrap_or(&tgt_up);
        let is_services = matches!(tgt_base,
            "NICKSERV" | "NS" | "USERSERV" | "US" | "CHANSERV" | "CS" | "MEMOSERV" | "MS"
            | "OPERSERV" | "OS" | "HOSTSERV" | "HS" | "BOTSERV" | "BS");
        if is_services {
            // Convergent: any message to a service may carry a credential in some
            // subcommand — do NOT enumerate cred verbs (that blocklist is never
            // complete; mirrors client redactSensitive). Drop the whole body.
            return format!("{} {} :<redacted>", verb, target);
        }
        // Ordinary PRIVMSG/NOTICE: drop the body entirely (may be plaintext).
        return format!("{} {} :<{}B body redacted>", verb, target,
                       parts.get(2).map(|s| s.len()).unwrap_or(0));
    }
    // Bare service pseudo-command aliases: `NICKSERV IDENTIFY <pw>`, `NS IDENTIFY <pw>`,
    // `USERSERV LOGIN <acct> <pw>`, `CS SET PASSWORD ...` etc. (ratbox-services and others
    // accept the service name as a top-level command). These bypass the PRIVMSG/PASS/
    // AUTHENTICATE forms above and would otherwise hit the default truncation branch,
    // leaking the credential to logs.
    {
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        let verb = parts.first().copied().unwrap_or("");
        // Strip an optional @server suffix before matching the service name.
        let verb_base = verb.split('@').next().unwrap_or(verb).to_uppercase();
        let is_service = matches!(verb_base.as_str(),
            "NICKSERV" | "NS" | "USERSERV" | "US" | "CHANSERV" | "CS" | "MEMOSERV" | "MS"
            | "OPERSERV" | "OS" | "HOSTSERV" | "HS" | "BOTSERV" | "BS");
        let has_args = parts.get(1).map(|s| !s.trim().is_empty()).unwrap_or(false);
        if is_service && has_args {
            // Convergent: mask ALL args of any bare service-directed line (do NOT
            // enumerate credential subcommands — that blocklist is never complete and
            // missed e.g. SETPASS/SIDENTIFY/CONFIRM; mirrors client redactSensitive).
            return format!("{} <redacted>", verb);
        }
    }
    // Default: char-safe truncation to 80 chars.
    let truncated: String = line.chars().take(80).collect();
    truncated
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
            '\u{2028}' => out.push_str("\\u2028"),  // JS line terminators (pre-ES2019 break-out)
            '\u{2029}' => out.push_str("\\u2029"),
            _    => out.push(c),
        }
    }
    out
}
